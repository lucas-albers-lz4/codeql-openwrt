"""Synthetic API controls over a genuinely signed fixture start and queue."""

import copy
import json
import os
import shutil
from contextlib import contextmanager
from datetime import UTC, datetime
from unittest import TestCase
from unittest.mock import patch

from tools import default_branch_authenticated_start as authenticated
from tools import default_branch_backlog_issued as issued
from tools import default_branch_failed_execution_capture as failure
from tools import default_branch_private_final_capture as custody
from tools import default_branch_private_start as private
from tools import default_branch_reservation_reconcile as reconcile
from tools import test_default_branch_authenticated_start as fixtures


class FailedExecutionCaptureTests(TestCase):
    def setUp(self):
        self.fixture = fixtures.AuthenticatedStartTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.run = json.loads((self.fixture.observation / "run-api.json").read_bytes())
        self.job = json.loads(
            (self.fixture.observation / "jobs-api.json").read_bytes()
        )["jobs"][0]
        self.run.update(
            status="completed", conclusion="failure", updated_at="2026-11-26T12:01:03Z"
        )
        self.job.update(
            status="completed",
            conclusion="failure",
            completed_at="2026-11-26T12:01:02Z",
        )
        self.first = {"run": self.run, "jobs": {"jobs": [self.job], "total_count": 1}}
        self.second = copy.deepcopy(self.first)
        self.urls = []
        self.endpoint = f"repos/{reconcile.REPOSITORY}/actions/runs/9"
        self.endpoints = {
            self.endpoint: "run",
            self.endpoint + "/attempts/1/jobs?per_page=100": "jobs",
        }

    def _network(self):
        def fetch(endpoint, limit):
            self.assertEqual(limit, reconcile.MAX_API)
            role = self.endpoints[endpoint]
            stage = self.first if len(self.urls) < 2 else self.second
            self.urls.append(endpoint)
            raw = issued.canonical_bytes(stage[role])
            return raw, {
                "endpoint": endpoint,
                "http_status": 200,
                "size": len(raw),
                "sha256": issued.digest(raw),
            }

        return fetch

    def capture(self):
        self.urls = []
        with patch.object(
            private, "_root_is_durable", return_value=self.root
        ), patch.object(failure, "_network", self._network), patch.object(
            custody,
            "_now",
            return_value=datetime(2026, 11, 26, 12, 1, 4, tzinfo=UTC),
        ):
            return failure.capture_failed_execution(self.root, fixtures.TEST_KEY, 9, 1)

    def capture_dirs(self):
        parent = self.root / failure.CAPTURE_DIR
        return sorted(parent.iterdir()) if parent.exists() else []

    def test_signed_failure_without_artifact_and_exact_custody(self):
        before = self.fixture.db.read_bytes()
        with patch.object(issued, "issue_terminal", side_effect=AssertionError("CAS")):
            result = self.capture()
        self.assertEqual(self.fixture.db.read_bytes(), before)
        self.assertEqual(result["status"], "verified_failed_execution_bytes")
        self.assertFalse(result["terminal_action_issued"])
        self.assertEqual(result["terminal"]["run_conclusion"], "failure")
        self.assertEqual(self.urls, list(self.endpoints) * 2)
        directory = self.root / result["capture_path"]
        self.assertEqual(
            {path.name for path in directory.iterdir()},
            {
                "manifest.json",
                "first-run-api.json",
                "first-jobs-api.json",
                "second-run-api.json",
                "second-jobs-api.json",
                "receipt.json",
            },
        )
        self.assertEqual(
            issued.digest((directory / "receipt.json").read_bytes()),
            result["receipt_sha256"],
        )
        manifest_raw = (directory / "manifest.json").read_bytes()
        receipt = json.loads((directory / "receipt.json").read_bytes())
        self.assertEqual(receipt["invocation_id"], result["invocation_id"])
        self.assertEqual(receipt["manifest_sha256"], issued.digest(manifest_raw))
        self.assertEqual(json.loads(manifest_raw)["invocation_id"], result["invocation_id"])
        self.assertEqual(json.loads(manifest_raw)["reservation_sha256"],
                         authenticated.verify_authenticated_start(self.root, fixtures.TEST_KEY)["reservation_sha256"])

    def test_same_execution_new_invocation_and_collision_rejected(self):
        first = self.capture()
        second = self.capture()
        self.assertNotEqual(first["invocation_id"], second["invocation_id"])
        self.assertNotEqual(first["capture_path"], second["capture_path"])
        self.assertEqual(len(self.capture_dirs()), 2)
        with patch.object(failure.secrets, "token_hex", return_value=first["invocation_id"]), self.assertRaises(failure.FailedExecutionError):
            self.capture()
        self.assertEqual(self.urls, [])
        self.assertEqual(len(self.capture_dirs()), 2)

    def test_active_success_and_inconsistent_failure_matrix(self):
        for run_status, run_conclusion, job_conclusion in (
            ("in_progress", None, None),
            ("completed", "success", "success"),
            ("completed", "failure", "cancelled"),
            ("completed", "failure", "success"),
        ):
            with self.subTest(
                run_conclusion=run_conclusion, job_conclusion=job_conclusion
            ):
                self.first["run"]["status"] = run_status
                self.first["run"]["conclusion"] = run_conclusion
                self.first["jobs"]["jobs"][0]["conclusion"] = job_conclusion
                with self.assertRaises(failure.FailedExecutionError):
                    self.capture()
                # The failed capture owns its path; discard only fixture output.
                shutil.rmtree(self.root / failure.CAPTURE_DIR)

    def test_cancelled_and_timed_out_pairs(self):
        for conclusion in ("cancelled", "timed_out"):
            with self.subTest(conclusion=conclusion):
                for stage in (self.first, self.second):
                    stage["run"]["conclusion"] = conclusion
                    stage["jobs"]["jobs"][0]["conclusion"] = conclusion
                result = self.capture()
                self.assertEqual(result["terminal"]["run_conclusion"], conclusion)
                self.assertEqual(result["terminal"]["job_conclusion"], conclusion)
                shutil.rmtree(self.root / failure.CAPTURE_DIR)

    def test_attempt_job_head_and_listing_controls(self):
        for role, key, value in (
            ("run", "run_attempt", 2),
            ("jobs", "id", 34),
            ("jobs", "run_attempt", 2),
            ("run", "head_sha", "f" * 40),
            ("run", "workflow_id", 1),
        ):
            with self.subTest(role=role, key=key):
                target = (
                    self.first[role] if role == "run" else self.first["jobs"]["jobs"][0]
                )
                original = target[key]
                target[key] = value
                with self.assertRaises(failure.FailedExecutionError):
                    self.capture()
                target[key] = original
                shutil.rmtree(self.root / failure.CAPTURE_DIR)
        self.first["jobs"]["total_count"] = 2
        with self.assertRaises(failure.FailedExecutionError):
            self.capture()

    def test_second_observation_drift_and_stale_head(self):
        self.second["run"]["conclusion"] = "cancelled"
        self.second["jobs"]["jobs"][0]["conclusion"] = "cancelled"
        with self.assertRaises(failure.FailedExecutionError):
            self.capture()
        shutil.rmtree(self.root / failure.CAPTURE_DIR)
        self.second = copy.deepcopy(self.first)
        original = authenticated.verify_authenticated_start
        calls = 0

        def stale(root, key):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.fixture.db.write_bytes(b"changed")
            return original(root, key)

        with patch.object(
            authenticated, "verify_authenticated_start", side_effect=stale
        ), self.assertRaises(failure.FailedExecutionError):
            self.capture()

    def test_sequence_two_before_start_reread(self):
        original = failure._start_bytes
        advanced = False

        def advance(root, key, expected):
            nonlocal advanced
            if not advanced:
                advanced = True
                att = self.fixture.fixture._terminal_attestation("failed_execution")
                issued.issue_terminal(
                    root, 1, expected["start_sha256"], key, att, "2026-11-26T12:02:00Z"
                )
            return original(root, key, expected)

        with patch.object(
            failure, "_start_bytes", side_effect=advance
        ), self.assertRaises(failure.FailedExecutionError):
            self.capture()
        self.assertTrue(advanced)
        self.assertFalse((self.root / failure.CAPTURE_DIR).exists())

    def test_late_directory_check_fails_before_receipt_publication(self):
        original = custody._directory

        @contextmanager
        def changed_mode(parent, name, **kwargs):
            with original(parent, name, **kwargs) as descriptor:
                yield descriptor
                if isinstance(name, str) and name.startswith("default-branch-failed-9-1-"):
                    os.fchmod(descriptor, 0o755)

        with patch.object(custody, "_directory", changed_mode), self.assertRaises(
            failure.FailedExecutionError
        ):
            self.capture()
        self.assertEqual(len(self.capture_dirs()), 1)
        self.assertFalse((self.capture_dirs()[0] / "receipt.json").exists())

    def test_extra_entry_and_published_readback_failure(self):
        original_write = custody._write

        def extra(parent, name, raw, limit):
            result = original_write(parent, name, raw, limit)
            if name == custody.PENDING_RECEIPT:
                descriptor = os.open(
                    "extra", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=parent
                )
                os.close(descriptor)
            return result

        with patch.object(custody, "_write", side_effect=extra), self.assertRaises(
            failure.FailedExecutionError
        ):
            self.capture()
        directory = self.capture_dirs()[0]
        self.assertFalse((directory / "receipt.json").exists())
        shutil.rmtree(self.root / failure.CAPTURE_DIR)

        original_read = custody._read
        published = False
        original_publish = custody._publish_receipt

        def publish(parent, raw):
            nonlocal published
            original_publish(parent, raw)
            published = True

        def unreadable(parent, name, limit, **kwargs):
            if published and name == custody.RECEIPT:
                raise custody.CaptureError("fixture readback failure")
            return original_read(parent, name, limit, **kwargs)

        with (
            patch.object(custody, "_publish_receipt", side_effect=publish),
            patch.object(custody, "_read", side_effect=unreadable),
            self.assertRaises(failure.FailedExecutionError),
        ):
            self.capture()
        self.assertTrue(published)
        self.assertEqual(len(self.capture_dirs()), 1)
        self.assertFalse((self.capture_dirs()[0] / "receipt.json").exists())

    def test_transport_redirect_and_partial_custody(self):
        def interrupted():
            calls = 0

            def fetch(_endpoint, _limit):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raw = issued.canonical_bytes(self.first["run"])
                    return raw, {
                        "endpoint": _endpoint,
                        "http_status": 200,
                        "size": len(raw),
                        "sha256": issued.digest(raw),
                    }
                raise custody.CaptureError("canonical metadata interrupted")

            return fetch

        with patch.object(failure, "_network", interrupted), patch.object(
            private, "_root_is_durable", return_value=self.root
        ), self.assertRaises(failure.FailedExecutionError):
            failure.capture_failed_execution(self.root, fixtures.TEST_KEY, 9, 1)
        directory = self.capture_dirs()[0]
        self.assertEqual(
            {path.name for path in directory.iterdir()}, {"manifest.json", "first-run-api.json"}
        )
        retried = self.capture()
        self.assertNotEqual(directory, self.root / retried["capture_path"])

        with patch.object(
            custody,
            "_curl",
            return_value=(302, [b"https://example.invalid/redirect"], b""),
        ), self.assertRaises(custody.CaptureError):
            custody._fetch_metadata(self.endpoint, reconcile.MAX_API, "fixture-token")
