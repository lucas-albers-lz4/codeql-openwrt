from __future__ import annotations

import contextlib
import hashlib
from http.client import HTTPResponse
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import uuid

from tools import canonical_source_preflight as preflight
from tools import event_corpus_manifest as route_oracle
from tools import full_tree_candidates as selector


ROOT = Path(__file__).resolve().parents[1]


def git_oid(kind: str, body: bytes) -> str:
    header = f"{kind} {len(body)}\0".encode("ascii")
    return hashlib.sha1(header + body, usedforsecurity=False).hexdigest()


def git_tree(children: list[tuple[str, str, str, str]]) -> str:
    payload = bytearray()
    for mode, kind, name, oid in sorted(
            children,
            key=lambda item: (item[2] + ("/" if item[1] == "tree" else "")).encode("utf-8")):
        payload.extend((mode.lstrip("0") or "0").encode("ascii") + b" " +
                       name.encode("utf-8") + b"\0" + bytes.fromhex(oid))
    return git_oid("tree", bytes(payload))


def api_row(path: str, mode: str, kind: str, oid: str) -> dict[str, str]:
    return {"path": path, "mode": mode, "type": kind, "sha": oid}


class CanonicalSourcePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = json.loads((ROOT / "docs/current-corpus-source-v0.6.json").read_bytes())
        self.event = {
            "kind": "default_branch_commit",
            "source_role": "incoming_default_branch_first_parent",
            "repository": "openwrt",
            "head_commit": "a" * 40,
            "head_tree": "b" * 40,
            "base_commit": "c" * 40,
            "base_tree": "d" * 40,
            "first_parent_commit": "c" * 40,
            "control_commit": "e" * 40,
            "policy_base_commit": self.policy["pins"]["openwrt"],
            "policy_sha256": preflight.POLICY_SHA256,
            "route_oracle_script_sha256": hashlib.sha256(
                Path(route_oracle.__file__).read_bytes()).hexdigest(),
            "selector_script_sha256": hashlib.sha256(
                Path(selector.__file__).read_bytes()).hexdigest(),
        }
        self.manifest = {
            "schema": "mvp-default-branch-commit-corpus-v1",
            "pins": {**self.policy["pins"], "openwrt": self.event["head_commit"]},
            "event": self.event,
        }

    def test_frozen_policy_and_event_derive_exact_source_pins(self):
        pins, controls = preflight.derive_pins(self.policy, self.manifest)
        self.assertEqual(pins, self.manifest["pins"])
        self.assertEqual(controls, {"event_base": "c" * 40,
                                    "event_control": "e" * 40})

    def test_control_must_be_distinct_from_event_source(self):
        self.event["control_commit"] = self.event["head_commit"]
        with self.assertRaisesRegex(preflight.PreflightError, "control must be distinct"):
            preflight.derive_pins(self.policy, self.manifest)

    def test_event_repo_is_fixed_to_openwrt(self):
        self.event["repository"] = "luci"
        with self.assertRaisesRegex(preflight.PreflightError, "requires an OpenWrt event"):
            preflight.derive_pins(self.policy, self.manifest)

    def test_manifest_cannot_substitute_non_event_policy_pin(self):
        self.manifest["pins"]["packages"] = "f" * 40
        with self.assertRaisesRegex(preflight.PreflightError, "source pins differ"):
            preflight.derive_pins(self.policy, self.manifest)

    def test_reconstructs_nested_and_empty_git_trees_and_returns_leaf_paths(self):
        leaf = git_oid("blob", b"inner\n")
        top = git_oid("blob", b"top\n")
        empty_oid = git_tree([])
        nested_oid = git_tree([("100644", "blob", "leaf.uc", leaf)])
        root_oid = git_tree([
            ("040000", "tree", "empty", empty_oid),
            ("040000", "tree", "nested", nested_oid),
            ("100644", "blob", "top.txt", top),
        ])
        document = {"sha": root_oid, "truncated": False, "tree": [
            api_row("empty", "040000", "tree", empty_oid),
            api_row("nested", "040000", "tree", nested_oid),
            api_row("nested/leaf.uc", "100644", "blob", leaf),
            api_row("top.txt", "100644", "blob", top),
        ]}
        leaves, tree_count = preflight._checked_tree_document(document, root_oid)
        self.assertEqual(tree_count, 3)
        self.assertEqual(set(leaves), {"nested/leaf.uc", "top.txt"})
        self.assertEqual(leaves["nested/leaf.uc"], ("100644", "blob", leaf))

    def test_rejects_truncated_and_duplicate_tree_rows(self):
        empty_oid = git_tree([])
        root_oid = git_tree([("040000", "tree", "empty", empty_oid)])
        row = api_row("empty", "040000", "tree", empty_oid)
        with self.assertRaisesRegex(preflight.PreflightError, "truncated"):
            preflight._checked_tree_document(
                {"sha": root_oid, "truncated": True, "tree": [row]}, root_oid)
        with self.assertRaisesRegex(preflight.PreflightError, "duplicate"):
            preflight._checked_tree_document(
                {"sha": root_oid, "truncated": False, "tree": [row, row]}, root_oid)

    def test_rejects_unlisted_tree_descendant_and_bad_mode_type_pair(self):
        leaf = git_oid("blob", b"leaf")
        nested_oid = git_tree([("100644", "blob", "leaf", leaf)])
        root_oid = git_tree([("040000", "tree", "nested", nested_oid)])
        omitted = {"sha": root_oid, "truncated": False,
                   "tree": [api_row("nested", "040000", "tree", nested_oid)]}
        with self.assertRaisesRegex(preflight.PreflightError, "tree object hash differs"):
            preflight._checked_tree_document(omitted, root_oid)
        bad_pair = {"sha": root_oid, "truncated": False,
                    "tree": [api_row("nested", "999999", "tree", nested_oid)]}
        with self.assertRaisesRegex(preflight.PreflightError, "mode or type"):
            preflight._checked_tree_document(bad_pair, root_oid)

    def test_recipe_review_and_outside_signal_statuses_stay_partial(self):
        self.assertEqual(
            preflight._final_status("canonical_api_tree_delta_verified", True, 3),
            ("canonical_source_verified_source_oracle_partial", 3))
        self.assertEqual(
            preflight._final_status("recipe_delta_requires_review", True, 0),
            ("policy_base_recipe_delta_requires_review", 4))
        self.assertEqual(
            preflight._final_status("unresolved", False, 3),
            ("policy_base_provenance_unresolved", 4))

    def test_http_read_preserves_chunk_framing_and_checks_content_length(self):
        class MemorySocket:
            def __init__(self, response_bytes: bytes):
                self.stream = io.BytesIO(response_bytes)

            def makefile(self, _mode):
                return self.stream

            def settimeout(self, _seconds):
                return None

        class URLResponse(HTTPResponse):
            def geturl(self):
                return self.url

        url = preflight.API_ROOT + "/git/commits/" + "a" * 40
        framed = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                  b"Content-Type: application/json\r\n\r\n"
                  b"7\r\n{\"x\":1}\r\n0\r\n\r\n")
        response = URLResponse(MemorySocket(framed))
        response.begin()
        response.url = url
        body, _ = preflight._read_api_response(response, url, 1024,
                                               preflight.time.monotonic() + 5)
        self.assertEqual(body, b'{"x":1}')

        short = URLResponse(MemorySocket(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"))
        short.begin()
        short.url = url
        with self.assertRaisesRegex(preflight.PreflightError, "Content-Length"):
            preflight._read_api_response(short, url, 1024,
                                         preflight.time.monotonic() + 5)

    def test_tree_pair_passes_fixed_commit_and_tree_requests_through_api_seam(self):
        base_data, head_data = b"base\n", b"head\n"
        base_blob, head_blob = git_oid("blob", base_data), git_oid("blob", head_data)
        base_tree = git_tree([("100644", "blob", "README.md", base_blob)])
        head_tree = git_tree([("100644", "blob", "README.md", head_blob)])
        base_commit, head_commit = preflight.POLICY_BASE_COMMIT, "a" * 40
        responses = [
            json.dumps({"sha": base_commit, "tree": {"sha": base_tree}}).encode(),
            json.dumps({"sha": base_tree, "truncated": False,
                        "tree": [api_row("README.md", "100644", "blob", base_blob)]}).encode(),
            json.dumps({"sha": head_commit, "tree": {"sha": head_tree}}).encode(),
            json.dumps({"sha": head_tree, "truncated": False,
                        "tree": [api_row("README.md", "100644", "blob", head_blob)]}).encode(),
        ]
        calls = []

        def fake_get(url, token, *, limit, home, tmp):
            calls.append((url, token, limit, home, tmp))
            raw = responses[len(calls) - 1]
            return raw, {"url": url, "status": 200, "redirects_followed": 0,
                         "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_dir = root / "api"
            api_dir.mkdir()
            home = root / "home"
            tmp = root / "tmp"
            home.mkdir()
            tmp.mkdir()
            direct = {"status": "direct_sha_fetch_failed", "local_cache_used": False}
            with mock.patch.object(preflight, "POLICY_BASE_TREE", base_tree), \
                    mock.patch.object(preflight, "_api_get", side_effect=fake_get):
                delta, _raw = preflight._canonical_tree_pair(
                    base_commit, head_commit, api_dir=api_dir, token="t" * 32,
                    policy=self.policy, direct_git_fetch=direct, home=home, tmp=tmp)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(call[3] == home and call[4] == tmp for call in calls))
        self.assertEqual(["/git/commits/" in call[0] for call in calls],
                         [True, False, True, False])
        self.assertEqual(delta["changed_path_count"], 1)
        self.assertEqual(delta["status"], "canonical_api_tree_delta_verified")
        self.assertFalse(delta["policy_base_git_commit_object_acquired"])

    def test_offline_run_wiring_keeps_source_verifier_partial_separate_from_fetch(self):
        work_layout = tempfile.TemporaryDirectory(prefix="preflight-work-layout-")
        self.addCleanup(work_layout.cleanup)
        ledger_root = Path(work_layout.name) / "ledger"
        work_root = ledger_root / "work"
        consumer_root = work_root / "consumer"
        consumer_root.mkdir(parents=True)
        (ledger_root / "AGENTS.md").write_text("synthetic ledger fixture\n")
        cache_root = work_root / ("canonical-source-launcher-cache-" + uuid.uuid4().hex)
        cache_root.mkdir(mode=0o700)
        os.chmod(cache_root, 0o700)
        run_root = work_root / ("preflight-contract-" + uuid.uuid4().hex)
        scratch = tempfile.TemporaryDirectory(prefix="preflight-inputs-")
        self.addCleanup(scratch.cleanup)
        self.addCleanup(lambda: shutil.rmtree(run_root, ignore_errors=True))
        event = dict(self.event)
        manifest = {"schema": "mvp-default-branch-commit-corpus-v1",
                    "pins": dict(self.manifest["pins"]), "event": event,
                    "selected": [], "excluded": []}
        manifest_raw = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
        manifest_path = Path(scratch.name) / "manifest.json"
        manifest_path.write_bytes(manifest_raw)
        coverage = {"schema": "ucode-default-branch-corpus-coverage-v1",
                    "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                    "source_pins": manifest["pins"], "event": event}
        coverage_path = Path(scratch.name) / "coverage.json"
        coverage_path.write_text(json.dumps(coverage))
        routing_path = Path(scratch.name) / "routing.json"
        routing_path.write_text(json.dumps({"decisions": []}))
        args = SimpleNamespace(run_root=Path(run_root.name),
                               policy=ROOT / "docs/current-corpus-source-v0.6.json",
                               manifest=manifest_path,
                               coverage=coverage_path, routing=routing_path)

        def fake_acquire(repo, commit, checkout, **_kwargs):
            checkout.mkdir(mode=0o700)
            base_object = {"commit": event["base_commit"], "tree": event["base_tree"]}
            extra = ({"event_base": base_object,
                      "event_control": {"commit": event["control_commit"],
                                        "tree": event["base_tree"]}}
                     if repo == "openwrt" else {})
            return {"commit": commit,
                    "tree": event["head_tree"] if repo == "openwrt" else "f" * 40,
                    "object_store_bytes": 100, "materialized_worktree_bytes": 100,
                    "additional_objects": extra,
                    "direct_only_fetches": {"policy_base": {
                        "status": "direct_sha_fetch_failed", "local_cache_used": False}}
                    if repo == "openwrt" else {},
                    "commit_parent_records": {"parents": [event["first_parent_commit"]]}
                    if repo == "openwrt" else None}

        oracle = {"status": "bounded_selected_excluded_match", "selected": 128,
                  "excluded": 13, "route_classes": {"plain": 93, "markup": 35},
                  "tracked_candidate_signals_accounted_for": False,
                  "canonical_git_provenance_verified": False,
                  "source_candidates_outside_frozen_denominator": [{"repo": "packages"} for _ in range(17)]}
        oracle_raw = (json.dumps(oracle) + "\n").encode()

        def fake_oracle(_snapshots, _checkouts, root, _home, _tmp, *, timeout):
            preflight._write_exclusive(root / "source-oracle.json", oracle_raw)
            return 3, oracle_raw, b"", 0.01, ["python3", "-m", "tools.default_branch_source_truth"]

        delta = {"status": "canonical_api_tree_delta_verified",
                 "canonical_api_tree_delta_verified": True,
                 "recipe_delta_clear_under_frozen_policy": True,
                 "base_tree": preflight.POLICY_BASE_TREE,
                 "head_tree": event["head_tree"]}
        with mock.patch.object(preflight, "ROOT", consumer_root), \
                mock.patch.dict(os.environ, {"PYTHONPYCACHEPREFIX": str(cache_root)}), \
                mock.patch.object(preflight.shutil, "disk_usage",
                                  return_value=SimpleNamespace(free=20_000_000_000)), \
                mock.patch.object(preflight, "_base_checkout_receipt", return_value={"commit": preflight.BASE_COMMIT}), \
                mock.patch.object(preflight, "_acquire_repository", side_effect=fake_acquire), \
                mock.patch.object(preflight, "_api_token", return_value="t" * 32), \
                mock.patch.object(preflight, "_canonical_tree_pair", return_value=(delta, {})), \
                mock.patch.object(preflight, "_run_oracle", side_effect=fake_oracle), \
                mock.patch.object(preflight, "_git_text", return_value=("", {})), \
                mock.patch.object(preflight, "_is_read_only", return_value=True):
            code, receipt = preflight.run(args)
        self.assertEqual(code, preflight.EXIT_SOURCE_PARTIAL)
        self.assertEqual(receipt["status"], "canonical_source_verified_source_oracle_partial")
        self.assertEqual(receipt["source_oracle"]["outside_frozen_denominator_count"], 17)
        self.assertEqual(receipt["source_oracle"]["exit_code"], 3)
        self.assertTrue((run_root / "preflight-receipt.json").is_file())

    def test_api_paths_are_fixed_and_redirect_handler_does_not_follow(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with self.assertRaisesRegex(preflight.PreflightError, "fixed OpenWrt"):
                preflight._api_get("https://example.invalid/commits/" + "a" * 40,
                                   "x" * 32, limit=1024, home=home, tmp=home)
        handler = preflight.NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "found", {},
                                                   "https://other.invalid/path"))

    def test_run_root_traversal_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory(prefix="preflight-work-layout-") as directory:
            ledger_root = Path(directory) / "ledger"
            work_root = ledger_root / "work"
            consumer_root = work_root / "consumer"
            consumer_root.mkdir(parents=True)
            (ledger_root / "AGENTS.md").write_text("synthetic ledger fixture\n")
            with mock.patch.object(preflight, "ROOT", consumer_root):
                with self.assertRaisesRegex(preflight.PreflightError, "traversal"):
                    preflight._allowed_run_root(Path("../outside"))
                with self.assertRaisesRegex(preflight.PreflightError, "traversal"):
                    preflight._allowed_run_root(Path("/tmp/../outside"))

    def test_cli_summary_reports_api_base_commit_and_git_acquisition(self):
        receipt = {
            "status": "canonical_source_verified_source_oracle_partial",
            "run_root": "/tmp/canonical-source-run-test",
            "source_oracle": None,
            "policy_base_provenance": {
                "status": "canonical_api_tree_delta_verified",
                "base_commit": preflight.POLICY_BASE_COMMIT,
                "policy_base_git_commit_object_acquired": True,
                "recipe_delta_clear_under_frozen_policy": True,
            },
        }
        output = io.StringIO()
        with mock.patch.object(preflight, "run", return_value=(3, receipt)), \
                contextlib.redirect_stdout(output):
            code = preflight.main(["--run-root", "r", "--manifest", "m",
                                   "--coverage", "c", "--routing", "t"])
        summary = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(summary["policy_base_provenance"]["policy_base_commit"],
                         preflight.POLICY_BASE_COMMIT)
        self.assertTrue(summary["policy_base_provenance"][
            "policy_base_git_commit_object_acquired"])

    def test_exclusive_writer_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                preflight._write_exclusive(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
