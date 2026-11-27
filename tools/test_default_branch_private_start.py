"""Local fake-GitHub controls for the private default-branch start launcher."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools import default_branch_private_start as start
from tools import test_default_branch_live_observation as live_test_support
from tools import test_default_branch_reservation_reconcile as reconcile_fixtures


CONSUMER_HEAD = '456359574bbf3a5346d8d51cc5ddd9588ba930d0'
TEST_KEY = b'private-launcher-test-key-material-32-bytes'


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class DefaultBranchPrivateStartTests(unittest.TestCase):
    def setUp(self):
        live_tests = live_test_support.DefaultBranchLiveObservationTests()
        self.live_tests = live_tests
        with patch.object(reconcile_fixtures, 'CONSUMER_HEAD', CONSUMER_HEAD):
            live_tests.setUp()
        self.addCleanup(live_tests.doCleanups)
        action, _ = live_tests.fixture._action()
        self.policy = {
            'schema': start.POLICY_SCHEMA,
            'status': 'approved',
            'queue_id': action['queue_id'],
            'consumer_repository': start.REPOSITORY,
            'consumer_commit': CONSUMER_HEAD,
            'release_lock_sha256': _sha(
                (Path(__file__).resolve().parents[1] / 'docs/r3-release-lock.json').read_bytes()),
            'workflow': start.WORKFLOW,
            'job': start.JOB,
            'approval': {
                'approver': 'independent-reviewer@example.test',
                'source': 'independent_human_review',
                'reference': 'mvp-review-record-2026-11-26',
                'approved_at': '2026-11-26T00:00:00Z',
            },
        }
        self.policy_path = live_tests.root / start.POLICY_NAME
        self._write_policy(self.policy)
        self.key_path = live_tests.root / start.KEY_NAME
        self.key_path.write_bytes(TEST_KEY)
        self.key_path.chmod(0o600)
        self.run = dict(live_tests.run)
        self.jobs = dict(live_tests.jobs)
        self.early_zip = live_tests._zip(live_tests._early_members())
        self.artifacts = live_tests._artifacts(self.early_zip)
        self.responses = [
            _json_bytes(self.run), _json_bytes(self.jobs),
            _json_bytes(self.artifacts), self.early_zip,
            _json_bytes(self.run), _json_bytes(self.jobs),
        ]
        self.api_root = Path(live_tests.fixture.parent) / 'fake-gh'
        self.api_root.mkdir(mode=0o700)
        self.gh_path = self.api_root / 'gh-fake'
        self.counter = self.api_root / 'counter'
        self.log = self.api_root / 'argv.jsonl'
        self.response_paths = []
        self._write_responses(self.responses)
        self._write_fake_gh()
        self.repo_root = Path(__file__).resolve().parents[1]

    def _write_policy(self, policy):
        self.policy_path.write_bytes(_json_bytes(policy))
        self.policy_path.chmod(0o600)

    def _write_responses(self, responses):
        self.counter.write_text('0')
        self.log.unlink(missing_ok=True)
        self.response_paths = []
        for index, raw in enumerate(responses):
            path = self.api_root / f'response-{index}.bin'
            path.write_bytes(raw)
            path.chmod(0o600)
            self.response_paths.append(path)

    def _write_fake_gh(self, extra=''):
        script = f'''#!{sys.executable}
from pathlib import Path
import json, os, sys
root = Path(os.environ['FAKE_GH_ROOT'])
counter = root / 'counter'
index = int(counter.read_text())
counter.write_text(str(index + 1))
with (root / 'argv.jsonl').open('a') as handle:
    handle.write(json.dumps(sys.argv[1:]) + '\\n')
{extra}
sys.stdout.buffer.write((root / f'response-{{index}}.bin').read_bytes())
'''
        self.gh_path.write_text(script)
        self.gh_path.chmod(0o700)

    def _launch(self, *, run_id=None, attempt=1, **kwargs):
        return start.launch(
            self.live_tests.root,
            self.live_tests.run_id if run_id is None else run_id,
            attempt, gh_path=str(self.gh_path),
            env_overrides={'FAKE_GH_ROOT': str(self.api_root)},
            repository_root=self.repo_root,
            enforce_durable_root=False,
            enforce_checkout=False,
            **kwargs)

    def _assert_no_issue(self):
        with closing(sqlite3.connect(self.live_tests.fixture.database)) as db:
            self.assertEqual(db.execute('SELECT seq,hash FROM issued_head').fetchone(),
                             (0, issued.ZERO_HASH))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM issued_actions').fetchone()[0], 0)

    def test_positive_fetches_retains_six_exact_bodies_then_reads_key_and_cas(self):
        class FixtureDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 11, 26, 12, 0, 1, tzinfo=timezone.utc)

        original_read_key = start._read_key
        original_issue_start = issued.issue_start
        original_fsync_directory = start._fsync_directory
        observed = {'key': False}
        fsync_order = []

        def read_key_after_custody(root):
            capture = root / start.OBSERVATION_DIR / \
                f'default-branch-start-{self.live_tests.run_id}-1'
            receipt = capture / 'receipt.json'
            self.assertTrue(receipt.is_file())
            record = json.loads(receipt.read_bytes())
            self.assertEqual(set(record['raw_files']), {
                'run', 'jobs', 'artifacts', 'early_artifact_zip',
                'recheck_run', 'recheck_jobs',
            })
            expected = {
                'run': self.responses[0],
                'jobs': self.responses[1],
                'artifacts': self.responses[2],
                'early_artifact_zip': self.responses[3],
                'recheck_run': self.responses[4],
                'recheck_jobs': self.responses[5],
            }
            for key, raw in expected.items():
                item = record['raw_files'][key]
                retained = root / item['path']
                self.assertEqual(retained.read_bytes(), raw)
                self.assertEqual(item['size'], len(raw))
                self.assertEqual(item['sha256'], _sha(raw))
            observed['key'] = True
            return original_read_key(root)

        def issue_after_key(*args, **kwargs):
            self.assertTrue(observed['key'])
            return original_issue_start(*args, **kwargs)

        def record_fsync(path):
            fsync_order.append(Path(path))
            return original_fsync_directory(path)

        with patch.object(start, '_read_key', side_effect=read_key_after_custody), \
             patch.object(issued, 'issue_start', side_effect=issue_after_key), \
             patch.object(start, '_fsync_directory', side_effect=record_fsync), \
             patch.object(start, 'datetime', FixtureDateTime):
            result = self._launch()

        self.assertEqual(result['status'], 'issued_start')
        self.assertEqual(result['fetch_count'], 6)
        self.assertEqual(result['run_id'], self.live_tests.run_id)
        self.assertEqual(result['job_id'], 700)
        self.assertTrue(observed['key'])
        capture = self.live_tests.root / start.OBSERVATION_DIR / \
            f'default-branch-start-{self.live_tests.run_id}-1'
        self.assertEqual(stat.S_IMODE(capture.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((capture / 'receipt.json').stat().st_mode), 0o600)
        commands = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(commands), 6)
        self.assertEqual([item[-1] for item in commands], [
            f'repos/{start.REPOSITORY}/actions/runs/{self.live_tests.run_id}',
            f'repos/{start.REPOSITORY}/actions/runs/{self.live_tests.run_id}/jobs?per_page=100',
            f'repos/{start.REPOSITORY}/actions/runs/{self.live_tests.run_id}/artifacts?per_page=100',
            f'repos/{start.REPOSITORY}/actions/artifacts/9000/zip',
            f'repos/{start.REPOSITORY}/actions/runs/{self.live_tests.run_id}',
            f'repos/{start.REPOSITORY}/actions/runs/{self.live_tests.run_id}/jobs?per_page=100',
        ])
        self.assertEqual(fsync_order[:3], [
            self.live_tests.root,
            self.live_tests.root / start.OBSERVATION_DIR,
            capture,
        ])
        self.assertEqual(fsync_order[-1], capture)

    def test_private_policy_queue_mismatch_fails_before_receipt_key_or_signer(self):
        wrong = dict(self.policy)
        wrong['queue_id'] = 'f' * 32
        self._write_policy(wrong)
        with patch.object(start, '_read_key', side_effect=AssertionError('key read')), \
             patch.object(issued, 'issue_start', side_effect=AssertionError('signed')):
            with self.assertRaisesRegex(start.PrivateStartError, 'approved private policy'):
                self._launch()
        self._assert_no_issue()
        self.assertFalse((self.live_tests.root / start.OBSERVATION_DIR).exists())

    def test_synthetic_completed_run_and_job_are_rejected_before_key_or_signer(self):
        completed_run = dict(self.run, status='completed', conclusion='success')
        completed_jobs = json.loads(_json_bytes(self.jobs))
        completed_jobs['jobs'][0].update(status='completed', conclusion='success')
        self._write_responses([
            _json_bytes(completed_run), _json_bytes(completed_jobs),
            _json_bytes(self.artifacts),
        ])
        with patch.object(start, '_read_key', side_effect=AssertionError('key read')), \
             patch.object(issued, 'issue_start', side_effect=AssertionError('signed')):
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'initial canonical GitHub observation'):
                self._launch()
        self.assertEqual(int(self.counter.read_text()), 3)
        self._assert_no_issue()
        self.assertFalse((self.live_tests.root / start.OBSERVATION_DIR).exists())

    def test_actual_completed_run_45875169837_is_a_local_rejection_control(self):
        ledger_work = self.repo_root.parent
        capture = ledger_work / 'default-branch-early-live-retry-20261126'
        reconcile_dir = capture / 'reconcile-work' / \
            'reservation-reconcile-45875169837-1-pnjqa4sb'
        observation = capture / 'live-observation'
        required = [
            reconcile_dir / 'run-api.json', reconcile_dir / 'jobs-api.json',
            observation / 'artifacts-api.json', observation / 'early.zip',
        ]
        if not all(path.is_file() for path in required):
            self.skipTest('actual completed-run 45875169837 raw capture is unavailable')
        self._write_responses([
            required[0].read_bytes(), required[1].read_bytes(),
            required[2].read_bytes(),
        ])
        with patch.object(start, '_read_key', side_effect=AssertionError('key read')), \
             patch.object(issued, 'issue_start', side_effect=AssertionError('signed')):
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'initial canonical GitHub observation'):
                self._launch(run_id=45875169837)
        self.assertEqual(int(self.counter.read_text()), 3)
        self._assert_no_issue()
        self.assertFalse((self.live_tests.root / start.OBSERVATION_DIR).exists())

    def test_changed_policy_during_second_fetch_fails_before_key_or_signer(self):
        changed = dict(self.policy)
        changed['approval'] = dict(self.policy['approval'],
                                   reference='changed-after-preflight')
        changed_path = self.api_root / 'changed-policy.json'
        changed_path.write_bytes(_json_bytes(changed))
        changed_path.chmod(0o600)
        self._write_fake_gh(extra='''
if index == 5:
    Path(os.environ['FAKE_GH_POLICY']).write_bytes(
        Path(os.environ['FAKE_GH_CHANGED_POLICY']).read_bytes())
''')
        env = {'FAKE_GH_ROOT': str(self.api_root),
               'FAKE_GH_POLICY': str(self.policy_path),
               'FAKE_GH_CHANGED_POLICY': str(changed_path)}
        with patch.object(start, '_read_key', side_effect=AssertionError('key read')), \
             patch.object(issued, 'issue_start', side_effect=AssertionError('signed')):
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'policy changed during live capture'):
                start.launch(
                    self.live_tests.root, self.live_tests.run_id, 1,
                    gh_path=str(self.gh_path), env_overrides=env,
                    repository_root=self.repo_root, enforce_durable_root=False,
                    enforce_checkout=False)
        self._assert_no_issue()
        self.assertFalse((self.live_tests.root / start.OBSERVATION_DIR).exists())

    def test_checkout_change_after_second_fetch_fails_before_key_or_signer(self):
        with patch.object(start, '_check_checkout', side_effect=[
                {'consumer_commit': CONSUMER_HEAD,
                 'release_lock_sha256': self.policy['release_lock_sha256']},
                {'consumer_commit': 'b' * 40,
                 'release_lock_sha256': self.policy['release_lock_sha256']}]) as check:
            with patch.object(start, '_read_key', side_effect=AssertionError('key read')), \
                 patch.object(issued, 'issue_start', side_effect=AssertionError('signed')):
                with self.assertRaisesRegex(start.PrivateStartError,
                                            'checkout changed during live capture'):
                    start.launch(
                        self.live_tests.root, self.live_tests.run_id, 1,
                        gh_path=str(self.gh_path),
                        env_overrides={'FAKE_GH_ROOT': str(self.api_root)},
                        repository_root=self.repo_root,
                        enforce_durable_root=False, enforce_checkout=True)
        self.assertEqual(check.call_count, 2)
        self._assert_no_issue()
        self.assertFalse((self.live_tests.root / start.OBSERVATION_DIR).exists())

    def test_partial_raw_custody_failure_leaves_no_receipt_key_read_or_start(self):
        original_write = start._write_raw_exclusive
        calls = {'count': 0}

        def fail_on_third_file(*args, **kwargs):
            calls['count'] += 1
            if calls['count'] == 3:
                raise start.PrivateStartError('injected custody write failure')
            return original_write(*args, **kwargs)

        with patch.object(start, '_write_raw_exclusive', side_effect=fail_on_third_file), \
             patch.object(start, '_read_key', side_effect=AssertionError('key read')), \
             patch.object(issued, 'issue_start', side_effect=AssertionError('signed')):
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'injected custody write failure'):
                self._launch()
        capture = self.live_tests.root / start.OBSERVATION_DIR / \
            f'default-branch-start-{self.live_tests.run_id}-1'
        self.assertTrue((capture / 'run-api.json').is_file())
        self.assertTrue((capture / 'jobs-api.json').is_file())
        self.assertFalse((capture / 'receipt.json').exists())
        self._assert_no_issue()

    def test_proxy_ca_and_hosted_runner_overrides_are_rejected_for_real_cli_path(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://proxy.invalid:8080'},
                        clear=True):
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'proxy or custom CA'):
                start._trusted_network_environment()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True):
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'must not run in a hosted'):
                start._trusted_network_environment()

    def test_gh_executable_with_world_writable_ancestor_is_rejected(self):
        unsafe = self.api_root / 'world-writable'
        unsafe.mkdir(mode=0o700)
        executable = unsafe / 'gh'
        shutil.copyfile(self.gh_path, executable)
        executable.chmod(0o700)
        unsafe.chmod(0o777)
        try:
            with self.assertRaisesRegex(start.PrivateStartError,
                                        'unsafe ancestor'):
                start._resolve_gh(str(executable))
        finally:
            unsafe.chmod(0o700)

    def test_existing_capture_path_and_duplicate_receipt_fail_before_fetch(self):
        parent = self.live_tests.root / start.OBSERVATION_DIR
        parent.mkdir(mode=0o700)
        capture = parent / f'default-branch-start-{self.live_tests.run_id}-1'
        capture.mkdir(mode=0o700)
        with self.assertRaisesRegex(start.PrivateStartError, 'capture already exists'):
            self._launch()
        self.assertEqual(int(self.counter.read_text()), 0)
        self._assert_no_issue()

    def test_policy_symlink_hardlink_and_fifo_are_rejected(self):
        self.policy_path.unlink()
        self.policy_path.symlink_to(self.api_root / 'changed-policy.json')
        with self.assertRaisesRegex(start.PrivateStartError, 'unavailable or unsafe'):
            start._load_policy(self.live_tests.root)
        self.policy_path.unlink()
        self._write_policy(self.policy)
        alias = self.live_tests.root / 'policy-alias.json'
        os.link(self.policy_path, alias)
        with self.assertRaisesRegex(start.PrivateStartError, '0600 singly-linked'):
            start._load_policy(self.live_tests.root)
        alias.unlink()
        self.policy_path.unlink()
        os.mkfifo(self.policy_path, 0o600)
        with self.assertRaisesRegex(start.PrivateStartError, '0600 singly-linked'):
            start._load_policy(self.live_tests.root)

    def test_key_symlink_hardlink_and_fifo_are_rejected(self):
        self.key_path.unlink()
        self.key_path.symlink_to(self.api_root / 'response-0.bin')
        with self.assertRaisesRegex(start.PrivateStartError, 'unavailable or unsafe'):
            start._read_key(self.live_tests.root)
        self.key_path.unlink()
        self.key_path.write_bytes(TEST_KEY)
        self.key_path.chmod(0o600)
        alias = self.live_tests.root / 'key-alias'
        os.link(self.key_path, alias)
        with self.assertRaisesRegex(start.PrivateStartError, 'at least 32 bytes'):
            start._read_key(self.live_tests.root)
        alias.unlink()
        self.key_path.unlink()
        os.mkfifo(self.key_path, 0o600)
        with self.assertRaisesRegex(start.PrivateStartError, 'at least 32 bytes'):
            start._read_key(self.live_tests.root)

    def test_durable_root_rejects_checkout_work_and_known_temp_roots(self):
        with self.assertRaisesRegex(start.PrivateStartError, 'outside the repository'):
            start._root_is_durable(self.live_tests.root, self.repo_root)
        temp_parent = self.live_tests.root.parent / 'outside-private'
        temp_parent.mkdir(mode=0o700)
        temp_root = temp_parent / 'private'
        temp_root.mkdir(mode=0o700)
        with patch.object(start.intake, 'private_root', return_value=temp_root), \
             patch.object(start.tempfile, 'gettempdir', return_value=str(temp_parent)), \
             patch.dict(os.environ, {'TMPDIR': str(temp_parent)}):
            with self.assertRaisesRegex(start.PrivateStartError, 'temporary directories'):
                start._root_is_durable(temp_root, Path('/Users/test/checkout'))

    def test_structural_macos_temp_root_rejected_even_with_safe_tmpdir(self):
        temp_root = Path('/private/var/folders/aa/bbbbbbbbbbbbbbb/T/private')
        with patch.object(start.intake, 'private_root', return_value=temp_root), \
             patch.object(start.tempfile, 'gettempdir', return_value='/Users/test/private-cache'), \
             patch.dict(os.environ, {'TMPDIR': '/Users/test/private-cache'}):
            with self.assertRaisesRegex(start.PrivateStartError, 'macOS per-user'):
                start._root_is_durable(temp_root, Path('/Users/test/checkout'))

    def test_cli_has_no_raw_json_or_gh_override_arguments(self):
        help_run = subprocess.run(
            [sys.executable, '-B', '-m', 'tools.default_branch_private_start', '--help'],
            cwd=self.repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, text=True)
        self.assertEqual(help_run.returncode, 0)
        self.assertIn('--private-root', help_run.stdout)
        self.assertIn('--run-id', help_run.stdout)
        self.assertIn('--attempt', help_run.stdout)
        self.assertNotIn('--attestation', help_run.stdout)
        self.assertNotIn('--observation', help_run.stdout)
        self.assertNotIn('--gh', help_run.stdout)

    def test_v3_cas_deadline_is_checked_after_transaction_contention(self):
        components = self.live_tests._observe()['attestation_components']
        attestation = dict(components, observation_sha256='a' * 64)
        observed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            '+00:00', 'Z')
        blocker = sqlite3.connect(self.live_tests.fixture.database,
                                  timeout=5, check_same_thread=False)
        blocker.execute('BEGIN IMMEDIATE')
        release = threading.Thread(target=lambda: (time.sleep(0.12), blocker.commit()))
        release.start()
        try:
            with self.assertRaisesRegex(issued.IssuedActionError, 'deadline expired'):
                issued.issue_start(
                    self.live_tests.root, 0, issued.ZERO_HASH, TEST_KEY,
                    self.live_tests.approved_policy, attestation, observed_at,
                    deadline_monotonic=time.monotonic() + 0.04)
        finally:
            release.join(timeout=2)
            blocker.close()
        self._assert_no_issue()


if __name__ == '__main__':
    unittest.main()
