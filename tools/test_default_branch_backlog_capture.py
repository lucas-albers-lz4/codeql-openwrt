from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools import default_branch_backlog_capture as capture
from tools import default_branch_backlog_intake as intake
from tools import test_default_branch_backlog_intake as intake_tests


class FakeProcess:
    def __init__(self, body, status=0):
        read_fd, write_fd = os.pipe()
        if body:
            os.write(write_fd, body)
        os.close(write_fd)
        self.stdout = os.fdopen(read_fd, 'rb', buffering=0)
        self.status = status
        self.killed = False

    def poll(self):
        return self.status

    def wait(self, timeout=None):
        return self.status

    def kill(self):
        self.killed = True
        self.status = -9


class CaptureTests(unittest.TestCase):
    def setUp(self):
        work = Path(__file__).resolve().parents[1] / 'work'
        work.mkdir(mode=0o700, exist_ok=True)
        os.chmod(work, 0o700)
        self.tmp = tempfile.TemporaryDirectory(prefix='backlog-capture-', dir=work)
        self.fx = intake_tests.Fixture(self.tmp.name)
        _, _, _, self.previous, self.current, _ = self.fx.make_initial_pair()
        self.responses = {}
        self.calls = []
        self._add_bundle(self.previous)
        self._add_bundle(self.current)

    def tearDown(self):
        self.tmp.cleanup()

    def _add_bundle(self, bundle):
        run = bundle['run_doc']
        run_id = run['id']
        attempt = run['run_attempt']
        run_endpoint = (f'repos/{intake.REPOSITORY}/actions/runs/{run_id}/'
                        f'attempts/{attempt}')
        artifacts_endpoint = (f'repos/{intake.REPOSITORY}/actions/runs/{run_id}/'
                             'artifacts?per_page=100&page=1')
        artifact = json.loads(bundle['artifacts_api'].read_bytes())
        artifacts = {'total_count': 1, 'artifacts': [artifact]}
        self.responses[run_endpoint] = bundle['run_api'].read_bytes()
        self.responses[artifacts_endpoint] = json.dumps(
            artifacts, indent=2, sort_keys=True).encode() + b'\n'
        self.responses[f'repos/{intake.REPOSITORY}/actions/artifacts/'
                       f'{bundle["artifact_id"]}/zip'] = bundle['zip'].read_bytes()

    def _launcher(self, args, **kwargs):
        self.assertEqual(args[:4], ['gh', 'api', '--hostname', 'github.com'])
        self.assertEqual(kwargs['stdin'], capture.subprocess.DEVNULL)
        self.assertIsNotNone(kwargs['stdout'])
        self.assertEqual(kwargs['stderr'], capture.subprocess.DEVNULL)
        endpoint = args[4]
        self.calls.append(tuple(args))
        value = self.responses[endpoint]
        if isinstance(value, list):
            body, status = value.pop(0)
        else:
            body, status = value, 0
        return FakeProcess(body, status)

    def _capture(self):
        with patch.object(capture.subprocess, 'Popen', side_effect=self._launcher):
            return capture.capture(self.fx.private, 1001, 1, 1002, 1)

    def _artifacts_endpoint(self, bundle):
        return (f'repos/{intake.REPOSITORY}/actions/runs/'
                f'{bundle["run_doc"]["id"]}/artifacts?per_page=100&page=1')

    def _run_endpoint(self, bundle):
        return (f'repos/{intake.REPOSITORY}/actions/runs/'
                f'{bundle["run_doc"]["id"]}/attempts/{bundle["run_doc"]["run_attempt"]}')

    def test_success_captures_exact_bytes_and_runs_offline_intake(self):
        result = self._capture()
        self.assertEqual(result['status'], 'capture_and_intake_completed')
        self.assertEqual(result['capture']['status'], 'gh_api_responses_verified')
        self.assertEqual(result['intake']['status'], 'intake_recorded')
        self.assertEqual(result['intake']['commits_added'], 7)
        self.assertEqual(result['intake']['custody'], 'offline_retained_api_metadata')
        self.assertEqual(len(self.calls), 10)
        stage = Path(result['capture']['private_staging_directory'])
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
        expected_names = {
            f'{role}{suffix}'
            for role in ('previous', 'current')
            for suffix in ('-run-api.json', '-artifacts-api.json', '.zip',
                           '-run-api-confirm.json', '-artifacts-api-confirm.json')
        }
        self.assertEqual({path.name for path in stage.iterdir()}, expected_names)
        for role, bundle in (('previous', self.previous), ('current', self.current)):
            self.assertEqual((stage / f'{role}.zip').read_bytes(), bundle['zip'].read_bytes())
            self.assertEqual((stage / f'{role}-run-api.json').read_bytes(),
                             bundle['run_api'].read_bytes())
            expected_artifacts = json.dumps({
                'total_count': 1,
                'artifacts': [json.loads(bundle['artifacts_api'].read_bytes())],
            }, indent=2, sort_keys=True).encode() + b'\n'
            self.assertEqual((stage / f'{role}-artifacts-api.json').read_bytes(),
                             expected_artifacts)
            self.assertEqual((stage / f'{role}-run-api-confirm.json').read_bytes(),
                             bundle['run_api'].read_bytes())
            self.assertEqual((stage / f'{role}-artifacts-api-confirm.json').read_bytes(),
                             expected_artifacts)
        for path in stage.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)
            self.assertEqual(path.stat().st_nlink, 1, path.name)
        self.assertEqual(stat.S_IMODE(
            (self.fx.private / 'default-branch-backlog.sqlite3').stat().st_mode), 0o600)

    def test_intake_uses_verified_bytes_after_staged_file_changes(self):
        original = capture._role_capture

        def change_staged_file(stage, role, run_id, attempt):
            result = original(stage, role, run_id, attempt)
            if role == 'current':
                (stage / 'previous.zip').unlink()
            return result

        with patch.object(capture, '_role_capture', side_effect=change_staged_file):
            result = self._capture()
        self.assertEqual(result['intake']['status'], 'intake_recorded')
        self.assertEqual(result['intake']['commits_added'], 7)
        self.assertEqual(result['capture']['runs'][0]['zip_sha256'],
                         capture.hashlib.sha256(self.previous['zip'].read_bytes()).hexdigest())

    def test_nonzero_gh_status_fails_without_intake(self):
        endpoint = self._run_endpoint(self.previous)
        self.responses[endpoint] = [(self.responses[endpoint], 1)]
        with self.assertRaisesRegex(capture.CaptureError, 'gh api request failed'):
            self._capture()
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())
        self.assertFalse(any('artifact-id' in item for call in self.calls for item in call))

    def test_failed_run_identity_rejected_before_download_or_intake(self):
        doc = json.loads(self.previous['run_api'].read_bytes())
        doc['conclusion'] = 'failure'
        self.responses[self._run_endpoint(self.previous)] = json.dumps(doc).encode()
        with self.assertRaisesRegex(capture.CaptureError, 'successful default-branch'):
            self._capture()
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())
        self.assertEqual(len(self.calls), 1)

    def test_incomplete_ambiguous_expired_and_wrongly_linked_artifacts_rejected(self):
        endpoint = self._artifacts_endpoint(self.previous)
        original = json.loads(self.responses[endpoint])
        cases = []
        missing = {'total_count': 0, 'artifacts': []}
        cases.append(('missing', missing, 'missing or ambiguous'))
        incomplete = dict(original, total_count=2)
        cases.append(('incomplete', incomplete, 'incomplete'))
        duplicate = json.loads(json.dumps(original))
        duplicate['artifacts'].append(dict(duplicate['artifacts'][0], id=999999))
        duplicate['total_count'] = 2
        cases.append(('ambiguous', duplicate, 'ambiguous'))
        expired = json.loads(json.dumps(original))
        expired['artifacts'][0]['expired'] = True
        cases.append(('expired', expired, 'expired'))
        linked_wrong = json.loads(json.dumps(original))
        linked_wrong['artifacts'][0]['workflow_run']['id'] += 1
        cases.append(('wrong linkage', linked_wrong, 'linkage mismatch'))
        for label, document, message in cases:
            with self.subTest(label=label):
                self.responses[endpoint] = json.dumps(document).encode()
                self.calls.clear()
                with self.assertRaisesRegex(capture.CaptureError, message):
                    self._capture()
                self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())
                self.assertEqual(len(self.calls), 2)
        self.responses[endpoint] = json.dumps(original).encode()

    def test_zip_digest_mismatch_rejected(self):
        endpoint = self._artifacts_endpoint(self.previous)
        document = json.loads(self.responses[endpoint])
        document['artifacts'][0]['digest'] = 'sha256:' + '0' * 64
        self.responses[endpoint] = json.dumps(document).encode()
        with self.assertRaisesRegex(capture.CaptureError, 'digest differs'):
            self._capture()
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

    def test_changed_reconfirmation_rejected(self):
        endpoint = self._run_endpoint(self.previous)
        changed = json.loads(self.responses[endpoint])
        changed['updated_at'] = '2026-11-26T00:00:01Z'
        self.responses[endpoint] = [
            (self.responses[endpoint], 0), (json.dumps(changed).encode(), 0)]
        with self.assertRaisesRegex(capture.CaptureError, 'changed during artifact capture'):
            self._capture()
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

    def test_zip_response_byte_bound_enforced_before_intake(self):
        zip_endpoint = (f'repos/{intake.REPOSITORY}/actions/artifacts/'
                        f'{self.previous["artifact_id"]}/zip')
        archive = self.responses[zip_endpoint]
        limit = len(archive) - 1
        artifacts_endpoint = self._artifacts_endpoint(self.previous)
        document = json.loads(self.responses[artifacts_endpoint])
        document['artifacts'][0]['size_in_bytes'] = limit
        self.responses[artifacts_endpoint] = json.dumps(document).encode()
        with patch.object(capture, 'MAX_ZIP', limit):
            with self.assertRaisesRegex(capture.CaptureError, 'exceeds byte bound'):
                self._capture()
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

    def test_artifact_id_is_derived_and_cannot_be_passed_on_cli(self):
        stderr = io.StringIO()
        argv = ['--private-root', str(self.fx.private),
                '--previous-run-id', '1001', '--previous-attempt', '1',
                '--current-run-id', '1002', '--current-attempt', '1',
                '--previous-artifact-id', '1']
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            capture.main(argv)
        self.assertEqual(raised.exception.code, 2)
        self.assertIn('unrecognized arguments', stderr.getvalue())
        self.assertEqual(self.calls, [])

    def test_private_root_alias_and_special_file_rejected_before_gh(self):
        work = Path(self.tmp.name)
        alias = work / 'private-alias'
        alias.symlink_to(self.fx.private, target_is_directory=True)
        fifo = work / 'private-fifo'
        os.mkfifo(fifo, 0o600)
        for root in (alias, fifo, Path('/') if os.name != 'nt' else alias):
            with self.subTest(root=str(root)):
                with self.assertRaises(capture.CaptureError):
                    capture.capture(root, 1001, 1, 1002, 1)
                self.assertEqual(self.calls, [])
                self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

    def test_exclusive_capture_output_and_hardlink_rejection(self):
        target = self.fx.private / 'existing.json'
        target.write_bytes(b'original')
        target.chmod(0o600)
        with patch.object(capture.subprocess, 'Popen') as launcher:
            with self.assertRaisesRegex(capture.CaptureError, 'exclusive'):
                capture._fetch_to_file('ignored', target, capture.MAX_API)
        launcher.assert_not_called()
        self.assertEqual(target.read_bytes(), b'original')

        alias = self.fx.private / 'existing-hardlink.json'
        os.link(target, alias)
        with self.assertRaisesRegex(capture.CaptureError, 'bounded private regular'):
            capture._read_private(target, capture.MAX_API)
        self.assertEqual(target.stat().st_nlink, 2)


if __name__ == '__main__':
    unittest.main()
