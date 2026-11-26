"""Offline transport, terminal identity and private custody controls."""
import copy
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from tools import default_branch_backlog_issued as issued
from tools import default_branch_private_final_capture as capture
from tools import default_branch_private_start as private
from tools import default_branch_reservation_reconcile as reconcile


RUN_ID, ATTEMPT, JOB_ID, EARLY_ID, FINAL_ID = 9, 1, 33, 44, 45
HEAD = '4' * 40
REPO_ID, WORKFLOW_ID = 1454767376, 431720768
TIME = '2026-11-26T12:00:'
EXPIRES = '2027-02-24T12:00:00Z'
ZIP_ENDPOINT = f'repos/{reconcile.REPOSITORY}/actions/artifacts/45/zip'
SIGNED_URL = ('https://productionresultssa9.blob.core.windows.net'
              '/actions-results/archive.zip?sig=fixture')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive(raw):
    output = BytesIO()
    with ZipFile(output, 'w') as zip_file:
        zip_file.writestr('fixture', raw)
    return output.getvalue()


def private_bytes(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


class PrivateFinalCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.root.chmod(0o700)
        self.capture_path = self.root / 'terminal-captures/default-branch-final-9-1'
        self.early_zip = archive(b'early bytes')
        self.final_zip = archive(b'final bytes')
        repository = {'id': REPO_ID, 'full_name': reconcile.REPOSITORY}
        run = {
            'id': RUN_ID, 'run_attempt': ATTEMPT, 'repository': repository,
            'head_repository': repository, 'workflow_id': WORKFLOW_ID,
            'path': reconcile.SCAN_WORKFLOW, 'event': 'workflow_dispatch',
            'head_branch': 'main', 'head_sha': HEAD,
            'status': 'in_progress', 'conclusion': None,
            'run_started_at': TIME + '01Z', 'updated_at': TIME + '05Z',
        }
        job = {
            'name': reconcile.SCAN_JOB, 'id': JOB_ID, 'run_id': RUN_ID,
            'run_attempt': ATTEMPT, 'head_sha': HEAD,
            'status': 'in_progress', 'conclusion': None,
            'started_at': TIME + '02Z', 'completed_at': None,
        }
        early = self.artifact(EARLY_ID, 'start', self.early_zip, TIME + '03Z')
        final = self.artifact(FINAL_ID, 'scan', self.final_zip, TIME + '06Z')
        issued_at = TIME + '04Z'
        att = {
            'schema': issued.START_SCHEMA, 'kind': 'start', 'queue_id': '6' * 32,
            'reservation_sequence': 1, 'reservation_sha256': '7' * 64,
            'identity': {
                'repository': 'openwrt/openwrt', 'ref': 'main', 'ordinal': 1,
                'commit_sha': '1' * 40, 'tree_sha': '2' * 40,
                'first_parent_sha': '3' * 40, 'intake_id': 'intake', 'receipt_seq': 1,
            },
            'origin_receipt_sha256': 'a' * 64, 'origin_gap_sha256': '8' * 64,
            'policy_sha256': 'b' * 64, 'consumer_commit': HEAD,
            'release_lock_sha256': '5' * 64, 'run_id': RUN_ID, 'run_attempt': ATTEMPT,
            'job_id': JOB_ID, 'workflow': reconcile.SCAN_WORKFLOW, 'job': reconcile.SCAN_JOB,
            'early_artifact': {'id': EARLY_ID, 'size': len(self.early_zip),
                               'sha256': sha(self.early_zip)},
        }
        start_bodies = {
            'run': ('run-api.json', issued.canonical_bytes(run)),
            'jobs': ('jobs-api.json', issued.canonical_bytes({'jobs': [job], 'total_count': 1})),
            'artifacts': ('artifacts-api.json',
                          issued.canonical_bytes({'artifacts': [early], 'total_count': 1})),
            'early_artifact_zip': ('early-artifact.zip', self.early_zip),
        }
        for role in ('run', 'jobs'):
            name, raw = start_bodies[role]
            start_bodies[f'recheck_{role}'] = ('recheck-' + name, raw)
        self.early_path = self.root / 'observations/default-branch-start-9-1'
        self.early_path.parent.mkdir(mode=0o700)
        self.early_path.mkdir(mode=0o700)
        files = {}
        for role, (name, raw) in start_bodies.items():
            path = self.early_path / name
            private_bytes(path, raw)
            files[role] = {'path': path.relative_to(self.root).as_posix(), 'size': len(raw),
                           'sha256': sha(raw)}
            if role != 'early_artifact_zip':
                att[role + '_api_sha256'] = sha(raw)
        receipt = {
            **att, 'schema': private.RECEIPT_SCHEMA, 'observed_at': issued_at,
            'status': 'verified_observation_retained', 'repository': reconcile.REPOSITORY,
            'early_artifact': {**att['early_artifact'], 'name': early['name']},
            'raw_files': files,
        }
        receipt_raw = issued.canonical_bytes(receipt)
        private_bytes(self.early_path / 'receipt.json', receipt_raw)
        att['observation_sha256'] = sha(receipt_raw)
        # Well-formed dummy MAC deliberately provides no authentication.
        self.start = issued.canonical_bytes({
            'schema': issued.ISSUED_SCHEMA, 'issued_seq': 1,
            'previous_issued_sha256': issued.ZERO_HASH, 'observed_at': issued_at,
            'attestation': att, 'mac': '0' * 64,
        })
        self.terminal = {
            'run': {**run, 'status': 'completed', 'conclusion': 'success',
                    'updated_at': TIME + '09Z'},
            'jobs': {'jobs': [{**job, 'status': 'completed', 'conclusion': 'success',
                               'completed_at': TIME + '08Z'}], 'total_count': 1},
            'artifacts': {'artifacts': [early, final], 'total_count': 2},
        }
        self.second = copy.deepcopy(self.terminal)
        self.requests = []
        self.network_opened = False
        self.endpoint = 'repos/' + reconcile.REPOSITORY + '/actions/runs/9'
        self.endpoints = {
            self.endpoint: 'run',
            self.endpoint + '/attempts/1/jobs?per_page=100': 'jobs',
            self.endpoint + '/artifacts?per_page=100': 'artifacts',
        }
        self.clock = patch.object(capture, '_now', return_value=datetime(
            2026, 11, 26, 12, 0, 10, tzinfo=timezone.utc))
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def artifact(self, artifact_id, label, raw, created):
        return {
            'id': artifact_id, 'name': f'default-branch-{label}-{RUN_ID}-{ATTEMPT}',
            'size_in_bytes': len(raw), 'digest': 'sha256:' + sha(raw),
            'expired': False, 'created_at': created, 'updated_at': created,
            'expires_at': EXPIRES, 'workflow_run': {
                'id': RUN_ID, 'repository_id': REPO_ID, 'head_repository_id': REPO_ID,
                'head_branch': 'main', 'head_sha': HEAD,
            },
        }

    def network(self, directory):
        self.assertEqual(directory, self.capture_path / 'gh-config')
        self.assertEqual(list(directory.iterdir()), [])
        self.network_opened = True

        def fetch(url, limit):
            self.assertEqual(limit, reconcile.MAX_API)
            observation = self.second if len(self.requests) >= 4 else self.terminal
            self.requests.append(url)
            raw = issued.canonical_bytes(observation[self.endpoints[url]])
            return raw, {'endpoint': url, 'size': len(raw), 'sha256': sha(raw)}

        def download(url, limit):
            self.assertEqual((url, limit), (ZIP_ENDPOINT,
                             self.terminal['artifacts']['artifacts'][1]['size_in_bytes']))
            self.requests.append(url)
            return self.final_zip, {'endpoint': url}

        return fetch, download

    def run_capture(self):
        # Use the foreground public entry point with in-process-only fixture adapters.
        with patch.object(private, '_root_is_durable', return_value=self.root), \
             patch.object(capture, '_network', self.network):
            return capture.capture(self.root, self.start, RUN_ID, ATTEMPT)

    def test_endpoints_raw_custody_and_evidence_limit(self):
        with patch.object(private, '_read_key', side_effect=AssertionError('key access')), \
             patch.object(issued, 'issue_terminal', side_effect=AssertionError('CAS')):
            result = self.run_capture()
        self.assertEqual(self.requests, list(self.endpoints) + [ZIP_ENDPOINT] +
                         list(self.endpoints))
        self.assertEqual(result['status'], 'captured_bytes_only')
        self.assertFalse(result['start_authenticated'])
        self.assertEqual(result['job_id'], JOB_ID)
        self.assertEqual(result['supplied_start_sha256'], sha(self.start))
        self.assertEqual(result['final_artifact'],
                         {'id': FINAL_ID, 'size': len(self.final_zip), 'sha256': sha(self.final_zip)})
        self.assertEqual(len(result['raw_files']), 7)
        for name, record in result['raw_files'].items():
            path = self.capture_path / name
            body = path.read_bytes()
            self.assertEqual(record, {'size': len(body), 'sha256': sha(body)})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.capture_path / 'final-artifact.zip').read_bytes(), self.final_zip)
        receipt = (self.capture_path / 'receipt.json').read_bytes()
        self.assertEqual(result['receipt_sha256'], sha(receipt))
        self.assertEqual(self.capture_path.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(capture.CaptureError, 'already exists'):
            self.run_capture()
        self.assertEqual((self.capture_path / 'receipt.json').read_bytes(), receipt)

    def test_interrupted_fetch_leaves_partial_custody_and_blocks_implicit_retry(self):
        network = self.network

        def interrupted(directory):
            fetch, download = network(directory)

            def fail_on_jobs(url, limit):
                if url.endswith('/jobs?per_page=100'):
                    raise capture.CaptureError('fixture transport interruption')
                return fetch(url, limit)

            return fail_on_jobs, download

        with patch.object(self, 'network', interrupted):
            with self.assertRaisesRegex(capture.CaptureError, 'transport interruption'):
                self.run_capture()
        first_path = self.capture_path / 'first-run-api.json'
        expected = issued.canonical_bytes(self.terminal['run'])
        self.assertEqual(first_path.read_bytes(), expected)
        self.assertFalse((self.capture_path / 'receipt.json').exists())
        with self.assertRaisesRegex(capture.CaptureError, 'already exists'):
            self.run_capture()
        self.assertEqual(first_path.read_bytes(), expected)
        self.assertEqual(self.requests, [self.endpoint])

    def test_wrong_job_at_same_name_is_ineligible(self):
        self.terminal['jobs']['jobs'][0]['id'] = JOB_ID + 1
        with self.assertRaisesRegex(capture.CaptureError, 'differs from the supplied start'):
            self.run_capture()
        self.assertNotIn(ZIP_ENDPOINT, self.requests)

    def test_run_rerun_race_refuses_receipt(self):
        self.second['run']['run_attempt'] += 1
        with self.assertRaises(capture.CaptureError):
            self.run_capture()
        self.assertTrue((self.capture_path / 'second-run-api.json').exists())
        self.assertFalse((self.capture_path / 'receipt.json').exists())

    def test_second_artifact_digest_drift_refuses_receipt(self):
        self.second['artifacts']['artifacts'][1]['digest'] = 'sha256:' + '7' * 64
        with self.assertRaisesRegex(capture.CaptureError, 'observations differ'):
            self.run_capture()
        self.assertFalse((self.capture_path / 'receipt.json').exists())

    def test_same_count_duplicate_job_is_ineligible(self):
        jobs = self.terminal['jobs']
        jobs['jobs'].append({**jobs['jobs'][0], 'name': 'contract'})
        jobs['total_count'] = 2
        with self.assertRaises(capture.CaptureError):
            self.run_capture()
        self.assertNotIn(ZIP_ENDPOINT, self.requests)

    def test_truncated_artifacts_listing_is_ineligible(self):
        self.terminal['artifacts']['total_count'] += 1
        with self.assertRaises(capture.CaptureError):
            self.run_capture()
        self.assertNotIn(ZIP_ENDPOINT, self.requests)

    def test_expired_artifact_is_ineligible(self):
        self.terminal['artifacts']['artifacts'][1]['expired'] = True
        with self.assertRaises(capture.CaptureError):
            self.run_capture()
        self.assertNotIn(ZIP_ENDPOINT, self.requests)

    def test_wrong_workflow_id_is_ineligible(self):
        self.terminal['run']['workflow_id'] = WORKFLOW_ID + 1
        with self.assertRaisesRegex(capture.CaptureError, 'workflow ID differs'):
            self.run_capture()
        self.assertNotIn(ZIP_ENDPOINT, self.requests)

    def test_same_length_final_zip_substitution_is_ineligible(self):
        self.final_zip = self.final_zip[:-1] + bytes([self.final_zip[-1] ^ 1])
        with self.assertRaisesRegex(capture.CaptureError, 'ZIP differs'):
            self.run_capture()
        self.assertFalse((self.capture_path / 'receipt.json').exists())

    def test_hardlinked_early_file_is_rejected_before_network(self):
        os.link(self.early_path / 'early-artifact.zip', self.root / 'alias.zip')
        with self.assertRaisesRegex(capture.CaptureError, 'unsafe or unbounded'):
            self.run_capture()
        self.assertFalse(self.network_opened)

    def test_unsigned_missing_start_is_rejected_before_network(self):
        self.start = b''
        with self.assertRaisesRegex(capture.CaptureError, 'sequence-one bytes'):
            self.run_capture()
        self.assertFalse(self.network_opened)

    def test_capture_parent_alias_is_rejected_before_network(self):
        other = self.root / 'other'
        other.mkdir(mode=0o700)
        (self.root / 'terminal-captures').symlink_to(other)
        with self.assertRaisesRegex(capture.CaptureError, 'directory is unsafe'):
            self.run_capture()
        self.assertFalse(self.network_opened)
        self.assertEqual(list(other.iterdir()), [])


class RedirectTests(unittest.TestCase):
    def test_curl_pins_config_and_streams_secrets_only_on_stdin(self):
        spawn = subprocess.Popen
        token = 'fixture-token'
        response = b'HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n\r\nzip'

        def fixture(argv, **kwargs):
            self.assertEqual(argv[:4], ['/usr/bin/curl', '--disable', '--config', '-'])
            self.assertIn('--globoff', argv)
            self.assertNotIn('--location', argv)
            self.assertNotIn(token, str(argv))
            self.assertNotIn(SIGNED_URL, str(argv))
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
            child = (
                'import sys\n'
                'config = sys.stdin.buffer.read()\n'
                f'assert config == {expected!r}\n'
                f'sys.stdout.buffer.write({response!r})\n'
            )
            return spawn([sys.executable, '-c', child], **kwargs)

        for supplied_token in (token, None):
            url = 'https://api.github.com/' + ZIP_ENDPOINT if supplied_token else SIGNED_URL
            expected = f'url = "{url}"\n'.encode()
            if supplied_token:
                expected += f'header = "Authorization: Bearer {supplied_token}"\n'.encode()
            with self.subTest(credential=bool(supplied_token)):
                with patch.object(capture.subprocess, 'Popen', side_effect=fixture):
                    self.assertEqual(capture._curl(url, 3, 2, token=supplied_token),
                                     (200, [], b'zip'))

    def test_only_api_request_receives_credential(self):
        responses = [(302, [SIGNED_URL.encode()], b''), (200, [], b'zip')]
        with patch.object(capture, '_curl', side_effect=responses) as request:
            raw, receipt = capture._download_zip(ZIP_ENDPOINT, 3, 'fixture-token')
        self.assertEqual(raw, b'zip')
        self.assertNotIn('sig=fixture', str(receipt))
        self.assertNotIn('fixture-token', str(receipt))
        self.assertEqual(request.call_args_list[0].kwargs, {'token': 'fixture-token'})
        self.assertEqual(request.call_args_list[1].kwargs, {})

    def test_invalid_redirect_never_reaches_second_host(self):
        for url in (SIGNED_URL.replace('https', 'http', 1),
                    SIGNED_URL.replace('.blob.core.windows.net', '.invalid'),
                    SIGNED_URL.replace('https://', 'https://user@'),
                    SIGNED_URL + '#fragment', SIGNED_URL + '\\',
                    SIGNED_URL + '\r\nheader: injection'):
            with self.subTest(url=url):
                with patch.object(capture, '_curl', return_value=(302, [url.encode()], b'')) as req:
                    with self.assertRaises(capture.CaptureError):
                        capture._download_zip(ZIP_ENDPOINT, 3, 'fixture-token')
                    req.assert_called_once()

    def test_second_redirect_is_rejected(self):
        first = (302, [SIGNED_URL.encode()], b'')
        with patch.object(capture, '_curl', return_value=first) as request:
            with self.assertRaisesRegex(capture.CaptureError, 'direct ZIP body'):
                capture._download_zip(ZIP_ENDPOINT, 3, 'fixture-token')
        self.assertEqual(request.call_count, 2)
