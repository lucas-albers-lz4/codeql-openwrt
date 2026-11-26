import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from incoming_poll import PollError
from incoming_queue import encoded
import operator_queue_complete as completion
import operator_queue_failure as failure
import operator_queue_start as starter


class IssuerBoundaryTests(unittest.TestCase):
    def test_private_key_file_rejects_alias_fifo_and_hardlink(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory).resolve()
            key = root / 'issuer.key'
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(b'k' * 32)
            self.assertEqual(starter.read_key(key, root), b'k' * 32)
            alias = root / 'alias.key'
            alias.symlink_to(key)
            with self.assertRaises(PollError):
                starter.read_key(alias, root)
            fifo = root / 'pipe.key'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(PollError):
                starter.read_key(fifo, root)
            hardlink = root / 'hardlink.key'
            os.link(key, hardlink)
            with self.assertRaises(PollError):
                starter.read_key(hardlink, root)

    def test_early_final_exact_and_changed_final_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspace = root / 'start-workspace'
            workspace.mkdir(mode=0o700)
            final = root / 'final'
            (final / 'inputs').mkdir(parents=True)
            raw_files = {name: (name + '\n').encode() for name in completion.EARLY}
            raw_files['receipt.json'] = b'{}\n'
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as z:
                for name, raw in raw_files.items():
                    z.writestr(name, raw)
            zip_bytes = archive.getvalue()
            (workspace / 'download.zip').write_bytes(zip_bytes)
            for name in completion.EARLY:
                (final / 'inputs' / name).write_bytes(raw_files[name])
            observed = {'status': 'verified_read_only', 'run_id': 123,
                        'attempt': 1, 'job_id': 456, 'consumer_commit': 'a'*40,
                        'artifact_id': 789,
                        'artifact_sha256': hashlib.sha256(zip_bytes).hexdigest(),
                        'reservation_sequence': 5, 'reservation_sha256': 'b'*64,
                        'policy_sha256': 'c'*64,
                        'early_files': {name: hashlib.sha256(raw).hexdigest()
                                        for name, raw in raw_files.items()}}
            receipt = encoded(observed)
            (workspace / 'verified-observation.json').write_bytes(receipt)
            start = {'attestation': {'observation_sha256': hashlib.sha256(receipt).hexdigest(),
                     'job': {'run_id': 123, 'attempt': 1, 'id': 456,
                             'consumer_commit': 'a'*40},
                     'early_artifact': {'id': 789,
                                        'sha256': hashlib.sha256(zip_bytes).hexdigest()},
                     'reservation': 5, 'reservation_digest': 'b'*64,
                     'policy_sha256': 'c'*64}}
            result = completion.early_final(start, workspace / 'verified-observation.json',
                                            root, final)
            self.assertEqual(set(result), set(completion.EARLY))
            (final / 'inputs' / 'dispatch-inputs.json').write_bytes(b'changed\n')
            with self.assertRaisesRegex(PollError, 'early and final'):
                completion.early_final(start, workspace / 'verified-observation.json',
                                       root, final)

    def test_start_payload_uses_verified_observation_and_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspace = root / 'live-workspace'
            workspace.mkdir(mode=0o700)
            commit = 'a'*40
            observed = {'status': 'verified_read_only', 'verifier_dirty': False,
                        'verifier_commit': commit, 'consumer_commit': commit,
                        'policy_sha256': '1'*64, 'queue_id': 'b'*32,
                        'reservation_sequence': 5,
                        'reservation_sha256': '2'*64, 'job_id': 456,
                        'artifact_id': 789, 'artifact_sha256': '3'*64,
                        'run_api_sha256': '4'*64, 'jobs_api_sha256': '5'*64,
                        'artifacts_api_sha256': '6'*64,
                        'recheck_run_api_sha256': '7'*64,
                        'recheck_jobs_api_sha256': '8'*64,
                        'operator_workspace': str(workspace)}
            policy = {'consumer_commit': commit, 'queue_id': 'b'*32}
            reservation = {'sequence': 5, 'event_id': 'event',
                           'source': {'commit': 'c'*40},
                           'control_sha': 'd'*40}
            class Database:
                def close(self):
                    pass
            with patch.object(starter.observation, 'check', return_value=observed), \
                 patch.object(starter.observation, 'read_policy',
                              return_value=(policy, '1'*64)), \
                 patch.object(starter.observation, 'reserved_queue',
                              return_value=(reservation, '2'*64)), \
                 patch.object(starter, 'clean_checkout', return_value=commit), \
                 patch.object(starter, 'read_key', return_value=b'k'*32), \
                 patch.object(starter, 'open_queue', return_value=Database()), \
                 patch.object(starter, 'issue_start',
                              return_value=({'sequence': 6}, '9'*64)) as issued:
                result = starter.start(root / 'queue.db', root, root / 'policy.json',
                                       root / 'key', 123, 1)
            payload = issued.call_args.args[2]
            self.assertEqual(result['status'], 'started')
            self.assertEqual(payload['job']['id'], 456)
            self.assertEqual(payload['early_artifact'], {'id': 789, 'sha256': '3'*64})
            self.assertEqual(payload['source_sha'], 'c'*40)
            self.assertEqual(payload['observation_sha256'], hashlib.sha256(
                (workspace / 'verified-observation.json').read_bytes()).hexdigest())

    def test_completion_payload_uses_verified_final_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspace = root / 'final-workspace'
            snapshot = workspace / 'extracted/issuer-freeze-123-1/snapshot'
            names = ('release-lock.json', 'inputs/event-corpus-manifest.json',
                     'event/out/successful.json', 'event/out/errors.json',
                     'event/out/default-suite.sarif',
                     'control/control-assertion.json')
            for name in names:
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((name + '\n').encode())
            (snapshot.parent / 'inventory.json').write_bytes(b'inventory\n')
            commit = 'a'*40
            job = {'workflow': '.github/workflows/incoming-event-preflight.yml',
                   'job': 'released-event-scan', 'run_id': 123, 'attempt': 1,
                   'id': 456, 'consumer_commit': commit}
            att = {'policy_sha256': '1'*64, 'job': job, 'queue_id': 'b'*32,
                   'event_id': 'event', 'reservation': 5,
                   'reservation_digest': '2'*64, 'run_id': '123-1',
                   'control_sha': 'c'*40}
            start = {'sequence': 6, 'attestation': att}
            final = {'status': 'verified_read_only', 'job_id': 456,
                     'artifact_id': 789, 'artifact_sha256': '3'*64,
                     'operator_workspace': str(workspace),
                     'link': {'queue_state': 'started', 'started_job_id': 456,
                              'reservation_sequence': 5,
                              'reservation_sha256': '2'*64,
                              'scan_status': 'clean_scan', 'result_count': 0,
                              'source': {'commit': 'd'*40, 'tree': 'e'*40}}}
            policy = {'consumer_commit': commit, 'queue_id': 'b'*32}
            class Database:
                def close(self):
                    pass
            with patch.object(completion, 'issued_start', return_value=(start, '4'*64)), \
                 patch.object(completion.observation, 'read_policy',
                              return_value=(policy, '1'*64)), \
                 patch.object(completion.custody, 'check', return_value=final), \
                 patch.object(completion, 'early_final', return_value={'x': '5'*64}), \
                 patch.object(completion.starter, 'clean_checkout', return_value=commit), \
                 patch.object(completion.starter, 'read_key', return_value=b'k'*32), \
                 patch.object(completion, 'open_queue', return_value=Database()), \
                 patch.object(completion, 'issue_complete',
                              return_value=({'sequence': 7}, '6'*64)) as issued:
                result = completion.complete(root / 'queue.db', root,
                    root / 'policy.json', root / 'key',
                    root / 'start-workspace/verified-observation.json', 123, 1)
            payload = issued.call_args.args[2]
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(payload['final_artifact'], {'id': 789, 'sha256': '3'*64})
            self.assertEqual(payload['sarif_sha256'], hashlib.sha256(
                (snapshot / 'event/out/default-suite.sarif').read_bytes()).hexdigest())
            self.assertEqual(payload['start_sha256'], '4'*64)
            self.assertEqual(payload['source'], {'commit': 'd'*40, 'tree': 'e'*40})

    def test_failure_requires_terminal_exact_job(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            commit = 'a'*40
            job = {'workflow': '.github/workflows/incoming-event-preflight.yml',
                   'job': 'released-event-scan', 'run_id': 123,
                   'attempt': 1, 'id': 456, 'consumer_commit': commit}
            start = {'sequence': 6, 'attestation': {
                'policy_sha256': '1'*64, 'job': job, 'queue_id': 'b'*32,
                'event_id': 'event', 'reservation': 5,
                'reservation_digest': '2'*64, 'run_id': '123-1'}}
            policy = {'consumer_commit': commit, 'queue_id': 'b'*32}
            run = {'id': 123, 'run_attempt': 1,
                   'repository': {'full_name': 'lucas-albers-lz4/codeql-openwrt'},
                   'path': job['workflow'], 'event': 'workflow_dispatch',
                   'head_sha': commit, 'status': 'completed',
                   'conclusion': 'failure'}
            jobs = {'total_count': 1, 'jobs': [{
                'id': 456, 'name': 'released-event-scan', 'run_id': 123,
                'run_attempt': 1, 'head_sha': commit, 'status': 'completed',
                'conclusion': 'failure'}]}
            class Database:
                def close(self):
                    pass
            with patch.object(failure.completion, 'issued_start',
                              return_value=(start, '3'*64)), \
                 patch.object(failure.observation, 'read_policy',
                              return_value=(policy, '1'*64)), \
                 patch.object(failure.custody, 'fetch',
                              side_effect=[encoded(run), encoded(jobs)]) as fetch, \
                 patch.object(failure.starter, 'clean_checkout', return_value=commit), \
                 patch.object(failure.starter, 'read_key', return_value=b'k'*32), \
                 patch.object(failure, 'open_queue', return_value=Database()), \
                 patch.object(failure, 'issue_failure',
                              return_value=({'sequence': 7}, '4'*64)) as issued:
                result = failure.fail(root / 'queue.db', root, root / 'policy.json',
                                      root / 'key', 123, 1)
            self.assertEqual(result['status'], 'pending_retry')
            self.assertEqual(issued.call_args.args[2]['job']['id'], 456)
            run['status'] = 'in_progress'
            with patch.object(failure.completion, 'issued_start',
                              return_value=(start, '3'*64)), \
                 patch.object(failure.observation, 'read_policy',
                              return_value=(policy, '1'*64)), \
                 patch.object(failure.custody, 'fetch',
                              side_effect=[encoded(run), encoded(jobs)]), \
                 patch.object(failure, 'issue_failure') as blocked:
                with self.assertRaises(PollError):
                    failure.fail(root / 'queue.db', root, root / 'policy.json',
                                 root / 'key', 123, 1)
                blocked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
