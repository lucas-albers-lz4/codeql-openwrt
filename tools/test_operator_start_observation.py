import hashlib
import json
import tempfile
from pathlib import Path
import unittest

import operator_start_observation as start


class StartObservationTests(unittest.TestCase):
    def setUp(self):
        self.commit = 'a' * 40
        self.source = 'b' * 40
        self.control = 'c' * 40
        self.digest = 'd' * 64
        self.queue_id = 'e' * 32
        self.policy = {'consumer_commit': self.commit,
                       'workflow': '.github/workflows/incoming-event-preflight.yml',
                       'queue_id': self.queue_id}
        self.run = {'id': 123, 'run_attempt': 1,
                    'repository': {'full_name': 'lucas-albers-lz4/codeql-openwrt'},
                    'path': self.policy['workflow'], 'event': 'workflow_dispatch',
                    'head_sha': self.commit, 'status': 'in_progress', 'conclusion': None,
                    'created_at': '2026-01-01T00:00:00Z'}
        self.job = {'id': 456, 'name': 'released-event-scan', 'run_id': 123,
                    'run_attempt': 1, 'head_sha': self.commit,
                    'status': 'in_progress', 'conclusion': None,
                    'started_at': '2026-01-01T00:01:00Z'}
        self.artifact = {'id': 789, 'name': 'incoming-start-123-1',
                         'workflow_run': {'id': 123}, 'expired': False,
                         'size_in_bytes': 100, 'digest': 'sha256:' + 'f' * 64,
                         'created_at': '2026-01-01T00:02:00Z'}
        self.event_id = json.dumps(['openwrt/openwrt', 'pull_request', 17,
                                    self.source], separators=(',', ':'))
        self.reservation = {'schema': 'incoming-queue-manual-reservation-v1',
                            'status': 'reserved_only', 'queue_id': self.queue_id,
                            'sequence': 5, 'event_id': self.event_id,
                            'observed_at': '2025-12-31T23:59:00Z',
                            'source': {'commit': self.source, 'tree': None},
                            'control_sha': self.control}

    def api(self):
        return start.verify_live_api(self.run,
                                     {'total_count': 1, 'jobs': [self.job]},
                                     {'total_count': 1, 'artifacts': [self.artifact]},
                                     123, 1, self.policy)

    def test_live_api_exact(self):
        self.assertEqual(self.api()[0]['id'], 456)
        start.verify_order(self.run, self.reservation)

    def test_run_before_reservation_rejected(self):
        self.reservation['observed_at'] = '2026-01-01T00:00:01Z'
        with self.assertRaisesRegex(start.StartError, 'predates'):
            start.verify_order(self.run, self.reservation)

    def test_finished_or_wrong_job_rejected(self):
        self.job['status'] = 'completed'
        with self.assertRaises(start.StartError):
            self.api()
        self.job['status'] = 'in_progress'
        self.job['head_sha'] = '0' * 40
        with self.assertRaises(start.StartError):
            self.api()

    def test_wrong_artifact_or_incomplete_page_rejected(self):
        self.artifact['workflow_run']['id'] = 999
        with self.assertRaises(start.StartError):
            self.api()
        self.artifact['workflow_run']['id'] = 123
        with self.assertRaises(start.StartError):
            start.verify_live_api(self.run,
                                  {'total_count': 2, 'jobs': [self.job]},
                                  {'total_count': 1, 'artifacts': [self.artifact]},
                                  123, 1, self.policy)

    def test_malformed_nested_api_rejected(self):
        self.run['repository'] = None
        with self.assertRaisesRegex(start.StartError, 'object shape'):
            self.api()

    def files(self, root):
        values = {
            'dispatch-inputs.json': {'schema': 'incoming-dispatch-inputs-v1',
                'status': 'claimed_unverified', 'run_id': '123-1',
                'upstream': 'openwrt', 'pr_number': 17,
                'source_sha': self.source, 'control_sha': self.control,
                'queue_id': self.queue_id, 'reservation_sequence': 5,
                'reservation_sha256': self.digest},
            'reservation-claim.json': {'schema': 'incoming-reservation-claim-v1',
                'status': 'claimed_unverified', 'run_id': '123-1',
                'queue_id': self.queue_id, 'reservation_sequence': 5,
                'reservation_sha256': self.digest, 'event_id': self.event_id,
                'source_sha': self.source, 'control_sha': self.control},
            'replayed-receipt.json': {'schema': 'incoming-event-receipt-v1',
                'status': 'identities_resolved_only', 'repository': 'openwrt',
                'pr_number': 17, 'base_repository': 'openwrt/openwrt',
                'repository_url': 'https://github.com/openwrt/openwrt.git',
                'event_type': 'manual_sha_drill', 'source': {'commit': self.source},
                'base': {'commit': self.control},
                'control': {'commit': self.control}},
            'scan-pull-api-response.json': {'state': 'open', 'number': 17,
                'head': {'sha': self.source},
                'base': {'sha': self.control,
                         'repo': {'full_name': 'openwrt/openwrt'}}},
        }
        raw = {name: (json.dumps(value, sort_keys=True) + '\n').encode()
               for name, value in values.items()}
        receipt = {'schema': 'incoming-early-start-observation-v1',
                   'status': 'retained_non_issuing', 'run_id': '123-1',
                   'consumer_commit': self.commit,
                   'files': {name: hashlib.sha256(data).hexdigest()
                             for name, data in raw.items()}}
        raw['receipt.json'] = (json.dumps(receipt, sort_keys=True) + '\n').encode()
        for name, data in raw.items():
            (root / name).write_bytes(data)
        return values

    def test_early_files_exact_and_wrong_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = self.files(root)
            result = start.verify_early_files(root, self.reservation, self.digest,
                                              123, 1, self.policy)
            self.assertEqual(len(result), 5)
            values['reservation-claim.json']['source_sha'] = '0' * 40
            forged = (json.dumps(values['reservation-claim.json'], sort_keys=True) + '\n').encode()
            (root / 'reservation-claim.json').write_bytes(forged)
            receipt = json.loads((root / 'receipt.json').read_bytes())
            receipt['files']['reservation-claim.json'] = hashlib.sha256(forged).hexdigest()
            (root / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
            with self.assertRaises(start.StartError):
                start.verify_early_files(root, self.reservation, self.digest,
                                         123, 1, self.policy)

    def test_forged_pr_number_with_updated_receipt_hash_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = self.files(root)
            values['scan-pull-api-response.json']['number'] = 99
            forged = (json.dumps(values['scan-pull-api-response.json'], sort_keys=True) + '\n').encode()
            (root / 'scan-pull-api-response.json').write_bytes(forged)
            receipt = json.loads((root / 'receipt.json').read_bytes())
            receipt['files']['scan-pull-api-response.json'] = hashlib.sha256(forged).hexdigest()
            (root / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
            with self.assertRaisesRegex(start.StartError, 'canonical PR'):
                start.verify_early_files(root, self.reservation, self.digest,
                                         123, 1, self.policy)


if __name__ == '__main__':
    unittest.main()
