import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from incoming_poll import PollError
from incoming_queue import apply_attested, encoded, open_queue
from incoming_queue_issued import issue_start, issue_complete, issue_failure


class IssuedQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / 'queue.db'
        self.db = open_queue(self.path, create=True)
        self.addCleanup(self.db.close)
        self.key = b'k' * 32
        self.source, self.control, self.tree, self.commit = ('a'*40, 'b'*40,
                                                             'c'*40, 'd'*40)
        self.event_id = json.dumps(['openwrt/openwrt', 'pull_request', 17,
                                    self.source], separators=(',', ':'))
        self.queue_id = self.db.execute(
            "SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        reservation = {'schema': 'incoming-queue-manual-reservation-v1',
                       'status': 'reserved_only', 'queue_id': self.queue_id,
                       'sequence': 5, 'observed_at': '2026-01-01T00:00:00Z',
                       'event_id': self.event_id,
                       'source': {'commit': self.source, 'tree': None},
                       'control_sha': self.control}
        raw = encoded(reservation)
        self.reservation_digest = hashlib.sha256(raw).hexdigest()
        self.db.execute('INSERT INTO history VALUES (?,?,?)',
                        (5, self.reservation_digest, raw))
        event = {'source': {'commit': self.source, 'tree': None},
                 'base_commit': self.control}
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                        (self.event_id, 'subject', encoded(event),
                         '2026-01-01T00:00:00Z', 'reserved', 0, None,
                         'manual_reserved', 5, self.reservation_digest, None))
        self.db.commit()
        self.job = {'workflow': '.github/workflows/incoming-event-preflight.yml',
                    'job': 'released-event-scan', 'run_id': 123, 'attempt': 1,
                    'id': 456, 'consumer_commit': self.commit}

    def start_payload(self):
        return {'schema': 'incoming-issued-start-v1', 'kind': 'start',
                'queue_id': self.queue_id, 'event_id': self.event_id,
                'reservation': 5, 'reservation_digest': self.reservation_digest,
                'run_id': '123-1', 'job': self.job, 'source_sha': self.source,
                'control_sha': self.control, 'policy_sha256': '1'*64,
                'early_artifact': {'id': 789, 'sha256': '2'*64},
                'observation_sha256': '3'*64, 'run_api_sha256': '4'*64,
                'jobs_api_sha256': '5'*64, 'artifacts_api_sha256': '6'*64,
                'recheck_run_api_sha256': '7'*64,
                'recheck_jobs_api_sha256': '8'*64}

    def complete_payload(self, start_digest):
        return {'schema': 'incoming-issued-completion-v1', 'kind': 'complete',
                'queue_id': self.queue_id, 'event_id': self.event_id,
                'reservation': 5, 'reservation_digest': self.reservation_digest,
                'run_id': '123-1', 'job': self.job, 'start_sequence': 6,
                'start_sha256': start_digest,
                'final_artifact': {'id': 999, 'sha256': '9'*64},
                'custody_sha256': 'a'*64, 'early_final_sha256': 'b'*64,
                'source': {'commit': self.source, 'tree': self.tree},
                'control_commit': self.control, 'release_lock_sha256': 'c'*64,
                'manifest_sha256': 'd'*64, 'extraction_sha256': 'e'*64,
                'sarif_sha256': 'f'*64, 'control_sha256': '0'*64,
                'freeze_inventory_sha256': '1'*64,
                'consumer_disposition': 'clean', 'result_count': 0}

    def failure_payload(self, start_digest):
        return {'schema': 'incoming-issued-failure-v1', 'kind': 'failure',
                'queue_id': self.queue_id, 'event_id': self.event_id,
                'reservation': 5, 'reservation_digest': self.reservation_digest,
                'run_id': '123-1', 'job': self.job, 'start_sequence': 6,
                'start_sha256': start_digest, 'run_api_sha256': 'a'*64,
                'jobs_api_sha256': 'b'*64, 'run_conclusion': 'failure',
                'job_conclusion': 'failure'}

    def test_start_and_completion_cas(self):
        start, digest = issue_start(self.db, (5, self.reservation_digest),
                                    self.start_payload(), self.key,
                                    '2026-01-01T00:01:00Z')
        self.assertEqual(start['sequence'], 6)
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('started', 1))
        completion, final = issue_complete(self.db, (6, digest),
                                            self.complete_payload(digest), self.key,
                                            '2026-01-01T00:02:00Z')
        self.assertEqual(completion['sequence'], 7)
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('completed', 1))
        with self.assertRaises(PollError):
            issue_complete(self.db, (6, digest), self.complete_payload(digest),
                           self.key, '2026-01-01T00:03:00Z')

    def test_wrong_job_or_source_rejected_without_mutation(self):
        before = self.path.read_bytes()
        wrong_job = self.start_payload()
        wrong_job['job'] = dict(self.job, id=0)
        with self.assertRaises(PollError):
            issue_start(self.db, (5, self.reservation_digest), wrong_job,
                        self.key, '2026-01-01T00:01:00Z')
        wrong_source = self.start_payload()
        wrong_source['source_sha'] = '0'*40
        with self.assertRaises(PollError):
            issue_start(self.db, (5, self.reservation_digest), wrong_source,
                        self.key, '2026-01-01T00:01:00Z')
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('reserved', 0))
        self.assertEqual(self.path.read_bytes(), before)

    def test_completion_wrong_start_or_job_rejected(self):
        _, digest = issue_start(self.db, (5, self.reservation_digest),
                                self.start_payload(), self.key,
                                '2026-01-01T00:01:00Z')
        for bad in (dict(self.complete_payload(digest), start_sha256='0'*64),
                    dict(self.complete_payload(digest), job=dict(self.job, id=999)),
                    dict(self.complete_payload(digest), control_commit='0'*40)):
            with self.assertRaises(PollError):
                issue_complete(self.db, (6, digest), bad, self.key,
                               '2026-01-01T00:02:00Z')
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('started', 1))

    def test_legacy_recovery_cannot_clear_issued_start(self):
        _, digest = issue_start(self.db, (5, self.reservation_digest),
                                self.start_payload(), self.key,
                                '2026-01-01T00:01:00Z')
        legacy = {'kind': 'recover', 'queue_id': self.queue_id,
                  'event_id': self.event_id, 'reservation': 5,
                  'reservation_digest': self.reservation_digest,
                  'run_id': '123-1'}
        mac = hmac.new(self.key, encoded(legacy), hashlib.sha256).hexdigest()
        with self.assertRaises(PollError):
            apply_attested(self.db, (6, digest), legacy, mac, self.key,
                           '2026-01-01T00:02:00Z')
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('started', 1))

    def test_issued_failure_returns_to_pending_once(self):
        _, digest = issue_start(self.db, (5, self.reservation_digest),
                                self.start_payload(), self.key,
                                '2026-01-01T00:01:00Z')
        result, final = issue_failure(self.db, (6, digest),
                                      self.failure_payload(digest), self.key,
                                      '2026-01-01T00:02:00Z')
        self.assertEqual(result['sequence'], 7)
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('pending', 1))
        with self.assertRaises(PollError):
            issue_failure(self.db, (6, digest), self.failure_payload(digest),
                          self.key, '2026-01-01T00:03:00Z')

    def test_issued_retry_start_increments_existing_attempt(self):
        raw = self.db.execute('SELECT document FROM history WHERE seq=5').fetchone()[0]
        reservation = json.loads(raw)
        reservation['attempts_before'] = 1
        new_raw = encoded(reservation)
        self.reservation_digest = hashlib.sha256(new_raw).hexdigest()
        self.db.execute('UPDATE history SET digest=?,document=? WHERE seq=5',
                        (self.reservation_digest, new_raw))
        self.db.execute('UPDATE events SET attempts=1,reservation_digest=?',
                        (self.reservation_digest,))
        self.db.commit()
        issue_start(self.db, (5, self.reservation_digest), self.start_payload(),
                    self.key, '2026-01-01T00:01:00Z')
        self.assertEqual(self.db.execute('SELECT status,attempts FROM events').fetchone(),
                         ('started', 2))


if __name__ == '__main__':
    unittest.main()
