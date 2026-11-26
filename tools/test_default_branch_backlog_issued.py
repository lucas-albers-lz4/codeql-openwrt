"""Offline v2→v3 migration, issued MAC, CAS and concurrency controls."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools.test_default_branch_backlog_intake import Fixture


ZERO_HASH = '0' * 64
TEST_KEY = b'disposable-offline-key-for-unit-tests-32b'
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
OBSERVED = '2026-11-26T12:01:00Z'


class DefaultBranchBacklogIssuedTests(unittest.TestCase):
    def setUp(self):
        work = Path(__file__).resolve().parents[1] / 'work'
        work.mkdir(mode=0o700, exist_ok=True)
        os.chmod(work, 0o700)
        self.tmp = tempfile.TemporaryDirectory(prefix='backlog-issued-', dir=work)
        self.fx = Fixture(self.tmp.name)
        self.root = self.fx.private
        self.database = self.root / issued.DATABASE_NAME
        self.release_lock = Path(__file__).resolve().parents[1] / 'docs/r3-release-lock.json'
        lock_sha = hashlib.sha256(self.release_lock.read_bytes()).hexdigest()
        self.policy_path = Path(self.tmp.name) / 'reservation-policy.json'
        self.policy_path.write_text(json.dumps({
            'schema': reservation.POLICY_SCHEMA,
            'consumer_commit': 'a' * 40,
            'workflow': reservation.WORKFLOW,
            'release_lock_sha256': lock_sha,
        }, sort_keys=True, separators=(',', ':')) + '\n')
        self.policy_path.chmod(0o600)
        _, current, _, previous_bundle, current_bundle, _ = self.fx.make_initial_pair()
        self.fx.run_intake(previous_bundle, current_bundle)
        self.current_checkpoint, _, successor_bundle = self.fx.make_empty_successor(
            current, current_bundle, run_id=1004)
        self.fx.run_intake(current_bundle, successor_bundle)
        self.current_bundle = successor_bundle
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0], 7)

    def tearDown(self):
        self.tmp.cleanup()

    def _identity(self, ordinal=1):
        with closing(sqlite3.connect(self.database)) as db:
            row = db.execute('''
                SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
                       b.first_parent_sha,b.intake_id,i.receipt_seq
                FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
                WHERE b.repository='openwrt/openwrt' AND b.ordinal=?
            ''', (ordinal,)).fetchone()
        self.assertIsNotNone(row)
        return dict(zip(('repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                         'first_parent_sha', 'intake_id', 'receipt_seq'), row))

    def _migrate_v2(self, *, reserve=True, expires_at=None):
        reservation.migrate_v1(self.root)
        if reserve:
            identity = self._identity()
            reservation.reserve(
                self.root, 0, ZERO_HASH, identity, self.policy_path,
                self.release_lock, 'offline-operator',
                expires_at or (NOW + timedelta(hours=24)).isoformat(), now=NOW)

    def _approved_policy(self):
        with closing(sqlite3.connect(self.database)) as db:
            raw = db.execute(
                'SELECT body_json FROM reservation_actions WHERE action_seq=1').fetchone()[0]
        policy = json.loads(raw)['policy']
        return {'consumer_commit': policy['consumer_commit'],
                'release_lock_sha256': policy['release_lock_sha256']}

    def _attestation(self, *, run_id=9991001, run_attempt=1, job_id=9991002):
        with closing(sqlite3.connect(self.database)) as db:
            row = db.execute(
                'SELECT body_json,action_hash FROM reservation_actions WHERE action_seq=1').fetchone()
        body = json.loads(row[0])
        return {
            'schema': issued.START_SCHEMA,
            'kind': 'start',
            'queue_id': body['queue_id'],
            'reservation_sequence': body['action_seq'],
            'reservation_sha256': row[1],
            'identity': body['identity'],
            'origin_receipt_sha256': body['origin']['receipt_hash'],
            'origin_gap_sha256': body['origin']['gap_sha256'],
            'policy_sha256': body['policy']['policy_sha256'],
            'consumer_commit': body['policy']['consumer_commit'],
            'release_lock_sha256': body['policy']['release_lock_sha256'],
            'run_id': run_id,
            'run_attempt': run_attempt,
            'job_id': job_id,
            'workflow': reservation.WORKFLOW,
            'job': issued.START_JOB,
            'early_artifact': {'id': 9991003, 'sha256': '1' * 64, 'size': 1234},
            'observation_sha256': '2' * 64,
            'run_api_sha256': '3' * 64,
            'jobs_api_sha256': '4' * 64,
            'artifacts_api_sha256': '5' * 64,
            'recheck_run_api_sha256': '6' * 64,
            'recheck_jobs_api_sha256': '7' * 64,
        }

    def _bare_attestation(self, queue_id):
        return {
            'schema': issued.START_SCHEMA,
            'kind': 'start',
            'queue_id': queue_id,
            'reservation_sequence': 1,
            'reservation_sha256': '8' * 64,
            'identity': self._identity(),
            'origin_receipt_sha256': '9' * 64,
            'origin_gap_sha256': 'a' * 64,
            'policy_sha256': hashlib.sha256(self.policy_path.read_bytes()).hexdigest(),
            'consumer_commit': 'a' * 40,
            'release_lock_sha256': hashlib.sha256(self.release_lock.read_bytes()).hexdigest(),
            'run_id': 9991001,
            'run_attempt': 1,
            'job_id': 9991002,
            'workflow': reservation.WORKFLOW,
            'job': issued.START_JOB,
            'early_artifact': {'id': 9991003, 'sha256': '1' * 64, 'size': 1234},
            'observation_sha256': '2' * 64,
            'run_api_sha256': '3' * 64,
            'jobs_api_sha256': '4' * 64,
            'artifacts_api_sha256': '5' * 64,
            'recheck_run_api_sha256': '6' * 64,
            'recheck_jobs_api_sha256': '7' * 64,
        }

    def _v2_snapshot(self):
        with closing(sqlite3.connect(self.database)) as db:
            return issued._v1_v2_snapshot(db)

    def _migrate_v3(self, *, reserve=True, expires_at=None):
        self._migrate_v2(reserve=reserve, expires_at=expires_at)
        before = self._v2_snapshot()
        result = issued.migrate_v2_to_v3(self.root)
        self.assertEqual(self._v2_snapshot(), before)
        return result

    def _issued_snapshot(self):
        with closing(sqlite3.connect(self.database)) as db:
            return (db.execute('SELECT * FROM issued_head').fetchall(),
                    db.execute('SELECT * FROM issued_actions').fetchall())

    def _issue(self, attestation=None, observed_at=OBSERVED, *, key=TEST_KEY,
               approved_policy=None, expected_seq=0, expected_hash=ZERO_HASH):
        return issued.issue_start(
            self.root, expected_seq, expected_hash, key,
            approved_policy or self._approved_policy(),
            attestation or self._attestation(), observed_at)

    def test_v2_to_v3_migration_adds_only_new_chain_and_preserves_v1_v2_bytes(self):
        self._migrate_v2()
        before = self._v2_snapshot()
        with closing(sqlite3.connect(self.database)) as db:
            original_reservation = db.execute(
                'SELECT previous_hash,body_json,action_hash FROM reservation_actions').fetchone()
        result = issued.migrate_v2_to_v3(self.root)
        self.assertEqual(result['status'], 'migrated_v2_to_v3')
        self.assertEqual(result['reservation_action_count'], 1)
        self.assertEqual(result['receipt_count'], 2)
        self.assertEqual(result['commit_count'], 7)
        self.assertEqual(self._v2_snapshot(), before)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 3)
            self.assertEqual(db.execute(
                'SELECT previous_hash,body_json,action_hash FROM reservation_actions').fetchone(),
                original_reservation)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE reservation_actions SET body_json='{}' WHERE action_seq=1")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('DELETE FROM reservation_actions WHERE action_seq=1')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM issued_actions').fetchone()[0], 0)
        self.assertEqual(issued.issued_head(self.root), {
            'queue_id': result['queue_id'], 'seq': 0, 'sha256': ZERO_HASH,
            'action_count': 0, 'hmac_verified': False})
        with self.assertRaisesRegex(issued.IssuedActionError, 'requires the v2 reservation'):
            issued.migrate_v2_to_v3(self.root)

    def test_empty_reservation_v2_migrates_without_fabricating_start(self):
        result = self._migrate_v3(reserve=False)
        self.assertEqual(result['reservation_action_count'], 0)
        self.assertEqual(issued.issued_head(self.root)['action_count'], 0)

    def test_start_requires_exactly_one_reservation(self):
        self._migrate_v3(reserve=False)
        with closing(sqlite3.connect(self.database)) as db:
            queue_id = db.execute(
                'SELECT queue_id FROM queue_metadata WHERE singleton=1').fetchone()[0]
        approved = {
            'consumer_commit': 'a' * 40,
            'release_lock_sha256': hashlib.sha256(self.release_lock.read_bytes()).hexdigest(),
        }
        with self.assertRaisesRegex(issued.IssuedActionError, 'exactly one v2 reservation'):
            issued.issue_start(self.root, 0, ZERO_HASH, TEST_KEY, approved,
                               self._bare_attestation(queue_id), OBSERVED)
        self.assertEqual(issued.issued_head(self.root)['action_count'], 0)

    def test_v2_to_v3_ddl_failure_rolls_back_schema_and_rows(self):
        self._migrate_v2()
        before = self._v2_snapshot()
        create = issued._create_v3_objects

        def fail_after_ddl(conn, queue_id):
            create(conn, queue_id)
            raise RuntimeError('injected v3 DDL failure')

        with patch.object(issued, '_create_v3_objects', side_effect=fail_after_ddl):
            with self.assertRaisesRegex(RuntimeError, 'injected v3 DDL failure'):
                issued.migrate_v2_to_v3(self.root)
        self.assertEqual(self._v2_snapshot(), before)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND substr(name,1,7)!='sqlite_'" )}
        self.assertEqual(tables, {'cursor', 'intakes', 'commit_backlog', 'receipts',
                                  'queue_metadata', 'reservation_actions', 'action_head'})

    def test_signed_start_mac_document_hash_and_append_only_chain(self):
        self._migrate_v3()
        result = self._issue()
        self.assertEqual(result['status'], 'issued_start')
        self.assertEqual(result['issued_seq'], 1)
        head = issued.issued_head(self.root, TEST_KEY)
        self.assertTrue(head['hmac_verified'])
        self.assertEqual(head['seq'], 1)
        with closing(sqlite3.connect(self.database)) as db:
            row = db.execute('SELECT * FROM issued_actions WHERE seq=1').fetchone()
            for statement in (
                    "UPDATE issued_actions SET document_json='{}' WHERE seq=1",
                    'DELETE FROM issued_actions WHERE seq=1'):
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(statement)
            self.assertEqual(db.execute(
                'SELECT seq,hash FROM issued_head WHERE singleton=1').fetchone(),
                (1, result['issued_sha256']))
        document_raw = row[2].encode('utf-8')
        self.assertTrue(document_raw.endswith(b'\n'))
        self.assertEqual(hashlib.sha256(document_raw).hexdigest(), result['issued_sha256'])
        document = json.loads(document_raw)
        mac = document.pop('mac')
        expected_mac = hmac.new(
            TEST_KEY, issued.DOMAIN + issued.canonical_bytes(document),
            hashlib.sha256).hexdigest()
        self.assertEqual(mac, expected_mac)
        with closing(sqlite3.connect(self.database)) as db:
            db.row_factory = sqlite3.Row
            self.assertEqual(issued.verify_issued_chain(
                db, TEST_KEY)['sha256'], result['issued_sha256'])
        with self.assertRaisesRegex(issued.IssuedActionError, 'MAC mismatch'):
            issued.issued_head(self.root, b'wrong-disposable-key-32-bytes-long')

    def test_later_intake_preserves_signed_start_chain(self):
        self._migrate_v3()
        self._issue()
        _, _, next_bundle = self.fx.make_empty_successor(
            self.current_checkpoint, self.current_bundle, run_id=1005)
        result = self.fx.run_intake(self.current_bundle, next_bundle)
        self.assertEqual(result['status'], 'intake_recorded')
        self.assertEqual(issued.issued_head(self.root, TEST_KEY)['seq'], 1)
        self.assertEqual(issued.issued_head(self.root, TEST_KEY)['action_count'], 1)

    def test_stale_cas_duplicate_action_and_bad_binding_do_not_mutate(self):
        self._migrate_v3()
        before = self._issued_snapshot()
        with self.assertRaisesRegex(issued.IssuedActionError, 'stale issued action head'):
            self._issue(expected_seq=1, expected_hash='a' * 64)
        wrong = self._attestation()
        wrong['consumer_commit'] = 'b' * 40
        with self.assertRaisesRegex(issued.IssuedActionError, 'differs from exact'):
            self._issue(wrong)
        self.assertEqual(self._issued_snapshot(), before)
        self._issue()
        started = self._issued_snapshot()
        with self.assertRaisesRegex(issued.IssuedActionError, 'stale issued action head'):
            self._issue(expected_seq=0, expected_hash=ZERO_HASH)
        self.assertEqual(self._issued_snapshot(), started)

    def test_approved_policy_and_reservation_expiry_are_checked(self):
        self._migrate_v3()
        wrong_policy = self._approved_policy()
        wrong_policy['consumer_commit'] = 'b' * 40
        with self.assertRaisesRegex(issued.IssuedActionError, 'approved policy differs'):
            self._issue(approved_policy=wrong_policy)
        with self.assertRaisesRegex(issued.IssuedActionError, 'after an unexpired reservation'):
            self._issue(observed_at='2026-11-28T12:00:00Z')
        self.assertEqual(self._issued_snapshot()[0][0][3], ZERO_HASH)

    def test_malformed_key_and_path_are_rejected_without_mutation(self):
        self._migrate_v3()
        before = self._issued_snapshot()
        for key in (None, b'', b'x' * 31, bytearray(b'x' * 32), 'x' * 32):
            with self.subTest(key_type=type(key).__name__), self.assertRaisesRegex(
                    issued.IssuedActionError, 'at least 32 bytes'):
                self._issue(key=key)
            self.assertEqual(self._issued_snapshot(), before)
        root_alias = Path(self.tmp.name) / 'private-alias'
        root_alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(issued.IssuedActionError, 'symlink'):
            issued.issued_head(root_alias)
        db_alias = self.root / 'database-alias.sqlite3'
        os.link(self.database, db_alias)
        with self.assertRaisesRegex(issued.IssuedActionError, 'singly linked'):
            issued.issued_head(self.root)
        db_alias.unlink()
        self.assertEqual(self._issued_snapshot(), before)

    def test_migration_rejects_tampered_reservation_chain_before_adding_v3(self):
        self._migrate_v2()
        before = self._v2_snapshot()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('DROP TRIGGER reservation_actions_no_update')
            db.execute("UPDATE reservation_actions SET action_hash=? WHERE action_seq=1",
                       ('a' * 64,))
            db.execute("CREATE TRIGGER reservation_actions_no_update BEFORE UPDATE ON reservation_actions "
                       "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END")
            db.commit()
        tampered = self._v2_snapshot()
        with self.assertRaisesRegex(reservation.ReservationError, 'hash mismatch'):
            issued.migrate_v2_to_v3(self.root)
        self.assertEqual(self._v2_snapshot(), tampered)
        self.assertNotEqual(tampered, before)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)

    def test_migration_rejects_tampered_reservation_head_before_adding_v3(self):
        self._migrate_v2()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE action_head SET action_seq=0,action_hash=? WHERE singleton=1',
                       (ZERO_HASH,))
            db.commit()
        before = self._v2_snapshot()
        with self.assertRaisesRegex(reservation.ReservationError, 'head differs'):
            issued.migrate_v2_to_v3(self.root)
        self.assertEqual(self._v2_snapshot(), before)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)

    def test_migration_rejects_tampered_receipt_chain_before_adding_v3(self):
        self._migrate_v2()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE receipts SET receipt_hash=? WHERE receipt_seq=1',
                       ('a' * 64,))
            db.commit()
        before = self._v2_snapshot()
        with self.assertRaisesRegex(intake.IntakeError, 'receipt chain hash mismatch'):
            issued.migrate_v2_to_v3(self.root)
        self.assertEqual(self._v2_snapshot(), before)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)

    def test_two_concurrent_same_head_issuers_produce_one_start(self):
        self._migrate_v3()
        barrier = threading.Barrier(2)

        def writer(run_id):
            barrier.wait(timeout=5)
            try:
                return self._issue(self._attestation(run_id=run_id,
                                                     job_id=run_id + 10))
            except issued.IssuedActionError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(writer, (9992001, 9993001)))
        self.assertEqual(sum(isinstance(item, dict) for item in outcomes), 1)
        errors = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), 'stale issued action head')
        head = issued.issued_head(self.root, TEST_KEY)
        self.assertEqual(head['seq'], 1)
        self.assertEqual(head['action_count'], 1)
        self.assertTrue(head['hmac_verified'])

    def test_issued_test_is_wired_into_discovery_contract_workflow(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    '.github/workflows/incoming-discovery-manual.yml').read_text()
        self.assertIn('tools.test_default_branch_backlog_issued', workflow)


if __name__ == '__main__':
    unittest.main()
