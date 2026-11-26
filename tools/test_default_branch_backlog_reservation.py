"""Focused migration, exact-origin reservation and CAS controls."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_reservation as reservation
from tools import incoming_poll as poll
from tools.test_default_branch_backlog_intake import (
    Fixture, _compare_commit, checkpoint, event, gap_record, json_bytes, sha)


ZERO_HASH = '0' * 64


class DefaultBranchBacklogReservationTests(unittest.TestCase):
    def setUp(self):
        work = Path(__file__).resolve().parents[1] / 'work'
        work.mkdir(mode=0o700, exist_ok=True)
        os.chmod(work, 0o700)
        self.tmp = tempfile.TemporaryDirectory(prefix='backlog-reservation-', dir=work)
        self.fx = Fixture(self.tmp.name)
        self.root = self.fx.private
        self.policy_path = Path(self.tmp.name) / 'reservation-policy.json'
        self.release_lock = Path(__file__).resolve().parents[1] / 'docs/r3-release-lock.json'
        lock_sha = hashlib.sha256(self.release_lock.read_bytes()).hexdigest()
        self.policy_path.write_text(json.dumps({
            'schema': reservation.POLICY_SCHEMA,
            'consumer_commit': 'a' * 40,
            'workflow': reservation.WORKFLOW,
            'release_lock_sha256': lock_sha,
        }, sort_keys=True, separators=(',', ':')) + '\n')
        self.policy_path.chmod(0o600)
        self.now = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
        self._build_two_intake_v1()

    def tearDown(self):
        self.tmp.cleanup()

    @property
    def database(self):
        return self.root / reservation.DATABASE_NAME

    def _build_two_intake_v1(self):
        _, current, _, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        self.fx.run_intake(prev_bundle, current_bundle)
        second_checkpoint, _, second_bundle = self.fx.make_empty_successor(current, current_bundle)
        # The second discovery keeps the exact same seven rows while moving the
        # cursor and receipt chain to sequence 2.
        self.fx.run_intake(current_bundle, second_bundle)
        self.current_checkpoint = second_checkpoint
        self.current_bundle = second_bundle
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0], 7)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commit_backlog WHERE status='pending'").fetchone()[0], 7)

    def _v1_snapshot(self):
        with closing(sqlite3.connect(self.database)) as db:
            return {
                table: db.execute('SELECT * FROM ' + table + ' ORDER BY ' + order).fetchall()
                for table, order in (
                    ('cursor', 'singleton'), ('intakes', 'receipt_seq'),
                    ('commit_backlog', 'repository,ref,commit_sha'),
                    ('receipts', 'receipt_seq'))
            }

    def _identity(self, ordinal=1):
        with closing(sqlite3.connect(self.database)) as db:
            row = db.execute('''
                SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
                       b.first_parent_sha,b.intake_id,i.receipt_seq
                FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
                WHERE b.repository='openwrt/openwrt' AND b.ordinal=?
            ''', (ordinal,)).fetchone()
        self.assertIsNotNone(row)
        keys = ('repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                'first_parent_sha', 'intake_id', 'receipt_seq')
        return dict(zip(keys, row))

    def _migrate(self):
        return reservation.migrate_v1(self.root)

    def _reserve(self, identity=None, *, seq=0, head=ZERO_HASH,
                 operator='operator@example.test', policy=None, expires_at=None):
        return reservation.reserve(
            self.root, seq, head, identity or self._identity(),
            policy or self.policy_path, self.release_lock, operator,
            expires_at or (self.now + timedelta(hours=24)).isoformat(), now=self.now)

    def _action_snapshot(self):
        with closing(sqlite3.connect(self.database)) as db:
            return (
                db.execute('SELECT * FROM action_head').fetchall(),
                db.execute('SELECT * FROM reservation_actions').fetchall(),
                db.execute('SELECT COUNT(*) FROM commit_backlog').fetchone(),
                db.execute('SELECT COUNT(*) FROM receipts').fetchone(),
            )

    def test_explicit_v1_migration_preserves_two_intakes_and_seven_rows(self):
        before = self._v1_snapshot()
        migrated = self._migrate()
        after = self._v1_snapshot()
        self.assertEqual(migrated['status'], 'migrated_v1_to_v2')
        self.assertEqual(migrated['receipt_count'], 2)
        self.assertEqual(migrated['commit_count'], 7)
        self.assertEqual(after, before)
        self.assertEqual(reservation.action_head(self.root)['action_seq'], 0)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commit_backlog WHERE status='pending'").fetchone()[0], 7)
        with self.assertRaisesRegex(reservation.ReservationError, 'requires the pending-only v1'):
            self._migrate()

    def test_format_valid_policy_is_recorded_as_an_operator_claim(self):
        self._migrate()
        identity = self._identity(ordinal=3)
        result = self._reserve(identity)
        self.assertEqual(result['status'], 'reserved_only')
        self.assertEqual(result['action_seq'], 1)
        self.assertEqual(result['identity'], identity)
        self.assertEqual(result['origin']['receipt_seq'], identity['receipt_seq'])
        self.assertEqual(result['origin']['current_run_id'], 1002)
        self.assertEqual(result['origin']['current_attempt'], 1)
        self.assertEqual(result['origin']['current_artifact_id'], 101002)
        with closing(sqlite3.connect(self.database)) as db:
            current_checkpoint = db.execute(
                'SELECT current_checkpoint_sha256 FROM intakes WHERE receipt_seq=?',
                (identity['receipt_seq'],)).fetchone()[0]
        self.assertEqual(result['origin']['current_checkpoint_sha256'], current_checkpoint)
        self.assertEqual(result['policy']['workflow'], reservation.WORKFLOW)
        self.assertEqual(result['policy']['consumer_commit'], 'a' * 40)
        self.assertEqual(result['policy']['policy_sha256'],
                         hashlib.sha256(self.policy_path.read_bytes()).hexdigest())
        self.assertEqual(result['policy']['release_lock_sha256'],
                         hashlib.sha256(self.release_lock.read_bytes()).hexdigest())
        self.assertEqual(result['policy']['release_tag'], 'v0.1.0-rc.1')
        self.assertEqual(result['policy']['release_commit'],
                         '131605a726b7a79eb926886d07bf44eb721fe450')
        self.assertEqual(result['expires_at'], '2026-11-27T12:00:00Z')
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commit_backlog WHERE status='pending'").fetchone()[0], 7)
            body = json.loads(db.execute(
                'SELECT body_json FROM reservation_actions WHERE action_seq=1').fetchone()[0])
        self.assertEqual(body['action'], 'reserve')
        self.assertEqual(body['status'], 'reserved_only')
        self.assertNotIn('run_id', body)
        self.assertNotIn('start', body)
        self.assertNotIn('complete', body)
        self.assertEqual(reservation.action_head(self.root)['action_count'], 1)

    def test_later_intake_preserves_existing_reservation_action(self):
        self._migrate()
        self._reserve(self._identity(ordinal=4))
        _, _, successor_bundle = self.fx.make_empty_successor(
            self.current_checkpoint, self.current_bundle, run_id=1004)
        result = self.fx.run_intake(self.current_bundle, successor_bundle)
        self.assertEqual(result['status'], 'intake_recorded')
        self.assertEqual(reservation.action_head(self.root)['action_count'], 1)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 3)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM reservation_actions').fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commit_backlog WHERE status='pending'").fetchone()[0], 7)

    def test_luci_master_default_branch_commit_can_be_reserved(self):
        luci_parent = Path(self.tmp.name) / 'luci-master-case'
        luci_parent.mkdir(mode=0o700)
        luci_fx = Fixture(luci_parent)
        previous, _, _, previous_bundle, _, _ = luci_fx.make_initial_pair()
        tips = {item['repository']: item
                for item in poll.replay_observed_doc(previous)}
        old_luci = tips['openwrt/luci']
        commit_sha, tree_sha = sha('luci-master-commit'), sha('luci-master-tree')
        commit = _compare_commit(commit_sha, tree_sha, old_luci['source']['commit'])
        tips['openwrt/luci'] = event('openwrt/luci', commit_sha, tree_sha, ref='master')
        previous_raw = json_bytes(previous)
        current = checkpoint(tips, previous['decisions'],
                             hashlib.sha256(previous_raw).hexdigest())
        linked_gap = gap_record(previous, current, [commit], repository='openwrt/luci')
        current_bundle = luci_fx.bundle(
            1002, 1, current, prior_run=1001, prior_attempt=1,
            version=2, gap=linked_gap)
        luci_fx.run_intake(previous_bundle, current_bundle)
        reservation.migrate_v1(luci_fx.private)
        with closing(sqlite3.connect(luci_fx.private / reservation.DATABASE_NAME)) as db:
            row = db.execute('''
                SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
                       b.first_parent_sha,b.intake_id,i.receipt_seq
                FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
            ''').fetchone()
        identity = dict(zip(('repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                             'first_parent_sha', 'intake_id', 'receipt_seq'), row))
        result = reservation.reserve(
            luci_fx.private, 0, ZERO_HASH, identity, self.policy_path,
            self.release_lock, 'luci-operator',
            (self.now + timedelta(hours=24)).isoformat(), now=self.now)
        self.assertEqual(result['identity']['repository'], 'openwrt/luci')
        self.assertEqual(result['identity']['ref'], 'master')

    def test_second_connection_stale_head_and_duplicate_conflict_do_not_mutate(self):
        self._migrate()
        self._reserve()
        before = self._action_snapshot()
        current = reservation.action_head(self.root)
        stale = self._identity()
        stale['tree_sha'] = 'f' * 40
        with self.assertRaisesRegex(reservation.ReservationError, 'stale'):
            self._reserve(stale, seq=current['action_seq'], head=current['action_sha256'])
        with self.assertRaisesRegex(reservation.ReservationError, 'already occupies'):
            self._reserve(self._identity(), seq=current['action_seq'], head=current['action_sha256'])
        with self.assertRaisesRegex(reservation.ReservationError, 'already occupies'):
            self._reserve(self._identity(ordinal=2), seq=current['action_seq'],
                          head=current['action_sha256'])
        with self.assertRaisesRegex(reservation.ReservationError, 'stale reservation action head'):
            self._reserve(self._identity(), seq=0, head=ZERO_HASH)
        self.assertEqual(self._action_snapshot(), before)

    def test_two_concurrent_cas_writers_produce_one_action(self):
        self._migrate()
        barrier = threading.Barrier(2)

        def writer(ordinal):
            barrier.wait(timeout=5)
            try:
                return reservation.reserve(
                    self.root, 0, ZERO_HASH, self._identity(ordinal),
                    self.policy_path, self.release_lock, f'writer{ordinal}',
                    (self.now + timedelta(hours=24)).isoformat(), now=self.now)
            except reservation.ReservationError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(writer, (1, 2)))
        self.assertEqual(sum(isinstance(item, dict) for item in outcomes), 1)
        errors = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), 'stale reservation action head')
        self.assertEqual(reservation.action_head(self.root)['action_seq'], 1)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM reservation_actions').fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commit_backlog WHERE status='pending'").fetchone()[0], 7)

    def test_expired_or_overlong_reservation_rejects_without_mutation(self):
        self._migrate()
        before = self._action_snapshot()
        for expiry in ('2026-11-26T11:00:00+00:00', '2026-12-04T12:00:01+00:00'):
            with self.subTest(expiry=expiry), self.assertRaisesRegex(
                    reservation.ReservationError, 'reservation expiry'):
                self._reserve(expires_at=expiry)
            self.assertEqual(self._action_snapshot(), before)

    def test_policy_release_lock_mismatch_rejects_before_queue_mutation(self):
        self._migrate()
        before = self._action_snapshot()
        wrong = Path(self.tmp.name) / 'wrong-policy.json'
        wrong.write_text(json.dumps({
            'schema': reservation.POLICY_SCHEMA,
            'consumer_commit': 'a' * 40,
            'workflow': reservation.WORKFLOW,
            'release_lock_sha256': 'f' * 64,
        }))
        wrong.chmod(0o600)
        with self.assertRaisesRegex(reservation.ReservationError, 'does not bind exact'):
            self._reserve(policy=wrong)
        self.assertEqual(self._action_snapshot(), before)

    def test_policy_symlink_hardlink_and_fifo_rejected_before_queue_mutation(self):
        self._migrate()
        before = self._action_snapshot()
        symlink = Path(self.tmp.name) / 'policy-symlink.json'
        symlink.symlink_to(self.policy_path)
        hardlink = Path(self.tmp.name) / 'policy-hardlink.json'
        os.link(self.policy_path, hardlink)
        fifo = Path(self.tmp.name) / 'policy-fifo.json'
        os.mkfifo(fifo, 0o600)
        for policy_path in (symlink, hardlink, fifo):
            with self.subTest(policy=policy_path.name), self.assertRaises(
                    reservation.ReservationError):
                self._reserve(policy=policy_path)
            self.assertEqual(self._action_snapshot(), before)

    def test_database_symlink_hardlink_fifo_and_sidecar_rejected(self):
        self._migrate()
        alias = self.root / 'database-alias.sqlite3'
        os.link(self.database, alias)
        with self.assertRaisesRegex(reservation.ReservationError, 'singly linked'):
            reservation.action_head(self.root)
        alias.unlink()

        sidecar = Path(str(self.database) + '-wal')
        sidecar.write_bytes(b'not opened')
        sidecar.chmod(0o600)
        with self.assertRaisesRegex(reservation.ReservationError, 'sidecar'):
            reservation.action_head(self.root)
        sidecar.unlink()

        saved = self.root / 'saved.sqlite3'
        self.database.rename(saved)
        self.database.symlink_to(saved.name)
        with self.assertRaisesRegex(reservation.ReservationError, 'symlink'):
            reservation.action_head(self.root)
        self.database.unlink()
        saved.rename(self.database)

        self.database.rename(saved)
        os.mkfifo(self.database, 0o600)
        with self.assertRaisesRegex(reservation.ReservationError, 'regular file'):
            reservation.action_head(self.root)
        self.database.unlink()
        saved.rename(self.database)
        self.assertEqual(reservation.action_head(self.root)['action_seq'], 0)

    def test_migration_ddl_failure_rolls_back_every_schema_change(self):
        before = self._v1_snapshot()
        create = reservation._create_v2_objects

        def fail_after_ddl(conn, queue_id):
            create(conn, queue_id)
            raise RuntimeError('injected DDL failure')

        with patch.object(reservation, '_create_v2_objects', side_effect=fail_after_ddl):
            with self.assertRaisesRegex(RuntimeError, 'injected DDL failure'):
                self._migrate()
        self.assertEqual(self._v1_snapshot(), before)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND substr(name,1,7)!='sqlite_'")}
            self.assertEqual(tables, {'cursor', 'intakes', 'commit_backlog', 'receipts'})

    def test_action_body_tampering_and_append_only_guards_reject(self):
        self._migrate()
        self._reserve()
        with closing(sqlite3.connect(self.database)) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE reservation_actions SET body_json='{}' WHERE action_seq=1")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('DELETE FROM reservation_actions WHERE action_seq=1')
            db.execute('DROP TRIGGER reservation_actions_no_update')
            body = json.loads(db.execute(
                'SELECT body_json FROM reservation_actions WHERE action_seq=1').fetchone()[0])
            body['operator'] = 'changed-operator'
            db.execute('UPDATE reservation_actions SET body_json=? WHERE action_seq=1',
                       (reservation.canonical_json(body),))
            db.execute("CREATE TRIGGER reservation_actions_no_update BEFORE UPDATE ON reservation_actions "
                       "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END")
            db.commit()
        with self.assertRaisesRegex(reservation.ReservationError, 'hash mismatch'):
            reservation.action_head(self.root)

    def test_action_head_tampering_rejects(self):
        self._migrate()
        self._reserve()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE action_head SET action_seq=0, action_hash=? WHERE singleton=1",
                       (ZERO_HASH,))
            db.commit()
        with self.assertRaisesRegex(reservation.ReservationError, 'head differs'):
            reservation.action_head(self.root)

    def test_cli_migrates_and_prints_action_head(self):
        stdout = tempfile.TemporaryFile(mode='w+t')
        with patch('sys.stdout', stdout):
            self.assertEqual(reservation.main(['--private-root', str(self.root), '--migrate-v1']), 0)
        stdout.seek(0)
        self.assertEqual(json.loads(stdout.read())['status'], 'migrated_v1_to_v2')
        stdout.seek(0)
        stdout.truncate(0)
        with patch('sys.stdout', stdout):
            self.assertEqual(reservation.main(['--private-root', str(self.root), '--head']), 0)
        stdout.seek(0)
        head = json.loads(stdout.read())
        self.assertEqual(head['action_seq'], 0)
        stdout.seek(0)
        stdout.truncate(0)
        identity = self._identity()
        args = [
            '--private-root', str(self.root), '--reserve',
            '--expected-action-sequence', str(head['action_seq']),
            '--expected-action-sha256', head['action_sha256'],
            '--repository', identity['repository'], '--ref', identity['ref'],
            '--ordinal', str(identity['ordinal']), '--commit-sha', identity['commit_sha'],
            '--tree-sha', identity['tree_sha'], '--first-parent-sha', identity['first_parent_sha'],
            '--intake-id', identity['intake_id'], '--receipt-seq', str(identity['receipt_seq']),
            '--policy', str(self.policy_path), '--release-lock', str(self.release_lock),
            '--operator', 'cli-operator', '--expires-at', '2026-11-27T12:00:00Z',
        ]
        with patch('sys.stdout', stdout):
            self.assertEqual(reservation.main(args), 0)
        stdout.seek(0)
        self.assertEqual(json.loads(stdout.read())['status'], 'reserved_only')
        stdout.close()


if __name__ == '__main__':
    unittest.main()
