"""Real v3 issuer and retained-byte controls for read-only start preflight."""
from contextlib import closing
import os
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from tools import default_branch_authenticated_start as preflight
from tools import default_branch_backlog_issued as issued
from tools import default_branch_private_final_capture as capture
from tools import default_branch_private_start as private
from tools import default_branch_reservation_reconcile as reconcile
from tools import test_default_branch_backlog_issued as issued_tests

TEST_KEY = issued_tests.TEST_KEY
OBSERVED = issued_tests.OBSERVED


def put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


class AuthenticatedStartTests(unittest.TestCase):
    def setUp(self):
        self.fixture = issued_tests.DefaultBranchBacklogIssuedTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.db = self.fixture.database
        self.fixture._migrate_v3()
        self.att = self.fixture._attestation(run_id=9, run_attempt=1, job_id=33)
        head = self.att['consumer_commit']
        repository = {'id': capture.REPOSITORY_ID, 'full_name': reconcile.REPOSITORY}
        run = {
            'id': 9, 'run_attempt': 1, 'repository': repository,
            'head_repository': repository, 'workflow_id': capture.WORKFLOW_ID,
            'path': reconcile.SCAN_WORKFLOW, 'event': 'workflow_dispatch',
            'head_branch': 'main', 'head_sha': head, 'status': 'in_progress',
            'conclusion': None, 'run_started_at': '2026-11-26T12:00:01Z',
        }
        job = {
            'id': 33, 'name': reconcile.SCAN_JOB, 'run_id': 9,
            'run_attempt': 1, 'head_sha': head, 'status': 'in_progress',
            'conclusion': None, 'started_at': '2026-11-26T12:00:02Z',
        }
        early_zip = b'fixture-early-zip-bytes'
        artifact = {
            'id': 44, 'name': 'default-branch-start-9-1',
            'size_in_bytes': len(early_zip),
            'digest': 'sha256:' + issued.digest(early_zip),
            'expired': False, 'created_at': '2026-11-26T12:00:03Z',
            'updated_at': '2026-11-26T12:00:04Z',
            'expires_at': '2027-02-24T12:00:00Z',
            'workflow_run': {
                'id': 9, 'repository_id': capture.REPOSITORY_ID,
                'head_repository_id': capture.REPOSITORY_ID,
                'head_branch': 'main', 'head_sha': head,
            },
        }
        bodies = {
            'run': issued.canonical_bytes(run),
            'jobs': issued.canonical_bytes({'jobs': [job], 'total_count': 1}),
            'artifacts': issued.canonical_bytes({'artifacts': [artifact], 'total_count': 1}),
            'recheck_run': issued.canonical_bytes(run),
            'recheck_jobs': issued.canonical_bytes({'jobs': [job], 'total_count': 1}),
            'early_artifact_zip': early_zip,
        }
        self.att['early_artifact'] = {
            'id': 44, 'size': len(early_zip), 'sha256': issued.digest(early_zip),
        }
        observation = self.root / 'observations/default-branch-start-9-1'
        observation.parent.mkdir(mode=0o700)
        observation.mkdir(mode=0o700)
        files = {}
        for role, (name, digest_key) in capture.START_RAW.items():
            raw = bodies[role]
            put(observation / name, raw)
            files[role] = {
                'path': f'observations/default-branch-start-9-1/{name}',
                'size': len(raw), 'sha256': issued.digest(raw),
            }
            if digest_key:
                self.att[digest_key] = issued.digest(raw)
        receipt = {
            'schema': private.RECEIPT_SCHEMA,
            'status': 'verified_observation_retained',
            'repository': reconcile.REPOSITORY,
            'observed_at': OBSERVED,
            **{key: self.att[key] for key in (
                'run_id', 'run_attempt', 'job_id', 'consumer_commit',
                'release_lock_sha256', 'workflow', 'job', 'queue_id',
                'reservation_sequence', 'reservation_sha256')},
            'early_artifact': {**self.att['early_artifact'], 'name': artifact['name']},
            'raw_files': files,
        }
        put(observation / 'receipt.json', issued.canonical_bytes(receipt))
        self.att['observation_sha256'] = issued.digest(
            (observation / 'receipt.json').read_bytes())
        self.fixture._issue(self.att)
        self.observation = observation

    def verify(self, key=TEST_KEY):
        return preflight.verify_authenticated_start(self.root, key)

    def replace_and_resign_jobs(self, raw):
        put(self.observation / 'jobs-api.json', raw)
        receipt_path = self.observation / 'receipt.json'
        receipt = json.loads(receipt_path.read_bytes())
        receipt['raw_files']['jobs']['size'] = len(raw)
        receipt['raw_files']['jobs']['sha256'] = issued.digest(raw)
        put(receipt_path, issued.canonical_bytes(receipt))
        self.att['jobs_api_sha256'] = issued.digest(raw)
        self.att['observation_sha256'] = issued.digest(receipt_path.read_bytes())
        _, document_raw, document_hash = issued._signed_document(
            self.att, TEST_KEY, OBSERVED)
        # Fixture-only re-signing mutates the synthetic issued row; the
        # production verifier has no writer or signing interface.
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('DROP TRIGGER issued_actions_no_update')
            conn.execute('UPDATE issued_actions SET document_json=?, action_sha256=? '
                         'WHERE seq=1', (document_raw.decode('utf-8'), document_hash))
            conn.execute('UPDATE issued_head SET hash=?', (document_hash,))
            conn.execute("CREATE TRIGGER issued_actions_no_update BEFORE UPDATE ON "
                         "issued_actions BEGIN SELECT RAISE(ABORT, 'issued actions are "
                         "append-only'); END")

    def test_positive_is_read_only_and_scoped(self):
        before = self.db.read_bytes()
        result = self.verify()
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(result['status'], 'authenticated_start')
        self.assertEqual(result['issued_seq'], 1)
        self.assertEqual(result['start_sha256'], self.fixture._issued_snapshot()[1][0][3])
        self.assertEqual(result['observation_sha256'], self.att['observation_sha256'])
        self.assertEqual(result['early_artifact'], self.att['early_artifact'])
        self.assertEqual(len(result['raw_sha256']), 6)
        self.assertFalse(result['completed_scan_verified'])
        self.assertFalse(result['final_proof_verified'])
        self.assertFalse(any((self.root / (issued.DATABASE_NAME + suffix)).exists()
                             for suffix in ('-journal', '-wal', '-shm')))

    def test_wrong_key_and_non_bytes_key(self):
        for key in (b'x' * 32, 'not-key-bytes'):
            with self.subTest(key=type(key)):
                with self.assertRaises(preflight.AuthenticatedStartError):
                    self.verify(key)

    def test_tampered_raw_receipt_and_extra_entry(self):
        for name in ('run-api.json', 'receipt.json', 'early-artifact.zip'):
            with self.subTest(name=name):
                path = self.observation / name
                original = path.read_bytes()
                put(path, original + b'x')
                with self.assertRaises(preflight.AuthenticatedStartError):
                    self.verify()
                put(path, original)
        put(self.observation / 'extra.json', b'{}')
        with self.assertRaises(preflight.AuthenticatedStartError):
            self.verify()

    def test_head_drift_and_seq_two(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE issued_head SET hash=?", ('f' * 64,))
        with self.assertRaises(preflight.AuthenticatedStartError):
            self.verify()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('UPDATE issued_head SET hash=(SELECT action_sha256 FROM issued_actions WHERE seq=1)')
        terminal = self.fixture._terminal_attestation('failed_execution')
        issued.issue_terminal(self.root, 1, self.fixture._issued_snapshot()[1][0][3],
                              TEST_KEY, terminal, '2026-11-26T12:02:00Z')
        with self.assertRaises(preflight.AuthenticatedStartError):
            self.verify()

    def test_sidecar_is_rejected_before_sqlite_open(self):
        put(self.root / (issued.DATABASE_NAME + '-wal'), b'not-a-real-sidecar')
        with patch.object(sqlite3, 'connect', side_effect=AssertionError('SQLite opened')):
            with self.assertRaises(preflight.AuthenticatedStartError):
                self.verify()

    def test_signed_duplicate_json_key_rejected(self):
        valid = json.loads((self.observation / 'jobs-api.json').read_bytes())
        raw = (b'{"jobs":[],"jobs":' +
               json.dumps(valid['jobs'], separators=(',', ':')).encode() +
               b',"total_count":1}\n')
        self.replace_and_resign_jobs(raw)
        with self.assertRaises(preflight.AuthenticatedStartError) as raised:
            self.verify()
        self.assertIsInstance(raised.exception.__cause__, reconcile.ReconcileError)

    def test_signed_invalid_api_is_normalized(self):
        self.replace_and_resign_jobs(issued.canonical_bytes(
            {'jobs': [], 'total_count': 0}))
        with self.assertRaises(preflight.AuthenticatedStartError):
            self.verify()

    def test_database_substitution_before_open_is_rejected(self):
        original_open = os.open
        replaced = False

        def substitute(path, flags, *args, **kwargs):
            nonlocal replaced
            if path == issued.DATABASE_NAME and not replaced:
                replaced = True
                moved = self.root / 'old-database'
                raw = self.db.read_bytes()
                self.db.rename(moved)
                put(self.db, raw)
            return original_open(path, flags, *args, **kwargs)

        with patch.object(preflight.os, 'open', side_effect=substitute):
            with self.assertRaises(preflight.AuthenticatedStartError):
                self.verify()
        self.assertTrue(replaced)

    def test_database_replacement_and_sidecar_after_snapshot_rejected(self):
        original_snapshot = preflight._open_read_only

        def replace_after(root_fd):
            result = original_snapshot(root_fd)
            raw = self.db.read_bytes()
            self.db.rename(self.root / 'old-database')
            put(self.db, raw)
            return result

        with patch.object(preflight, '_open_read_only', side_effect=replace_after):
            with self.assertRaises(preflight.AuthenticatedStartError):
                self.verify()

        self.db.unlink()
        (self.root / 'old-database').rename(self.db)

        def sidecar_after(root_fd):
            result = original_snapshot(root_fd)
            put(self.root / (issued.DATABASE_NAME + '-wal'), b'late-sidecar')
            return result

        with patch.object(preflight, '_open_read_only', side_effect=sidecar_after):
            with self.assertRaises(preflight.AuthenticatedStartError):
                self.verify()

    def test_database_alias_and_hardlink_rejected_before_sqlite_open(self):
        alias = self.root / 'database-alias'
        os.link(self.db, alias)
        with patch.object(sqlite3, 'connect', side_effect=AssertionError('SQLite opened')):
            with self.assertRaises(preflight.AuthenticatedStartError):
                self.verify()
        alias.unlink()
        moved = self.root / 'database-moved'
        self.db.rename(moved)
        os.symlink(moved.name, self.db)
        with patch.object(sqlite3, 'connect', side_effect=AssertionError('SQLite opened')):
            with self.assertRaises(preflight.AuthenticatedStartError):
                self.verify()

    def test_alias_and_hardlink_before_read(self):
        target = self.observation / 'run-api.json'
        original = target.read_bytes()
        target.unlink()
        os.symlink('jobs-api.json', target)
        with self.assertRaises(preflight.AuthenticatedStartError):
            self.verify()
        target.unlink()
        put(target, original)
        os.link(target, self.root / 'alias')
        with self.assertRaises(preflight.AuthenticatedStartError):
            self.verify()
