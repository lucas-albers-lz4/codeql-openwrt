"""Disposable-key controls for the private failure issuer core."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from unittest import TestCase
from unittest.mock import patch

from tools import default_branch_backlog_issued as issued
from tools import default_branch_failed_execution_capture as failure
from tools import default_branch_private_final_capture as custody
from tools import default_branch_private_start as private
from tools import default_branch_private_terminal_issuer as issuer
from tools import test_default_branch_authenticated_start as start_fixture
from tools import test_default_branch_failed_execution_capture as failure_fixture


class PrivateTerminalIssuerTests(TestCase):
    def setUp(self):
        self.fixture = failure_fixture.FailedExecutionCaptureTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)

    def _issue(self):
        with patch.object(private, '_root_is_durable',
                          return_value=self.fixture.root), patch.object(
                failure, '_network', self.fixture._network), patch.object(
                custody, '_now',
                return_value=datetime(2026, 11, 26, 12, 1, 4, tzinfo=UTC)):
            return issuer.issue_failed_execution(
                self.fixture.root, start_fixture.TEST_KEY, 9, 1)

    def test_captured_failure_signs_both_raw_observations_and_preserves_backlog(self):
        with closing(sqlite3.connect(self.fixture.fixture.db)) as db:
            before = tuple(db.execute('SELECT * FROM receipts').fetchall())
            before += tuple(db.execute('SELECT * FROM commit_backlog').fetchall())
            before += tuple(db.execute('SELECT * FROM action_head').fetchall())
        result = self._issue()
        self.assertEqual(result['kind'], 'failed_execution')
        self.assertEqual(result['issued_seq'], 2)
        self.assertRegex(result['capture_invocation_id'], r'^[0-9a-f]{32}$')
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['sha256'],
            result['issued_sha256'])
        with closing(sqlite3.connect(self.fixture.fixture.db)) as db:
            row = db.execute('SELECT document_json FROM issued_actions WHERE seq=2').fetchone()
            after = tuple(db.execute('SELECT * FROM receipts').fetchall())
            after += tuple(db.execute('SELECT * FROM commit_backlog').fetchall())
            after += tuple(db.execute('SELECT * FROM action_head').fetchall())
        self.assertEqual(after, before)
        document = json.loads(row[0])
        evidence = document['attestation']['evidence']
        self.assertEqual(evidence['schema'],
                         'operator-default-branch-terminal-observation-v2')
        self.assertEqual(evidence['capture_receipt_sha256'],
                         result['capture_receipt_sha256'])
        directory = next((self.fixture.root / failure.CAPTURE_DIR).iterdir())
        for prefix in ('first', 'second'):
            for role in ('run', 'jobs'):
                name = f'{prefix}-{role}-api.json'
                self.assertEqual(evidence[f'{prefix}_{role}_api_sha256'],
                                 issued.digest((directory / name).read_bytes()))
        self.assertEqual(evidence['run_conclusion'], 'failure')
        self.assertEqual(evidence['job_conclusion'], 'failure')

    def test_active_job_cannot_sign(self):
        self.fixture.first['run']['status'] = 'in_progress'
        self.fixture.first['run']['conclusion'] = None
        self.fixture.first['jobs']['jobs'][0]['conclusion'] = None
        with self.assertRaises(issuer.PrivateTerminalIssuerError):
            self._issue()
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_wrong_attempt_cannot_capture_or_sign(self):
        with (patch.object(private, '_root_is_durable',
                           return_value=self.fixture.root),
              self.assertRaises(issuer.PrivateTerminalIssuerError)):
            issuer.issue_failed_execution(
                self.fixture.root, start_fixture.TEST_KEY, 9, 2)
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_self_consistent_replacement_after_capture_cannot_sign(self):
        original = failure.capture_failed_execution

        def replaced(*args):
            result = original(*args)
            directory = self.fixture.root / result['capture_path']
            receipt = directory / 'receipt.json'
            data = json.loads(receipt.read_bytes())
            data['terminal']['run_conclusion'] = 'cancelled'
            data['terminal']['job_conclusion'] = 'cancelled'
            for prefix in ('first', 'second'):
                for role in ('run', 'jobs'):
                    name = f'{prefix}-{role}-api.json'
                    path = directory / name
                    body = json.loads(path.read_bytes())
                    if role == 'run':
                        body['conclusion'] = 'cancelled'
                    else:
                        body['jobs'][0]['conclusion'] = 'cancelled'
                    raw = issued.canonical_bytes(body)
                    path.write_bytes(raw)
                    data['raw_files'][name] = {
                        'size': len(raw), 'sha256': issued.digest(raw),
                    }
            receipt.write_bytes(issued.canonical_bytes(data))
            return result

        with (patch.object(failure, 'capture_failed_execution', side_effect=replaced),
              self.assertRaises(issuer.PrivateTerminalIssuerError)):
            self._issue()
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_existing_capture_invocation_substitution_cannot_sign(self):
        prior = self.fixture.capture()
        original = failure.capture_failed_execution

        def substituted(*args):
            result = original(*args)
            return {**result, 'invocation_id': prior['invocation_id'],
                    'capture_path': prior['capture_path']}

        with (patch.object(failure, 'capture_failed_execution', side_effect=substituted),
              self.assertRaises(issuer.PrivateTerminalIssuerError)):
            self._issue()
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_self_consistent_manifest_substitution_cannot_sign(self):
        original = failure.capture_failed_execution

        for field, value in (('attempt', True), ('reservation_sha256', 'f' * 64)):
            with self.subTest(field=field):
                def replaced(*args, field=field, value=value):
                    result = original(*args)
                    directory = self.fixture.root / result['capture_path']
                    manifest_path = directory / 'manifest.json'
                    manifest = json.loads(manifest_path.read_bytes())
                    manifest[field] = value
                    manifest_raw = issued.canonical_bytes(manifest)
                    manifest_path.write_bytes(manifest_raw)
                    receipt_path = directory / 'receipt.json'
                    receipt = json.loads(receipt_path.read_bytes())
                    receipt['manifest_sha256'] = issued.digest(manifest_raw)
                    receipt_raw = issued.canonical_bytes(receipt)
                    receipt_path.write_bytes(receipt_raw)
                    return {**result, 'manifest_sha256': issued.digest(manifest_raw),
                            'receipt_sha256': issued.digest(receipt_raw)}

                with (patch.object(failure, 'capture_failed_execution', side_effect=replaced),
                      self.assertRaises(issuer.PrivateTerminalIssuerError)):
                    self._issue()
                self.assertEqual(issued.issued_head(
                    self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_expired_transaction_deadline_rolls_back(self):
        original = issued.issue_terminal

        def late(*args, **kwargs):
            kwargs['monotonic_deadline'] = -1.0
            return original(*args, **kwargs)

        with (patch.object(issued, 'issue_terminal', side_effect=late),
              self.assertRaises(issuer.PrivateTerminalIssuerError)):
            self._issue()
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_reservation_policy_substitution_cannot_sign(self):
        with (patch.object(issuer, '_start_policy_sha256', return_value='f' * 64),
              self.assertRaises(issuer.PrivateTerminalIssuerError)):
            self._issue()
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)

    def test_database_replacement_at_writer_handoff_cannot_sign(self):
        original = issued.issue_terminal

        def replaced(*args, **kwargs):
            database = self.fixture.fixture.db
            substitute = database.with_name('replacement.sqlite3')
            substitute.write_bytes(database.read_bytes())
            os.chmod(substitute, 0o600)
            os.replace(substitute, database)
            return original(*args, **kwargs)

        with (patch.object(issued, 'issue_terminal', side_effect=replaced),
              self.assertRaises(issuer.PrivateTerminalIssuerError)):
            self._issue()
        self.assertEqual(issued.issued_head(
            self.fixture.root, start_fixture.TEST_KEY)['seq'], 1)
