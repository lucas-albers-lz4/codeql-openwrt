"""Disposable signed-queue controls for the keyless witness classifier."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from unittest import TestCase
from unittest.mock import patch

from tools import default_branch_authenticated_start as authenticated
from tools import default_branch_backlog_issued as issued
from tools import default_branch_failed_execution_capture as failure
from tools import default_branch_head_witness as witness
from tools import default_branch_private_final_capture as custody
from tools import default_branch_private_start as private
from tools import default_branch_private_terminal_issuer as issuer
from tools import test_default_branch_authenticated_start as start_fixture
from tools import test_default_branch_failed_execution_capture as failure_fixture


class HeadWitnessTests(TestCase):
    def setUp(self):
        self.fixture = failure_fixture.FailedExecutionCaptureTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.start = self.fixture.fixture.verify()
        self.start_sha = self.start['start_sha256']
        self.queue_id = self.start['queue_id']
        self.reservation = self.start['reservation_sha256']
        self.witness_id = 'a' * 32
        self.generation = 'b' * 32
        self.first = self._record('head', 1, self.start_sha,
                                  issued.ZERO_HASH, issued.ZERO_HASH, 'c' * 32)

    def _record(self, kind, sequence, digest, base, previous, invocation):
        return issued.canonical_bytes({
            'schema': witness.SCHEMA, 'witness_id': self.witness_id,
            'queue_id': self.queue_id, 'queue_generation': self.generation,
            'reservation_sha256': self.reservation, 'kind': kind,
            'sequence': sequence, 'issued_sha256': digest,
            'base_issued_sha256': base, 'previous_record_sha256': previous,
            'invocation_id': invocation,
        })

    def _queue(self):
        return authenticated.read_authenticated_head_snapshot(
            self.root, start_fixture.TEST_KEY)

    def _classify(self, records, snapshot=None, **overrides):
        arguments = {
            'witness_id': self.witness_id,
            'queue_generation': self.generation,
            'queue_snapshot': self._queue() if snapshot is None else snapshot,
        }
        arguments.update(overrides)
        return witness.reconcile_records(records, **arguments)

    def _terminal(self):
        with patch.object(private, '_root_is_durable', return_value=self.root), \
             patch.object(failure, '_network', self.fixture._network), \
             patch.object(custody, '_now',
                          return_value=datetime(2026, 11, 26, 12, 1, 4,
                                                tzinfo=UTC)):
            return issuer.issue_failed_execution(
                self.root, start_fixture.TEST_KEY, 9, 1)

    def test_signed_start_and_fresh_failure_classify_all_recovery_states(self):
        before = self.fixture.fixture.db.read_bytes()
        self.assertEqual(self._classify([self.first]), 'ready')
        self.assertEqual(self.fixture.fixture.db.read_bytes(), before)
        result = self._terminal()
        self.assertEqual(result['issued_seq'], 2)
        self.assertEqual(self._classify([self.first]), 'freeze')
        intent = self._record('pending_intent', 2, result['issued_sha256'],
                              self.start_sha, witness.record_sha256(self.first),
                              result['capture_invocation_id'])
        self.assertEqual(self._classify([self.first, intent]), 'finalize_pending')
        final = self._record('head', 2, result['issued_sha256'], self.start_sha,
                             witness.record_sha256(intent),
                             result['capture_invocation_id'])
        self.assertEqual(self._classify([self.first, intent, final]),
                         'existing_terminal')
        # A genuine seq-2 snapshot cannot be composed with another valid-format
        # start or reservation, even if the proposed terminal digest matches.
        for field, replacement in (('start_sha', 'e' * 64),
                                   ('reservation', 'f' * 64)):
            with self.subTest(field=field), patch.object(self, field, replacement):
                different_first = self._record('head', 1, self.start_sha,
                                                issued.ZERO_HASH,
                                                issued.ZERO_HASH, 'c' * 32)
                different_intent = self._record(
                    'pending_intent', 2, result['issued_sha256'],
                    self.start_sha, witness.record_sha256(different_first),
                    result['capture_invocation_id'])
                with self.assertRaises(witness.WitnessError):
                    self._classify([different_first, different_intent],
                                   self._queue())
        self.assertEqual(self._classify([], self._queue()), 'freeze')
        mismatch = self._record('pending_intent', 2, 'f' * 64,
                                self.start_sha, witness.record_sha256(self.first),
                                result['capture_invocation_id'])
        self.assertEqual(self._classify([self.first, mismatch]), 'freeze')
        # Restore exact older, still HMAC-valid SQLite bytes, then reopen them.
        old_copy = self.root / 'older-valid-queue.sqlite3'
        old_copy.write_bytes(before)
        old_copy.chmod(0o600)
        os.replace(old_copy, self.fixture.fixture.db)
        old_valid = self._queue()
        self.assertEqual((old_valid['seq'], old_valid['sha256']),
                         (1, self.start_sha))
        self.assertEqual(self._classify([self.first, intent], old_valid),
                         'quarantine')
        self.assertEqual(self._classify([self.first, intent, final], old_valid),
                         'freeze')
        self.assertEqual(self._classify([], old_valid), 'freeze')

    def test_active_job_near_miss_preserves_signed_start_and_ready_witness(self):
        self.fixture.first['run']['status'] = 'in_progress'
        self.fixture.first['run']['conclusion'] = None
        self.fixture.first['jobs']['jobs'][0]['conclusion'] = None
        with self.assertRaises(issuer.PrivateTerminalIssuerError):
            self._terminal()
        self.assertEqual(self._queue()['seq'], 1)
        self.assertEqual(self._classify([self.first]), 'ready')

    def test_head_adapter_uses_only_checked_memory_snapshot(self):
        original_connect = sqlite3.connect
        opens = []

        def checked_connect(path, *args, **kwargs):
            opens.append(path)
            self.assertEqual(path, ':memory:')
            return original_connect(path, *args, **kwargs)

        with patch.object(authenticated.sqlite3, 'connect', side_effect=checked_connect):
            self.assertEqual(self._queue()['start_sha256'], self.start_sha)
        self.assertEqual(opens, [':memory:'])

        sidecar = self.fixture.fixture.db.with_name(
            self.fixture.fixture.db.name + '-wal')
        sidecar.write_bytes(b'unexpected sidecar')
        try:
            with patch.object(authenticated.sqlite3, 'connect',
                              side_effect=AssertionError('SQLite opened')), \
                 self.assertRaises(authenticated.AuthenticatedStartError):
                self._queue()
        finally:
            sidecar.unlink()
        for key in (b'wrong-key', b'x' * 32):
            with self.subTest(key=key), self.assertRaises(
                    authenticated.AuthenticatedStartError):
                authenticated.read_authenticated_head_snapshot(self.root, key)

    def test_record_canonicality_chain_identity_and_authentication_controls(self):
        self.assertEqual(witness.parse_record(self.first)['issued_sha256'],
                         self.start_sha)
        for raw in (self.first[:-1], self.first + b' ',
                    self.first.replace(b'"schema":', b'"schema":1,"schema":'),
                    b'[]\n', self.first + b'x'):
            with self.subTest(raw=raw[:30]), self.assertRaises(witness.WitnessError):
                witness.parse_record(raw)
        bad = json.loads(self.first)
        bad['queue_generation'] = 'd' * 32
        with self.assertRaises(witness.WitnessError):
            self._classify([issued.canonical_bytes(bad)])
        bad['queue_generation'] = self.generation
        bad['previous_record_sha256'] = 'e' * 64
        with self.assertRaises(witness.WitnessError):
            self._classify([issued.canonical_bytes(bad)])
        for head in (dict(self._queue(), hmac_verified=False),
                     dict(self._queue(), queue_id='d' * 32),
                     dict(self._queue(), start_sha256='d' * 64),
                     dict(self._queue(), reservation_sha256='d' * 64)):
            with self.assertRaises(witness.WitnessError):
                self._classify([self.first], head)
        intent = self._record('pending_intent', 2, 'd' * 64, self.start_sha,
                              witness.record_sha256(self.first), 'e' * 32)
        wrong_final = self._record('head', 2, 'd' * 64, self.start_sha,
                                   witness.record_sha256(intent), 'f' * 32)
        with self.assertRaises(witness.WitnessError):
            self._classify([self.first, intent, wrong_final])

    def test_pending_same_start_does_not_authorize_another_signature(self):
        # The classifier reports custody state only; it never invokes issuer.
        intent = self._record('pending_intent', 2, 'd' * 64, self.start_sha,
                              witness.record_sha256(self.first), 'e' * 32)
        with closing(sqlite3.connect(self.fixture.fixture.db)) as db:
            before = db.execute('SELECT COUNT(*) FROM issued_actions').fetchone()[0]
        self.assertEqual(self._classify([self.first, intent]), 'quarantine')
        with closing(sqlite3.connect(self.fixture.fixture.db)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM issued_actions').fetchone()[0],
                             before)
