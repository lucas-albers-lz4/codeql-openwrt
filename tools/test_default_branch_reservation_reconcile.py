"""Read-only default-branch claim reconciliation controls and replay tests."""
from datetime import datetime, timedelta, timezone
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from zipfile import ZipFile, ZIP_DEFLATED

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools import default_branch_reservation_claim as scan_claim
from tools import default_branch_reservation_reconcile as reconcile
from tools import incoming_poll as poll
from tools.test_default_branch_backlog_intake import Fixture


RUN_ID = 45868959396
RUN_ATTEMPT = 1
CONSUMER_HEAD = '2c8ee0aaf26bde314a631f9f852dcff569231436'
WRONG_POLICY_HEAD = '097098679c75a8918d357811aafb391293e58d99'
REPO_ID = 1454767376
ZERO_HASH = '0' * 64


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class DefaultBranchReservationReconcileTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(__file__).resolve().parents[1] / 'work'
        self.work.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.work, 0o700)
        self.tmp = tempfile.TemporaryDirectory(prefix='reservation-reconcile-', dir=self.work)
        self.parent = Path(self.tmp.name)
        self.fx = Fixture(self.parent)
        self.root = self.fx.private
        self.consumer = CONSUMER_HEAD
        self.previous, self.current, self.gap, self.previous_bundle, self.current_bundle, self.commits = \
            self.fx.make_initial_pair(version=2)
        self.fx.run_intake(self.previous_bundle, self.current_bundle)
        self.policy_path = self.parent / 'policy.json'
        self.release_lock = Path(__file__).resolve().parents[1] / 'docs/r3-release-lock.json'
        self._write_policy(self.consumer)
        reservation.migrate_v1(self.root)
        self.identity = self._load_identity()
        reservation.reserve(
            self.root, 0, ZERO_HASH, self.identity,
            self.policy_path, self.release_lock, 'operator@example.test',
            '2026-11-27T12:00:00Z', now=datetime(2026, 11, 26, 12, 0,
                                                tzinfo=timezone.utc))
        self.members, self.run, self.jobs, self.artifacts = self._scan_fixture()

    def tearDown(self):
        self.tmp.cleanup()

    @property
    def database(self):
        return self.root / reservation.DATABASE_NAME

    def _write_policy(self, consumer):
        self.policy_path.write_bytes(json_bytes({
            'schema': reservation.POLICY_SCHEMA,
            'consumer_commit': consumer,
            'workflow': reservation.WORKFLOW,
            'release_lock_sha256': digest(self.release_lock.read_bytes()),
        }))
        self.policy_path.chmod(0o600)

    def _load_identity(self):
        with closing(sqlite3.connect(self.database)) as db:
            row = db.execute('''
                SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
                       b.first_parent_sha,b.intake_id,i.receipt_seq
                FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
                WHERE b.repository='openwrt/openwrt' AND b.ordinal=1
            ''').fetchone()
        self.assertIsNotNone(row)
        keys = ('repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                'first_parent_sha', 'intake_id', 'receipt_seq')
        return dict(zip(keys, row))

    def _action(self):
        with closing(sqlite3.connect(self.database)) as db:
            body_json, action_hash = db.execute(
                'SELECT body_json,action_hash FROM reservation_actions WHERE action_seq=1'
            ).fetchone()
        return json.loads(body_json), action_hash

    def _scan_fixture(self, *, triplet=None, scan_run_id=RUN_ID,
                      scan_attempt=RUN_ATTEMPT, status='claimed_unverified'):
        action, action_hash = self._action()
        asserted = triplet or {
            'queue_id': action['queue_id'], 'reservation_sequence': action['action_seq'],
            'reservation_sha256': action_hash,
        }
        old_tips = {item['repository']: item
                    for item in poll.replay_observed_doc(self.previous)}
        selected = self.commits[0]
        previous_sha = self.previous_bundle['decisions_sha256']
        current_sha = self.current_bundle['decisions_sha256']
        with ZipFile(self.previous_bundle['zip']) as archive:
            previous_raw = archive.read('decisions.json')
        with ZipFile(self.current_bundle['zip']) as archive:
            current_raw = archive.read('decisions.json')
            gap_raw = archive.read('gap/gap.json')
        gap_sha = digest(gap_raw)
        inventory_raw = b'{"inventory":"synthetic source-first inventory"}\n'
        identity = {
            'schema': 'default-branch-event-identity-v1',
            'status': 'identities_resolved_only',
            'repository': 'openwrt/openwrt', 'ref': 'main',
            'source': {'commit': selected['sha'], 'tree': selected['commit']['tree']['sha']},
            'base': {'commit': selected['parents'][0]['sha'],
                     'tree': old_tips['openwrt/openwrt']['source']['tree']},
            'control': {'commit': 'e' * 40, 'tree': '9' * 40},
            'gap_sha256': gap_sha,
            'previous_checkpoint_sha256': previous_sha,
            'current_checkpoint_sha256': current_sha,
        }
        identity_raw = json_bytes(identity)
        manifest = {
            'schema': 'mvp-default-branch-commit-corpus-v1',
            'status': 'source_first_default_branch_oracle_only',
            'event': {
                'kind': 'default_branch_commit',
                'source_role': 'incoming_default_branch_first_parent',
                'repository': 'openwrt',
                'base_commit': identity['base']['commit'],
                'base_tree': identity['base']['tree'],
                'head_commit': identity['source']['commit'],
                'head_tree': identity['source']['tree'],
                'first_parent_commit': selected['parents'][0]['sha'],
                'control_commit': identity['control']['commit'],
                'gap_sha256': gap_sha,
                'previous_checkpoint_sha256': previous_sha,
                'current_checkpoint_sha256': current_sha,
                'consumer_commit': self.consumer,
                'identity_receipt_sha256': digest(identity_raw),
                'candidate_inventory_sha256': digest(inventory_raw),
            },
        }
        manifest_raw = json_bytes(manifest)
        previous_path = self.parent / 'replay-previous.json'
        current_path = self.parent / 'replay-current.json'
        gap_path = self.parent / 'replay-gap.json'
        previous_path.write_bytes(previous_raw)
        current_path.write_bytes(current_raw)
        gap_path.write_bytes(gap_raw)
        dispatch = {
            'previous_run_id': '1001', 'previous_run_attempt': '1',
            'previous_sha256': previous_sha,
            'current_run_id': '1002', 'current_run_attempt': '1',
            'current_sha256': current_sha, 'gap_sha256': gap_sha,
            'repository': 'openwrt/openwrt', 'source_sha': selected['sha'],
            'control_sha': identity['control']['commit'],
        }
        execution = {'run_id': str(scan_run_id), 'run_attempt': str(scan_attempt),
                     'consumer_head': self.consumer, 'actual_head': self.consumer}
        claim_fields = {key: str(value) for key, value in asserted.items()}
        claim_record = scan_claim.claim(
            claim_fields, identity, manifest, previous_path, current_path, gap_path,
            dispatch, execution, identity_raw, manifest_raw)
        if status != 'claimed_unverified':
            claim_record['status'] = status
            claim_record['asserted_reservation'] = None
        prefix = f'default-branch-inputs-{scan_run_id}-{scan_attempt}/'
        members = {
            prefix + 'previous-run-api.json': self.previous_bundle['run_api'].read_bytes(),
            prefix + 'current-run-api.json': self.current_bundle['run_api'].read_bytes(),
            prefix + 'previous/decisions.json': previous_raw,
            prefix + 'current/decisions.json': current_raw,
            prefix + 'current/gap/gap.json': gap_raw,
            prefix + 'identity.json': identity_raw,
            prefix + 'manifest.json': manifest_raw,
            prefix + 'inventory.json': inventory_raw,
            prefix + 'reservation-claim.json': json_bytes(claim_record),
            f'r3-ucode-{scan_run_id}-{scan_attempt}/receipt.json': b'{"status":"retained"}\n',
        }
        run = {
            'id': scan_run_id, 'run_attempt': scan_attempt,
            'repository': {'id': REPO_ID, 'full_name': reconcile.REPOSITORY},
            'head_repository': {'id': REPO_ID, 'full_name': reconcile.REPOSITORY},
            'path': reconcile.SCAN_WORKFLOW, 'event': 'workflow_dispatch',
            'head_branch': 'main', 'head_sha': self.consumer,
            'status': 'completed', 'conclusion': 'success',
        }
        jobs = {'total_count': 1, 'jobs': [{
            'id': 700, 'name': reconcile.SCAN_JOB, 'run_id': scan_run_id,
            'run_attempt': scan_attempt, 'head_sha': self.consumer,
            'status': 'completed', 'conclusion': 'success',
        }]}
        zip_raw = self._zip(members)
        artifacts = {'total_count': 1, 'artifacts': [{
            'id': 9000, 'name': f'{reconcile.SCAN_ARTIFACT_PREFIX}{scan_run_id}-{scan_attempt}',
            'expired': False, 'size_in_bytes': len(zip_raw),
            'digest': 'sha256:' + digest(zip_raw),
            'workflow_run': {
                'id': scan_run_id, 'repository_id': REPO_ID,
                'head_repository_id': REPO_ID, 'head_branch': 'main',
                'head_sha': self.consumer,
            },
        }]}
        return members, run, jobs, artifacts

    @staticmethod
    def _zip(members):
        from io import BytesIO
        stream = BytesIO()
        with ZipFile(stream, 'w', ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        return stream.getvalue()

    def _observe(self, *, members=None, run=None, jobs=None, artifacts=None,
                 start_raw=None):
        members = self.members if members is None else members
        run = self.run if run is None else run
        jobs = self.jobs if jobs is None else jobs
        artifacts = self.artifacts if artifacts is None else artifacts
        zip_raw = self._zip(members)
        artifacts = json.loads(json.dumps(artifacts))
        artifacts['artifacts'][0]['size_in_bytes'] = len(zip_raw)
        artifacts['artifacts'][0]['digest'] = 'sha256:' + digest(zip_raw)
        return reconcile.reconcile_bytes(
            self.root, json_bytes(run), json_bytes(jobs), json_bytes(artifacts),
            zip_raw, run['id'], run['run_attempt'], self.work,
            start_raw=start_raw)

    def _issue_fixture_start(self, *, issue=True):
        issued.migrate_v2_to_v3(self.root)
        body, reservation_hash = self._action()
        policy = body['policy']
        att = {
            'schema': issued.START_SCHEMA, 'kind': 'start',
            'queue_id': body['queue_id'], 'reservation_sequence': 1,
            'reservation_sha256': reservation_hash, 'identity': body['identity'],
            'origin_receipt_sha256': body['origin']['receipt_hash'],
            'origin_gap_sha256': body['origin']['gap_sha256'],
            'policy_sha256': policy['policy_sha256'],
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
            'run_id': RUN_ID, 'run_attempt': RUN_ATTEMPT, 'job_id': 700,
            'workflow': reservation.WORKFLOW, 'job': issued.START_JOB,
            'early_artifact': {'id': 100, 'size': 1, 'sha256': 'a' * 64},
            'observation_sha256': 'b' * 64,
            'run_api_sha256': 'c' * 64, 'jobs_api_sha256': 'd' * 64,
            'artifacts_api_sha256': 'e' * 64,
            'recheck_run_api_sha256': 'f' * 64,
            'recheck_jobs_api_sha256': '1' * 64,
        }
        key = b'fixture-key-32-bytes-exactly-0000'
        if not issue:
            return issued._signed_document(att, key, '2026-11-26T12:00:01Z')[1]
        issued.issue_start(
            self.root, 0, issued.ZERO_HASH, key,
            {'consumer_commit': policy['consumer_commit'],
             'release_lock_sha256': policy['release_lock_sha256']},
            att, '2026-11-26T12:00:01Z')
        with closing(sqlite3.connect(self.database)) as db:
            return db.execute(
                'SELECT document_json FROM issued_actions WHERE seq=1'
            ).fetchone()[0].encode('utf-8')

    def test_v3_replay_binds_supplied_start_to_exact_issued_head(self):
        start_raw = self._issue_fixture_start()
        before = digest(self.database.read_bytes())
        result = self._observe(start_raw=start_raw)
        self.assertEqual(result['status'], 'claim_reconciled_read_only')
        self.assertEqual(result['database']['schema_version'],
                         intake.ISSUED_SCHEMA_VERSION)
        self.assertTrue(result['database']['supplied_start_head_bound'])
        self.assertFalse(result['database']['start_mac_verified'])
        self.assertEqual(before, digest(self.database.read_bytes()))
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                    'supplied start differs from exact v3 issued head'):
            forged = json.loads(start_raw)
            forged['mac'] = '0' * 64
            self._observe(start_raw=issued.canonical_bytes(forged))
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE issued_head SET hash=?', ('0' * 64,))
        with self.assertRaises(reconcile.ReconcileError):
            self._observe(start_raw=start_raw)

    def test_v3_replay_rejects_job_drift_and_already_issued_terminal(self):
        start_raw = self._issue_fixture_start()
        jobs = json.loads(json.dumps(self.jobs))
        jobs['jobs'][0]['id'] = 701
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                    'claimed run/job/reservation'):
            self._observe(jobs=jobs, start_raw=start_raw)
        start_doc = json.loads(start_raw)
        start = start_doc['attestation']
        attestation = {
            'schema': issued.TERMINAL_SCHEMA, 'kind': 'failed_execution',
            **{key: start[key] for key in (
                'queue_id', 'reservation_sequence', 'reservation_sha256',
                'identity', 'run_id', 'run_attempt', 'job_id', 'workflow', 'job')},
            'start_sha256': digest(start_raw),
            'evidence': {
                'schema': 'operator-default-branch-terminal-observation-v1',
                'run_api_sha256': 'a' * 64, 'jobs_api_sha256': 'b' * 64,
                'run_status': 'completed', 'run_conclusion': 'failure',
                'job_status': 'completed', 'job_conclusion': 'failure',
            },
        }
        issued.issue_terminal(
            self.root, 1, digest(start_raw),
            b'fixture-key-32-bytes-exactly-0000', attestation,
            '2026-11-26T12:02:00Z')
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                    'supplied start differs from exact v3 issued head'):
            self._observe(start_raw=start_raw)

    def test_v3_replay_rejects_unissued_well_formed_start(self):
        start_raw = self._issue_fixture_start(issue=False)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                    'supplied start differs from exact v3 issued head'):
            self._observe(start_raw=start_raw)

    def test_matching_claim_replays_exact_archive_and_leaves_database_byte_identical(self):
        before = digest(self.database.read_bytes())
        result = self._observe()
        after = digest(self.database.read_bytes())
        self.assertEqual(result['status'], 'claim_reconciled_read_only')
        self.assertEqual(result['claim_status'], 'claimed_unverified')
        self.assertEqual(result['reservation']['identity'], self.identity)
        self.assertEqual(result['canonical_run']['head_sha'], CONSUMER_HEAD)
        self.assertEqual(result['database'], {
            'read_only': True,
            'schema_version': intake.RESERVATION_SCHEMA_VERSION,
            'receipt_chain_verified': True,
            'action_chain_verified': True,
        })
        self.assertEqual(before, after)
        self.assertFalse(Path(str(self.database) + '-journal').exists())
        self.assertFalse(Path(str(self.database) + '-wal').exists())
        self.assertTrue(any('not directly to a particular job' in item
                            for item in result['limitations']))
        self.assertTrue(any('not authenticated by this local ledger' in item
                            for item in result['limitations']))

    def test_scan_checkpoint_and_gap_bytes_must_equal_private_archive_bytes(self):
        for member in (
                'default-branch-inputs-45868959396-1/previous/decisions.json',
                'default-branch-inputs-45868959396-1/current/decisions.json',
                'default-branch-inputs-45868959396-1/current/gap/gap.json'):
            with self.subTest(member=member):
                changed = dict(self.members)
                changed[member] += b'\n'
                with self.assertRaisesRegex(reconcile.ReconcileError,
                                           'differs from exact retained archive bytes'):
                    self._observe(members=changed)

    def test_forged_well_formed_triplet_does_not_match_local_action(self):
        _, action_hash = self._action()
        changed, run, jobs, artifacts = self._scan_fixture(triplet={
            'queue_id': self._action()[0]['queue_id'],
            'reservation_sequence': 1,
            'reservation_sha256': '8' * 64 if action_hash != '8' * 64 else '7' * 64,
        })
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'action hash differs from local queue'):
            self._observe(members=changed, run=run, jobs=jobs, artifacts=artifacts)

    def test_claim_origin_and_identity_member_tampering_are_rejected(self):
        claim_name = 'default-branch-inputs-45868959396-1/reservation-claim.json'
        changed = dict(self.members)
        claim = json.loads(changed[claim_name])
        claim['linked_discovery_origin']['current_run_id'] += 1
        changed[claim_name] = json_bytes(claim)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'differs from exact source replay'):
            self._observe(members=changed)
        changed = dict(self.members)
        identity_name = 'default-branch-inputs-45868959396-1/identity.json'
        identity = json.loads(changed[identity_name])
        identity['source']['commit'] = '0' * 40
        changed[identity_name] = json_bytes(identity)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'identity or manifest digest differs'):
            self._observe(members=changed)

    def test_policy_consumer_mismatch_from_live_observation_is_rejected(self):
        action, _ = self._action()
        action['policy']['consumer_commit'] = WRONG_POLICY_HEAD
        body_json = reservation.canonical_json(action)
        action_hash = reservation.digest((ZERO_HASH + '\n' + body_json).encode())
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('BEGIN')
            db.execute('DROP TRIGGER reservation_actions_no_update')
            db.execute('UPDATE reservation_actions SET body_json=?,action_hash=? '
                       'WHERE action_seq=1', (body_json, action_hash))
            db.execute('UPDATE action_head SET action_hash=? WHERE singleton=1',
                       (action_hash,))
            db.execute(
                "CREATE TRIGGER reservation_actions_no_update BEFORE UPDATE ON reservation_actions "
                "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END")
            db.commit()
        changed, run, jobs, artifacts = self._scan_fixture(triplet={
            'queue_id': action['queue_id'], 'reservation_sequence': 1,
            'reservation_sha256': action_hash,
        })
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'policy consumer_commit differs from canonical scan run head'):
            self._observe(members=changed, run=run, jobs=jobs, artifacts=artifacts)

    def test_wrong_run_attempt_consumer_job_artifact_and_incomplete_listings_fail(self):
        cases = (
            ('wrong run', {**self.run, 'id': self.run['id'] + 1}, self.jobs, self.artifacts,
             'run identity'),
            ('wrong attempt', {**self.run, 'run_attempt': 2}, self.jobs, self.artifacts,
             'run identity'),
            ('wrong consumer', {**self.run, 'head_sha': '1' * 40}, self.jobs, self.artifacts,
             'scan job does not match'),
            ('wrong job', self.run, {'total_count': 1, 'jobs': [{**self.jobs['jobs'][0],
                                                                 'name': 'other-job'}]},
             self.artifacts, 'scan job is missing'),
            ('wrong artifact run', self.run, self.jobs,
             {'total_count': 1, 'artifacts': [{**self.artifacts['artifacts'][0],
                                              'workflow_run': {**self.artifacts['artifacts'][0]['workflow_run'],
                                                               'id': self.run['id'] + 1}}]},
             'artifact run linkage'),
            ('invalid artifact ID', self.run, self.jobs,
             {'total_count': 1, 'artifacts': [{**self.artifacts['artifacts'][0], 'id': 0}]},
             'invalid or duplicate ID'),
            ('ambiguous exact artifact', self.run, self.jobs,
             {'total_count': 2, 'artifacts': self.artifacts['artifacts'] * 2},
             'artifacts API listing contains an invalid or duplicate ID'),
            ('incomplete jobs', self.run, {'total_count': 2, 'jobs': self.jobs['jobs']},
             self.artifacts, 'jobs API listing is incomplete'),
            ('incomplete artifacts', self.run, self.jobs,
             {'total_count': 2, 'artifacts': self.artifacts['artifacts']},
             'artifacts API listing is incomplete'),
        )
        for label, run, jobs, artifacts, reason in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                    reconcile.ReconcileError, reason):
                self._observe(run=run, jobs=jobs, artifacts=artifacts)

    def test_scan_artifact_size_digest_and_unsafe_member_controls(self):
        zip_raw = self._zip(self.members)
        artifacts = json.loads(json.dumps(self.artifacts))
        artifacts['artifacts'][0]['size_in_bytes'] += 1
        with self.assertRaisesRegex(reconcile.ReconcileError, 'size differs'):
            reconcile.reconcile_bytes(self.root, json_bytes(self.run), json_bytes(self.jobs),
                                      json_bytes(artifacts), zip_raw, RUN_ID, RUN_ATTEMPT,
                                      self.work)
        artifacts = json.loads(json.dumps(self.artifacts))
        artifacts['artifacts'][0]['digest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(reconcile.ReconcileError, 'digest differs'):
            reconcile.reconcile_bytes(self.root, json_bytes(self.run), json_bytes(self.jobs),
                                      json_bytes(artifacts), zip_raw, RUN_ID, RUN_ATTEMPT,
                                      self.work)
        unsafe = dict(self.members)
        unsafe['../escape'] = b'x'
        with self.assertRaisesRegex(reconcile.ReconcileError, 'unsafe scan artifact member'):
            self._observe(members=unsafe)

    def test_failed_and_absent_claim_records_are_not_reconciled(self):
        failed = dict(self.members)
        prefix = 'default-branch-inputs-45868959396-1/'
        failed.pop(prefix + 'reservation-claim.json')
        failed[prefix + 'reservation-claim-failure.json'] = json_bytes({
            'schema': 'default-branch-reservation-claim-failure-v1',
            'status': 'claim_failed', 'error_type': 'ClaimError', 'reason': 'fixture',
        })
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'scan claim failed and has no successful claim record'):
            self._observe(members=failed)
        absent, run, jobs, artifacts = self._scan_fixture(status='absent')
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'reservation claim is explicitly absent'):
            self._observe(members=absent, run=run, jobs=jobs, artifacts=artifacts)

    def test_database_action_hash_tamper_fails_closed(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('BEGIN')
            db.execute('DROP TRIGGER reservation_actions_no_update')
            db.execute('UPDATE reservation_actions SET action_hash=? WHERE action_seq=1',
                       ('f' * 64,))
            db.execute(
                "CREATE TRIGGER reservation_actions_no_update BEFORE UPDATE ON reservation_actions "
                "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END")
            db.commit()
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'action chain did not verify'):
            self._observe()

    def test_scan_zip_triplet_and_actual_api_bytes_are_bound(self):
        changed = dict(self.members)
        name = 'default-branch-inputs-45868959396-1/reservation-claim.json'
        claim = json.loads(changed[name])
        claim['asserted_reservation']['reservation_sha256'] = 'a' * 64
        changed[name] = json_bytes(claim)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'action hash differs from local queue'):
            self._observe(members=changed)
        changed = dict(self.members)
        name = 'default-branch-inputs-45868959396-1/current-run-api.json'
        api = json.loads(changed[name])
        api['run_attempt'] = 2
        changed[name] = json_bytes(api)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'current scan artifact API identity differs'):
            self._observe(members=changed)

    def test_malformed_identity_shape_and_out_of_range_sequence_fail_cleanly(self):
        changed = dict(self.members)
        name = 'default-branch-inputs-45868959396-1/identity.json'
        identity = json.loads(changed[name])
        identity['source'] = []
        changed[name] = json_bytes(identity)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'malformed source or control'):
            self._observe(members=changed)
        changed = dict(self.members)
        name = 'default-branch-inputs-45868959396-1/reservation-claim.json'
        claim = json.loads(changed[name])
        claim['asserted_reservation']['reservation_sequence'] = 10 ** 80
        changed[name] = json_bytes(claim)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'triplet is incomplete or absent'):
            self._observe(members=changed)
        changed = dict(self.members)
        name = 'default-branch-inputs-45868959396-1/reservation-claim.json'
        claim = json.loads(changed[name])
        claim['linked_input_sha256'] = ['not', 'an', 'object']
        changed[name] = json_bytes(claim)
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'claim linked input digest record is malformed'):
            self._observe(members=changed)
    def test_intake_receipt_hash_tampering_fails_before_claim_link(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('BEGIN')
            db.execute('UPDATE receipts SET receipt_hash=? WHERE receipt_seq=1',
                       ('f' * 64,))
            db.commit()
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'receipt or action chain did not verify'):
            self._observe()


if __name__ == '__main__':
    unittest.main()
