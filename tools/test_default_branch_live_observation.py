"""Synthetic controls for object-only live default-branch observations."""
from contextlib import closing
import copy
import json
from pathlib import Path
import sqlite3
import stat
import unittest
import warnings
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools import default_branch_live_observation as live
from tools import default_branch_reservation_reconcile as reconcile
from tools import default_branch_start_artifact as early
from tools import test_default_branch_reservation_reconcile as reconcile_test_fixtures


digest = reconcile_test_fixtures.digest
json_bytes = reconcile_test_fixtures.json_bytes


class DefaultBranchLiveObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = reconcile_test_fixtures.DefaultBranchReservationReconcileTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.run_id = self.fixture.run['id']
        self.attempt = self.fixture.run['run_attempt']
        issued.migrate_v2_to_v3(self.root)

        self.source_members = {}
        scan_prefix = f'default-branch-inputs-{self.run_id}-{self.attempt}/'
        for name in live.EARLY_SOURCE_NAMES:
            self.source_members[name] = self.fixture.members[scan_prefix + name]

        self.run = copy.deepcopy(self.fixture.run)
        self.run['status'] = 'in_progress'
        self.run['conclusion'] = None
        self.jobs = copy.deepcopy(self.fixture.jobs)
        self.jobs['jobs'][0]['status'] = 'in_progress'
        self.jobs['jobs'][0]['conclusion'] = None
        action, _ = self.fixture._action()
        self.approved_policy = {
            'consumer_commit': action['policy']['consumer_commit'],
            'release_lock_sha256': action['policy']['release_lock_sha256'],
        }

    def tearDown(self):
        # setUp attaches the disposable fixture's cleanup to this test.
        pass

    def _receipt(self, source_members=None):
        source_members = self.source_members if source_members is None else source_members
        return {
            'schema': live.EARLY_RECEIPT_SCHEMA,
            'status': 'retained_non_issuing',
            'run_id': f'{self.run_id}-{self.attempt}',
            'consumer_repository': reconcile.REPOSITORY,
            'consumer_commit': self.approved_policy['consumer_commit'],
            'reservation_claim_status': 'claimed_unverified',
            'files': {
                name: {'bytes': len(raw), 'sha256': digest(raw)}
                for name, raw in source_members.items()
            },
        }

    @staticmethod
    def _zip(members, *, duplicate=None, omit=None, extra=None):
        from io import BytesIO

        stream = BytesIO()
        with ZipFile(stream, 'w', ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                if name == omit:
                    continue
                info = ZipInfo(name)
                info.compress_type = ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, raw)
                if name == duplicate:
                    duplicate_info = ZipInfo(name)
                    duplicate_info.compress_type = ZIP_DEFLATED
                    duplicate_info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(duplicate_info, raw)
            if extra is not None:
                info = ZipInfo(extra[0])
                info.compress_type = ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, extra[1])
        return stream.getvalue()

    def _early_members(self, source_members=None, receipt=None):
        source_members = (dict(self.source_members) if source_members is None
                          else dict(source_members))
        receipt = self._receipt(source_members) if receipt is None else receipt
        return {**source_members, 'receipt.json': json_bytes(receipt)}

    def _artifacts(self, zip_raw):
        return {
            'total_count': 1,
            'artifacts': [{
                'id': 9000,
                'name': f'{live.EARLY_ARTIFACT_PREFIX}{self.run_id}-{self.attempt}',
                'expired': False,
                'size_in_bytes': len(zip_raw),
                'digest': 'sha256:' + digest(zip_raw),
                'workflow_run': {
                    'id': self.run_id,
                    'repository_id': self.run['repository']['id'],
                    'head_repository_id': self.run['repository']['id'],
                    'head_branch': 'main',
                    'head_sha': self.run['head_sha'],
                },
            }],
        }

    def _observe(self, *, source_members=None, receipt=None, zip_raw=None,
                 run=None, jobs=None, artifacts=None, recheck_run=None,
                 recheck_jobs=None, approved_policy=None):
        run = copy.deepcopy(self.run if run is None else run)
        jobs = copy.deepcopy(self.jobs if jobs is None else jobs)
        if zip_raw is None:
            zip_raw = self._zip(self._early_members(source_members, receipt))
        artifacts = self._artifacts(zip_raw) if artifacts is None else copy.deepcopy(artifacts)
        recheck_run = copy.deepcopy(run if recheck_run is None else recheck_run)
        recheck_jobs = copy.deepcopy(jobs if recheck_jobs is None else recheck_jobs)
        return live.verify_live_observation_bytes(
            self.root, json_bytes(run), json_bytes(jobs), json_bytes(artifacts),
            zip_raw, self.run_id, self.attempt,
            self.approved_policy if approved_policy is None else approved_policy,
            json_bytes(recheck_run), json_bytes(recheck_jobs))

    def test_positive_returns_bytes_only_validated_components_without_observation_digest(self):
        before = self.fixture.database.stat()
        early_zip = self._zip(self._early_members())
        result = self._observe(zip_raw=early_zip)
        after = self.fixture.database.stat()
        self.assertEqual(result['status'], 'verified_bytes_only')
        self.assertEqual(result['database']['schema_version'], 3)
        self.assertTrue(result['database']['issued_head_empty'])
        components = result['attestation_components']
        self.assertEqual(components['queue_id'], self.fixture._action()[0]['queue_id'])
        self.assertEqual(components['job_id'], 700)
        self.assertEqual(components['early_artifact']['sha256'], digest(early_zip))
        self.assertNotIn('observation_sha256', components)
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns))
        with self.assertRaises(issued.IssuedActionError):
            issued._validate_start(components)

    def test_completed_run_and_job_are_rejected(self):
        run = copy.deepcopy(self.run)
        run.update(status='completed', conclusion='success')
        jobs = copy.deepcopy(self.jobs)
        jobs['jobs'][0].update(status='completed', conclusion='success')
        with self.assertRaisesRegex(live.LiveObservationError, 'in-progress'):
            self._observe(run=run, jobs=jobs)

    def test_forged_but_valid_format_triplet_is_rejected(self):
        source = dict(self.source_members)
        claim = json.loads(source['reservation-claim.json'])
        claim['asserted_reservation'] = {
            'queue_id': 'f' * 32,
            'reservation_sequence': 9,
            'reservation_sha256': 'e' * 64,
        }
        source['reservation-claim.json'] = json_bytes(claim)
        with self.assertRaisesRegex(reconcile.ReconcileError, 'claim queue ID'):
            self._observe(source_members=source)

    def test_changed_source_with_recomputed_file_receipt_is_rejected(self):
        source = dict(self.source_members)
        source['current/decisions.json'] += b'{"tampered":true}\n'
        # _observe computes a fresh correct per-file hash receipt. The archive
        # and claim replay still expose the source mismatch.
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'differs from exact retained archive bytes'):
            self._observe(source_members=source)

    def test_policy_consumer_or_release_lock_mismatch_is_rejected(self):
        wrong = dict(self.approved_policy)
        wrong['release_lock_sha256'] = 'a' * 64
        with self.assertRaisesRegex(live.LiveObservationError, 'approved live'):
            self._observe(approved_policy=wrong)

    def test_nonempty_or_stale_v3_issued_head_is_rejected(self):
        with closing(sqlite3.connect(self.fixture.database)) as db:
            db.execute('UPDATE issued_head SET seq=1, hash=? WHERE singleton=1',
                       ('a' * 64,))
            db.commit()
        with self.assertRaisesRegex(reconcile.ReconcileError,
                                   'backlog receipt or action chain'):
            self._observe()

    def test_extra_zip_member_is_rejected(self):
        members = self._early_members()
        members['unexpected.bin'] = b'extra'
        with self.assertRaisesRegex(live.LiveObservationError, 'exactly ten'):
            self._observe(zip_raw=self._zip(members))

    def test_path_traversal_zip_member_is_rejected(self):
        members = self._early_members()
        members['../inventory.json'] = members.pop('inventory.json')
        with self.assertRaisesRegex(live.LiveObservationError, 'unsafe'):
            self._observe(zip_raw=self._zip(members))

    def test_duplicate_zip_member_is_rejected(self):
        members = self._early_members()
        duplicate_name = next(iter(members))
        omitted_name = next(name for name in members if name != duplicate_name)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            zip_raw = self._zip(members, duplicate=duplicate_name, omit=omitted_name)
        with self.assertRaisesRegex(live.LiveObservationError, 'duplicate'):
            self._observe(zip_raw=zip_raw)

    def test_nonregular_zip_member_is_rejected(self):
        from io import BytesIO

        members = self._early_members()
        stream = BytesIO()
        with ZipFile(stream, 'w', ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                info = ZipInfo(name)
                info.compress_type = ZIP_DEFLATED
                mode = stat.S_IFLNK | 0o777 if name == 'inventory.json' else stat.S_IFREG | 0o600
                info.external_attr = mode << 16
                archive.writestr(info, b'target' if name == 'inventory.json' else raw)
        with self.assertRaisesRegex(live.LiveObservationError, 'nonregular'):
            self._observe(zip_raw=stream.getvalue())

    def test_malformed_zip_is_rejected_after_matching_api_digest(self):
        with self.assertRaisesRegex(live.LiveObservationError, 'invalid early artifact ZIP'):
            self._observe(zip_raw=b'not a ZIP archive')

    def test_zip_byte_change_without_matching_metadata_is_rejected(self):
        early_zip = self._zip(self._early_members())
        original_artifacts = self._artifacts(early_zip)
        changed = bytearray(early_zip)
        changed[-1] ^= 0x01
        with self.assertRaisesRegex(live.LiveObservationError, 'ZIP size or digest'):
            self._observe(zip_raw=bytes(changed), artifacts=original_artifacts)

    def test_incomplete_or_ambiguous_jobs_and_artifacts_are_rejected(self):
        jobs = copy.deepcopy(self.jobs)
        jobs['total_count'] = 2
        with self.assertRaisesRegex(live.LiveObservationError, 'incomplete'):
            self._observe(jobs=jobs)

        jobs = copy.deepcopy(self.jobs)
        jobs['jobs'].append(dict(jobs['jobs'][0], id=701))
        jobs['total_count'] = 2
        with self.assertRaisesRegex(live.LiveObservationError, 'ambiguous'):
            self._observe(jobs=jobs)

        zip_raw = self._zip(self._early_members())
        artifacts = self._artifacts(zip_raw)
        artifacts['total_count'] = 2
        with self.assertRaisesRegex(live.LiveObservationError, 'incomplete'):
            self._observe(zip_raw=zip_raw, artifacts=artifacts)

    def test_attempt_head_artifact_and_recheck_identity_mismatches_are_rejected(self):
        run = copy.deepcopy(self.run)
        run['run_attempt'] += 1
        with self.assertRaisesRegex(live.LiveObservationError, 'in-progress'):
            self._observe(run=run)

        run = copy.deepcopy(self.run)
        jobs = copy.deepcopy(self.jobs)
        jobs['jobs'][0]['head_sha'] = 'b' * 40
        with self.assertRaisesRegex(live.LiveObservationError, 'live run identity'):
            self._observe(jobs=jobs)

        zip_raw = self._zip(self._early_members())
        artifacts = self._artifacts(zip_raw)
        artifacts['artifacts'][0]['workflow_run']['id'] += 1
        with self.assertRaisesRegex(live.LiveObservationError, 'run linkage'):
            self._observe(zip_raw=zip_raw, artifacts=artifacts)

        recheck_jobs = copy.deepcopy(self.jobs)
        recheck_jobs['jobs'][0]['id'] += 1
        with self.assertRaisesRegex(live.LiveObservationError, 'rechecked live'):
            self._observe(recheck_jobs=recheck_jobs)

    def test_early_receipt_file_hash_mismatch_is_rejected(self):
        members = self._early_members()
        receipt = json.loads(members['receipt.json'])
        receipt['files']['inventory.json']['sha256'] = 'c' * 64
        members['receipt.json'] = json_bytes(receipt)
        zip_raw = self._zip(members)
        with self.assertRaisesRegex(live.LiveObservationError, 'receipt digest'):
            self._observe(zip_raw=zip_raw)

    def test_actual_completed_run_458751_is_a_read_only_negative_when_retained_bytes_exist(self):
        repo_root = Path(__file__).resolve().parents[1]
        ledger_work = repo_root.parent
        observation = ledger_work / 'default-branch-early-live-retry-20261126' / 'live-observation'
        reconcile_dir = ledger_work / 'default-branch-early-live-retry-20261126' / 'reconcile-work' / \
            'reservation-reconcile-45875169837-1-pnjqa4sb'
        private_root = ledger_work / 'default-branch-v3-real-copy-20261126'
        policy_path = ledger_work / 'default-branch-early-live-retry-20261126' / \
            'reservation-policy.json'
        required = [
            observation / 'artifacts-api.json', observation / 'early.zip',
            reconcile_dir / 'run-api.json', reconcile_dir / 'jobs-api.json',
            private_root / reservation.DATABASE_NAME, policy_path,
        ]
        if not all(path.is_file() for path in required):
            self.skipTest('retained raw evidence for completed run 45875169837 is unavailable')
        policy_doc = json.loads(policy_path.read_bytes())
        approved = {
            'consumer_commit': policy_doc['consumer_commit'],
            'release_lock_sha256': policy_doc['release_lock_sha256'],
        }
        early_raw = (observation / 'early.zip').read_bytes()
        parsed_early = live._read_early_zip(early_raw, 45875169837, 1)
        self.assertEqual(set(parsed_early), live.EARLY_REQUIRED_NAMES)
        self.assertEqual(
            len(parsed_early['previous/decisions.json']) +
            len(parsed_early['current/decisions.json']), 95_093_559)
        before = (private_root / reservation.DATABASE_NAME).stat()
        with self.assertRaisesRegex(live.LiveObservationError, 'in-progress'):
            live.verify_live_observation_bytes(
                private_root,
                (reconcile_dir / 'run-api.json').read_bytes(),
                (reconcile_dir / 'jobs-api.json').read_bytes(),
                (observation / 'artifacts-api.json').read_bytes(),
                early_raw,
                45875169837, 1, approved,
                (reconcile_dir / 'run-api.json').read_bytes(),
                (reconcile_dir / 'jobs-api.json').read_bytes())
        after = (private_root / reservation.DATABASE_NAME).stat()
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns))


if __name__ == '__main__':
    unittest.main()
