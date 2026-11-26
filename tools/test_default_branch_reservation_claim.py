import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from tools import default_branch_reservation_claim as reservation_claim


PREVIOUS_SHA = '1' * 64
CURRENT_SHA = '2' * 64
BASE_SHA = 'a' * 40
BASE_TREE = 'b' * 40
SOURCE_SHA = 'c' * 40
SOURCE_TREE = 'd' * 40
CONTROL_SHA = 'e' * 40
CONSUMER_SHA = 'f' * 40


class DefaultBranchReservationClaimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.previous = self.root / 'previous.json'
        self.current = self.root / 'current.json'
        self.gap = self.root / 'gap.json'
        self.previous.write_bytes(b'previous checkpoint fixture\n')
        self.current.write_bytes(b'current checkpoint fixture\n')
        self.gap_raw = (json.dumps({'previous_sha256': PREVIOUS_SHA,
                                    'current_sha256': CURRENT_SHA},
                                   sort_keys=True) + '\n').encode()
        self.gap.write_bytes(self.gap_raw)
        self.identity_raw, self.identity = self.document({
            'schema': 'default-branch-event-identity-v1',
            'status': 'identities_resolved_only',
            'repository': 'openwrt/luci', 'ref': 'master',
            'source': {'commit': SOURCE_SHA, 'tree': SOURCE_TREE},
            'base': {'commit': BASE_SHA, 'tree': BASE_TREE},
            'control': {'commit': CONTROL_SHA, 'tree': '9' * 40},
            'gap_sha256': self.gap_sha,
            'previous_checkpoint_sha256': PREVIOUS_SHA,
            'current_checkpoint_sha256': CURRENT_SHA,
        })
        self.manifest_raw, self.manifest = self.document({
            'schema': 'mvp-default-branch-commit-corpus-v1',
            'status': 'source_first_default_branch_oracle_only',
            'event': {
                'kind': 'default_branch_commit',
                'source_role': 'incoming_default_branch_first_parent',
                'repository': 'luci', 'base_commit': BASE_SHA,
                'base_tree': BASE_TREE, 'head_commit': SOURCE_SHA,
                'head_tree': SOURCE_TREE, 'first_parent_commit': BASE_SHA,
                'control_commit': CONTROL_SHA,
                'gap_sha256': self.gap_sha,
                'previous_checkpoint_sha256': PREVIOUS_SHA,
                'current_checkpoint_sha256': CURRENT_SHA,
                'consumer_commit': CONSUMER_SHA,
                'identity_receipt_sha256': hashlib.sha256(self.identity_raw).hexdigest(),
            },
        })
        self.dispatch = {
            'previous_run_id': '101', 'previous_run_attempt': '2',
            'previous_sha256': PREVIOUS_SHA,
            'current_run_id': '202', 'current_run_attempt': '3',
            'current_sha256': CURRENT_SHA, 'gap_sha256': self.gap_sha,
            'repository': 'openwrt/luci', 'source_sha': SOURCE_SHA,
            'control_sha': CONTROL_SHA,
        }
        self.execution = {'run_id': '900', 'run_attempt': '1',
                          'consumer_head': CONSUMER_SHA,
                          'actual_head': CONSUMER_SHA}
        self.rows = [{'commit': SOURCE_SHA, 'tree': SOURCE_TREE,
                      'first_parent': BASE_SHA}]
        self.interval = {'repository': 'openwrt/luci', 'ref': 'master',
                         'prior': {'commit': BASE_SHA, 'tree': BASE_TREE},
                         'state': 'bounded_fast_forward',
                         'first_parent_commits': self.rows}
        self.replay = patch.object(reservation_claim.poll, 'load_checkpoint',
                                   return_value=({}, PREVIOUS_SHA))
        self.verify = patch.object(reservation_claim.poll, 'verify_checkpoint_decisions',
                                   return_value=({'previous_sha256': PREVIOUS_SHA},
                                                 CURRENT_SHA, [], PREVIOUS_SHA, None))
        self.gap_replay = patch.object(reservation_claim.gap, 'replay_record',
                                       return_value=[self.interval])
        self.replay.start()
        self.verify.start()
        self.gap_replay.start()
        self.addCleanup(self.replay.stop)
        self.addCleanup(self.verify.stop)
        self.addCleanup(self.gap_replay.stop)

    @property
    def gap_sha(self):
        return hashlib.sha256(self.gap_raw).hexdigest()

    @staticmethod
    def document(value):
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        return raw, value

    def build(self, fields=None, identity=None, manifest=None, dispatch=None,
              execution=None, identity_raw=None, manifest_raw=None):
        return reservation_claim.claim(
            fields or dict.fromkeys(('queue_id', 'reservation_sequence',
                                     'reservation_sha256'), ''),
            self.identity if identity is None else identity,
            self.manifest if manifest is None else manifest,
            self.previous, self.current, self.gap,
            self.dispatch if dispatch is None else dispatch,
            self.execution if execution is None else execution,
            self.identity_raw if identity_raw is None else identity_raw,
            self.manifest_raw if manifest_raw is None else manifest_raw)

    def test_absent_claim_is_explicit_and_bound_to_derived_identity(self):
        result = self.build()
        self.assertEqual(result['status'], 'absent')
        self.assertIsNone(result['asserted_reservation'])
        self.assertEqual(result['derived_source'], {
            'repository': 'openwrt/luci', 'ref': 'master',
            'commit_sha': SOURCE_SHA, 'tree_sha': SOURCE_TREE,
            'first_parent_sha': BASE_SHA, 'ordinal': 1})
        self.assertEqual(result['linked_discovery_origin']['previous_run_id'], 101)
        self.assertEqual(result['linked_discovery_origin']['current_run_id'], 202)
        self.assertEqual(result['execution']['workflow_run_id'], 900)
        self.assertEqual(result['linked_input_sha256']['manifest'],
                         hashlib.sha256(self.manifest_raw).hexdigest())
        self.assertNotEqual(result['status'], 'success')

    def test_forged_but_well_formed_triplet_remains_unverified(self):
        fields = {'queue_id': '0' * 32, 'reservation_sequence': '7',
                  'reservation_sha256': '8' * 64}
        result = self.build(fields)
        self.assertEqual(result['status'], 'claimed_unverified')
        self.assertEqual(result['asserted_reservation'], {
            'queue_id': '0' * 32, 'reservation_sequence': 7,
            'reservation_sha256': '8' * 64})
        self.assertTrue(any('not checked against the private queue' in item
                            for item in result['limitations']))

    def test_partial_claim_is_rejected(self):
        fields = {'queue_id': '0' * 32, 'reservation_sequence': '',
                  'reservation_sha256': '8' * 64}
        with self.assertRaisesRegex(reservation_claim.ClaimError, 'incomplete'):
            self.build(fields)

    def test_malformed_triplet_is_rejected(self):
        valid = {'queue_id': '0' * 32, 'reservation_sequence': '7',
                 'reservation_sha256': '8' * 64}
        for key, value in (('queue_id', 'not-a-queue'),
                           ('reservation_sequence', '07'),
                           ('reservation_sequence', '0'),
                           ('reservation_sha256', '8' * 63)):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    reservation_claim.ClaimError, 'invalid reservation claim'):
                self.build({**valid, key: value})

    def test_manifest_or_dispatch_mismatch_to_derived_identity_is_rejected(self):
        changed = json.loads(json.dumps(self.manifest))
        changed['event']['head_tree'] = '0' * 40
        with self.assertRaisesRegex(reservation_claim.ClaimError,
                                    'manifest differs from resolved'):
            self.build(manifest=changed)
        changed_dispatch = {**self.dispatch, 'source_sha': '0' * 40}
        with self.assertRaisesRegex(reservation_claim.ClaimError,
                                    'dispatch inputs differ'):
            self.build(dispatch=changed_dispatch)

    def test_manifest_must_bind_exact_identity_receipt_bytes(self):
        changed = json.loads(json.dumps(self.manifest))
        changed['event']['identity_receipt_sha256'] = '0' * 64
        raw, changed = self.document(changed)
        with self.assertRaisesRegex(reservation_claim.ClaimError,
                                    'identity receipt digest differs'):
            self.build(manifest=changed, manifest_raw=raw)

    def test_read_json_stops_at_bound_plus_one_byte(self):
        oversized = self.root / 'oversized.json'
        oversized.write_bytes(b'x' * 11)
        with patch.object(reservation_claim, 'MAX_INPUT', 10), \
                self.assertRaisesRegex(reservation_claim.ClaimError,
                                       'invalid oversized fixture'):
            reservation_claim.read_json(oversized, 'oversized fixture')

    def test_wrong_interval_ordinal_or_consumer_head_is_rejected(self):
        self.rows.append({'commit': SOURCE_SHA, 'tree': SOURCE_TREE,
                          'first_parent': SOURCE_SHA})
        with self.assertRaisesRegex(reservation_claim.ClaimError,
                                    'resolved source is not uniquely enumerated'):
            self.build()
        self.rows.pop()
        execution = {**self.execution, 'actual_head': '0' * 40}
        with self.assertRaisesRegex(reservation_claim.ClaimError, 'consumer head differs'):
            self.build(execution=execution)

    def test_failed_claim_does_not_write_a_success_artifact(self):
        identity_path = self.root / 'identity.json'
        manifest_path = self.root / 'manifest.json'
        identity_path.write_bytes(self.identity_raw)
        manifest_path.write_bytes(self.manifest_raw)
        base_env = {
            'PREVIOUS_RUN_ID': '101', 'PREVIOUS_RUN_ATTEMPT': '2',
            'PREVIOUS_SHA256': PREVIOUS_SHA,
            'CURRENT_RUN_ID': '202', 'CURRENT_RUN_ATTEMPT': '3',
            'CURRENT_SHA256': CURRENT_SHA, 'GAP_SHA256': self.gap_sha,
            'REPOSITORY': 'openwrt/luci', 'SOURCE_SHA': SOURCE_SHA,
            'CONTROL_SHA': CONTROL_SHA, 'GITHUB_RUN_ID': '900',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': CONSUMER_SHA,
            'CONSUMER_HEAD': CONSUMER_SHA,
        }
        cases = (
            ('malformed', {'QUEUE_ID': '0' * 32, 'RESERVATION_SEQUENCE': '0',
                           'RESERVATION_SHA256': '8' * 64}),
            ('partial', {'QUEUE_ID': '0' * 32, 'RESERVATION_SEQUENCE': '',
                         'RESERVATION_SHA256': '8' * 64}),
        )
        for label, claim_env in cases:
            with self.subTest(label=label):
                case_root = self.root / label
                case_root.mkdir()
                output_path = case_root / 'claim.json'
                with patch.dict(os.environ, {**base_env, **claim_env}, clear=False), \
                        contextlib.redirect_stderr(io.StringIO()):
                    code = reservation_claim.main([
                        '--previous', str(self.previous), '--current', str(self.current),
                        '--gap', str(self.gap), '--identity', str(identity_path),
                        '--manifest', str(manifest_path), '--output', str(output_path)])
                self.assertEqual(code, 2)
                self.assertFalse(output_path.exists())
                failure_path = case_root / 'reservation-claim-failure.json'
                failure = json.loads(failure_path.read_bytes())
                self.assertEqual(failure['schema'],
                                 'default-branch-reservation-claim-failure-v1')
                self.assertEqual(failure['status'], 'claim_failed')
                self.assertNotIn('asserted_reservation', failure)
                self.assertNotEqual(failure['status'], 'success')

    def test_workflow_contract_wires_optional_inputs_and_always_retains_claim(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    '.github/workflows/default-branch-commit-scan.yml').read_text()
        for field in ('queue_id', 'reservation_sequence', 'reservation_sha256'):
            match = re.search(rf'(?m)^      {field}:\n((?:^        .*\n)+)', workflow)
            self.assertIsNotNone(match)
            section = match.group(1)
            self.assertIn('required: false', section)
            self.assertIn("default: ''", section)
        self.assertLess(workflow.index('tools.default_branch_corpus_manifest'),
                        workflow.index('Retain same-job default-branch reservation claim'))
        self.assertLess(workflow.index('Retain same-job default-branch reservation claim'),
                        workflow.index('Verify pinned immutable release in same job'))
        self.assertIn('reservation-claim.json', workflow)
        self.assertIn('reservation-claim-failure.json', workflow)
        self.assertIn('tools.test_default_branch_reservation_claim', workflow)
        self.assertNotIn('default-branch-backlog.sqlite3', workflow)
        self.assertIn('if: always()', workflow)


if __name__ == '__main__':
    unittest.main()
