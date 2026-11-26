import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import direct_commit_corpus_manifest as direct
from tools import incoming_poll as poll


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


class DirectCommitCorpusManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.control = self.root / 'control'
        self.source.mkdir()
        self.control.mkdir()
        self.base = 'a'*40
        self.head = 'b'*40
        self.fixed = 'c'*40
        self.path = 'protocols/luci-proto-openvpn/root/usr/share/rpcd/ucode/luci.openvpn.uc'
        self.policy = {'schema': 'mvp-openvpn-historical-source-v0.1',
                       'pins': {'luci': self.head},
                       'admitted_additions': [{'path': self.path, 'base_commit': self.base}]}
        self.identity = {'schema': 'default-branch-event-identity-v1',
                         'status': 'identities_resolved_only',
                         'repository': 'openwrt/luci', 'ref': 'master',
                         'source': {'commit': self.head, 'tree': '1'*40},
                         'base': {'commit': self.base, 'tree': '2'*40},
                         'control': {'commit': self.fixed, 'tree': '3'*40}}
        self.inventory = {'status': 'inventory_ready', 'admitted_additions': [self.path]}
        self.checked = {'schema': 'direct-commit-admission-check-v1',
                        'status': 'source_policy_input_verified_only'}
        self.checked['identity_receipt_sha256'] = direct.digest(raw(self.identity))
        self.base_manifest = {'schema': 'mvp-incoming-event-corpus-v1',
                              'event': {'pr_number': None}, 'boundaries': [], 'selected': []}

    def build(self, *, identity=None, admission=None, inventory=None, policy=None):
        policy_raw = raw(self.policy if policy is None else policy)
        identity_raw = raw(self.identity if identity is None else identity)
        admission_raw = raw(self.checked if admission is None else admission)
        inventory_raw = raw(self.inventory if inventory is None else inventory)
        with patch.object(direct, 'POLICY_SHA256', direct.digest(raw(self.policy))), \
             patch.object(direct.admission, 'verify', return_value={
                 'schema': 'direct-commit-admission-check-v1',
                 'status': 'source_policy_input_verified_only'}), \
             patch.object(direct.candidates, 'compare', return_value=self.inventory), \
             patch.object(direct.corpus, 'build', return_value=copy.deepcopy(self.base_manifest)) as inner:
            result = direct.build_manifest(policy_raw, identity_raw, admission_raw,
                                           inventory_raw, self.source, self.control)
        return result, inner

    def test_exact_inputs_bind_to_direct_commit_manifest(self):
        result, inner = self.build()
        self.assertEqual(result['schema'], 'mvp-direct-commit-corpus-v1')
        self.assertEqual(result['status'], 'historical_direct_commit_source_first_oracle_only')
        self.assertEqual(result['event']['kind'], 'direct_commit')
        self.assertNotIn('pr_number', result['event'])
        self.assertEqual(result['event']['identity_receipt_sha256'],
                         direct.digest(raw(self.identity)))
        self.assertEqual(result['event']['admission_check_sha256'],
                         direct.digest(raw(self.checked)))
        self.assertEqual(result['event']['candidate_inventory_sha256'],
                         direct.digest(raw(self.inventory)))
        self.assertEqual(inner.call_args.kwargs['admitted_additions'], (self.path,))
        self.assertEqual(result['event']['direct_builder_script_sha256'],
                         direct.digest(Path(direct.__file__).read_bytes()))
        self.assertEqual(result['event']['selector_script_sha256'],
                         direct.digest((direct.ROOT / 'tools/full_tree_candidates.py').read_bytes()))

    def test_historical_source_identity_keeps_distinct_schema(self):
        identity = copy.deepcopy(self.identity)
        identity['schema'] = 'historical-direct-commit-source-identity-v1'
        identity['status'] = 'historical_objects_resolved_only'
        identity['policy_ref_context'] = identity.pop('ref')
        checked = copy.deepcopy(self.checked)
        checked['identity_receipt_sha256'] = direct.digest(raw(identity))
        result, _ = self.build(identity=identity, admission=checked)
        self.assertEqual(result['event']['identity_receipt_sha256'],
                         direct.digest(raw(identity)))
        self.assertEqual(result['event']['kind'], 'direct_commit')

    def test_tampered_receipt_inventory_or_policy_rejected(self):
        changed = copy.deepcopy(self.checked)
        changed['identity_receipt_sha256'] = '0'*64
        with self.assertRaisesRegex(poll.PollError, 'admission check differs'):
            self.build(admission=changed)
        changed = copy.deepcopy(self.inventory)
        changed['status'] = 'review_required'
        with self.assertRaisesRegex(poll.PollError, 'inventory differs'):
            self.build(inventory=changed)
        changed = copy.deepcopy(self.policy)
        changed['pins']['luci'] = '0'*40
        with self.assertRaisesRegex(poll.PollError, 'policy digest differs'):
            self.build(policy=changed)
        changed = copy.deepcopy(self.identity)
        changed['source']['commit'] = '0'*40
        with self.assertRaisesRegex(poll.PollError, 'revision differs'):
            self.build(identity=changed)

    def test_cli_rejects_dirty_consumer_before_reading_inputs(self):
        output = self.root / 'out.json'
        args = ['--identity', str(self.root / 'missing'), '--admission-check', str(self.root / 'missing'),
                '--inventory', str(self.root / 'missing'), '--source-checkout', str(self.source),
                '--control-checkout', str(self.control), '--output', str(output)]
        with patch.object(direct.event, 'safe_git', return_value=' M modified'), \
             patch('sys.stderr'):
            self.assertEqual(direct.main(args), 2)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
