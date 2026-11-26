import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import default_branch_corpus_manifest as branch
from tools import incoming_poll as poll


class DefaultBranchManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = {name: self.root / (name + '.json') for name in
                      ('policy', 'previous', 'current', 'gap', 'identity', 'inventory')}
        self.source, self.control = self.root / 'source', self.root / 'control'
        self.source.mkdir()
        self.control.mkdir()
        self.previous_sha, self.current_sha = 'a' * 64, 'b' * 64
        self.policy = {'pins': {'openwrt': 'd' * 40}}
        self.identity = {
            'schema': 'default-branch-event-identity-v1',
            'status': 'identities_resolved_only', 'repository': 'openwrt/openwrt',
            'source': {'commit': '1' * 40, 'tree': '2' * 40},
            'base': {'commit': '3' * 40, 'tree': '4' * 40},
            'control': {'commit': '5' * 40, 'tree': '6' * 40},
            'previous_checkpoint_sha256': self.previous_sha,
            'current_checkpoint_sha256': self.current_sha}
        self.inventory = {'status': 'inventory_ready'}
        self.gap_record = {'previous_sha256': self.previous_sha,
                           'current_sha256': self.current_sha}
        for name, value in (('policy', self.policy), ('gap', self.gap_record),
                            ('inventory', self.inventory)):
            self.paths[name].write_text(json.dumps(value))
        self.paths['previous'].write_text('{}')
        self.paths['current'].write_text('{}')
        self.identity['gap_sha256'] = hashlib.sha256(self.paths['gap'].read_bytes()).hexdigest()
        self.paths['identity'].write_text(json.dumps(self.identity))
        self.base_manifest = {'schema': 'mvp-incoming-event-corpus-v1',
                              'event': {'pr_number': None}, 'boundaries': []}

    def build(self, identity=None, inventory=None):
        if identity is not None:
            self.paths['identity'].write_text(json.dumps(identity))
        if inventory is not None:
            self.paths['inventory'].write_text(json.dumps(inventory))
        with patch.object(branch, 'POLICY', self.paths['policy']), \
             patch.object(branch, 'POLICY_SHA256', branch.digest(self.paths['policy'])), \
             patch.object(branch.poll, 'verify_checkpoint_decisions',
                          return_value=({}, self.current_sha, [], self.previous_sha, None)), \
             patch.object(branch.poll, 'load_checkpoint',
                          return_value=({}, self.previous_sha)), \
             patch.object(branch.gap, 'load_gap', return_value=self.gap_record), \
             patch.object(branch.gap, 'replay_record', return_value=[]), \
             patch.object(branch.branch_event, 'resolve',
                          return_value=self.identity), \
             patch.object(branch.candidates, 'compare',
                          return_value=self.inventory), \
             patch.object(branch.corpus, 'build',
                          return_value=copy.deepcopy(self.base_manifest)), \
             patch.object(branch.branch_event, 'safe_git',
                          side_effect=lambda root, command, *args:
                          '' if command == 'status' else 'c' * 40):
            return branch.build(self.paths['previous'], self.paths['current'],
                                self.paths['gap'], self.paths['identity'],
                                self.paths['inventory'], self.source, self.control)

    def test_linked_identity_and_inventory_bind_distinct_manifest(self):
        result = self.build()
        self.assertEqual(result['schema'], 'mvp-default-branch-commit-corpus-v1')
        self.assertEqual(result['status'], 'source_first_default_branch_oracle_only')
        self.assertEqual(result['event']['first_parent_commit'], self.identity['base']['commit'])
        self.assertEqual(result['event']['gap_sha256'], self.identity['gap_sha256'])
        self.assertEqual(result['event']['policy_base_commit'], self.policy['pins']['openwrt'])
        self.assertNotIn('pr_number', result['event'])

    def test_gap_and_inventory_tamper_fail_before_manifest(self):
        identity = copy.deepcopy(self.identity)
        identity['gap_sha256'] = '0' * 64
        with self.assertRaisesRegex(poll.PollError, 'event identity differs'):
            self.build(identity=identity)
        self.paths['identity'].write_text(json.dumps(self.identity))
        changed = {'status': 'review_required'}
        with self.assertRaisesRegex(poll.PollError, 'inventory differs'):
            self.build(inventory=changed)


if __name__ == '__main__':
    unittest.main()
