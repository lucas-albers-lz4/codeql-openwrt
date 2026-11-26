import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import full_tree_candidates as selector


class HistoricalOpenvpnPolicyTests(unittest.TestCase):
    SCHEMA = 'mvp-openvpn-historical-source-v0.1'
    NEW = 'protocols/luci-proto-openvpn/root/usr/share/rpcd/ucode/luci.openvpn.uc'
    RECIPE = 'protocols/luci-proto-openvpn/Makefile'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.root / 'luci.mk').write_text('root install\n')
        (self.root / 'old.uc').write_text('return 0;\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'parent')
        self.base = self.git('rev-parse', 'HEAD')
        for name in (self.NEW, self.RECIPE):
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
        (self.root / self.NEW).write_text('return 1;\n')
        (self.root / self.RECIPE).write_text('include ../../luci.mk\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'introduce')
        self.head = self.git('rev-parse', 'HEAD')
        self.policy = {
            'schema': self.SCHEMA,
            'selected': [self.row('old.uc'), self.row(self.NEW)],
            'excluded': [],
            'admitted_additions': [{
                'repository': 'luci', 'base_commit': self.base,
                'head_commit': self.head, 'path': self.NEW,
                'git_blob': self.blob(self.NEW),
                'sha256': self.hash(self.NEW), 'mode': '100644',
                'package_recipe_path': self.RECIPE,
                'package_recipe_blob': self.blob(self.RECIPE),
                'shared_recipe_path': 'luci.mk',
                'shared_recipe_blob': self.blob('luci.mk'),
                'admission_oracle_sha256':
                    '28e74f60ebc0dc8076ea3e92c8f5795817caf0f23aae03845a9d78c6cb77c1bd'}]}

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True).strip()

    def blob(self, name):
        return self.git('rev-parse', self.head + ':' + name)

    def hash(self, name):
        return hashlib.sha256((self.root / name).read_bytes()).hexdigest()

    def row(self, name):
        return {'repo': 'luci', 'source_path': name,
                'source_commit': self.head, 'git_blob': self.blob(name),
                'source_sha256': self.hash(name)}

    def compare(self, policy=None, head=None):
        policy = self.policy if policy is None else policy
        raw = json.dumps(policy, sort_keys=True).encode()
        with patch.dict(selector.EXPECTED_MANIFESTS,
                        {self.SCHEMA: hashlib.sha256(raw).hexdigest()}):
            return selector.compare(self.root, self.base,
                                    self.head if head is None else head,
                                    policy, raw, 'luci')

    def test_only_exact_added_path_is_admitted(self):
        got = self.compare()
        self.assertEqual(got['status'], 'inventory_ready')
        self.assertEqual(got['admitted_additions'], [self.NEW])
        self.assertEqual([(row['source_path'], row['events']) for row in got['events']
                          if row['events']], [(self.NEW, ['candidate_added'])])

    def test_wrong_blob_recipe_or_parent_fails(self):
        for field, value in (('git_blob', '0'*40), ('sha256', '0'*64),
                             ('package_recipe_blob', '0'*40),
                             ('base_commit', '0'*40)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.policy)
                changed['admitted_additions'][0][field] = value
                with self.assertRaises(selector.SelectorError):
                    self.compare(changed)

    def test_extra_candidate_and_stale_selected_identity_fail(self):
        changed = copy.deepcopy(self.policy)
        changed['selected'][0]['source_sha256'] = '0'*64
        with self.assertRaisesRegex(selector.SelectorError, 'source identity'):
            self.compare(changed)
        (self.root / 'extra.uc').write_text('return 3;\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'another candidate')
        with self.assertRaises(selector.SelectorError):
            self.compare(head=self.git('rev-parse', 'HEAD'))

    def test_committed_historical_policy_digest_and_census(self):
        path = Path(__file__).resolve().parents[1] / 'docs/openvpn-historical-source-v0.1.json'
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '16d372ac21d87576c3ed3cd90036059e54f3cb0d8082f3094a032bd33190403a')
        doc = json.loads(raw)
        self.assertEqual((len(doc['selected']), len(doc['excluded'])), (112, 11))
        self.assertEqual(doc['admitted_additions'][0]['path'], self.NEW)


if __name__ == '__main__':
    unittest.main()
