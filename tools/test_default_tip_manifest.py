import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import default_tip_manifest as adapter, event_corpus_manifest as builder, full_tree_candidates as selector


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


class DefaultManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / 'run'
        self.run.mkdir()
        source = self.run / 'source'
        subprocess.run(['git', 'init', '-q', str(source)], check=True)
        git(source, 'config', 'user.name', 'test')
        git(source, 'config', 'user.email', 'test@example.invalid')
        (source / 'file.uc').write_text('return 1\n')
        git(source, 'add', 'file.uc')
        git(source, 'commit', '-qm', 'control')
        self.control = {'commit': git(source, 'rev-parse', 'HEAD'), 'tree': git(source, 'rev-parse', 'HEAD^{tree}')}
        subprocess.run(['git', 'clone', '-q', str(source), str(self.run / 'control')], check=True)
        (source / 'file.uc').write_text('return 2\n')
        git(source, 'commit', '-qam', 'event')
        self.source = {'commit': git(source, 'rev-parse', 'HEAD'), 'tree': git(source, 'rev-parse', 'HEAD^{tree}')}

    def prepare(self, repo, mutate=None):
        base = self.control['commit']
        row = {'repo': repo, 'source_path': 'file.uc', 'source_commit': base,
               'source_sha256': hashlib.sha256(b'return 1\n').hexdigest(),
               'git_blob': git(self.run / 'control', 'rev-parse', base + ':file.uc'),
               'proposed_installed_path': 'usr/share/ucode/file.uc',
               'expected_route': {'classification': 'plain', 'reason': 'ucode_extension'}}
        policy = {'schema': builder.POLICY_SCHEMA, 'pins': {'openwrt': base, 'luci': base, 'packages': 'b'*40},
                  'selected': [row], 'excluded': []}
        raw = json.dumps(policy).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (self.root / 'docs').mkdir(exist_ok=True)
        (self.root / 'docs/current-corpus-source-v0.6.json').write_bytes(raw)
        def binding(identity):
            return {'checkpoint_sha256': 'a'*64, 'event_key': ['openwrt/' + repo, 'default_branch', 'main', identity['commit'], '', ''], 'observed_at': '2026-11-24T12:00:00Z'}
        receipt = {'schema': 'incoming-event-receipt-v1', 'status': 'identities_resolved_only',
                   'event_type': 'default_branch', 'repository': repo, 'discovery_repository': 'openwrt/' + repo,
                   'ref': 'main', 'source': self.source, 'control': self.control, 'policy_pin': base,
                   'discovery': binding(self.source), 'control_discovery': {**binding(self.control), 'observed_at': '2026-11-23T12:00:00Z'}}
        if mutate:
            mutate(receipt)
        receipt_path = self.root / 'receipt.json'
        receipt_path.write_text(json.dumps(receipt))
        with patch.object(adapter, 'ROOT', self.root), patch.object(adapter, 'POLICY_SHA256', digest), \
             patch.object(builder, 'POLICY_SHA256', digest), patch.dict(selector.EXPECTED_MANIFESTS, {builder.POLICY_SCHEMA: digest}):
            (self.root / 'tools').mkdir(exist_ok=True)
            (self.root / 'tools/event_corpus_manifest.py').write_text('test script')
            adapter.prepare(receipt_path, self.run, self.root / 'output')

    def test_both_v3_repositories_produce_exact_distinct_oracles(self):
        for repo in ('openwrt', 'luci'):
            with self.subTest(repo=repo):
                self.prepare(repo)
                output = self.root / 'output'
                event = json.loads((output / 'event-manifest.json').read_text())
                control = json.loads((output / 'control-manifest.json').read_text())
                self.assertEqual(event['selected'][0]['source_commit'], self.source['commit'])
                self.assertEqual(control['selected'][0]['source_commit'], self.control['commit'])
                self.assertEqual(event['event']['base_tree'], control['event']['base_tree'])
                self.assertEqual(control['event']['source_role'], 'clean_control')
                import shutil
                shutil.rmtree(output)

    def test_rejects_checkout_and_identity_drift(self):
        with self.assertRaisesRegex(ValueError, 'checkpoint identity'):
            self.prepare('openwrt', lambda receipt: receipt['control_discovery']['event_key'].__setitem__(3, '0'*40))
        (self.run / 'source/file.uc').write_text('dirty')
        with self.assertRaisesRegex(ValueError, 'checkout drift'):
            self.prepare('openwrt')

    def test_rejects_new_unreviewed_candidate(self):
        source = self.run / 'source'
        (source / 'new.uc').write_text('return 3\n')
        git(source, 'add', 'new.uc')
        git(source, 'commit', '-qm', 'new candidate')
        self.source = {'commit': git(source, 'rev-parse', 'HEAD'), 'tree': git(source, 'rev-parse', 'HEAD^{tree}')}
        with self.assertRaisesRegex(ValueError, 'inventory requires review'):
            self.prepare('luci')


if __name__ == '__main__':
    unittest.main()
