import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import issuer_artifact_freeze as freeze


class ArtifactInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'out').mkdir()
        (self.root / 'out/result.json').write_text('{"ok":true}\n')

    def test_hashes_actual_bytes(self):
        rows = freeze._inventory(self.root, {'out/result.json'}, set())
        self.assertEqual(rows['out/result.json']['sha256'], hashlib.sha256(b'{"ok":true}\n').hexdigest())

    def test_snapshot_copies_then_checks_bytes(self):
        run_id = '123-1'
        inputs = self.root / ('event-input-' + run_id)
        inputs.mkdir()
        (inputs / 'receipt.json').write_text('original')
        digest = hashlib.sha256(b'original').hexdigest()
        record = {'artifacts': {'inputs': {'receipt.json': {'sha256': digest, 'bytes': 8}},
                                'event': {}, 'control': {}, 'r3': {}}}
        freeze.snapshot(self.root, run_id, record)
        copied = self.root / ('issuer-freeze-' + run_id) / 'snapshot/inputs/receipt.json'
        self.assertEqual(copied.read_bytes(), b'original')
        self.assertEqual(copied.stat().st_mode & 0o222, 0)
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            freeze.snapshot(self.root, run_id, record)

    def test_rejects_symlink_and_alias(self):
        (self.root / 'out/link.json').symlink_to('result.json')
        with self.assertRaisesRegex(RuntimeError, 'alias|regular'):
            freeze._inventory(self.root, {'out/result.json', 'out/link.json'}, set())
        (self.root / 'out/link.json').unlink()
        os.link(self.root / 'out/result.json', self.root / 'out/link.json')
        with self.assertRaisesRegex(RuntimeError, 'alias|regular'):
            freeze._inventory(self.root, {'out/result.json', 'out/link.json'}, set())

    def test_rejects_extra_file_and_directory(self):
        (self.root / 'out/extra.txt').write_text('surprise')
        with self.assertRaisesRegex(RuntimeError, 'unexpected artifacts'):
            freeze._inventory(self.root, {'out/result.json'}, set())
        (self.root / 'out/extra.txt').unlink()
        (self.root / 'extra').mkdir()
        with self.assertRaisesRegex(RuntimeError, 'unexpected artifact directory'):
            freeze._inventory(self.root, {'out/result.json'}, set())

    def test_rejects_parent_directory_symlink(self):
        (self.root / 'linked').symlink_to(self.root / 'out', target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'symlink directory'):
            freeze._inventory(self.root, {'out/result.json'}, set())

    def test_source_path_rejects_alias_parent(self):
        (self.root / 'linked').symlink_to(self.root / 'out', target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'alias'):
            freeze._no_alias(self.root, 'linked/result.json')


class SourceRecheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.run = self.root / 'run'
        self.run.mkdir()
        self.source = self.root / 'source'
        self.control = self.root / 'control'
        for checkout in (self.source, self.control):
            subprocess.run(['git', 'init', '-q', str(checkout)], check=True)
            subprocess.run(['git', '-C', str(checkout), 'config', 'user.email', 'test@example.invalid'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'config', 'user.name', 'Test'], check=True)
            (checkout / 'file.uc').write_text('source\n')
            subprocess.run(['git', '-C', str(checkout), 'add', 'file.uc'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'commit', '-qm', 'source'], check=True)
        self.identity = {checkout: {'commit': freeze._git(checkout, 'rev-parse', 'HEAD'),
                                    'tree': freeze._git(checkout, 'rev-parse', 'HEAD^{tree}')}
                         for checkout in (self.source, self.control)}
        receipt = {'repository': 'openwrt', 'source': self.identity[self.source],
                   'control': self.identity[self.control], 'base': self.identity[self.source]}
        (self.inputs / 'replayed-receipt.json').write_text(json.dumps(receipt))
        self.row = {'repo': 'openwrt', 'source_path': 'file.uc', 'proposed_installed_path': 'file.uc',
                    'source_sha256': hashlib.sha256(b'source\n').hexdigest(),
                    'source_commit': self.identity[self.source]['commit'],
                    'git_blob': freeze._git(self.source, 'rev-parse', 'HEAD:file.uc')}
        for role in ('event-corpus', 'control-corpus'):
            stage = self.run / role / 'stage'
            stage.mkdir(parents=True)
            (stage / 'file.uc').write_text('source\n')
            sources = self.run / role / 'sources'
            sources.mkdir()
            checkout = self.source if role == 'event-corpus' else self.control
            subprocess.run(['git', 'clone', '-q', str(checkout), str(sources / 'openwrt')], check=True)

    def check(self):
        with patch.object(freeze, 'canonical_repository'), patch.object(
                freeze, 'validate_event_manifest', side_effect=[
                    {'selected': [self.row], 'excluded': [], 'pins': {'openwrt': self.identity[self.source]['commit']}},
                    {'selected': [self.row], 'excluded': [], 'pins': {'openwrt': self.identity[self.control]['commit']}}]):
            return freeze._source_recheck(self.source, self.control, self.inputs, self.run)

    def test_clean_git_and_source_bytes_pass(self):
        self.assertEqual(self.check()['event']['checkout'], self.identity[self.source])

    def test_dirty_checkout_rejected(self):
        (self.source / 'file.uc').write_text('drift\n')
        with self.assertRaisesRegex(RuntimeError, 'checkout drift'):
            self.check()

    def test_staged_byte_drift_rejected(self):
        (self.run / 'control-corpus/stage/file.uc').write_text('drift\n')
        with self.assertRaisesRegex(RuntimeError, 'source/stage byte drift'):
            self.check()

    def test_git_tree_mismatch_rejected(self):
        receipt = json.loads((self.inputs / 'replayed-receipt.json').read_text())
        receipt['control']['tree'] = '0' * 40
        (self.inputs / 'replayed-receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(RuntimeError, 'checkout drift'):
            self.check()
