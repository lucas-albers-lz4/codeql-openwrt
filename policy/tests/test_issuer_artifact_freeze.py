import hashlib
import json
import os
from pathlib import Path
import shutil
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
        output_root = freeze.create_output_root(self.root, run_id)
        lock = self.root / 'docs/r3-release-lock.json'
        lock.parent.mkdir()
        lock.write_text('lock')
        record = {'artifacts': {'inputs': {'receipt.json': {'sha256': digest, 'bytes': 8}},
                                'event': {}, 'control': {}, 'r3': {}},
                  'release_lock': {'sha256': hashlib.sha256(b'lock').hexdigest()}}
        with patch.object(freeze, 'ROOT', self.root):
            freeze.snapshot(self.root, run_id, record)
        copied = self.root / ('issuer-freeze-' + run_id) / 'snapshot/inputs/receipt.json'
        self.assertEqual(copied.read_bytes(), b'original')
        self.assertEqual(copied.stat().st_mode & 0o222, 0)
        with patch.object(freeze, 'ROOT', self.root), self.assertRaisesRegex(RuntimeError, 'already exists'):
            freeze.snapshot(self.root, run_id, record)

    def test_preexisting_output_symlink_is_rejected(self):
        target = self.root / 'target'
        target.mkdir()
        (self.root / 'issuer-freeze-123-1').symlink_to(target, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            freeze.create_output_root(self.root, '123-1')
        self.assertEqual(list(target.iterdir()), [])

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
        for checkout, timestamp in ((self.source, '2024-01-01T00:00:00+0000'),
                                    (self.control, '2024-01-02T00:00:00+0000')):
            subprocess.run(['git', 'init', '-q', str(checkout)], check=True)
            subprocess.run(['git', '-C', str(checkout), 'config', 'user.email', 'test@example.invalid'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'config', 'user.name', 'Test'], check=True)
            (checkout / 'file.uc').write_text('source\n')
            subprocess.run(['git', '-C', str(checkout), 'add', 'file.uc'], check=True)
            git_env = {**os.environ, 'GIT_AUTHOR_DATE': timestamp, 'GIT_COMMITTER_DATE': timestamp}
            subprocess.run(['git', '-C', str(checkout), 'commit', '-qm', 'source'],
                           check=True, env=git_env)
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
        self.control_row = {**self.row, 'source_commit': self.identity[self.control]['commit'],
                            'git_blob': freeze._git(self.control, 'rev-parse', 'HEAD:file.uc')}
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
                    {'selected': [self.control_row], 'excluded': [], 'pins': {'openwrt': self.identity[self.control]['commit']}}]):
            return freeze._source_recheck(self.source, self.control, self.inputs, self.run)

    def test_clean_git_and_source_bytes_pass(self):
        self.assertNotEqual(self.identity[self.source]['commit'], self.identity[self.control]['commit'])
        self.assertEqual(self.identity[self.source]['tree'], self.identity[self.control]['tree'])
        result = self.check()
        self.assertEqual(result['event']['checkout'], self.identity[self.source])
        self.assertEqual(result['control']['checkout'], self.identity[self.control])

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

    def test_explicit_excluded_git_symlink_hashes_link_text(self):
        for checkout in (self.source, self.control):
            (checkout / 'bootstrap-dark').symlink_to('../theme')
            subprocess.run(['git', '-C', str(checkout), 'add', 'bootstrap-dark'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'commit', '-qm', 'tracked link'], check=True)
        identities = {checkout: {'commit': freeze._git(checkout, 'rev-parse', 'HEAD'),
                                 'tree': freeze._git(checkout, 'rev-parse', 'HEAD^{tree}')}
                      for checkout in (self.source, self.control)}
        receipt = {'repository': 'openwrt', 'source': identities[self.source],
                   'control': identities[self.control], 'base': identities[self.source]}
        (self.inputs / 'replayed-receipt.json').write_text(json.dumps(receipt))
        for role, checkout in (('event-corpus', self.source), ('control-corpus', self.control)):
            dest = self.run / role / 'sources/openwrt'
            shutil.rmtree(dest)
            subprocess.run(['git', 'clone', '-q', str(checkout), str(dest)], check=True)
        excluded = {'repo': 'openwrt', 'source_path': 'bootstrap-dark',
                    'reason': 'tracked symlink; target not followed',
                    'sha256': hashlib.sha256(b'../theme').hexdigest()}
        oracles = [{'selected': [], 'excluded': [excluded], 'pins': {'openwrt': identities[checkout]['commit']}}
                   for checkout in (self.source, self.control)]
        with patch.object(freeze, 'canonical_repository'), patch.object(
                freeze, 'validate_event_manifest', side_effect=oracles):
            self.assertEqual(freeze._source_recheck(self.source, self.control, self.inputs, self.run)['event']['stage_files'], [])
        excluded['reason'] = 'ordinary exclusion'
        with patch.object(freeze, 'canonical_repository'), patch.object(
                freeze, 'validate_event_manifest', side_effect=oracles), self.assertRaisesRegex(RuntimeError, 'alias'):
            freeze._source_recheck(self.source, self.control, self.inputs, self.run)


class FreezeEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.temp = Path(self.tmp.name)
        self.run_id = '123-1'
        self.sha = 'a' * 40
        freeze.create_output_root(self.temp, self.run_id)
        self.inputs = self.temp / 'event-input-123-1'
        self.inputs.mkdir()
        for name in ('event-source-123-1', 'event-control-123-1'):
            (self.temp / name / '.git').mkdir(parents=True)
        for name in freeze.INPUT_FILES:
            path = self.inputs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}')
        (self.inputs / 'consumer-graph.json').write_text(json.dumps({
            'schema': 'incoming-consumer-graph-workflow-v1', 'status': 'checked',
            'run_id': self.run_id, 'consumer_sha': self.sha}))
        self.run = self.temp / 'r3-event-123-1'
        for name in ('home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db',
                     'out', 'commands', 'cli', 'bundle'):
            (self.run / name).mkdir(parents=True, exist_ok=True)
        for name in ('preflight.json', 'receipt.json'):
            (self.run / name).write_text('{}')
        for case in ('openvpn-parent', 'openvpn-fixed'):
            output = self.run / 'out' / case
            output.mkdir()
            for name in freeze.R3_OUT:
                (output / name).write_text('{}')
        self._commands(self.run)
        for role in ('event', 'control'):
            scan = self.run / (role + '-corpus')
            for name in ('home', 'tmp', 'cache', 'downloads', 'sources', 'stage',
                         'db', 'out', 'commands', 'bundle'):
                (scan / name).mkdir(parents=True, exist_ok=True)
            for name in ('preflight.json', 'receipt.json'):
                (scan / name).write_text('{}')
            if role == 'control':
                (scan / 'control-assertion.json').write_text('{}')
            for name in freeze.SCAN_OUT:
                (scan / 'out' / name).write_text('{}')
            (scan / 'stage/file.uc').write_text('source')
            self._commands(scan)
        lock = self.temp / 'docs/r3-release-lock.json'
        lock.parent.mkdir()
        lock.write_text('lock')
        (self.run / 'preflight.json').write_text(json.dumps({
            'lock_sha256': hashlib.sha256(b'lock').hexdigest(), 'consumer_sha': self.sha}))

    def _commands(self, root):
        (root / 'commands.json').write_text(json.dumps([{'label': 'one', 'stdout': 'commands/one.stdout',
            'stderr': 'commands/one.stderr', 'time': 'commands/one.time'}]))
        for suffix in ('stdout', 'stderr', 'time'):
            (root / 'commands' / ('one.' + suffix)).write_text('receipt')

    def check(self, *, graph_failure=False):
        identities = {role: {'stage_files': ['file.uc']} for role in ('event', 'control')}
        def graph_recheck(temp, run_id, event, control, path):
            if graph_failure:
                raise RuntimeError('graph replay rejected')
            path.write_text(json.dumps({'status': 'checked', 'run_id': run_id,
                                        'consumer_sha': self.sha}))
        with patch.object(freeze, 'ROOT', self.temp), patch.object(
                freeze, '_source_recheck', return_value=identities), patch.object(
                freeze.issuer_workflow_graph, 'run', side_effect=graph_recheck), patch.object(
                freeze, '_git', side_effect=lambda root, *args: self.sha if args[-1] == 'HEAD' else ''), patch.dict(
                os.environ, {'GITHUB_SHA': self.sha}):
            return freeze.freeze(self.temp, self.run_id)

    def test_freezes_exact_attempt_artifacts(self):
        result = self.check()
        self.assertEqual(result['status'], 'frozen')
        self.assertEqual(result['artifacts']['event']['stage']['file.uc']['sha256'],
                         hashlib.sha256(b'source').hexdigest())

    def test_rejects_input_fifo_before_json_read(self):
        graph = self.inputs / 'consumer-graph.json'
        graph.unlink()
        os.mkfifo(graph)
        with self.assertRaisesRegex(RuntimeError, 'not regular'):
            self.check()

    def test_rejects_unlisted_staged_file(self):
        (self.run / 'event-corpus/stage/extra.uc').write_text('surprise')
        with self.assertRaisesRegex(RuntimeError, 'unexpected artifacts'):
            self.check()

    def test_rejects_hardlinked_staged_file(self):
        stage = self.run / 'event-corpus/stage/file.uc'
        os.link(stage, self.temp / 'alias.uc')
        with self.assertRaisesRegex(RuntimeError, 'alias'):
            self.check()

    def test_rejects_wrong_graph_run_identity(self):
        graph = self.inputs / 'consumer-graph.json'
        value = json.loads(graph.read_text())
        value['run_id'] = 'other-1'
        graph.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'graph drift'):
            self.check()

    def test_rejects_input_symlink_before_json_read(self):
        graph = self.inputs / 'consumer-graph.json'
        graph.unlink()
        graph.symlink_to(self.temp / 'missing.json')
        with self.assertRaisesRegex(RuntimeError, 'not regular'):
            self.check()

    def test_graph_recheck_failure_propagates(self):
        with self.assertRaisesRegex(RuntimeError, 'graph replay rejected'):
            self.check(graph_failure=True)

    def test_precheck_rejects_preexisting_graph_report(self):
        with patch.object(freeze, 'ROOT', self.temp), self.assertRaisesRegex(RuntimeError, 'unexpected artifacts'):
            freeze.precheck(self.temp, self.run_id, graph_ready=False)

    def test_precheck_rejects_checkout_root_alias(self):
        checkout = self.temp / 'event-source-123-1'
        shutil.rmtree(checkout)
        checkout.symlink_to(self.temp / 'event-control-123-1', target_is_directory=True)
        with patch.object(freeze, 'ROOT', self.temp), self.assertRaisesRegex(RuntimeError, 'unsafe event/control'):
            freeze.precheck(self.temp, self.run_id, graph_ready=False)

    def test_precheck_rejects_staged_hardlink_before_graph(self):
        os.link(self.run / 'event-corpus/stage/file.uc', self.temp / 'linked.uc')
        (self.inputs / 'consumer-graph.json').unlink()
        with patch.object(freeze, 'ROOT', self.temp), self.assertRaisesRegex(RuntimeError, 'alias'):
            freeze.precheck(self.temp, self.run_id, graph_ready=False)

    def test_real_graph_report_wiring_is_frozen(self):
        graph = freeze.issuer_workflow_graph
        identities = {role: {'stage_files': ['file.uc']} for role in ('event', 'control')}
        (self.temp / 'docs/r3-release-lock.json').write_text('{}')
        (self.run / 'preflight.json').write_text(json.dumps({
            'lock_sha256': hashlib.sha256(b'{}').hexdigest(), 'consumer_sha': self.sha}))
        with patch.object(freeze, 'ROOT', self.temp), patch.object(graph, 'ROOT', self.temp), patch.object(
                freeze, '_source_recheck', return_value=identities), patch.object(
                freeze, '_git', side_effect=lambda root, *args: self.sha if args[-1] == 'HEAD' else ''), patch.object(
                graph, 'pinned'), patch.object(graph, 'validate_event_manifest', return_value={}), patch.object(
                graph, 'check_event_and_control', return_value=({'status': 'triage_required'}, {'status': 'clean_scan'})), patch.object(
                graph.subprocess, 'check_output', return_value=self.sha), patch.dict(
                os.environ, {'GITHUB_SHA': self.sha}):
            result = freeze.freeze(self.temp, self.run_id)
        self.assertEqual(result['status'], 'frozen')
        report = self.temp / 'issuer-freeze-123-1/graph-recheck.json'
        self.assertEqual(json.loads(report.read_text())['run_id'], self.run_id)
        self.assertEqual(result['graph_recheck']['sha256'], hashlib.sha256(report.read_bytes()).hexdigest())
