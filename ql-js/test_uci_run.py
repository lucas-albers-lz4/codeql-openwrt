import tempfile
import json
from collections import Counter
import unittest
from pathlib import Path
from unittest.mock import patch

import uci_run


class RunnerTests(unittest.TestCase):
    def test_command_vectors_are_bounded_and_use_ids(self):
        vectors = uci_run.commands(Path('/wrapper'), Path('/packs'), Path('/run/source'), Path('/run'))
        self.assertEqual(len(vectors), 11)
        for cmd in (vectors[0], vectors[1], vectors[3], vectors[5], vectors[7], vectors[9]):
            self.assertIn('--threads=1', cmd)
            self.assertIn('--ram=2048', cmd)
        self.assertIn('--entities=id', vectors[-1])
        self.assertIn('--entities=url,string', vectors[2])
        self.assertTrue(all(cmd[0] == '/wrapper' for cmd in vectors))

    def test_validation_rechecks_source_and_requires_exact_multiset(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            for name in ('files', 'errors', 'uci_surface'):
                (out / (name + '.json')).write_bytes(b'{}')
            rows = [{'source': 'a.js'}]
            with patch.object(uci_run.gate, 'check_staged') as staged, \
                 patch.object(uci_run.gate, 'check_results') as checks, \
                 patch.object(uci_run.uci_source_conversion, 'convert', return_value=Counter({('expected',): 1})), \
                 patch.object(uci_run.uci_inventory, 'project_details', return_value=(Counter({('other',): 1}), {('other',): [-1]})):
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    uci_run.validate(out, rows, b'oracle', Counter({('expected',): 1}))
                self.assertEqual(staged.call_count, 1)
                self.assertEqual(checks.call_count, 0)
                self.assertIn(b'-1', (out / 'mismatch.json').read_bytes())
                self.assertFalse((out / 'ACCEPTED.json').exists())

    def test_decoded_symlink_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'target').write_bytes(b'{}')
            (out / 'accept-files.json').symlink_to(out / 'target')
            with patch.object(uci_run.gate, 'check_staged'):
                with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                    uci_run.check_gate(out, [], 'accept')

    def test_candidate_fields_and_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'uci_surface.json').write_bytes(b'{}')
            key = ('a.js', 1, 2, 1, 5, 'bare', 'dot', True, 'get')
            with patch.object(uci_run.gate, 'check_staged'), \
                 patch.object(uci_run.uci_inventory, 'project_details',
                              return_value=(Counter({key: 2}), {key: [-2, 5]})):
                uci_run.validate(out, [], b'oracle', Counter({key: 2}))
            row = json.loads((out / 'candidates.json').read_bytes())[0]
            self.assertEqual((row['family'], row['assessment'], row['property'], row['ids']),
                             ('rpc_surface', 'candidate', 'get', [-2, 5]))

    def test_invalid_output_leaf_rejected_before_writes_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            wrapper, oracle, pins = root / 'wrapper', root / 'oracle', root / 'pins'
            wrapper.write_bytes(b'wrapper'); oracle.write_bytes(b'oracle')
            packs, git = root / 'packs', root / 'git'
            packs.mkdir(); git.mkdir()
            pin_data = json.dumps({'inputs': {}, 'packs': {}, 'resolutions':
                                   {'files': 'x', 'errors': 'x', 'uci_surface': 'x'}}).encode()
            pins.write_bytes(pin_data)
            output = root / 'wrong'
            args = ['--wrapper', str(wrapper), '--wrapper-log', str(root / 'wrapper.log'),
                    '--packs', str(packs), '--luci-git', str(git), '--oracle', str(oracle),
                    '--pins', str(pins), '--pins-sha256', uci_run.digest(pin_data), '--output', str(output)]
            before = sorted(p.name for p in root.iterdir())
            with patch.object(uci_run.gate, 'build_manifest') as build, \
                 patch.object(uci_run.subprocess, 'run') as child:
                with self.assertRaisesRegex(ValueError, 'attempt output directory'):
                    uci_run.main(args)
                build.assert_not_called()
                child.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual(before, sorted(p.name for p in root.iterdir()))

    def test_commands_propagate_wrapper_failure_before_receipt(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            wrapper, oracle = root / 'wrapper', root / 'oracle'
            wrapper.write_bytes(b'wrapper')
            oracle.write_bytes(b'oracle')
            packs, git = root / 'packs', root / 'git'
            packs.mkdir()
            git.mkdir()
            output = root / 'output'
            rows = [{'source': f'{i}.js', 'blob': 'blob'} for i in range(88)]
            (packs / 'pack').write_bytes(b'pack')
            (root / 'wrapper.log').write_bytes(b'')
            (root / 'wrapper.log').chmod(0o600)
            pin_data = json.dumps({'inputs': {}, 'packs': {'pack': uci_run.digest(b'pack')},
                                   'resolutions': {'files': 'x', 'errors': 'x', 'uci_surface': 'x'}}).encode()
            pins = root / 'pins'
            pins.write_bytes(pin_data)
            args = ['--wrapper-log', str(root / 'wrapper.log'), '--pins', str(pins), '--pins-sha256', uci_run.digest(pin_data), '--wrapper', str(wrapper), '--oracle', str(oracle), '--packs', str(packs),
                    '--luci-git', str(git), '--output', str(output)]
            with patch.object(uci_run.gate, 'build_manifest', return_value=rows), \
                 patch.object(uci_run.gate, 'check_manifest'), \
                 patch.object(uci_run.gate, 'check_staged'), \
                 patch.object(uci_run.gate, 'run', return_value=b'source'), \
                 patch.object(uci_run.uci_source_conversion, 'convert', return_value=Counter()), \
                 patch.object(uci_run, 'inputs', return_value={}), \
                 patch.object(uci_run.uci_source_conversion, 'MULTISET_SHA256', uci_run.digest(b'oracle')), \
                 patch.object(uci_run.subprocess, 'run', return_value=subprocess.CompletedProcess(['wrapper'], 1, b'failed stdout', b'failed stderr')):
                with self.assertRaises(subprocess.CalledProcessError):
                    uci_run.main(args)
            self.assertTrue((output / 'commands.log').exists())
            self.assertFalse((output / 'ACCEPTED.json').exists())
            self.assertIn('failed stderr', (output / 'commands.log').read_text())

    def test_mocked_complete_and_each_gate_failure(self):
        import subprocess
        for failure in (None, 'accept', 'check'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                wrapper, oracle, log = root / 'wrapper', root / 'oracle', root / 'wrapper.log'
                wrapper.write_bytes(b'wrapper'); oracle.write_bytes(b'oracle'); log.write_bytes(b''); log.chmod(0o600)
                packs, git = root / 'packs', root / 'git'
                packs.mkdir(); git.mkdir(); (packs / 'pack').write_bytes(b'pack')
                out = root / 'output'
                rows = [{'source': f'{i}.js', 'blob': 'blob', 'sha256': uci_run.digest(b'source')} for i in range(88)]
                resolution = b'expected resolver stdout'
                pins_data = json.dumps({'inputs': {}, 'packs': {'pack': uci_run.digest(b'pack')},
                    'resolutions': {n: uci_run.digest(resolution) for n in ('files', 'errors', 'uci_surface')}}).encode()
                pins = root / 'pins'; pins.write_bytes(pins_data)
                args = ['--wrapper', str(wrapper), '--wrapper-log', str(log), '--packs', str(packs),
                        '--luci-git', str(git), '--oracle', str(oracle), '--pins', str(pins),
                        '--pins-sha256', uci_run.digest(pins_data), '--output', str(out)]
                called = []
                def run(cmd, **kwargs):
                    called.append(cmd)
                    self.assertEqual(kwargs['env']['CODEQL_ISOLATION_ATTEMPT'], str(root))
                    with log.open('ab') as stream: stream.write(b'wrapper trace\n')
                    if cmd[1] == 'version':
                        return subprocess.CompletedProcess(cmd, 0, b'toolchain release 2.27.4. test', b'JAVA_TOOL_OPTIONS=/tmp/attempt')
                    if cmd[1] == 'resolve':
                        return subprocess.CompletedProcess(cmd, 0, resolution, b'JAVA_TOOL_OPTIONS=/tmp/attempt')
                    if cmd[1:3] == ['database', 'create']:
                        return subprocess.CompletedProcess(cmd, 0)
                    if cmd[1:3] == ['query', 'run']:
                        Path(cmd[cmd.index('--output') + 1]).write_bytes(b'bqrs')
                    else:
                        path = Path(cmd[cmd.index('--output') + 1]); label = path.stem
                        if label.endswith('files'):
                            values = [[str(out / 'source' / row['source'])] for row in rows]
                            if failure and label == failure + '-files': values = values[:-1]
                            cols = [{'kind': 'String'}]
                        elif label.endswith('errors'):
                            values, cols = [], [{'kind': 'String'}] * 3
                        else:
                            values, cols = [], [{'kind': 'Entity'}] + [{'kind': 'String'}] * 10
                        path.write_text(json.dumps({'#select': {'columns': cols, 'tuples': values}}))
                    return subprocess.CompletedProcess(cmd, 0)
                with patch.object(uci_run.gate, 'build_manifest', return_value=rows), \
                     patch.object(uci_run.gate, 'check_manifest'), \
                     patch.object(uci_run.gate, 'run', return_value=b'source'), \
                     patch.object(uci_run, 'inputs', return_value={}), \
                     patch.object(uci_run.uci_source_conversion, 'MULTISET_SHA256', uci_run.digest(b'oracle')), \
                     patch.object(uci_run.uci_source_conversion, 'convert', return_value=Counter()), \
                     patch.object(uci_run.subprocess, 'run', side_effect=run):
                    if failure:
                        with self.assertRaisesRegex(ValueError, 'extracted file mismatch'): uci_run.main(args)
                        self.assertFalse((out / 'ACCEPTED.json').exists())
                        self.assertFalse(any('uci_surface.ql' in ' '.join(c) and c[1:3] == ['query', 'run'] for c in called))
                    else:
                        self.assertEqual(uci_run.main(args), 0)
                        receipt = json.loads((out / 'ACCEPTED.json').read_bytes())
                        self.assertIn('wrapper.log', receipt['output_sha256'])
                        self.assertEqual(json.loads((out / 'candidates.json').read_bytes()), [])
                    self.assertIn('JAVA_TOOL_OPTIONS=/tmp/attempt', (out / 'commands.log').read_text())


if __name__ == '__main__':
    unittest.main()
