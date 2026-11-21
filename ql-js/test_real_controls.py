"""Offline controls for the default-minified extraction check."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('real_controls', HERE / 'real_controls.py')
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


class DefaultMinifiedOmissionTest(unittest.TestCase):
    def setUp(self):
        rows = json.loads((HERE / 'manifest.json').read_text(encoding='utf-8'))
        self.expected = [row['source'] for row in rows]
        self.minified = 'libs/luci-lib-uqr/htdocs/luci-static/resources/uqr.js'
        self.actual = [path for path in self.expected if path != self.minified]

    def test_exact_manifest_remainder_is_accepted(self):
        controls.check_default_minified_omission(self.expected, self.actual, self.minified)

    def test_missing_other_file_plus_substitution_is_rejected(self):
        other = next(path for path in self.expected if path != self.minified)
        mutated = [path for path in self.actual if path != other]
        mutated.append('extern/replacement.js')
        with self.assertRaisesRegex(ValueError, 'paths differ'):
            controls.check_default_minified_omission(self.expected, mutated, self.minified)

    def test_entry_point_rejects_missing_file_plus_substitution(self):
        other = next(path for path in self.expected if path != self.minified)
        actual = [path for path in self.actual if path != other]
        actual.append('extern/replacement.js')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate_output = root / 'gate'
            source = gate_output / 'source'
            source.mkdir(parents=True)
            (source / self.expected[0]).parent.mkdir(parents=True, exist_ok=True)
            (source / self.expected[0]).write_text('// fixture\n', encoding='utf-8')
            source = source.resolve()
            expected_paths = [str(source / path) for path in self.expected]
            actual_paths = [str(source / path) for path in actual[:-1]] + [str(root / actual[-1])]
            minified_path = str(source / self.minified)
            packs = root / 'packs'
            packs.mkdir()
            output = root / 'controls'
            files = {'#select': {'columns': [{'kind': 'String'}],
                                 'tuples': [[path] for path in actual_paths]}}
            errors = {'#select': {'columns': [{'kind': 'String'}] * 3, 'tuples': []}}
            argv = ['real_controls.py', '--codeql', sys.executable, '--packs', str(packs),
                    '--gate-output', str(gate_output), '--output', str(output)]
            with patch.object(sys, 'argv', argv), \
                 patch.object(controls.gate, 'check_staged'), \
                 patch.object(controls.gate, 'codeql_results', return_value=(files, errors)) as run:
                with patch.object(controls, 'check_default_minified_omission',
                                  wraps=controls.check_default_minified_omission) as check:
                    with self.assertRaisesRegex(RuntimeError, 'expected minified omission'):
                        controls.main()
                check.assert_called_once_with(expected_paths, actual_paths, minified_path)
            run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
