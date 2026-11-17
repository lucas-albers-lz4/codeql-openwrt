"""Raw-text regressions for all historical interchange input boundaries."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from policy import interchange_contract as contract

FIXTURES = Path(__file__).parent / 'fixtures'
SNAPSHOT = FIXTURES / 'ucode-snapshot'
VECTORS = FIXTURES / 'interchange-raw-v1.json'


def protected_json():
    return {p: p.read_bytes() for folder in ('reports', 'policy', 'corpus')
            for p in (contract.REPO_ROOT / folder).rglob('*.json')}


class RawInterchangeTests(unittest.TestCase):
    def assert_invalid_on_second_read(self, validate, filename, anchor, key):
        # This controls two reads, not an atomic filesystem snapshot guarantee.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(SNAPSHOT, root)
            target = root / 'docs' / filename
            original = target.read_text(encoding='utf-8')
            self.assertEqual(original.count(anchor), 1)
            invalid = original.replace(anchor, anchor + '\n    ' + anchor, 1)
            # A permissive JSON decoder would silently keep the same value.
            self.assertEqual(json.loads(invalid), json.loads(original))
            real_read_text = Path.read_text
            reads = []

            def change_after_first_read(path, *args, **kwargs):
                text = real_read_text(path, *args, **kwargs)
                if path == target:
                    reads.append(text)
                    if len(reads) == 1:
                        target.write_text(invalid, encoding='utf-8')
                return text

            with patch.object(Path, 'read_text', change_after_first_read):
                with self.assertRaisesRegex(contract.ContractError, f'duplicate JSON key {key!r}') as caught:
                    validate(root)
            self.assertIn(str(target), str(caught.exception))
            self.assertEqual(reads, [original, invalid])

    def test_coverage_reread_rejects_new_duplicate_key(self):
        for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
            with self.subTest(api=validate.__name__):
                self.assert_invalid_on_second_read(
                    validate, 'm4-coverage.json', '"profile": "luci-ssl-25.12",', 'profile')

    def test_snapshot_typed_reread_rejects_new_duplicate_key(self):
        self.assert_invalid_on_second_read(
            contract.validate_ucode_snapshot, 'm4-imported-callee-findings.json',
            '"producer": "step3",', 'producer')

    def test_raw_vectors_rejected_by_each_api_and_cli(self):
        before = protected_json()
        raw = VECTORS.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '37d41d361d417f519b1523a25ddbb9a2ffd4d90b7fce2140d17c03c14eac68da')
        vectors = json.loads(raw)
        self.assertEqual(vectors['contract'], 'interchange-raw-v1')
        self.assertEqual(len(vectors['cases']), 14)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(SNAPSHOT, root)
            for item in vectors['cases']:
                path = root / 'docs' / item['file']
                original = path.read_text(encoding='utf-8')
                self.assertEqual(original.count(item['anchor']), 1, item['name'])
                path.write_text(original.replace(item['anchor'], item['replacement'], 1), encoding='utf-8')
                for snapshot, validate in ((False, contract.validate_ucode_root), (True, contract.validate_ucode_snapshot)):
                    with self.subTest(case=item['name'], mode='snapshot' if snapshot else 'partial', entry='api'):
                        with self.assertRaisesRegex(contract.ContractError, item['error']):
                            validate(root)
                    with self.subTest(case=item['name'], mode='snapshot' if snapshot else 'partial', entry='cli'):
                        args = [sys.executable, '-B']
                        if sys.flags.optimize:
                            args.append('-O')
                        args += ['-m', 'policy.interchange_contract', '--ucode-root', str(root)]
                        if snapshot:
                            args.append('--snapshot')
                        result = subprocess.run(args, cwd=contract.REPO_ROOT, capture_output=True, text=True)
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertEqual(result.stdout, '')
                        self.assertIn(item['error'], result.stderr)
                        self.assertNotIn('Traceback', result.stderr)
                path.write_text(original, encoding='utf-8')
        self.assertEqual(before, protected_json())

    def test_historical_positive_controls_and_no_output_changes(self):
        before = protected_json()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(SNAPSHOT, root)
            typed = root / 'docs/m4-imported-callee-findings.json'
            rows = json.loads(typed.read_text(encoding='utf-8'))
            rows[0]['extra'] = {'nested': [None, True, 42, 1.5, 'NaN']}
            rows[0]['unknowns'].append('additional conservative unknown')
            typed.write_text(json.dumps(rows, sort_keys=True), encoding='utf-8')
            coverage = root / 'docs/m4-coverage.json'
            report = json.loads(coverage.read_text(encoding='utf-8'))
            report['negative_controls'].reverse()
            report['unknowns'].append('additional conservative unknown')
            coverage.write_text(json.dumps(report, sort_keys=True), encoding='utf-8')
            for snapshot, validate in ((False, contract.validate_ucode_root), (True, contract.validate_ucode_snapshot)):
                with self.subTest(snapshot=snapshot):
                    self.assertEqual(validate(root), (5, 19))
                    cmd = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
                    cmd += ['-m', 'policy.interchange_contract', '--ucode-root', str(root)]
                    if snapshot:
                        cmd.append('--snapshot')
                    result = subprocess.run(cmd, cwd=contract.REPO_ROOT, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('validated 19 typed ucode records in 5 arrays', result.stdout)
            (root / 'docs/m3-coverage.json').unlink()
            self.assertEqual(contract.validate_ucode_root(root), (5, 19))
            with self.assertRaisesRegex(contract.ContractError, 'missing'):
                contract.validate_ucode_snapshot(root)
        self.assertEqual(before, protected_json())


if __name__ == '__main__':
    unittest.main()
