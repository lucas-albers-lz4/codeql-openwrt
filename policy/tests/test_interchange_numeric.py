"""Raw numeric tokens at the interchange schema boundary."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from policy import interchange_contract as contract

SNAPSHOT = Path(__file__).parent / 'fixtures/ucode-snapshot'


class InterchangeNumericTests(unittest.TestCase):
    def test_integral_decimal_source_coordinate_in_apis_and_clis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(SNAPSHOT, root)
            target = root / 'docs/m3-findings.json'
            rows = json.loads(target.read_text(encoding='utf-8'))
            row = next(r for r in rows if r['record_id'] == 'm3:synthetic-taint-pos')
            row['source_location'] = dict(path='synthetic', start_line=1, start_column=1, end_line=1, end_column=1)
            text = json.dumps(rows)
            marker = '"start_line": 1'
            self.assertEqual(text.count(marker), 1)
            target.write_text(text.replace(marker, '"start_line": 1.0'), encoding='utf-8')
            for snapshot, validate in ((False, contract.validate_ucode_root), (True, contract.validate_ucode_snapshot)):
                with self.subTest(snapshot=snapshot, entry='api'):
                    self.assertEqual(validate(root), (5, 19))
                with self.subTest(snapshot=snapshot, entry='cli'):
                    cmd = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
                    cmd += ['-m', 'policy.interchange_contract', '--ucode-root', str(root)]
                    if snapshot:
                        cmd.append('--snapshot')
                    result = subprocess.run(cmd, cwd=contract.REPO_ROOT, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('validated 19 typed ucode records in 5 arrays', result.stdout)

    def test_raw_numeric_matrix_through_both_apis_and_clis(self):
        cases = (
            ('1', None), ('1e0', None), ('100e-2', None), ('1.000', None),
            ('9007199254740993.0', None), ('1e999999', None),
            ('1.5', 'expected integer'), ('1.00000000000000000001', 'expected integer'),
            ('0.99999999999999999999', 'expected integer'), ('1e-999999', 'expected integer'),
            ('true', 'expected integer'), ('false', 'expected integer'),
            ('0', 'below minimum'), ('0.0', 'below minimum'), ('-1e0', 'below minimum'),
            ('1e9999999999999999999999999999', 'cannot read JSON'),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(SNAPSHOT, root)
            target = root / 'docs/m3-findings.json'
            rows = json.loads(target.read_text(encoding='utf-8'))
            row = next(r for r in rows if r['record_id'] == 'm3:synthetic-taint-pos')
            row['source_location'] = dict(path='synthetic', start_line=1, start_column=1, end_line=1, end_column=1)
            text = json.dumps(rows)
            marker = '"start_line": 1'
            self.assertEqual(text.count(marker), 1)
            for token, error in cases:
                target.write_text(text.replace(marker, '"start_line": ' + token), encoding='utf-8')
                for snapshot, validate in ((False, contract.validate_ucode_root), (True, contract.validate_ucode_snapshot)):
                    with self.subTest(token=token, snapshot=snapshot, entry='api'):
                        if error:
                            with self.assertRaisesRegex(contract.ContractError, error):
                                validate(root)
                        else:
                            self.assertEqual(validate(root), (5, 19))
                    with self.subTest(token=token, snapshot=snapshot, entry='cli'):
                        cmd = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
                        cmd += ['-m', 'policy.interchange_contract', '--ucode-root', str(root)]
                        if snapshot:
                            cmd.append('--snapshot')
                        result = subprocess.run(cmd, cwd=contract.REPO_ROOT, capture_output=True, text=True)
                        if error:
                            self.assertEqual(result.returncode, 2, result.stderr)
                            self.assertIn(error, result.stderr)
                            self.assertNotIn('Traceback', result.stderr)
                            self.assertEqual(result.stdout, '')
                        else:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertIn('validated 19 typed ucode records in 5 arrays', result.stdout)

    def test_decimal_number_minimum_and_conditional_validation(self):
        schema = {'type': 'number', 'minimum': Decimal('1.00000000000000000001')}
        contract._check_schema_keywords(schema)
        for value, accepted in ((Decimal('1.00000000000000000001'), True),
                                (Decimal('1.00000000000000000000'), False),
                                (True, False), (float('inf'), False), (float('nan'), False)):
            with self.subTest(value=value):
                self.assertEqual(contract._matches_schema(value, schema), accepted)
                self.assertEqual(not contract._validate(value, schema, 'value'), accepted)
        conditional = {'if': schema, 'then': {'type': 'integer'}}
        self.assertTrue(contract._validate(Decimal('1.00000000000000000001'), conditional, 'value'))
        self.assertFalse(contract._validate(Decimal('1'), conditional, 'value'))

    def test_all_coordinate_fields_use_the_same_numeric_rule(self):
        schema = json.loads((contract.REPO_ROOT / 'schemas/finding.schema.json').read_text())
        row = {'record_type': 'taint_path', 'evidence_status': 'fact', 'producer': 'step3',
               'corpus_revision': 'rev', 'profile': 'profile',
               'source_location': dict(path='synthetic', start_line=1, start_column=1, end_line=1, end_column=1)}
        for field in ('start_line', 'start_column', 'end_line', 'end_column'):
            for value, accepted in ((Decimal('1e0'), True), (Decimal('1.00000000000000000001'), False),
                                    (Decimal('0.0'), False), (True, False)):
                with self.subTest(field=field, value=value):
                    row['source_location'][field] = value
                    self.assertEqual(not contract._validate(row, schema, 'row'), accepted)
            row['source_location'][field] = 1

    def test_report_only_line_keeps_exact_integer_token_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(SNAPSHOT, root)
            path = root / 'docs/m4-getfeatures-direct-exec-coverage.json'
            report = json.loads(path.read_text(encoding='utf-8'))
            line = report['call_sites'][0]['line']
            text = json.dumps(report)
            marker = f'"line": {line}'
            self.assertEqual(text.count(marker), 1)
            path.write_text(text.replace(marker, f'"line": {line}.0'), encoding='utf-8')
            for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
                with self.subTest(api=validate.__name__), self.assertRaisesRegex(contract.ContractError, 'malformed coverage call_sites'):
                    validate(root)


if __name__ == '__main__':
    unittest.main()
