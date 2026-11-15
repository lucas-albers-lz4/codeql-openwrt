"""Offline controls; historical decode is not a fresh producer handoff."""
import copy
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from policy import backend_declarations as c

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / 'policy/tests/fixtures'
HIST = FIX / 'backend-declarations-historical'
TABLE = (HIST / 'table.csv').read_bytes()
SOURCE = ROOT / 'policy/fixtures/getblock-source/usr/share/rpcd/ucode/luci'
GRANTS = json.loads((ROOT / 'policy/grants.json').read_bytes())
ORACLE = json.loads((FIX / 'luci-backend-source-v1.json').read_bytes())
EXPECTED_GRANTS = json.loads((FIX / 'luci-backend-grants-v1.json').read_bytes())
REPORT = ROOT / 'reports/luci-backend-declaration-comparison.json'


def csv_bytes(rows):
    f = io.StringIO(newline='')
    csv.writer(f, lineterminator='\n').writerows(rows)
    return f.getvalue().encode()


def rows():
    return list(csv.reader(io.StringIO(TABLE.decode(), newline='')))


def invalid_comparison_inputs(source_root, kind):
    """Single-fault inputs: all unspecified bytes and context stay valid."""
    good_success = csv_bytes([['f','col1'], [str(source_root/ORACLE['source_path']), '']])
    good_errors = csv_bytes([['error','col1','col2']])
    if kind == 'table':
        table = rows()
        substitution = copy.deepcopy(table); substitution[-1][2] = 'differentMethod'
        swapped = copy.deepcopy(table); swapped[1][4:], swapped[2][4:] = swapped[2][4:], swapped[1][4:]
        cases = [
            ('empty', b'', 'CSV header or row width mismatch'),
            ('header-only', csv_bytes(table[:1]), 'empty table is unknown'),
            ('omission', csv_bytes(table[:-1]), 'source identity/span multiset mismatch'),
            ('same-count-substitution', csv_bytes(substitution), 'source identity/span multiset mismatch'),
            ('duplicate', csv_bytes(table + [table[-1]]), 'source identity/span multiset mismatch'),
            ('span-swap', csv_bytes(swapped), 'source identity/span multiset mismatch'),
        ]
        return [(name, data, good_success, good_errors, error) for name,data,error in cases]
    success_row = [str(source_root/ORACLE['source_path']), '']
    return [
        ('wrong-success-path', TABLE, csv_bytes([['f','col1'], ['/wrong/source','']]), good_errors, 'successful extraction diagnostic mismatch'),
        ('misplaced-success-path', TABLE, csv_bytes([['f','col1'], ['',success_row[0]]]), good_errors, 'successful extraction diagnostic mismatch'),
        ('duplicate-success-path', TABLE, csv_bytes([['f','col1'], success_row, success_row]), good_errors, 'successful extraction diagnostic mismatch'),
        ('malformed-success', TABLE, b'f,col1\n"unterminated', good_errors, 'invalid UTF-8 CSV'),
        ('nonempty-errors', TABLE, good_success, csv_bytes([['error','col1','col2'], ['actual extraction failed','x','x']]), 'extraction errors reported'),
        ('malformed-errors', TABLE, good_success, b'error,col1,col2\n"unterminated', 'invalid UTF-8 CSV'),
    ]


def policy_artifacts():
    """Bytes and path set for actual policy, corpus and retained reports."""
    return {p.relative_to(ROOT): p.read_bytes()
            for directory in ('policy', 'corpus', 'reports')
            for p in (ROOT/directory).rglob('*')
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


class BackendComparisonTests(unittest.TestCase):
    def assert_json_exact(self, actual, expected):
        """Compare JSON recursively without Python's bool/int/float coercion."""
        self.assertIs(type(actual), type(expected))
        if isinstance(expected, dict):
            self.assertEqual(set(actual), set(expected))
            for key in expected:
                self.assert_json_exact(actual[key], expected[key])
        elif isinstance(expected, list):
            self.assertEqual(len(actual), len(expected))
            for item, wanted in zip(actual, expected):
                self.assert_json_exact(item, wanted)
        else:
            self.assertEqual(actual, expected)

    def test_historical_raw_artifacts_keep_original_digests(self):
        import hashlib
        lines = (HIST/'sha256.txt').read_text().splitlines()
        relative = [(digest,name) for digest,name in (line.split('  ',1) for line in lines) if not name.startswith('/')]
        self.assertEqual(len(relative),7)
        for digest,name in relative:
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((HIST/name).read_bytes()).hexdigest(), digest)
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), ORACLE['source_sha256'])

    def test_missing_table_is_not_an_empty_backend(self):
        with self.assertRaises(c.ValidationError):
            c.parse_table(b'')

    def test_historical_table_exact_source_multiset(self):
        found = c.validate_observations(c.parse_table(TABLE), ORACLE)
        self.assertEqual(len(found), 21)
        for mutation in ('remove', 'duplicate', 'substitute', 'span', 'coherent_omission'):
            with self.subTest(mutation=mutation):
                r = rows()
                if mutation in ('remove', 'coherent_omission'):
                    r.pop()
                elif mutation == 'duplicate':
                    r.append(r[-1])
                elif mutation == 'substitute':
                    r[-1][2] = 'differentMethod'
                else:
                    r[-1][4] = str(int(r[-1][4]) + 1)
                with self.assertRaises(c.ValidationError):
                    c.validate_observations(c.parse_table(csv_bytes(r)), ORACLE)

    def test_order_independence_and_all_coordinate_endpoints(self):
        original = c.validate_observations(c.parse_table(TABLE), ORACLE)
        r = rows()
        reversed_table = csv_bytes([r[0]]+list(reversed(r[1:])))
        self.assertEqual(original, c.validate_observations(c.parse_table(reversed_table), ORACLE))
        self.assertEqual(c.validate_grants(GRANTS, EXPECTED_GRANTS), c.validate_grants(list(reversed(GRANTS)), EXPECTED_GRANTS))
        for column in range(4,8):
            changed = rows(); changed[1][column] = str(int(changed[1][column])+1)
            with self.subTest(column=column), self.assertRaises(c.ValidationError):
                c.validate_observations(c.parse_table(csv_bytes(changed)), ORACLE)
        changed = rows(); changed[1][4:], changed[2][4:] = changed[2][4:], changed[1][4:]
        with self.assertRaises(c.ValidationError): c.validate_observations(c.parse_table(csv_bytes(changed)), ORACLE)

    def test_strict_table_syntax(self):
        bad = [b'', b'\xef\xbb\xbf'+TABLE, TABLE+b'\n', TABLE+b'"unterminated', TABLE.replace(b'"getVersion"', b'"getVersion"x', 1)]
        r = rows(); r[1][4] = '051'; bad.append(csv_bytes(r))
        r = rows(); r[1].pop(); bad.append(csv_bytes(r))
        r = rows(); r[0][0], r[0][1] = r[0][1], r[0][0]; bad.append(csv_bytes(r))
        for blob in bad:
            with self.subTest(blob=blob[:60]), self.assertRaises(c.ValidationError):
                c.parse_table(blob)

    def test_diagnostics_are_exact_and_strict(self):
        root = '/trusted/source'
        good = csv_bytes([['f', 'col1'], [root+'/'+ORACLE['source_path'], '']])
        errors = csv_bytes([['error', 'col1', 'col2']])
        c.validate_diagnostics(good, errors, root)
        bad = [b'', csv_bytes([['f','col1']]), csv_bytes([['f','col1'],['wrong',root+'/'+ORACLE['source_path']]]), csv_bytes([['f','col1'],[root+'/'+ORACLE['source_path'],'unexpected']]), good+good.splitlines(keepends=True)[1], b'"f"x,col1\n'+good.splitlines(keepends=True)[1], good.rstrip(b'\n')+b'"\n', b'f,col1\n"'+(root+'/'+ORACLE['source_path']).encode()+b'","']
        for blob in bad:
            with self.subTest(blob=blob), self.assertRaises(c.ValidationError):
                c.validate_diagnostics(blob, errors, root)
        with self.assertRaises(c.ValidationError):
            c.validate_diagnostics(good, errors+b'error,x,x\n', root)
        with self.assertRaises(c.ValidationError):
            c.validate_diagnostics(good, errors, '/other')

    def test_grant_identity_and_multiplicity(self):
        result = c.validate_grants(GRANTS, EXPECTED_GRANTS)
        self.assertEqual(len(result), 38)
        unrelated = next(x for x in GRANTS if x.get('ubus_object') != 'luci')
        with self.assertRaises(c.ValidationError):
            c.validate_grants(GRANTS + [copy.deepcopy(unrelated)], EXPECTED_GRANTS)
        for mutation in ('remove','duplicate','id','session','method','object','profile','corpus','expectation','entrypoint','type'):
            with self.subTest(mutation=mutation):
                g = copy.deepcopy(GRANTS)
                idx = next(i for i,x in enumerate(g) if x.get('ubus_object') == 'luci')
                if mutation == 'remove': g.pop(idx)
                elif mutation == 'duplicate': g.append(copy.deepcopy(g[idx]))
                else:
                    field = {'id':'record_id','session':'session_class','object':'ubus_object','corpus':'corpus_revision','expectation':'expectation_id','entrypoint':'entrypoint_id','type':'record_type'}.get(mutation,mutation)
                    g[idx][field] = 'substituted'
                with self.assertRaises(c.ValidationError):
                    c.validate_grants(g, EXPECTED_GRANTS)

    def test_report_actual_retained_reconciles_and_no_claims(self):
        report = c.make_report(c.validate_observations(c.parse_table(TABLE), ORACLE), c.validate_grants(GRANTS, EXPECTED_GRANTS))
        retained = c._json(REPORT.read_bytes())
        self.assert_json_exact(retained, report)
        self.assertEqual(report['summary'], {'declarations':21,'represented_methods':18,'grant_rows':38,'source_only':3,'grant_only':0})
        self.assertEqual(report['source_only'], ['getInitList','getUSBDevices','setInitAction'])
        self.assertEqual(len(next(x for x in report['declarations'] if x['method']=='getMountPoints')['grant_ids']),4)
        for x in report['declarations']:
            self.assertEqual(set(x), {'method','start_line','start_column','end_line','end_column','grant_ids','relation'})

    def test_context_pins_json_and_source_root(self):
        from unittest.mock import patch
        import shutil
        with self.assertRaises(c.ValidationError): c._json(b'{"a":1,"a":2}')
        with self.assertRaises(c.ValidationError): c._json(b'{"a":NaN}')
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            repo, source_root = base/'repo', base/'source'
            for relative in c.PINS:
                dst = repo/relative; dst.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/relative,dst)
            source = source_root/ORACLE['source_path']; source.parent.mkdir(parents=True); shutil.copyfile(SOURCE,source)
            extracted = csv_bytes([['f','col1'],[str(source),'']]); errors = csv_bytes([['error','col1','col2']])
            with patch.object(c,'ROOT',repo):
                c.compare(TABLE,extracted,errors,str(source_root))
                for relative in c.PINS:
                    with self.subTest(pin=relative):
                        path = repo/relative; original = path.read_bytes(); path.write_bytes(original+b' ')
                        with self.assertRaises(c.ValidationError): c.compare(TABLE,extracted,errors,str(source_root))
                        path.write_bytes(original)
                with self.assertRaises(c.ValidationError): c.compare(TABLE,extracted,errors,str(source_root)+'/../source')
                alias = base/'alias'; alias.symlink_to(source_root, target_is_directory=True)
                with self.assertRaises(c.ValidationError): c.compare(TABLE,extracted,errors,str(alias))
                source.write_bytes(b'impostor')
                with self.assertRaises(c.ValidationError): c.compare(TABLE,extracted,errors,str(source_root))

    def test_retained_report_against_independent_identity_map(self):
        report = c._json(REPORT.read_bytes())
        def check(value):
            self.assertEqual(set(value), {'artifact_format','format_version','source','context','scope','declarations','source_only','grant_only','summary'})
            self.assertEqual(value['artifact_format'], 'luci_backend_declaration_grant_comparison_report')
            self.assert_json_exact(value['format_version'], 1)
            self.assertEqual(value['source'], {'repository':ORACLE['source_repository'],'revision':ORACLE['source_revision'],'path':ORACLE['source_path'],'sha256':ORACLE['source_sha256']})
            self.assertEqual(value['context'], {'profile':'luci-ssl-25.12','corpus_revision':'sha256:b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a','producer_revision_reference':'d54c17a8cefc43ef9cde36d65558c986348aa7b2','query_sha256':'58d11ee8bf4f27db2dec4e34292d5155874f035bac8b98121c9ee8d85225a298','consumer_baseline_reference':'fc084f564660c8366022787aaf09e38f8ee32139'})
            self.assertEqual(value['scope'], ['Syntactic source declarations only; no runtime registration, reachability or execution is established.', 'Unmatched means no current materialized grant row, not denial or an ACL defect.', 'Offline validation does not attest fresh extraction or execution.'])
            expected = []
            for observation in ORACLE['observations']:
                ids = sorted(x['record_id'] for x in EXPECTED_GRANTS if x['method']==observation['method'])
                expected.append({k:v for k,v in observation.items() if k != 'key_line'} | {'grant_ids':ids,'relation':'current_grant_rows' if ids else 'no_current_grant_row'})
            self.assert_json_exact(value['declarations'], expected)
            self.assert_json_exact(value['summary'], {'declarations':21,'represented_methods':18,'grant_rows':38,'source_only':3,'grant_only':0})
            self.assertEqual(value['source_only'], ['getInitList','getUSBDevices','setInitAction'])
            self.assertEqual(value['grant_only'], [])
        check(report)
        for mutation in ('omission','duplicate','substitute','swap_grants','span','missing_scope','runtime_claim','summary','context'):
            value = copy.deepcopy(report)
            if mutation == 'omission': value['declarations'].pop()
            elif mutation == 'duplicate': value['declarations'].append(copy.deepcopy(value['declarations'][0]))
            elif mutation == 'substitute': value['declarations'][0]['method'] = 'other'
            elif mutation == 'swap_grants': value['declarations'][0]['grant_ids'], value['declarations'][3]['grant_ids'] = value['declarations'][3]['grant_ids'], value['declarations'][0]['grant_ids']
            elif mutation == 'span': value['declarations'][0]['start_line'] += 1
            elif mutation == 'missing_scope': value.pop('scope')
            elif mutation == 'runtime_claim': value['runtime_registered'] = True
            elif mutation == 'summary': value['summary']['grant_rows'] = 37
            else: value['context']['profile'] = 'wrong'
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError): check(value)

    def test_retained_file_readers_reject_representation_mutations(self):
        # Exercise the same retained-file tests against on-disk mutated copies;
        # the real retained path is also checked directly by both tests.
        from unittest.mock import patch
        original = REPORT.read_bytes()
        changes = [
            (b'"format_version": 1,', b'"format_version": 0,\n  "format_version": 1,', c.ValidationError),
            (b'"format_version": 1,', b'"format_version": true,', AssertionError),
            (b'"start_line": 51,', b'"start_line": 51.0,', AssertionError),
            (b'"declarations": 21,', b'"declarations": 21.0,', AssertionError),
            (b'"format_version": 1,', b'"format_version": NaN,', c.ValidationError),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/REPORT.name
            with patch(__name__+'.REPORT', path):
                for old,new,error in changes:
                    self.assertEqual(original.count(old), 1)
                    path.write_bytes(original.replace(old,new))
                    for check in (self.test_report_actual_retained_reconciles_and_no_claims,
                                  self.test_retained_report_against_independent_identity_map):
                        with self.subTest(mutation=new, check=check.__name__):
                            with self.assertRaises(error):
                                check()

    def _check_composed_invalid_inputs(self, kind, cli):
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root/ORACLE['source_path']
            source.parent.mkdir(parents=True)
            source.write_bytes(SOURCE.read_bytes())
            table_path, success_path, errors_path = (root/name for name in ('table.csv','success.csv','errors.csv'))
            good_success = csv_bytes([['f','col1'], [str(source), '']])
            good_errors = csv_bytes([['error','col1','col2']])
            before = policy_artifacts()
            cmd = [sys.executable] + (['-O'] if sys.flags.optimize else []) + [
                '-m', 'policy.backend_declarations', '--table', str(table_path),
                '--extracted', str(success_path), '--errors', str(errors_path), '--source-root', d]
            if cli:
                table_path.write_bytes(TABLE); success_path.write_bytes(good_success); errors_path.write_bytes(good_errors)
                valid = subprocess.run(cmd, cwd=ROOT, capture_output=True)
                self.assertEqual(valid.returncode, 0, valid.stderr)
                self.assert_json_exact(c._json(valid.stdout), c._json(REPORT.read_bytes()))
            else:
                valid = c.compare(TABLE, good_success, good_errors, d)
                self.assert_json_exact(valid, c._json(REPORT.read_bytes()))
            self.assertEqual(before, policy_artifacts())
            for name,table,success,errors,message in invalid_comparison_inputs(root,kind):
                with self.subTest(kind=kind, cli=cli, case=name):
                    if cli:
                        table_path.write_bytes(table); success_path.write_bytes(success); errors_path.write_bytes(errors)
                        result = subprocess.run(cmd, cwd=ROOT, capture_output=True)
                        self.assertNotEqual(result.returncode, 0, name)
                        self.assertEqual(result.stdout, b'')
                        self.assertIn(message.encode(), result.stderr)
                    else:
                        stdout = io.StringIO()
                        with redirect_stdout(stdout), self.assertRaisesRegex(c.ValidationError, message):
                            c.compare(table, success, errors, d)
                        self.assertEqual(stdout.getvalue(), '')
                    self.assertEqual(before, policy_artifacts())
            if cli and kind == 'table':
                table_path.unlink()
                success_path.write_bytes(good_success); errors_path.write_bytes(good_errors)
                result = subprocess.run(cmd, cwd=ROOT, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
                self.assertIn(b'comparison failed:', result.stderr)
                self.assertEqual(before, policy_artifacts())

    def test_invalid_tables_through_compare(self):
        self._check_composed_invalid_inputs('table', False)

    def test_invalid_tables_through_cli(self):
        self._check_composed_invalid_inputs('table', True)

    def test_invalid_diagnostics_through_compare(self):
        self._check_composed_invalid_inputs('diagnostics', False)

    def test_invalid_diagnostics_through_cli(self):
        self._check_composed_invalid_inputs('diagnostics', True)

    def test_cli_pinned_context_and_encoding_no_writes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / ORACLE['source_path']; source.parent.mkdir(parents=True); source.write_bytes(SOURCE.read_bytes())
            extracted = root/'success.csv'; extracted.write_bytes(csv_bytes([['f','col1'],[str(source),'']]))
            errors = root/'errors.csv'; errors.write_bytes(csv_bytes([['error','col1','col2']]))
            cmd = [sys.executable,'-m','policy.backend_declarations','--table',str(HIST/'table.csv'),'--extracted',str(extracted),'--errors',str(errors),'--source-root',d]
            before = {p: p.read_bytes() for p in (ROOT/'policy/grants.json', ROOT/'reports/coverage.json', ROOT/'reports/handler_effects.json', REPORT)}
            for encoding in ('utf-16','utf-8-sig'):
                env = dict(os.environ, PYTHONIOENCODING=encoding)
                p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True)
                self.assertEqual(p.returncode,0,p.stderr)
                self.assert_json_exact(c._json(p.stdout), c._json(REPORT.read_bytes()))
                self.assertFalse(p.stdout.startswith(b'\xef\xbb\xbf'))
            source.write_bytes(b'wrong source')
            p = subprocess.run(cmd,cwd=ROOT,capture_output=True)
            self.assertNotEqual(p.returncode,0); self.assertEqual(p.stdout,b'')
            self.assertEqual(before, {p:p.read_bytes() for p in before})


if __name__ == '__main__':
    unittest.main()
