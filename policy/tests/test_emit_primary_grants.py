"""Canonical publication must not retain unsupported assessed effects."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from policy import cgi_backup, cgi_download, ubus_file_exec_list_backup
from policy.interchange_contract import ContractError, join_policy_grants

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    (cgi_backup, 'policy:effect:cgi-backup-sensitive-read', 'luci-mod-system-flash-backup', 'policy:grant:root:cgi_io:cgi-backup'),
    (cgi_download, 'policy:effect:cgi-download-file-read', 'luci-mod-system-flash-download', 'policy:grant:root:cgi_io:cgi-download'),
    (ubus_file_exec_list_backup, 'policy:effect:ubus-file-exec-list-backup:list-backup', 'luci-mod-system-flash-list-backup', 'policy:grant:root:ubus_http:file.exec:list-backup'),
)


class CanonicalPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        for name in ('policy', 'corpus', 'reports', 'schemas'):
            shutil.copytree(ROOT / name, self.repo / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))

    def files(self):
        return {p.relative_to(self.repo): p.read_bytes() for d in ('policy', 'corpus', 'reports', 'schemas')
                for p in (self.repo / d).rglob('*') if p.is_file() and '__pycache__' not in p.parts}

    def emit(self):
        env = os.environ.copy()
        env.pop('PYTHONPATH', None)
        flags = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        return subprocess.run([sys.executable, *flags, '-B', '-m', 'policy', 'emit'], cwd=self.repo,
                              env=env, capture_output=True, text=True)

    def test_missing_delegated_support_rejects_before_any_write(self):
        fixture = self.repo / 'policy/fixtures/rpcd.config'
        original = fixture.read_text()
        line = "\tlist read 'luci-mod-system-flash'\n"
        self.assertEqual(original.count(line), 1)
        fixture.write_text(original.replace(line, ''))
        # Independently exercise the actual mutated producers and consumer join.
        # The root grant remains factual, but is supplementary to each expectation.
        for module, record_id, expectation, root_id in CASES:
            with self.subTest(record_id=record_id):
                grants, bundle, effects = module.build_artifacts(self.repo / 'policy/fixtures', self.repo)
                row = next(r for r in (effects if isinstance(effects, list) else [effects]) if r['record_id'] == record_id)
                self.assertEqual(row['expectation_id'], expectation)
                self.assertEqual(row['assessment'], 'intended_access')
                self.assertEqual([g['record_id'] for g in grants if g['record_id'] in row['evidence_refs']], [root_id])
                relevant = [d for d in bundle['decisions'] if d['record_id'].endswith(('cgi-backup-allow', 'cgi-download-allow', 'list-backup-allow'))]
                delegated = next(d for d in relevant if d['session_class'] == 'luci-mod-system-flash')
                root = next(d for d in relevant if d['session_class'] == 'root')
                self.assertNotEqual(delegated['outcome'], 'allow')
                self.assertEqual(root['outcome'], 'allow')
                with self.assertRaisesRegex(ContractError, 'primary expectation-matching grant'):
                    join_policy_grants(row, {g['record_id']: g for g in grants}, scope='aggregate')
        # Detect even an otherwise byte-identical early rewrite, including the first
        # output and files written before and after the aggregate in a normal run.
        for name in ('policy/uci_consumers.json', 'policy/grants.json',
                     'policy/cgi_backup_decisions.json', 'reports/m2-cgi-download-effect.json'):
            (self.repo / name).write_bytes(b'pre-existing sentinel\n')
        before = self.files()
        result = self.emit()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('Traceback', result.stderr)
        for _, record_id, expectation, _ in CASES:
            self.assertIn(record_id, result.stderr)
            self.assertIn(expectation, result.stderr)
        self.assertIn('primary expectation-matching grant', result.stderr)
        self.assertIn('not a denial', result.stderr)
        self.assertEqual(before, self.files())

    def test_retained_effect_is_validated_against_fresh_grants(self):
        catalog = self.repo / 'reports/handler_effects.json'
        rows = json.loads(catalog.read_text())
        row = next(r for r in rows if r['record_id'] == 'm4:effect:luci-setBlockDetect-system')
        row['evidence_refs'] = [ref for ref in row['evidence_refs']
                                if ref != 'policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect']
        catalog.write_text(json.dumps(rows))
        before = self.files()
        result = self.emit()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(row['record_id'], result.stderr)
        self.assertIn('primary expectation-matching grant', result.stderr)
        self.assertEqual(before, self.files())

    def test_stock_cli_is_byte_stable_and_joins_all_effects(self):
        before = self.files()
        for _ in range(2):
            result = self.emit()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(before, self.files())
        grants = json.loads((self.repo / 'policy/grants.json').read_text())
        by_id = {g['record_id']: g for g in grants}
        rows = json.loads((self.repo / 'reports/handler_effects.json').read_text())
        self.assertTrue(rows)
        for row in rows:
            join_policy_grants(row, by_id, scope='aggregate')
        for _, record_id, expectation, root_id in CASES:
            row = next(r for r in rows if r['record_id'] == record_id)
            self.assertEqual(row['expectation_id'], expectation)
            self.assertEqual(row['assessment'], 'intended_access')
            primary, supplementary = join_policy_grants(row, by_id, scope='aggregate')
            self.assertTrue(primary)
            self.assertEqual([g['record_id'] for g in supplementary], [root_id])


if __name__ == '__main__':
    unittest.main()
