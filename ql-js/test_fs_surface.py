"""Exact source-site controls for the syntactic fs access inventory."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'tests/fs_surface_fixture.js'


class FsSurfaceTest(unittest.TestCase):
    def test_normalization_rejects_foreign_selected_paths(self):
        path = HERE / 'fs_inventory.py'
        self.assertTrue(path.is_file(), 'fs inventory runner is missing')
        spec = importlib.util.spec_from_file_location('fs_inventory', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = Path('/selected')
        manifest = [{'source': 'a.js', 'installed': '/www/a.js'}]
        cols = [{'kind': 'String'}] * 5 + [{'kind': 'String', 'name': 'kind'},
                                              {'kind': 'String', 'name': 'property'},
                                              {'kind': 'String'}]
        rows = [['/selected/a.js', '3', '1', '3', '7', 'dot', 'read', 'candidate'],
                ['/extern/b.js', '3', '1', '3', '7', 'dot', 'read', 'candidate']]
        result = module.normalize_sites({'#select': {'columns': cols, 'tuples': rows}}, source, manifest)
        self.assertEqual(result, [{'source': 'a.js', 'installed': '/www/a.js',
                                   'start_line': 3, 'start_column': 1,
                                   'end_line': 3, 'end_column': 7, 'kind': 'dot',
                                   'property': 'read', 'type': 'rpc_surface', 'assessment': 'candidate'}])
        rows.append(['/selected/foreign.js', '3', '1', '3', '7', 'dot', 'read', 'candidate'])
        with self.assertRaisesRegex(ValueError, 'unexpected selected-root path'):
            module.normalize_sites({'#select': {'columns': cols, 'tuples': rows}}, source, manifest)

    def test_retained_inventory_matches_decoded_rows_and_anchor(self):
        import fs_inventory as inventory
        evidence = HERE / 'evidence/fs-surface'
        raw = json.loads((evidence / 'fs_surface.json').read_text())
        manifest = json.loads((HERE / 'manifest.json').read_text())
        report = json.loads((evidence / 'inventory.json').read_text())
        source = Path('/root/workspace/js69-fs-extraction-20261119/source')
        sites = inventory.normalize_sites(raw, source, manifest)
        self.assertEqual(sites, report['sites'])
        self.assertEqual(report['file_count'], 88)
        self.assertEqual(len(sites), 102)
        self.assertIn({'source': 'applications/luci-app-firewall/htdocs/luci-static/resources/view/firewall/custom.js',
                       'installed': '/www/luci-static/resources/view/firewall/custom.js',
                       'start_line': 8, 'start_column': 27, 'end_line': 8, 'end_column': 33,
                       'kind': 'dot', 'property': 'read', 'type': 'rpc_surface', 'assessment': 'candidate'}, sites)
        changed = {'#select': {'columns': raw['#select']['columns'], 'tuples': raw['#select']['tuples'][1:]}}
        self.assertNotEqual(inventory.normalize_sites(changed, source, manifest), sites)

    def test_normalization_rejects_duplicate_and_bad_classification(self):
        import fs_inventory as inventory
        source = Path('/selected')
        manifest = [{'source': 'a.js', 'installed': '/www/a.js'}]
        columns = [{'kind': 'String'}] * 5 + [{'kind': 'String', 'name': 'kind'},
                                                {'kind': 'String', 'name': 'property'},
                                                {'kind': 'String'}]
        row = ['/selected/a.js', '3', '1', '3', '7', 'dot', 'read', 'candidate']
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            inventory.normalize_sites({'#select': {'columns': columns, 'tuples': [row, row]}}, source, manifest)
        bad = row.copy()
        bad[5:7] = ['computed-index', 'read']
        with self.assertRaisesRegex(ValueError, 'classification'):
            inventory.normalize_sites({'#select': {'columns': columns, 'tuples': [bad]}}, source, manifest)

    @unittest.skipUnless(os.environ.get('JS69_CODEQL') and os.environ.get('JS69_PACKS'),
                         'set JS69_CODEQL and JS69_PACKS for real CodeQL controls')
    def test_exact_positive_and_negative_sites(self):
        query = Path(os.environ.get('JS69_FS_QUERY', str(HERE / 'fs_surface.ql')))
        self.assertTrue(query.is_file(), 'fs surface query is missing')
        codeql, packs = os.environ['JS69_CODEQL'], os.environ['JS69_PACKS']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / FIXTURE.name).write_bytes(FIXTURE.read_bytes())
            database, bqrs, decoded = root / 'db', root / 'sites.bqrs', root / 'sites.json'
            subprocess.run([codeql, 'database', 'create', str(database), '--language=javascript',
                            '--source-root=' + str(source), '--threads=2', '--ram=3072'],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.run([codeql, 'query', 'run', str(query), '--database', str(database),
                            '--additional-packs=' + packs, '--output', str(bqrs),
                            '--threads=2', '--ram=3072'], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.run([codeql, 'bqrs', 'decode', str(bqrs), '--format=json',
                            '--entities=url,string', '--output', str(decoded)], check=True)
            rows = json.loads(decoded.read_text())['#select']['tuples']
            expected_source = (source / FIXTURE.name).resolve()
            self.assertTrue(all(Path(row[0]).resolve() == expected_source for row in rows))
            rows = sorted([Path(row[0]).name, *row[1:]] for row in rows)
            self.assertEqual(rows, [
                ['fs_surface_fixture.js', '11', '1', '11', '7', 'literal-index', '123', 'candidate'],
                ['fs_surface_fixture.js', '3', '1', '3', '7', 'dot', 'read', 'candidate'],
                ['fs_surface_fixture.js', '4', '1', '4', '11', 'literal-index', 'write', 'candidate'],
                ['fs_surface_fixture.js', '5', '1', '5', '10', 'computed-index', '<unknown>', 'candidate'],
                ['fs_surface_fixture.js', '6', '15', '6', '21', 'dot', 'list', 'candidate'],
                ['fs_surface_fixture.js', '7', '30', '7', '36', 'dot', 'exec', 'candidate'],
            ])


if __name__ == '__main__':
    unittest.main()
