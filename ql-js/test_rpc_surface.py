"""Real-CodeQL, exact-site controls for the syntactic rpc access inventory."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
QUERY = HERE / 'rpc_surface.ql'
FIXTURE = HERE / 'tests/rpc_surface_fixture.js'


class RpcSurfaceTest(unittest.TestCase):
    def test_normalizes_only_exact_selected_paths(self):
        import importlib.util
        inventory = HERE / 'rpc_inventory.py'
        self.assertTrue(inventory.is_file(), 'rpc inventory runner is missing')
        spec = importlib.util.spec_from_file_location('rpc_inventory', inventory)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = Path('/selected')
        manifest = [{'source': 'a.js', 'installed': '/www/a.js'}]
        columns = [{'kind': 'String'}] * 5 + [{'kind': 'String', 'name': 'kind'}, {'kind': 'String'}]
        rows = [ ['/selected/a.js', '3', '1', '3', '11', 'dot', 'candidate'],
                 ['/extern/b.js', '3', '1', '3', '11', 'dot', 'candidate'] ]
        result = module.normalize_sites({'#select': {'columns': columns, 'tuples': rows}}, source, manifest)
        self.assertEqual(result, [{'source': 'a.js', 'installed': '/www/a.js',
                                   'start_line': 3, 'start_column': 1,
                                   'end_line': 3, 'end_column': 11,
                                   'kind': 'dot', 'type': 'rpc_surface', 'assessment': 'candidate'}])
        rows.append(['/selected/foreign.js', '3', '1', '3', '11', 'dot', 'candidate'])
        with self.assertRaisesRegex(ValueError, 'unexpected selected-root path'):
            module.normalize_sites({'#select': {'columns': columns, 'tuples': rows}}, source, manifest)

    def test_retained_inventory_matches_decoded_rows_and_anchors(self):
        import rpc_inventory as inventory
        evidence = HERE / 'evidence/rpc-surface'
        raw = json.loads((evidence / 'rpc_surface.json').read_text())
        manifest = json.loads((HERE / 'manifest.json').read_text())
        report = json.loads((evidence / 'inventory.json').read_text())
        source = Path('/root/workspace/js69-sites-extraction-20261119/source')
        sites = inventory.normalize_sites(raw, source, manifest)
        self.assertEqual(sites, report['sites'])
        self.assertEqual(report['file_count'], 88)
        self.assertEqual(len(sites), 98)
        self.assertIn({'source': 'modules/luci-base/htdocs/luci-static/resources/network.js',
                       'installed': '/www/luci-static/resources/network.js',
                       'start_line': 49, 'start_column': 32, 'end_line': 49, 'end_column': 42,
                       'kind': 'dot', 'type': 'rpc_surface', 'assessment': 'candidate'}, sites)
        self.assertIn({'source': 'applications/luci-app-firewall/htdocs/luci-static/resources/view/firewall/forwards.js',
                       'installed': '/www/luci-static/resources/view/firewall/forwards.js',
                       'start_line': 111, 'start_column': 17, 'end_line': 111, 'end_column': 27,
                       'kind': 'dot', 'type': 'rpc_surface', 'assessment': 'candidate'}, sites)
        self.assertNotEqual(inventory.normalize_sites(
            {'#select': {'columns': raw['#select']['columns'], 'tuples': raw['#select']['tuples'][1:]}},
            source, manifest), sites)

    def test_receipt_input_set_is_complete(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('rpc_inventory', HERE / 'rpc_inventory.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        receipt = json.loads((HERE / 'evidence/accepted/ACCEPTED.json').read_text())
        module.check_receipt(receipt)
        del receipt['input_sha256']['files.ql']
        with self.assertRaisesRegex(ValueError, 'acceptance input set'):
            module.check_receipt(receipt)

    @unittest.skipUnless(os.environ.get('JS69_CODEQL') and os.environ.get('JS69_PACKS'),
                         'set JS69_CODEQL and JS69_PACKS for real CodeQL controls')
    def test_exact_positive_and_negative_sites(self):
        query = Path(os.environ.get('JS69_QUERY', str(QUERY)))
        self.assertTrue(query.is_file(), 'rpc surface query is missing')
        codeql, packs = os.environ['JS69_CODEQL'], os.environ['JS69_PACKS']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / FIXTURE.name).write_bytes(FIXTURE.read_bytes())
            database = root / 'db'
            bqrs, decoded = root / 'sites.bqrs', root / 'sites.json'
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
            self.assertTrue(all(row[0] == str(source / FIXTURE.name) for row in rows))
            rows = sorted([Path(row[0]).name, *row[1:]] for row in rows)
            self.assertEqual(rows, [
                ['rpc_surface_fixture.js', '3', '1', '3', '11', 'dot', 'candidate'],
                ['rpc_surface_fixture.js', '4', '1', '4', '14', 'literal-index', 'candidate'],
                ['rpc_surface_fixture.js', '5', '1', '5', '8', 'computed-index', 'candidate'],
                ['rpc_surface_fixture.js', '6', '14', '6', '24', 'dot', 'candidate'],
                ['rpc_surface_fixture.js', '7', '24', '7', '34', 'dot', 'candidate'],
            ])


if __name__ == '__main__':
    unittest.main()
