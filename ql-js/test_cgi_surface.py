"""Controls for the bounded CGI syntax inventory."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def inventory():
    path = HERE / 'cgi_inventory.py'
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location('cgi_inventory', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CgiSurfaceTest(unittest.TestCase):
    def test_selected_rows_and_rejections(self):
        module = inventory()
        self.assertIsNotNone(module, 'CGI inventory runner is missing')
        source = Path('/selected')
        manifest = [{'source': 'a.js', 'installed': '/www/a.js'}]
        cols = [{'kind': 'String'}] * 5 + [{'name': 'kind', 'kind': 'String'}, {'name': 'endpoint', 'kind': 'String'}, {'kind': 'String'}]
        row = ['/selected/a.js', '1', '1', '1', '28', 'base-plus-string', '/cgi-x', 'candidate']
        doc = {'#select': {'columns': cols, 'tuples': [row]}}
        sites = module.normalize_sites(doc, source, manifest)
        self.assertEqual(sites, [{'source': 'a.js', 'installed': '/www/a.js', 'start_line': 1, 'start_column': 1, 'end_line': 1, 'end_column': 28, 'kind': 'base-plus-string', 'endpoint': '/cgi-x', 'type': 'rpc_surface', 'assessment': 'candidate'}])
        for replacement in ([*row[:1], '0', *row[2:]], ['/selected/foreign.js', *row[1:]], [*row[:-1], 'safe']):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.normalize_sites({'#select': {'columns': cols, 'tuples': [replacement]}}, source, manifest)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module.normalize_sites({'#select': {'columns': cols, 'tuples': [row, row]}}, source, manifest)

    def test_retained_rows_match_pin_specific_source_oracle(self):
        module = inventory()
        self.assertIsNotNone(module)
        evidence = HERE / 'evidence/cgi-surface'
        document = json.loads((evidence / 'cgi_surface.json').read_text())
        manifest = json.loads((HERE / 'manifest.json').read_text())
        report = json.loads((evidence / 'inventory.json').read_text())
        source = Path('/root/workspace/js69-sites-extraction-20261119/source')
        sites = module.normalize_sites(document, source, manifest)
        self.assertEqual(sites, report['sites'])
        self.assertEqual(report['file_count'], 88)
        actual = [[s['source'], s['start_line'], s['start_column'], s['end_line'], s['end_column'], s['kind'], s['endpoint']] for s in sites]
        oracle = json.loads((evidence / 'source-oracle.json').read_text())
        self.assertEqual(actual, oracle)
        self.assertEqual(len(actual), 6)
        self.assertNotEqual(actual[1:], oracle)

    @unittest.skipUnless(os.environ.get('JS69_CODEQL') and os.environ.get('JS69_PACKS') and os.environ.get('JS69_COMMON_CACHE'), 'real CodeQL controls require JS69_CODEQL, JS69_PACKS and JS69_COMMON_CACHE')
    def test_real_fixture(self):
        codeql, packs = os.environ['JS69_CODEQL'], os.environ['JS69_PACKS']
        query = Path(os.environ.get('JS69_CGI_QUERY', str(HERE / 'cgi_surface.ql')))
        self.assertTrue(query.is_file(), 'CGI query missing')
        fixture = HERE / 'tests/cgi_surface_fixture.js'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.mkdir()
            (source / fixture.name).write_bytes(fixture.read_bytes())
            db, bqrs, decoded = root / 'db', root / 'rows.bqrs', root / 'rows.json'
            subprocess.run([codeql, 'database', 'create', str(db), '--language=javascript', '--source-root=' + str(source), '--threads=1', '--ram=2048', '--common-caches=' + str(root / 'cache')], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.run([codeql, 'query', 'run', str(query), '--database', str(db), '--additional-packs=' + packs, '--output', str(bqrs), '--threads=1', '--ram=2048', '--no-default-compilation-cache', '--compilation-cache=' + str(root / 'compile'), '--common-caches=' + os.environ['JS69_COMMON_CACHE']], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.run([codeql, 'bqrs', 'decode', str(bqrs), '--format=json', '--output', str(decoded), '--common-caches=' + str(root / 'cache')], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            rows = json.loads(decoded.read_text())['#select']['tuples']
            self.assertTrue(all(row[0] == str(source / fixture.name) for row in rows))
            rows = sorted([Path(row[0]).name, *row[1:]] for row in rows)
            self.assertEqual(rows, EXPECTED_FIXTURE_ROWS)


EXPECTED_FIXTURE_ROWS = [
    ['cgi_surface_fixture.js', '2', '11', '2', '42', 'base-plus-string', '/cgi-download', 'candidate'],
    ['cgi_surface_fixture.js', '3', '11', '3', '40', 'template-base-and-suffix', '/cgi-upload', 'candidate'],
    ['cgi_surface_fixture.js', '4', '21', '4', '50', 'base-plus-string', '/cgi-backup', 'candidate'],
    ['cgi_surface_fixture.js', '5', '29', '5', '62', 'base-plus-string', '/cgi-exec', 'candidate'],
    ['cgi_surface_fixture.js', '6', '18', '6', '47', 'template-base-and-suffix', '/cgi-upload', 'candidate'],
    ['cgi_surface_fixture.js', '7', '15', '7', '48', 'template-base-and-suffix', '/cgi-upload', 'candidate'],
]

if __name__ == '__main__':
    unittest.main()
