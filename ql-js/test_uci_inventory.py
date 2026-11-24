import json
import tempfile
import unittest
from pathlib import Path
from collections import Counter
from uci_inventory import project, project_details, expected_rows, compare

class ProjectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name).resolve(); (self.source / 'a.js').write_text('uci.x')
        self.manifest = [{'source': 'a.js'}]
        self.row = [{'id': 4}, str(self.source / 'a.js'), '1', '1', '1', '5', 'bare', 'dot', 'true', 'x', 'candidate']
        self.doc = {'#select': {'columns': [{'kind': 'Entity'}] + [{'kind': 'String'} for _ in range(10)], 'tuples': [self.row]}}
    def encoded(self):
        return json.dumps(self.doc).encode()
    def test_equal_public_tuples_distinct_ids(self):
        other = self.row.copy(); other[0] = {'id': 5}
        self.doc['#select']['tuples'].append(other)
        self.assertEqual(project(self.encoded(), self.source, self.manifest), {('a.js', 1, 1, 1, 5, 'bare', 'dot', True, 'x'): 2})
    def test_duplicate_entity_rejected(self):
        self.doc['#select']['tuples'].append(self.row.copy())
        with self.assertRaisesRegex(ValueError, 'duplicate entity'): project(self.encoded(), self.source, self.manifest)
    def test_entity_id_required_and_not_boolean(self):
        for entity in [{}, {'id': True}, {'id': '4'}, {'id': 4, 'label': 'uci.x'}]:
            self.row[0] = entity
            with self.subTest(entity=entity), self.assertRaisesRegex(ValueError, 'entity identity'):
                project(self.encoded(), self.source, self.manifest)
    def test_negative_integer_id(self):
        self.row[0] = {'id': -4}
        self.assertEqual(sum(project(self.encoded(), self.source, self.manifest).values()), 1)
    def test_strict_raw_json(self):
        raw = self.encoded()
        cases = [raw.replace(b'"#select":', b'"#select": {}, "#select":', 1),
                 raw.replace(b'"id": 4', b'"id": 4, "id": 5', 1),
                 raw.replace(b'"id": 4', b'"id": NaN', 1),
                 raw.replace(b'"id": 4', b'"id": Infinity', 1),
                 raw.replace(b'"id": 4', b'"id": 1e9999', 1),
                 raw + b'\xff', b'{', self.doc]
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                project(invalid, self.source, self.manifest)
    def test_multiset_comparison(self):
        result = project(self.encoded(), self.source, self.manifest)
        compare(result, result.copy())
        with self.assertRaisesRegex(ValueError, 'multisets differ'): compare(result, Counter())
        key = next(iter(result))
        for count in (0, -1, True, 1.0):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, 'invalid multiset count'):
                compare(result, Counter({key: count}))
        with self.assertRaisesRegex(ValueError, 'multisets differ'):
            compare(result, Counter({key: 2}))
        with self.assertRaisesRegex(ValueError, 'multisets differ'):
            compare(result, Counter({('other',): 1}))

class ComparisonCLITest(ProjectionTest):
    def test_expected_validation_and_cli_mismatch(self):
        import subprocess
        import sys
        base = self.source
        expected = {'rows': [['a.js', 1, 1, 1, 5, 'bare', 'dot', True, 'x', 2]]}
        self.row[0] = {'id': -4}
        (base / 'result.json').write_bytes(self.encoded())
        (base / 'expected.json').write_text(json.dumps(expected))
        (base / 'manifest.json').write_text(json.dumps(self.manifest))
        cmd = [sys.executable, str(Path(__file__).with_name('uci_inventory.py')),
               '--result', str(base / 'result.json'), '--expected', str(base / 'expected.json'),
               '--manifest', str(base / 'manifest.json'), '--source', str(base)]
        result = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        detail = json.loads(result.stdout)
        self.assertEqual(detail['missing'][0]['count'], 1)
        self.assertEqual(detail['missing'][0]['actual_ids'], [-4])
        self.assertEqual(detail['extra'], [])
        expected['rows'][0][-1] = 1
        (base / 'expected.json').write_text(json.dumps(expected))
        result = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['match'])
        (base / 'expected.json').write_bytes(b'{"rows": [], "rows": []}')
        result = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'duplicate JSON key', result.stderr)

    def test_expected_rejects_duplicates_counts_and_foreign_paths(self):
        row = ['a.js', 1, 1, 1, 5, 'bare', 'dot', True, 'x', 1]
        for rows in ([row, row], [row[:-1] + [0]], [row[:-1] + [True]],
                     [['other.js', *row[1:]]], [row[:7] + [1] + row[8:]]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                expected_rows(json.dumps({'rows': rows}).encode(), self.source, self.manifest)

    def test_expected_rejects_path_aliases_and_invalid_empty_inventory(self):
        row = ['a.js', 1, 1, 1, 5, 'bare', 'dot', True, 'x', 1]
        for path in ('./a.js', 'dir/../a.js', 'dir//a.js', str(self.source / 'a.js')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                expected_rows(json.dumps({'rows': [[path, *row[1:]]]}).encode(), self.source, self.manifest)
        with self.assertRaises(ValueError):
            expected_rows(b'{"rows": []}', self.source / 'missing', [])
        with self.assertRaises(ValueError):
            expected_rows(b'{"rows": []}', self.source, [{'source': './a.js'}])

    def test_normalization_is_batched(self):
        from unittest.mock import patch
        import uci_inventory
        for identity in range(5, 25):
            row = self.row.copy()
            row[0] = {'id': identity}
            self.doc['#select']['tuples'].append(row)
        with patch.object(uci_inventory, 'normalize', wraps=uci_inventory.normalize) as check:
            result, ids = project_details(self.encoded(), self.source, self.manifest)
            self.assertEqual(check.call_count, 1)
        self.assertEqual(sum(result.values()), 21)
        self.assertEqual(len(next(iter(ids.values()))), 21)
        expected = {'rows': [['a.js', 1, 1, 1, 5, 'bare', 'dot', True, 'x', 21]]}
        with patch.object(uci_inventory, 'normalize', wraps=uci_inventory.normalize) as check:
            self.assertEqual(expected_rows(json.dumps(expected).encode(), self.source, self.manifest), result)
            self.assertEqual(check.call_count, 1)

    def test_extra_ids_retain_signed_identity(self):
        self.row[0] = {'id': -42}
        actual, ids = project_details(self.encoded(), self.source, self.manifest)
        self.assertEqual(ids[next(iter(actual))], [-42])

if __name__ == '__main__': unittest.main()
