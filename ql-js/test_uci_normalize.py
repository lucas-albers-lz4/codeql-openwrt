import tempfile
import unittest
from pathlib import Path
from uci_normalize import normalize

class NormalizeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name).resolve(); (self.source / 'a.js').write_text('x')
        self.manifest = [{'source': 'a.js'}]
        self.row = ['id1', str(self.source / 'a.js'), '1', '1', '1', '7', 'bare', 'computed-index', 'false', '<unknown>', 'candidate']
    def test_same_span_distinct_entities(self):
        other = self.row.copy(); other[0] = 'id2'
        self.assertEqual(list(normalize([self.row, other], self.source, self.manifest).values()), [2])
    def test_empty_dot_rejected_empty_known_computed_accepted(self):
        self.row[7:10] = ['dot', 'true', '']
        with self.assertRaisesRegex(ValueError, 'classification'): normalize([self.row], self.source, self.manifest)
        self.row[7] = 'computed-index'
        self.assertEqual(sum(normalize([self.row], self.source, self.manifest).values()), 1)
    def test_foreign_manifest_paths(self):
        for name in ['/tmp/a.js', '../a.js', 'a/../a.js', 'a\\b.js']:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'manifest path'):
                normalize([], self.source, [{'source': name}])
    def test_symlink_root_and_member_rejected(self):
        link = self.source / 'link'; link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'physical'): normalize([], link, self.manifest)
        (self.source / 'other.js').symlink_to(self.source / 'a.js')
        with self.assertRaisesRegex(ValueError, 'foreign'): normalize([], self.source, [{'source': 'other.js'}])
    def test_literal_unknown_distinct_from_unresolved(self):
        known = self.row.copy(); known[0] = 'id2'; known[8] = 'true'
        result = normalize([self.row, known], self.source, self.manifest)
        self.assertEqual(len(result), 2)
        self.assertEqual({key[-2:] for key in result}, {(False, '<unknown>'), (True, '<unknown>')})
    def test_foreign_row_path(self):
        self.row[1] = str(self.source / 'foreign.js')
        with self.assertRaisesRegex(ValueError, 'foreign path'): normalize([self.row], self.source, self.manifest)
    def test_malformed_and_reversed_coordinates(self):
        for index, value in [(2, '01'), (3, '0'), (4, 'x')]:
            row = self.row.copy(); row[index] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'invalid location'):
                normalize([row], self.source, self.manifest)
        self.row[2:6] = ['2', '1', '1', '7']
        with self.assertRaisesRegex(ValueError, 'reversed location'): normalize([self.row], self.source, self.manifest)
    def test_invalid_classifications(self):
        for index, value in [(6, 'object'), (7, 'literal-index'), (8, 'yes'), (9, 'value'), (10, 'call')]:
            row = self.row.copy(); row[index] = value
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'invalid classification'):
                normalize([row], self.source, self.manifest)
        self.row[7] = 'dot'
        with self.assertRaisesRegex(ValueError, 'invalid classification'): normalize([self.row], self.source, self.manifest)
    def test_duplicate_id(self):
        with self.assertRaisesRegex(ValueError, 'duplicate entity'): normalize([self.row, self.row], self.source, self.manifest)

if __name__ == '__main__': unittest.main()
