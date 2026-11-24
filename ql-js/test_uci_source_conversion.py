import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uci_source_conversion import convert, load_json, FIELDS

class ConversionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.data = b'uci.x\n'; (self.root / 'a.js').write_bytes(self.data)
        self.manifest = [{'source': 'a.js', 'sha256': hashlib.sha256(self.data).hexdigest()}]
        self.doc = dict.fromkeys(['planning_only', 'claim_scope', 'inputs', 'parser_provenance', 'interpretation', 'verification', 'limits'])
        self.doc.update(candidate_tuple_field_order=FIELDS, sources=[['a.js', self.manifest[0]['sha256']]], candidates=[[0, [1, 1, 1, 5], 'bare', 'dot', 'x', 'uci.x', 2]])
    def run_doc(self):
        raw = json.dumps(self.doc).encode()
        with patch('uci_source_conversion.MULTISET_SHA256', hashlib.sha256(raw).hexdigest()):
            return convert(raw, self.manifest, self.root)
    def test_valid(self):
        self.assertEqual(self.run_doc(), {('a.js', 1, 1, 1, 5, 'bare', 'dot', True, 'x'): 2})
    def test_digest_rejects_altered_or_deleted_candidates(self):
        raw = json.dumps(self.doc).encode()
        with patch('uci_source_conversion.MULTISET_SHA256', hashlib.sha256(raw).hexdigest()):
            self.doc['candidates'].clear()
            with self.assertRaisesRegex(ValueError, 'digest mismatch'): convert(json.dumps(self.doc).encode(), self.manifest, self.root)
    def test_source_bytes_rejected(self):
        (self.root / 'a.js').write_text('uci.y\n')
        with self.assertRaisesRegex(ValueError, 'source bytes'): self.run_doc()
    def test_expression_span_rejected(self):
        self.doc['candidates'][0][5] = 'uci.y'
        with self.assertRaisesRegex(ValueError, 'expression does not match'): self.run_doc()
    def test_duplicate_source_tuple_key(self):
        self.doc['candidates'].append(self.doc['candidates'][0][:])
        with self.assertRaisesRegex(ValueError, 'duplicate source tuple key'): self.run_doc()
    def test_schema_and_duplicate_key(self):
        self.doc['unexpected'] = 1
        with self.assertRaisesRegex(ValueError, 'document schema'): self.run_doc()
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'): load_json(io.StringIO('{"a":1,"a":2}'))

if __name__ == '__main__': unittest.main()
