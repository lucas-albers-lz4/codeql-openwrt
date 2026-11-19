"""Offline contract tests for the bounded JavaScript extraction gate."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("extraction_gate", HERE / "extraction_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def decoded(rows, columns=1):
    return {"#select": {"columns": [{"kind": "String"}] * columns, "tuples": rows}}


class ExtractionAcceptanceTest(unittest.TestCase):
    def test_exact_paths_and_no_errors_accept(self):
        gate.check_results(["a.js", "b.js"], decoded([["a.js"], ["b.js"]]), decoded([], 3))

    def test_missing_extra_and_duplicate_paths_reject(self):
        for rows in ([['a.js']], [['a.js'], ['b.js'], ['c.js']], [['a.js'], ['b.js'], ['b.js']]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                gate.check_results(['a.js', 'b.js'], decoded(rows), decoded([], 3))

    def test_parse_error_and_malformed_results_reject(self):
        for errors in (decoded([["a.js", "bad", "1"]], 3), {}, {"#select": {"tuples": []}}):
            with self.subTest(errors=errors), self.assertRaises(ValueError):
                gate.check_results(['a.js'], decoded([['a.js']]), errors)

    def test_source_identity_detects_changed_bytes_and_extra_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.js').write_bytes(b'original')
            rows = [{'source': 'a.js', 'sha256': hashlib.sha256(b'original').hexdigest()}]
            gate.check_staged(root, rows)
            (root / 'a.js').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                gate.check_staged(root, rows)
            (root / 'a.js').write_bytes(b'original')
            (root / 'extra.js').write_bytes(b'extra')
            with self.assertRaises(ValueError):
                gate.check_staged(root, rows)

    def test_manifest_identity_rejects_missing_or_altered_row(self):
        rows = json.loads((HERE / 'manifest.json').read_text())
        gate.check_manifest(rows, rows)
        for mutation in (rows[:-1], [{**rows[0], 'sha256': '0' * 64}] + rows[1:]):
            with self.subTest(rows=len(mutation)), self.assertRaises(ValueError):
                gate.check_manifest(rows, mutation)


if __name__ == '__main__':
    unittest.main()
