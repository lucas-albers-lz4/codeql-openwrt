"""Check retained shellquote reports against the pinned historical contract."""
import json
import unittest
from collections import Counter
from pathlib import Path

from policy import interchange_contract as contract
from policy.oracle import corpus_revision


ROOT = Path(__file__).resolve().parents[2]
FINDINGS = 'm4-shellquote-findings.json'
COVERAGE = 'm4-shellquote-coverage.json'


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


class RetainedShellquoteTests(unittest.TestCase):
    def test_retained_findings_match_historical_identity_and_semantics(self):
        manifest = load(ROOT / 'policy/ucode_snapshot_manifest.json')['typed'][FINDINGS]
        rows = load(ROOT / 'reports' / FINDINGS)
        schema = load(ROOT / 'schemas/finding.schema.json')
        self.assertEqual(Counter(row['record_id'] for row in rows),
                         Counter(manifest['rows'].keys()), 'retained record identity/multiplicity')
        for row in rows:
            rid = row['record_id']
            with self.subTest(record_id=rid):
                self.assertEqual(contract._validate(row, schema, rid), [])
                self.assertEqual(row['analysis_revision'], manifest['revision'])
                self.assertEqual(row['producer'], 'step3')
                self.assertEqual(row['corpus_revision'], corpus_revision())
                for key, expected in manifest['semantics'][rid].items():
                    if key == 'required_unknowns':
                        self.assertTrue(set(expected).issubset(row.get('unknowns', [])),
                                        f'{rid}: required unknowns missing')
                    else:
                        self.assertEqual(row.get(key), expected, f'{rid}: {key}')
                self.assertTrue(set(manifest['rows'][rid]).issubset(row.get('evidence_refs', [])))
                if row['evidence_status'] == 'inconclusive':
                    self.assertIn('Historical record_id retained', ' '.join(row['assumptions']))
                else:
                    self.assertIn('Synthetic quote_exe fixture', row['assumptions'])

    def test_retained_coverage_matches_historical_contract(self):
        spec = load(ROOT / 'policy/ucode_snapshot_manifest.json')['coverage'][COVERAGE]
        report = load(ROOT / 'reports' / COVERAGE)
        contract._validate_coverage(COVERAGE, report, spec)
