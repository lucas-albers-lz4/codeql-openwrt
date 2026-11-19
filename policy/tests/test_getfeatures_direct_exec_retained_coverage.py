"""Read and validate the retained getfeatures direct-exec coverage object."""

import copy
import json
import unittest
from pathlib import Path

from policy import interchange_contract as contract

ROOT = Path(__file__).resolve().parents[2]
NAME = "m4-getfeatures-direct-exec-coverage.json"


class RetainedGetfeaturesCoverageTests(unittest.TestCase):
    def _read_and_validate_retained(self):
        manifest = json.loads(
            (ROOT / "policy/ucode_snapshot_manifest.json").read_text(encoding="utf-8")
        )
        report = contract._read_document(ROOT / "reports" / NAME)
        contract._validate_coverage(NAME, report, manifest["coverage"][NAME])
        return report, manifest["coverage"][NAME]

    def test_actual_retained_coverage_matches_manifest_contract(self):
        report, _ = self._read_and_validate_retained()
        self.assertEqual(report["status"], "partial")

    def test_manifest_contract_accepts_order_only_changes(self):
        report, spec = self._read_and_validate_retained()
        reordered = copy.deepcopy(report)
        for value in reordered.values():
            if isinstance(value, list):
                value.reverse()
        contract._validate_coverage(NAME, reordered, spec)


if __name__ == "__main__":
    unittest.main()
