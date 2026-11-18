"""Retained imported-callee uncertainty, distinct from producer snapshot fixtures."""
import json
import unittest
from pathlib import Path

from policy import interchange_contract as contract
from policy.oracle import corpus_revision

ROOT = Path(__file__).resolve().parents[2]
NAME = "m4-imported-callee-findings.json"
RID = "m4:setInitAction-init_action-unresolved"


class RetainedImportedCalleeTests(unittest.TestCase):
    def test_actual_retained_imported_callee_keeps_identity_and_uncertainty(self):
        rows = contract._read_document(ROOT / "reports" / NAME)
        self.assertEqual([row["record_id"] for row in rows], [RID])
        row = rows[0]
        manifest = json.loads((ROOT / "policy/ucode_snapshot_manifest.json").read_text())
        spec = manifest["typed"][NAME]
        schema = json.loads((ROOT / "schemas/finding.schema.json").read_text())
        self.assertEqual(contract._validate(row, schema, RID), [])
        self.assertEqual(row["producer"], "step3")
        self.assertEqual(row["corpus_revision"], corpus_revision())
        # Consumer report prose differs from the historical producer snapshot;
        # pin shared semantic identity, not the producer's literal unknown text.
        for key, value in spec["semantics"][RID].items():
            if key != "required_unknowns":
                self.assertEqual(row.get(key), value, f"{RID}: {key}")
        self.assertTrue(row.get("unknowns"), f"{RID}: uncertainty missing")
        self.assertIn(
            "unresolved_call under M3 extract glob; not interprocedural path_found",
            row["unknowns"],
        )
        self.assertIn("live uhttpd/rpcd not executed", row["unknowns"])
        self.assertTrue(set(spec["rows"][RID]).issubset(row.get("evidence_refs", [])))
        contract.join_policy_grants(row, contract._load_grants(ROOT), scope="caller")
