"""Checks that the entrypoint coverage ledger is complete and conservative."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


class CoverageLedgerTests(unittest.TestCase):
    def test_every_inventoried_grant_or_effect_has_one_exact_coverage_row(self) -> None:
        ledger = json.loads((REPO / "reports/coverage.json").read_text())
        grants = json.loads((REPO / "policy/grants.json").read_text())
        effects = json.loads((REPO / "reports/handler_effects.json").read_text())

        keys = {
            (record["corpus_revision"], record["profile"], record["entrypoint_id"])
            for record in grants + effects
        }
        rows = ledger["entries"]
        row_keys = {
            (row["corpus_revision"], row["profile"], row["entrypoint_id"])
            for row in rows
        }
        self.assertEqual(row_keys, keys)
        self.assertEqual(len(rows), len(row_keys))
        self.assertEqual(ledger["artifact_format"], "entrypoint_coverage_ledger_report")
        self.assertIn("not a finding.schema.json", ledger["format_note"])
        self.assertNotIn("record_type", ledger)
        self.assertNotIn("producer", ledger)
        self.assertEqual(ledger["join_rule"], ["corpus_revision", "profile", "entrypoint_id"])
        self.assertNotIn("analysis_revision", ledger["join_rule"])
        self.assertIn("producer_local", ledger["analysis_revision_scope"])
        self.assertTrue(
            all(
                summary["corpus_revision"] == ledger["corpus_revision"]
                and summary["profile"] == ledger["profile"]
                for summary in ledger["analysis_summaries"]
            )
        )
        self.assertEqual(
            {row["status"] for row in rows},
            {"partial", "unresolved"},
        )

    def test_unmodeled_new_grants_are_partial_and_do_not_claim_paths(self) -> None:
        ledger = json.loads((REPO / "reports/coverage.json").read_text())
        by_id = {row["entrypoint_id"]: row for row in ledger["entries"]}
        expected = {
            "ubus_http:luci.getBlockDevices",
            "ubus_http:luci.setBlockDetect",
            "ubus_http:luci.getConntrackList",
            "ubus_http:luci.getProcessList",
        }
        for entrypoint_id in expected:
            row = by_id[entrypoint_id]
            self.assertEqual(row["status"], "partial")
            self.assertIsNotNone(row["analysis_revision"])
            self.assertNotIn("no_path", row)

        self.assertIn("Missing SARIF is unresolved", ledger["absence_rule"])
        self.assertTrue(all("SARIF" in row["note"] or row["status"] == "partial" for row in by_id.values()))
        self.assertTrue(all(row["status"] != "analyzed" for row in by_id.values()))

    def test_report_backed_m4_entrypoints_remain_partial(self) -> None:
        ledger = json.loads((REPO / "reports/coverage.json").read_text())
        by_id = {row["entrypoint_id"]: row for row in ledger["entries"]}
        expected = {
            "ubus_http:luci.getRealtimeStats": True,
            "ubus_http:luci.getSwconfigFeatures": False,
            "ubus_http:luci.getSwconfigPortState": False,
            "ubus_http:luci.setPassword": True,
            "ubus_http:luci.setLocaltime": False,
        }
        for entrypoint_id, has_local_inventory in expected.items():
            row = by_id[entrypoint_id]
            self.assertEqual(row["status"], "partial")
            self.assertEqual(row["analysis_revision"], "step3:request-args-exec-v1")
            self.assertEqual(row["coverage_ref"], "reports/m4-coverage.json")
            self.assertEqual(row["coverage_producer"], "step3")
            self.assertNotIn("producer", row)
            self.assertNotIn("no_path", row)
            extra_refs = row.get("additional_coverage_refs", [])
            if has_local_inventory:
                self.assertEqual(
                    extra_refs,
                    [
                        {
                            "coverage_ref": "reports/m4-realtime-password-quoted-locals-coverage.json",
                            "analysis_revision": "inventory:realtime-password-quoted-locals-v1",
                            "coverage_producer": "inventory",
                        }
                    ],
                )
            else:
                self.assertEqual(extra_refs, [])


if __name__ == "__main__":
    unittest.main()
