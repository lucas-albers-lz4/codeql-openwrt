#!/usr/bin/env python3
"""Guard the retained M4 setInitAction evidence without promoting it."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[2]
FINDINGS_PATH = REPO / "reports" / "m4-luci-sys-init-action-findings.json"
AGGREGATE_PATH = REPO / "reports" / "handler_effects.json"
GRANTS_PATH = REPO / "policy" / "grants.json"
SCHEMA_PATH = REPO / "schemas" / "finding.schema.json"

# Independent expectations grounded in the tracked caller source
# (policy/fixtures/getblock-source/usr/share/rpcd/ucode/luci), the
# interchange rules in docs/pack-contract.md, and issue #64's honesty gates.
# The helper sink and token inventory are facts; the cross-module syntactic
# pair is inconclusive while dataflow/runtime evidence is absent.
EXPECTED_ROWS = {
    "m4:luci-sys-init-action-system": {
        "record_type": "handler_effect",
        "evidence_status": "fact",
        "assessment": "unassessed",
        "unknowns": {
            "live uhttpd/rpcd not executed",
            "no M2 grant row for setInitAction in the first-release evaluator",
        },
    },
    "m4:setInitAction-action-token-switch": {
        "record_type": "backend_method",
        "evidence_status": "fact",
        "assessment": "unassessed",
        "unknowns": {"live uhttpd/rpcd not executed"},
    },
    "m4:setInitAction-init_action-syntactic-pair": {
        "record_type": "taint_path",
        "evidence_status": "inconclusive",
        "assessment": "unassessed",
        "unknowns": {
            "no CFG/SSA across the luci.sys import",
            "live uhttpd/rpcd not executed",
        },
    },
}


def _require(condition: bool, message: str) -> None:
    """Keep these guards active under python -O as well as normal execution."""
    if not condition:
        raise AssertionError(message)


def _validate_rows(rows: list[dict], schema: dict) -> None:
    """Check retained identities and semantics independently of input ordering."""
    _require(len(rows) == len(EXPECTED_ROWS), f"expected 3 retained rows, got {len(rows)}")
    ids = [row.get("record_id") for row in rows]
    _require(len(ids) == len(set(ids)), "duplicate retained record_id")
    _require(set(ids) == set(EXPECTED_ROWS), f"unexpected retained identities: {ids!r}")

    validator = Draft202012Validator(schema)
    by_id = {row["record_id"]: row for row in rows}
    for record_id, expected in EXPECTED_ROWS.items():
        row = by_id[record_id]
        validator.validate(row)
        for field in ("record_type", "evidence_status", "assessment"):
            _require(
                row.get(field) == expected[field],
                f"{record_id}: expected {field}={expected[field]!r}, got {row.get(field)!r}",
            )
        missing = expected["unknowns"] - set(row.get("unknowns", []))
        _require(not missing, f"{record_id}: missing required uncertainty {missing!r}")


def _validate_aggregate(rows: list[dict], aggregate: list[dict]) -> None:
    """Keep the copied helper effect aligned without relaxing its assessment."""
    source = next(row for row in rows if row["record_id"] == "m4:luci-sys-init-action-system")
    copies = [row for row in aggregate if row.get("record_id") == source["record_id"]]
    _require(len(copies) == 1, f"expected one aggregate copy, got {len(copies)}")
    copy = copies[0]
    for field, value in source.items():
        if field == "assumptions":
            expected_assumptions = value + [
                "Collected from reports/m4-luci-sys-init-action-findings.json; not a new query run"
            ]
            _require(copy.get(field) == expected_assumptions, "aggregate assumptions drifted")
        else:
            _require(copy.get(field) == value, f"aggregate handler_effect drifted in {field}")
    _require(set(copy) == set(source), "aggregate handler_effect fields drifted")


class TestSetInitActionRetainedEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))
        cls.aggregate = json.loads(AGGREGATE_PATH.read_text(encoding="utf-8"))
        cls.grants = json.loads(GRANTS_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_retained_rows_match_independent_identity_type_status_and_unknowns(self) -> None:
        _validate_rows(self.rows, self.schema)

    def test_copied_effect_remains_exactly_aligned_in_aggregate(self) -> None:
        _validate_aggregate(self.rows, self.aggregate)

    def test_unassessed_no_grant_semantics_remain_explicit(self) -> None:
        method_grants = [row for row in self.grants if row.get("method") == "setInitAction"]
        self.assertEqual(method_grants, [])
        effect = next(
            row for row in self.aggregate
            if row.get("record_id") == "m4:luci-sys-init-action-system"
        )
        self.assertEqual(effect["assessment"], "unassessed")
        self.assertFalse(any(ref.startswith("policy:grant:") for ref in effect["evidence_refs"]))

    def test_mutations_are_rejected(self) -> None:
        promoted = copy.deepcopy(self.rows)
        path_row = next(
            row for row in promoted
            if row.get("record_id") == "m4:setInitAction-init_action-syntactic-pair"
        )
        path_row["evidence_status"] = "path_found"
        with self.assertRaises(AssertionError):
            _validate_rows(promoted, self.schema)

        for record_id, expected in EXPECTED_ROWS.items():
            for uncertainty in expected["unknowns"]:
                incomplete = copy.deepcopy(self.rows)
                row = next(item for item in incomplete if item["record_id"] == record_id)
                row["unknowns"].remove(uncertainty)
                with self.subTest(record_id=record_id, uncertainty=uncertainty):
                    with self.assertRaises(AssertionError):
                        _validate_rows(incomplete, self.schema)

        omitted = copy.deepcopy(self.rows[:-1])
        with self.assertRaises(AssertionError):
            _validate_rows(omitted, self.schema)

        duplicated = copy.deepcopy(self.rows)
        duplicated.append(copy.deepcopy(duplicated[0]))
        with self.assertRaises(AssertionError):
            _validate_rows(duplicated, self.schema)

        substituted = copy.deepcopy(self.rows)
        substituted[0]["record_id"] = "m4:unexpected-substitute"
        with self.assertRaises(AssertionError):
            _validate_rows(substituted, self.schema)

        aggregate_missing = [
            row for row in self.aggregate if row.get("record_id") != "m4:luci-sys-init-action-system"
        ]
        with self.assertRaises(AssertionError):
            _validate_aggregate(self.rows, aggregate_missing)

        aggregate_promoted = copy.deepcopy(self.aggregate)
        aggregate_row = next(
            row for row in aggregate_promoted
            if row.get("record_id") == "m4:luci-sys-init-action-system"
        )
        aggregate_row["evidence_status"] = "path_found"
        with self.assertRaises(AssertionError):
            _validate_aggregate(self.rows, aggregate_promoted)


if __name__ == "__main__":
    unittest.main()
