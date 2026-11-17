#!/usr/bin/env python3
"""Guard the retained M4 setInitAction findings and coverage contract."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from policy import interchange_contract
from policy.oracle import corpus_revision

REPO = Path(__file__).resolve().parents[2]
FINDINGS_PATH = REPO / "reports" / "m4-luci-sys-init-action-findings.json"
COVERAGE_PATH = REPO / "reports" / "m4-luci-sys-init-action-coverage.json"
LEDGER_PATH = REPO / "reports" / "coverage.json"
AGGREGATE_PATH = REPO / "reports" / "handler_effects.json"
GRANTS_PATH = REPO / "policy" / "grants.json"
SCHEMA_PATH = REPO / "schemas" / "finding.schema.json"
ENTRYPOINT = "ubus_http:luci.setInitAction"
CORPUS_REVISION = corpus_revision()
ANALYSIS_REVISION = "step3:luci-sys-init-action-v1"
COVERAGE_REF = "reports/m4-luci-sys-init-action-coverage.json"
EFFECT_ID = "m4:luci-sys-init-action-system"

# Independent expectations grounded in the tracked RPC caller source
# (policy/fixtures/getblock-source/usr/share/rpcd/ucode/luci), the
# interchange contract, M4's explicitly limited source/dataflow scope, and
# issue #64's honesty gates. This family inventories a helper, an action
# switch, and a syntactic cross-module pair; it does not establish runtime
# execution or interprocedural taint.
EXPECTED_ROWS = {
    EFFECT_ID: {
        "record_type": "handler_effect",
        "evidence_status": "fact",
        "producer": "step3",
        "corpus_revision": CORPUS_REVISION,
        "profile": "luci-ssl-25.12",
        "analysis_revision": ANALYSIS_REVISION,
        "ingress": "ubus_http",
        "entrypoint_id": ENTRYPOINT,
        "ubus_object": "luci",
        "method": "setInitAction",
        "effect_id": "luci.sys.init_action.system",
        "target_id": "command:init_action",
        "op": "exec",
        "sink_kind": "system",
        "assessment": "unassessed",
        "evidence_refs": ["ql/src/m4/InitActionSystem.ql"],
        "unknowns": {
            "live uhttpd/rpcd not executed",
            "no M2 grant row for setInitAction in the first-release evaluator",
        },
    },
    "m4:setInitAction-action-token-switch": {
        "record_type": "backend_method",
        "evidence_status": "fact",
        "producer": "step3",
        "corpus_revision": CORPUS_REVISION,
        "profile": "luci-ssl-25.12",
        "analysis_revision": ANALYSIS_REVISION,
        "ingress": "ubus_http",
        "entrypoint_id": ENTRYPOINT,
        "ubus_object": "luci",
        "method": "setInitAction",
        "param_name": "action",
        "assessment": "unassessed",
        "evidence_refs": ["ql/src/m4/SetInitActionActionSwitch.ql"],
        "unknowns": {"live uhttpd/rpcd not executed"},
    },
    "m4:setInitAction-init_action-syntactic-pair": {
        "record_type": "taint_path",
        "evidence_status": "inconclusive",
        "producer": "step3",
        "corpus_revision": CORPUS_REVISION,
        "profile": "luci-ssl-25.12",
        "analysis_revision": ANALYSIS_REVISION,
        "ingress": "ubus_http",
        "entrypoint_id": ENTRYPOINT,
        "ubus_object": "luci",
        "method": "setInitAction",
        "param_name": "name",
        "sink_kind": "system",
        "assessment": "unassessed",
        "evidence_refs": ["ql/src/m4/InitActionCallerSinkPair.ql"],
        "unknowns": {
            "no CFG/SSA across the luci.sys import",
            "live uhttpd/rpcd not executed",
        },
    },
}

COVERAGE_IDENTITY = {
    "analysis_revision": ANALYSIS_REVISION,
    "profile": "luci-ssl-25.12",
    "entrypoint_id": ENTRYPOINT,
    "status": "partial",
}
COVERAGE_REQUIRED_ITEMS = {
    "extracted_files": {"luci", "sys.uc"},
    "analyzed": {
        "luci.sys init_action builtin system template",
        "setInitAction.call action token switch (inventory, not a sanitizer)",
        "syntactic pair of tainted init_action call with luci.sys system (not dataflow)",
    },
    "resolved_calls": {"system"},
    "unmodeled_branches": {
        "interprocedural CFG/SSA taint from setInitAction into init_action",
        "basename as a sanitizer (not modeled)",
        "setInitAction action token switch as a sanitizer (inventory only)",
    },
    "unsupported_constructs": {"generated AST.qll/CFG.qll (not imported)", "global dataflow/SSA"},
    "unknowns": {"live uhttpd/rpcd not executed", "no M2 grant row for setInitAction"},
}
LEDGER_EXPECTED = {
    "corpus_revision": corpus_revision(),
    "profile": "luci-ssl-25.12",
    "entrypoint_id": ENTRYPOINT,
    "status": "partial",
    "analysis_revision": ANALYSIS_REVISION,
    "coverage_ref": COVERAGE_REF,
    "grant_record_count": 0,
    "handler_effect_record_count": 1,
    "coverage_producer": "step3",
}


def _require(condition: bool, message: str) -> None:
    """Keep regression guards active under python -O."""
    if not condition:
        raise AssertionError(message)


def _validate_rows(rows: list[dict], schema: dict) -> None:
    """Check exact historical identities and contract-backed semantics."""
    _require(len(rows) == len(EXPECTED_ROWS), f"expected 3 retained rows, got {len(rows)}")
    ids = [row.get("record_id") for row in rows]
    _require(len(ids) == len(set(ids)), "duplicate retained record_id")
    _require(set(ids) == set(EXPECTED_ROWS), f"unexpected retained identities: {ids!r}")

    by_id = {row["record_id"]: row for row in rows}
    for record_id, expected in EXPECTED_ROWS.items():
        row = by_id[record_id]
        errors = interchange_contract._validate(row, schema, record_id)
        _require(not errors, f"{record_id}: schema validation failed: {errors!r}")
        for field, value in expected.items():
            if field == "unknowns":
                missing = value - set(row.get("unknowns", []))
                _require(not missing, f"{record_id}: required unknowns missing: {missing!r}")
            else:
                _require(row.get(field) == value, f"{record_id}: unexpected {field}: {row.get(field)!r}")


def _validate_coverage(report: object) -> None:
    """Pin family coverage identity and require every documented uncertainty."""
    if not isinstance(report, dict):
        raise AssertionError("setInitAction coverage report missing or not an object")
    for field, expected in COVERAGE_IDENTITY.items():
        _require(report.get(field) == expected, f"coverage identity mismatch in {field}")
    for field, expected in COVERAGE_REQUIRED_ITEMS.items():
        actual = report.get(field)
        if not isinstance(actual, list):
            raise AssertionError(f"coverage {field} missing or not a list")
        missing = expected - set(actual)
        _require(not missing, f"coverage {field} missing required items: {missing!r}")


def _validate_ledger(ledger: dict) -> None:
    """Bind exactly one ledger entry to the report and its effect/grant totals."""
    entries = ledger.get("entries")
    _require(isinstance(entries, list), "coverage ledger entries missing or not a list")
    matches = [row for row in entries if row.get("entrypoint_id") == ENTRYPOINT]
    _require(len(matches) == 1, f"expected exactly one setInitAction ledger row, got {len(matches)}")
    for field, expected in LEDGER_EXPECTED.items():
        _require(matches[0].get(field) == expected, f"ledger setInitAction {field} mismatch")


def _validate_aggregate(rows: list[dict], aggregate: list[dict]) -> None:
    """Keep the copied helper effect aligned without relaxing its assessment."""
    source = next(row for row in rows if row["record_id"] == EFFECT_ID)
    copies = [row for row in aggregate if row.get("record_id") == source["record_id"]]
    _require(len(copies) == 1, f"expected one aggregate copy, got {len(copies)}")
    copied = copies[0]
    for field, value in source.items():
        if field == "assumptions":
            expected_assumptions = value + [
                "Collected from reports/m4-luci-sys-init-action-findings.json; not a new query run"
            ]
            _require(copied.get(field) == expected_assumptions, "aggregate assumptions drifted")
        else:
            _require(copied.get(field) == value, f"aggregate handler_effect drifted in {field}")
    _require(set(copied) == set(source), "aggregate handler_effect fields drifted")


class TestSetInitActionRetainedEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))
        cls.coverage = json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))
        cls.ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.aggregate = json.loads(AGGREGATE_PATH.read_text(encoding="utf-8"))
        cls.grants = json.loads(GRANTS_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_retained_rows_match_independent_identity_type_status_and_unknowns(self) -> None:
        _validate_rows(self.rows, self.schema)

    def test_coverage_report_retains_partial_status_identity_and_unknowns(self) -> None:
        _validate_coverage(self.coverage)

    def test_coverage_ledger_links_exact_family_report_and_counts(self) -> None:
        _validate_ledger(self.ledger)

    def test_copied_effect_remains_exactly_aligned_in_aggregate(self) -> None:
        _validate_aggregate(self.rows, self.aggregate)

    def test_source_fixture_matches_the_pinned_caller_identity(self) -> None:
        caller = (REPO / "policy/fixtures/getblock-source/usr/share/rpcd/ucode/luci").read_text(
            encoding="utf-8"
        )
        self.assertIn("setInitAction: {", caller)
        self.assertIn("switch (request.args.action)", caller)
        self.assertIn("init_action(request.args.name, request.args.action)", caller)
        for token in ("enable", "disable", "start", "stop", "restart", "reload"):
            self.assertIn(f"case '{token}':", caller)
        self.assertIn("return { error: 'Invalid action' };", caller)

    def test_unassessed_no_grant_semantics_remain_explicit(self) -> None:
        method_grants = [row for row in self.grants if row.get("method") == "setInitAction"]
        self.assertEqual(method_grants, [])
        effect = next(row for row in self.aggregate if row.get("record_id") == EFFECT_ID)
        self.assertEqual(effect["assessment"], "unassessed")
        self.assertFalse(any(ref.startswith("policy:grant:") for ref in effect["evidence_refs"]))

    def test_mutations_are_rejected(self) -> None:
        promoted = copy.deepcopy(self.rows)
        path_row = next(row for row in promoted if row.get("record_id") == "m4:setInitAction-init_action-syntactic-pair")
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

        for record_id in EXPECTED_ROWS:
            for field, replacement in (
                ("method", "otherMethod"),
                ("entrypoint_id", "ubus_http:luci.otherMethod"),
            ):
                substituted = copy.deepcopy(self.rows)
                row = next(item for item in substituted if item["record_id"] == record_id)
                row[field] = replacement
                with self.subTest(record_id=record_id, field=field):
                    with self.assertRaises(AssertionError):
                        _validate_rows(substituted, self.schema)

        omitted = copy.deepcopy(self.rows[:-1])
        with self.assertRaises(AssertionError):
            _validate_rows(omitted, self.schema)

        duplicated = copy.deepcopy(self.rows)
        duplicated.append(copy.deepcopy(duplicated[0]))
        with self.assertRaises(AssertionError):
            _validate_rows(duplicated, self.schema)

        substituted_id = copy.deepcopy(self.rows)
        substituted_id[0]["record_id"] = "m4:unexpected-substitute"
        with self.assertRaises(AssertionError):
            _validate_rows(substituted_id, self.schema)

        for field, mutation in (
            ("status", "analyzed"),
            ("unknowns", []),
        ):
            changed_coverage = copy.deepcopy(self.coverage)
            changed_coverage[field] = mutation
            with self.subTest(coverage_field=field):
                with self.assertRaises(AssertionError):
                    _validate_coverage(changed_coverage)
        with self.assertRaises(AssertionError):
            _validate_coverage(None)

        for field, mutation in (
            ("coverage_ref", "reports/missing-setinitaction-coverage.json"),
            ("handler_effect_record_count", 0),
        ):
            changed_ledger = copy.deepcopy(self.ledger)
            row = next(item for item in changed_ledger["entries"] if item["entrypoint_id"] == ENTRYPOINT)
            row[field] = mutation
            with self.subTest(ledger_field=field):
                with self.assertRaises(AssertionError):
                    _validate_ledger(changed_ledger)

        aggregate_missing = [row for row in self.aggregate if row.get("record_id") != EFFECT_ID]
        with self.assertRaises(AssertionError):
            _validate_aggregate(self.rows, aggregate_missing)

        aggregate_promoted = copy.deepcopy(self.aggregate)
        aggregate_row = next(row for row in aggregate_promoted if row.get("record_id") == EFFECT_ID)
        aggregate_row["evidence_status"] = "path_found"
        with self.assertRaises(AssertionError):
            _validate_aggregate(self.rows, aggregate_promoted)


if __name__ == "__main__":
    unittest.main()
