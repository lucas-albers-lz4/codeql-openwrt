"""Tests for the offline typed ucode interchange validator."""

from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from policy.interchange_contract import (
    ContractError,
    REPO_ROOT,
    _check_schema_keywords,
    _validate,
    validate_ucode_root,
)


SCHEMA = json.loads((REPO_ROOT / "schemas/finding.schema.json").read_text(encoding="utf-8"))
LOCK_BYTES = (REPO_ROOT / "corpus/lock.json").read_bytes()
CORPUS_REVISION = "sha256:" + hashlib.sha256(LOCK_BYTES).hexdigest()


def base_row(**overrides):
    row = {
        "record_type": "taint_path",
        "evidence_status": "path_found",
        "producer": "step3",
        "record_id": "ucode:test-path",
        "corpus_revision": CORPUS_REVISION,
        "profile": "luci-ssl-25.12",
        "analysis_revision": "step3:request-args-exec-test-v1",
        "ingress": "ubus_http",
        "entrypoint_id": "ubus_http:luci.getFeatures",
        "ubus_object": "luci",
        "method": "getFeatures",
        "assessment": "unassessed",
        "assumptions": ["synthetic test row"],
        "unknowns": ["authorization not assessed"],
        "evidence_refs": ["ql/src/m4/Synthetic.ql"],
    }
    row.update(overrides)
    return row


class InterchangeContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ucode_root = Path(self.temp.name) / "ucode"
        (self.ucode_root / "docs").mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def write_array(self, rows, name="m4-findings.json"):
        path = self.ucode_root / "docs" / name
        path.write_text(json.dumps(rows), encoding="utf-8")
        return path

    def test_schema_requires_required_type_enum_and_uncertainty_fields(self):
        row = base_row()
        del row["profile"]
        self.assertTrue(any("missing required property 'profile'" in e for e in _validate(row, SCHEMA, "row")))
        row = base_row(method=7)
        self.assertTrue(any("row.method: expected string" in e for e in _validate(row, SCHEMA, "row")))
        row = base_row(record_type="imaginary_record")
        self.assertTrue(any("record_type" in e and "enum" in e for e in _validate(row, SCHEMA, "row")))
        row = base_row(unknowns=None)
        self.assertTrue(any("row.unknowns: expected array" in e for e in _validate(row, SCHEMA, "row")))
        row = base_row()
        del row["unknowns"]
        self.assertTrue(any("missing required property 'unknowns'" in e for e in _validate(row, SCHEMA, "row")))

    def test_schema_keyword_support_fails_closed(self):
        with self.assertRaisesRegex(ContractError, "unsupported schema keyword.*pattern"):
            _check_schema_keywords({"type": "string", "pattern": "x"})

    def test_stale_lock_hash_and_step4_are_rejected(self):
        self.write_array([base_row(corpus_revision="sha256:stale")])
        with self.assertRaisesRegex(ContractError, "corpus_revision does not match"):
            validate_ucode_root(self.ucode_root)
        self.write_array([base_row(producer="step4")])
        with self.assertRaisesRegex(ContractError, "producer 'step3'"):
            validate_ucode_root(self.ucode_root)

    def test_unknown_profile_is_rejected(self):
        self.write_array([base_row(profile="luci-ssl-25.12-fictional")])
        with self.assertRaisesRegex(ContractError, "unknown profile"):
            validate_ucode_root(self.ucode_root)

    def test_unassessed_taint_path_needs_no_invented_grant(self):
        self.write_array([base_row(assessment="unassessed")])
        self.assertEqual(validate_ucode_root(self.ucode_root), (1, 1))

        # A no_path row is not itself an authorization-path conclusion; its
        # existing assessment/expectation may stand without a fabricated ID.
        self.write_array([base_row(evidence_status="no_path", assessment="intended_access")])
        self.assertEqual(validate_ucode_root(self.ucode_root), (1, 1))

        self.write_array([base_row(evidence_status="path_found", assessment="intended_access")])
        with self.assertRaisesRegex(ContractError, "requires a cited policy grant"):
            validate_ucode_root(self.ucode_root)

    def test_cited_grants_validate_exact_join_keys_but_not_analysis_revision(self):
        grants = json.loads((REPO_ROOT / "policy/grants.json").read_text(encoding="utf-8"))
        grant = next(
            row for row in grants
            if row["entrypoint_id"] == "ubus_http:luci.getFeatures"
            and row.get("ubus_object") == "luci" and row.get("method") == "getFeatures"
        )
        row = base_row(
            assessment="intended_access",
            expectation_id="test-expectation",
            evidence_refs=[grant["record_id"]],
            analysis_revision="step3:an-independent-producer-revision",
        )
        self.write_array([row])
        self.assertEqual(validate_ucode_root(self.ucode_root), (1, 1))

        for field, wrong in (
            ("profile", "luci-ssl-25.12-no-ubusauth"),
            ("ingress", "dispatcher"),
            ("entrypoint_id", "ubus_http:luci.other"),
            ("method", "other"),
        ):
            with self.subTest(field=field):
                changed = dict(row)
                changed[field] = wrong
                self.write_array([changed])
                with self.assertRaisesRegex(ContractError, f"mismatched {field}"):
                    validate_ucode_root(self.ucode_root)

        changed = dict(row)
        changed["evidence_refs"] = ["policy:grant:missing"]
        self.write_array([changed])
        with self.assertRaisesRegex(ContractError, "cited grant ID does not exist"):
            validate_ucode_root(self.ucode_root)

    def test_authorization_assessment_requires_cited_grant(self):
        self.write_array([base_row(assessment="authorization_violation")])
        with self.assertRaisesRegex(ContractError, "requires a cited policy grant"):
            validate_ucode_root(self.ucode_root)

    def test_report_only_coverage_object_is_excluded(self):
        self.write_array([base_row()])
        (self.ucode_root / "docs" / "m4-coverage.json").write_text(
            json.dumps({"record_type": "entrypoint_coverage_ledger", "rows": []}),
            encoding="utf-8",
        )
        (self.ucode_root / "docs" / "getblock-observation.csv").write_text(
            "path,line,column,call\n", encoding="utf-8"
        )
        self.assertEqual(validate_ucode_root(self.ucode_root), (1, 1))


if __name__ == "__main__":
    unittest.main()
