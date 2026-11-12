#!/usr/bin/env python3
"""M2 conformance: handwritten expected cases vs evaluator vs C double."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    ERROR_ACCESS,
    ERROR_PARSE,
    PRODUCER,
    ROOT_FIXTURE_SID,
    acl_match,
    build_artifacts,
    corpus_revision,
    emit_artifacts,
    evaluate_call,
    evaluate_expected_case,
    load_expected_cases,
    load_world,
    login_test_permission,
    parse_call_params,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
IDENTITY = REQUIRED + ["analysis_revision", "record_id"]
C_SRC = REPO / "policy" / "c_double" / "uh_ubus_policy.c"


def _compile_c_double(dest: Path) -> Path:
    subprocess.run(
        ["gcc", *C_DOUBLE_FLAGS, "-o", str(dest), str(C_SRC)],
        check=True,
        cwd=REPO,
    )
    return dest


class TestHandwrittenCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {case["id"]: case for case in load_expected_cases()}
        cls.sessions = load_world()
        cls.grants, cls.bundle = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_getfeatures_allow(self) -> None:
        case = self.cases["unauthenticated-getFeatures-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "unauthenticated")
        self.assertEqual(result.sid, DEFAULT_SID)
        self.assertFalse(result.sid_rewritten)
        self.assertIsNone(result.jsonrpc_error)
        self.assertIsNotNone(result.matched)
        self.assertEqual(result.matched.object, "luci")
        self.assertEqual(result.matched.function, "getFeatures")
        self.assertEqual(result.matched.group, "unauthenticated")
        self.assertEqual(case["ingress"], "ubus_http")
        self.assertEqual(case["target_id"], "ubus:luci.getFeatures")
        self.assertEqual(case["op"], "invoke")
        self.assertEqual(case["entrypoint_id"], "ubus_http:luci.getFeatures")

    def test_unauthenticated_setpassword_deny(self) -> None:
        result = self._result("unauthenticated-setPassword-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
        self.assertIsNone(result.matched)
        self.assertFalse(self.cases["unauthenticated-setPassword-deny"]["expect_grant"])
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertFalse(any("setPassword" in record_id for record_id in grant_ids))

    def test_missing_sid_parse_error(self) -> None:
        case = self.cases["missing-sid-parse-error"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertFalse(result.sid_rewritten)
        self.assertIsNone(result.matched)
        not_labels = set(case["not"])
        self.assertIn("unauthenticated_allow", not_labels)
        self.assertIn("sentinel_rewrite", not_labels)
        self.assertIn("file_uci_absent_sid_skip", not_labels)
        self.assertNotEqual(result.outcome, "allow")
        self.assertNotEqual(result.sid, DEFAULT_SID)
        grant_sids = [row.get("session_class") for row in self.grants]
        self.assertNotIn(None, grant_sids)

    def test_root_star_getfeatures_allow(self) -> None:
        case = self.cases["root-star-getFeatures-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(result.sid, ROOT_FIXTURE_SID)
        self.assertIsNotNone(result.matched)
        self.assertEqual(result.matched.function, "getFeatures")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertIn("not a violation", case["note"])

    def test_evaluator_matches_every_handwritten_outcome(self) -> None:
        for case in self.cases.values():
            result = self._result(case["id"])
            self.assertEqual(result.outcome, case["expected_outcome"], case["id"])
            self.assertEqual(bool(case["expect_grant"] and result.outcome == "allow"), case["expect_grant"])


class TestGrantsAndDecisions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grants, cls.bundle = build_artifacts()

    def test_producer_is_policy_facts(self) -> None:
        for row in self.grants + self.bundle["decisions"]:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertNotEqual(row["producer"], "step4")
        self.assertEqual(self.bundle["producer"], PRODUCER)

    def test_identity_fields(self) -> None:
        revision = corpus_revision()
        for row in self.grants + self.bundle["decisions"]:
            for key in IDENTITY:
                self.assertIn(key, row, key)
            self.assertEqual(row["corpus_revision"], revision)
            self.assertEqual(row["profile"], "luci-ssl-25.12")
            self.assertEqual(row["analysis_revision"], "policy:ubus-getfeatures-v1")
            self.assertIn(row["record_type"], SCHEMA["properties"]["record_type"]["enum"])
            self.assertIn(row["evidence_status"], SCHEMA["properties"]["evidence_status"]["enum"])

    def test_grants_are_getfeatures_only(self) -> None:
        self.assertEqual(len(self.grants), 2)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(classes, {"unauthenticated", "root"})
        for row in self.grants:
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["evidence_status"], "fact")
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertEqual(row["ubus_object"], "luci")
            self.assertEqual(row["method"], "getFeatures")
            self.assertEqual(row["target_id"], "ubus:luci.getFeatures")
            self.assertEqual(row["op"], "invoke")
            self.assertEqual(row["entrypoint_id"], "ubus_http:luci.getFeatures")

    def test_decisions_cover_four_cases(self) -> None:
        ids = [row["record_id"] for row in self.bundle["decisions"]]
        self.assertEqual(
            ids,
            [
                "policy:decision:unauthenticated-getFeatures-allow",
                "policy:decision:unauthenticated-setPassword-deny",
                "policy:decision:missing-sid-parse-error",
                "policy:decision:root-star-getFeatures-allow",
            ],
        )
        parse = next(row for row in self.bundle["decisions"] if row["outcome"] == "jsonrpc_parse_error")
        self.assertEqual(parse["jsonrpc_error"]["code"], -32700)
        self.assertIn("unauthenticated_allow", parse["not"])
        self.assertIn(UNKNOWN_SNIPPET, " ".join(parse["unknowns"]))

    def test_unknowns_on_decisions(self) -> None:
        for row in self.bundle["decisions"]:
            self.assertTrue(row["unknowns"])
            self.assertTrue(row["assumptions"])

    def test_no_alloy_or_step4(self) -> None:
        self.assertFalse((REPO / "policy" / "alloy_input.json").exists())
        blob = json.dumps(self.grants) + json.dumps(self.bundle)
        self.assertNotIn("step4", blob)
        self.assertNotIn("alloy_input", blob)


UNKNOWN_SNIPPET = "Live rpcd and uhttpd were not executed"


class TestParseRules(unittest.TestCase):
    def test_empty_sid_is_not_parse_error(self) -> None:
        sid, obj, fun, data, rewritten, err = parse_call_params("", "luci", "getFeatures", {}, 0)
        self.assertIsNone(err)
        self.assertEqual(sid, "")
        self.assertFalse(rewritten)
        result = evaluate_call(sid="", object="luci", function="getFeatures", data={})
        self.assertEqual(result.outcome, "deny")

    def test_no_ubusauth_one_rewrites_missing_sid(self) -> None:
        sid, *_rest, rewritten, err = parse_call_params(None, "luci", "getFeatures", {}, 1)
        self.assertIsNone(err)
        self.assertTrue(rewritten)
        self.assertEqual(sid, DEFAULT_SID)

    def test_default_profile_does_not_rewrite(self) -> None:
        _sid, _obj, _fun, _data, rewritten, err = parse_call_params(
            None, "luci", "getFeatures", {}, 0
        )
        self.assertEqual(err, ERROR_PARSE)
        self.assertFalse(rewritten)

    def test_non_object_data_is_parse_error(self) -> None:
        for bad in ([], "not a table", 123, False, True, 1.5):
            with self.subTest(data=bad):
                _sid, _obj, _fun, _data, _rewritten, err = parse_call_params(
                    DEFAULT_SID, "luci", "getFeatures", bad, 0
                )
                self.assertEqual(err, ERROR_PARSE)
                result = evaluate_call(
                    sid=DEFAULT_SID, object="luci", function="getFeatures", data=bad
                )
                self.assertEqual(result.outcome, "jsonrpc_parse_error")
                self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
                self.assertNotEqual(result.outcome, "allow")

    def test_empty_object_data_reaches_acl_gate(self) -> None:
        result = evaluate_call(
            sid=DEFAULT_SID, object="luci", function="getFeatures", data={}
        )
        self.assertEqual(result.outcome, "allow")


class TestMatching(unittest.TestCase):
    def test_literal_getfeatures(self) -> None:
        self.assertTrue(acl_match("luci", "getFeatures", "luci", "getFeatures"))

    def test_literal_setpassword_does_not_match_getfeatures_grant(self) -> None:
        self.assertFalse(acl_match("luci", "getFeatures", "luci", "setPassword"))

    def test_uci_set_does_not_match_luci_grant(self) -> None:
        self.assertFalse(acl_match("luci", "getFeatures", "uci", "set"))

    def test_root_star_matches_unauthenticated_group(self) -> None:
        from policy.oracle import Login

        root = Login(username="root", read=["*"], write=["*"])
        self.assertTrue(login_test_permission(root, "read", "unauthenticated"))
        self.assertTrue(login_test_permission(None, "read", "unauthenticated"))
        self.assertFalse(login_test_permission(None, "read", "luci-base"))


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "uh_ubus_policy")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.exe), *args],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_parse_missing_sid(self) -> None:
        proc = self._run("parse", "0", "-", "luci", "getFeatures", "1")
        self.assertEqual(proc.stdout.strip(), "ERROR_PARSE")
        self.assertNotEqual(proc.returncode, 0)

    def test_parse_non_table_data(self) -> None:
        for kind in ("array", "string", "number", "bool"):
            with self.subTest(kind=kind):
                proc = self._run("parse", "0", DEFAULT_SID, "luci", "getFeatures", kind)
                self.assertEqual(proc.stdout.strip(), "ERROR_PARSE")
                self.assertNotEqual(proc.returncode, 0)
                decide = self._run(
                    "decide", "0", DEFAULT_SID, "luci", "getFeatures", kind, "luci", "getFeatures"
                )
                self.assertEqual(decide.stdout.strip(), "ERROR_PARSE")

    def test_parse_present_zero_sid(self) -> None:
        proc = self._run("parse", "0", DEFAULT_SID, "luci", "getFeatures", "1")
        self.assertTrue(proc.stdout.startswith("OK "))
        self.assertIn(f"sid={DEFAULT_SID}", proc.stdout)
        self.assertIn("rewritten=0", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_match_allow_and_deny(self) -> None:
        allow = self._run("match", "luci", "getFeatures", "luci", "getFeatures")
        deny = self._run("match", "luci", "getFeatures", "luci", "setPassword")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(deny.stdout.strip(), "DENY")

    def test_decide_four_cases(self) -> None:
        allow = self._run("decide", "0", DEFAULT_SID, "luci", "getFeatures", "1", "luci", "getFeatures")
        deny = self._run("decide", "0", DEFAULT_SID, "luci", "setPassword", "1", "luci", "getFeatures")
        parse = self._run("decide", "0", "-", "luci", "getFeatures", "1", "luci", "getFeatures")
        root = self._run("decide", "0", ROOT_FIXTURE_SID, "luci", "getFeatures", "1", "luci", "getFeatures")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(deny.stdout.strip(), "DENY")
        self.assertEqual(parse.stdout.strip(), "ERROR_PARSE")
        self.assertEqual(root.stdout.strip(), "ALLOW")

    def test_group_star(self) -> None:
        proc = self._run("group", "*", "unauthenticated")
        self.assertEqual(proc.stdout.strip(), "MATCH")

    def test_flags_record_fnm_noescape(self) -> None:
        proc = self._run("flags")
        self.assertIn("FNM_NOESCAPE=", proc.stdout)
        self.assertIn(DEFAULT_SID, proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_emit_matches_committed_files(self) -> None:
        grants, bundle = build_artifacts()
        committed_grants = json.loads((REPO / "policy" / "grants.json").read_text(encoding="utf-8"))
        committed_decisions = json.loads(
            (REPO / "policy" / "policy_decisions.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed_grants, grants)
        self.assertEqual(committed_decisions, bundle)

    def test_emit_helper_roundtrip(self) -> None:
        committed_grants = (REPO / "policy" / "grants.json").read_text(encoding="utf-8")
        committed_decisions = (REPO / "policy" / "policy_decisions.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "policy").mkdir()
            (root / "corpus").mkdir()
            shutil.copytree(REPO / "policy" / "fixtures", root / "policy" / "fixtures")
            shutil.copy2(REPO / "corpus" / "lock.json", root / "corpus" / "lock.json")
            grants_path, decisions_path = emit_artifacts(root)
            self.assertEqual(grants_path, root / "policy" / "grants.json")
            self.assertTrue(decisions_path.exists())
            expected_grants, expected_bundle = build_artifacts(
                root / "policy" / "fixtures", root
            )
            self.assertEqual(json.loads(grants_path.read_text(encoding="utf-8")), expected_grants)
            self.assertEqual(
                json.loads(decisions_path.read_text(encoding="utf-8")), expected_bundle
            )
        self.assertEqual(
            (REPO / "policy" / "grants.json").read_text(encoding="utf-8"), committed_grants
        )
        self.assertEqual(
            (REPO / "policy" / "policy_decisions.json").read_text(encoding="utf-8"),
            committed_decisions,
        )


if __name__ == "__main__":
    unittest.main()
