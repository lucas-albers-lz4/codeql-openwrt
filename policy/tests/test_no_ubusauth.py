#!/usr/bin/env python3
"""no_ubusauth=1 profile: handwritten cases vs evaluator vs C double."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.no_ubusauth import (  # noqa: E402
    ANALYSIS_REVISION,
    BASE_PROFILE,
    PROFILE,
    UNKNOWN_SID,
    build_artifacts,
    evaluate_expected_case,
    load_expected_cases,
)
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    ERROR_ACCESS,
    ERROR_OBJECT,
    ERROR_PARSE,
    PRODUCER,
    build_artifacts as luci_build_artifacts,
    corpus_revision,
    evaluate_call,
    load_world,
    parse_call_param_array,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
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
        cls.bundle = build_artifacts()
        cls.luci_grants, cls.luci_bundle = luci_build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_empty_sid_rewrites_and_skips(self) -> None:
        case = self.cases["no-ubusauth-empty-sid-getFeatures-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertTrue(result.sid_rewritten)
        self.assertEqual(result.sid, DEFAULT_SID)
        self.assertEqual(result.session_class, "unauthenticated")
        self.assertIsNone(result.matched)
        self.assertIsNone(result.jsonrpc_error)
        self.assertEqual(result.steps[-1]["invoke"], "skipped")
        self.assertEqual(result.steps[-1]["reason"], "conf.ubus_noauth")
        self.assertFalse(case["expect_grant"])
        control = evaluate_call(
            sid=None, object="luci", function="getFeatures", data={}, no_ubusauth=0
        )
        self.assertEqual(control.outcome, "jsonrpc_parse_error")
        self.assertEqual(control.jsonrpc_error, ERROR_PARSE)

    def test_null_and_omitted_sid_do_not_reserve_a_slot(self) -> None:
        result = self._result("no-ubusauth-null-sid-parse-error")
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertFalse(result.sid_rewritten)
        for params in ([None, "luci", "getFeatures", {}], ["luci", "getFeatures", {}]):
            sid, obj, fun, data, rewritten, error = parse_call_param_array(params, 1)
            self.assertEqual((sid, obj, fun, data), ("luci", "getFeatures", None, None))
            self.assertFalse(rewritten)
            self.assertEqual(error, ERROR_PARSE)

    def test_skipped_types_do_not_advance_the_policy_index(self) -> None:
        parsed = parse_call_param_array([None, "", 42, "luci", [], "getFeatures", {}], 1)
        self.assertEqual(parsed, (DEFAULT_SID, "luci", "getFeatures", {}, True, None))
        for key in ("object", "function"):
            args = dict(sid="", object="luci", function="getFeatures", data={}, no_ubusauth=1)
            args[key] = 123
            self.assertEqual(evaluate_call(**args).jsonrpc_error, ERROR_PARSE)
        incomplete = evaluate_call(sid=None, object=None, function=None, data={}, no_ubusauth=1)
        self.assertEqual(incomplete.jsonrpc_error, ERROR_PARSE)
        self.assertTrue(incomplete.sid_rewritten)
        self.assertNotIn("sentinel_rewrite", incomplete.steps[-1]["not"])

    def test_unknown_object_fails_before_skipping_auth(self) -> None:
        result = self._result("no-ubusauth-unknown-object-error")
        self.assertEqual(result.jsonrpc_error, ERROR_OBJECT)
        self.assertEqual(result.outcome, "jsonrpc_object_error")
        self.assertEqual(result.steps[-1]["step"], "ubus_lookup_id")
        self.assertFalse(any(s.get("invoke") == "skipped" for s in result.steps))

    def test_unauthenticated_setpassword_skip_is_not_a_grant(self) -> None:
        case = self.cases["no-ubusauth-unauthenticated-setPassword-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertFalse(result.sid_rewritten)
        self.assertEqual(result.sid, DEFAULT_SID)
        self.assertIsNone(result.matched)
        self.assertEqual(case["assessment"], "unassessed")
        self.assertFalse(case["expect_grant"])
        grant_ids = [row["record_id"] for row in self.luci_grants]
        self.assertNotIn(
            "policy:grant:unauthenticated:ubus_http:luci.setPassword", grant_ids
        )
        self.assertEqual(self.bundle["grants"], [])
        control = evaluate_call(
            sid=DEFAULT_SID,
            object="luci",
            function="setPassword",
            data={},
            no_ubusauth=0,
            sessions=self.sessions,
        )
        self.assertEqual(control.outcome, "deny")
        self.assertEqual(control.jsonrpc_error, ERROR_ACCESS)

    def test_unknown_sid_skip_is_not_unauthenticated_acl(self) -> None:
        result = self._result("no-ubusauth-unknown-sid-setPassword-allow")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.sid, UNKNOWN_SID)
        self.assertIsNone(result.session_class)
        self.assertIsNone(result.matched)
        self.assertFalse(result.sid_rewritten)
        control = evaluate_call(
            sid=UNKNOWN_SID,
            object="luci",
            function="setPassword",
            data={},
            no_ubusauth=0,
            sessions=self.sessions,
        )
        self.assertEqual(control.outcome, "deny")

    def test_parse_still_requires_data_table(self) -> None:
        result = self._result("no-ubusauth-missing-data-parse-error")
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertIsNone(result.matched)
        skip_steps = [step for step in result.steps if step.get("invoke") == "skipped"]
        self.assertEqual(skip_steps, [])

    def test_evaluator_matches_every_handwritten_outcome(self) -> None:
        for case in self.cases.values():
            result = self._result(case["id"])
            self.assertEqual(result.outcome, case["expected_outcome"], case["id"])
            self.assertFalse(case["expect_grant"])
            self.assertIsNone(result.matched)

    def test_luci_ssl_cases_stay_no_ubusauth_zero(self) -> None:
        from policy.oracle import load_expected_cases as load_luci_cases

        for case in load_luci_cases():
            self.assertEqual(int(case.get("no_ubusauth", 0)), 0, case["id"])


class TestDecisions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = build_artifacts()
        cls.luci_grants, _luci = luci_build_artifacts()

    def test_profile_and_revision_are_distinct(self) -> None:
        self.assertEqual(self.bundle["profile"], PROFILE)
        self.assertNotEqual(self.bundle["profile"], BASE_PROFILE)
        self.assertEqual(self.bundle["analysis_revision"], ANALYSIS_REVISION)
        self.assertNotEqual(self.bundle["analysis_revision"], "policy:ubus-luci-exec-methods-v2")
        self.assertEqual(self.bundle["corpus_revision"], luci_build_artifacts()[1]["corpus_revision"])
        self.assertEqual(
            self.bundle["corpus_revision"],
            "sha256:b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a",
        )
        self.assertEqual(self.bundle["grants"], [])
        self.assertEqual(self.bundle["producer"], PRODUCER)

    def test_decisions_do_not_join_luci_ssl_grants(self) -> None:
        luci_ids = {row["record_id"] for row in self.luci_grants}
        for row in self.bundle["decisions"]:
            with self.subTest(record_id=row["record_id"]):
                for key in REQUIRED:
                    self.assertIn(key, row, key)
                self.assertEqual(row["profile"], PROFILE)
                self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
                self.assertEqual(row["producer"], PRODUCER)
                self.assertEqual(row["record_type"], "policy_decision")
                self.assertEqual(row["evidence_status"], "fact")
                self.assertEqual(row["ingress"], "ubus_http")
                self.assertEqual(row["no_ubusauth"], 1)
                self.assertFalse(row["grant_emitted"])
                self.assertNotIn(row.get("assessment"), {"authorization_violation"})
                self.assertNotEqual(row["evidence_status"], "path_found")
                self.assertNotIn(row["record_id"], luci_ids)
                self.assertTrue(row["unknowns"])
                self.assertTrue(row["assumptions"])
        assessments = {row.get("assessment") for row in self.bundle["decisions"]}
        self.assertNotIn("authorization_violation", assessments)
        statuses = {row["evidence_status"] for row in self.bundle["decisions"]}
        self.assertNotIn("path_found", statuses)
        blob = json.dumps(self.bundle)
        self.assertNotIn("step4", blob)
        self.assertNotIn("alloy_input", blob)
        self.assertNotIn('"policy_grant"', blob)

    def test_decisions_cover_handwritten_cases(self) -> None:
        ids = [row["record_id"] for row in self.bundle["decisions"]]
        expected = [f"policy:decision:{case['id']}" for case in load_expected_cases()]
        self.assertEqual(ids, expected)
        parse = next(
            row for row in self.bundle["decisions"] if row["outcome"] == "jsonrpc_parse_error"
        )
        self.assertEqual(parse["jsonrpc_error"]["code"], -32700)

    def test_custom_root_revision_propagates_to_every_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "corpus").mkdir()
            (root / "corpus" / "lock.json").write_bytes(
                (REPO / "corpus" / "lock.json").read_bytes() + b"\n"
            )
            bundle = build_artifacts(REPO / "policy" / "fixtures", root)
            self.assertEqual(bundle["corpus_revision"], corpus_revision(root))
            self.assertTrue(all(row["corpus_revision"] == bundle["corpus_revision"]
                                for row in bundle["decisions"]))

    def test_cgi_and_dispatcher_not_emitted(self) -> None:
        for row in self.bundle["decisions"]:
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertNotIn("cgi_endpoint", row)
        blob = json.dumps(self.bundle["decisions"])
        self.assertNotIn("setInitAction", blob)
        self.assertTrue(all(row.get("ingress") != "dispatcher" for row in self.bundle["decisions"]))


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

    def test_parse_empty_sid_rewrites_but_null_is_parse_error(self) -> None:
        proc = self._run("parse", "1", "", "luci", "getFeatures", "1")
        self.assertTrue(proc.stdout.startswith("OK "))
        self.assertIn(f"sid={DEFAULT_SID}", proc.stdout)
        self.assertIn("rewritten=1", proc.stdout)
        self.assertEqual(proc.returncode, 0)
        control = self._run("parse", "0", "-", "luci", "getFeatures", "1")
        self.assertEqual(control.stdout.strip(), "ERROR_PARSE")
        missing = self._run("parse", "1", "-", "luci", "getFeatures", "1")
        self.assertEqual(missing.stdout.strip(), "ERROR_PARSE")
        for values in (("", "<number>", "getFeatures"), ("", "luci", "<array>")):
            bad_type = self._run("parse", "1", *values, "1")
            self.assertEqual(bad_type.stdout.strip(), "ERROR_PARSE")

    def test_decide_skips_acl(self) -> None:
        skip = self._run(
            "decide", "1", DEFAULT_SID, "luci", "setPassword", "1", "luci", "getFeatures"
        )
        self.assertEqual(skip.stdout.strip(), "ALLOW")
        control = self._run(
            "decide", "0", DEFAULT_SID, "luci", "setPassword", "1", "luci", "getFeatures"
        )
        self.assertEqual(control.stdout.strip(), "DENY")
        unknown = self._run(
            "decide", "1", UNKNOWN_SID, "luci", "setPassword", "1", "luci", "getFeatures"
        )
        self.assertEqual(unknown.stdout.strip(), "ALLOW")
        missing = self._run(
            "decide", "1", "-", "luci", "getFeatures", "1", "luci", "getFeatures"
        )
        self.assertEqual(missing.stdout.strip(), "ERROR_PARSE")
        parse = self._run(
            "decide", "1", DEFAULT_SID, "luci", "getFeatures", "0", "luci", "getFeatures"
        )
        self.assertEqual(parse.stdout.strip(), "ERROR_PARSE")
        unknown_object = self._run(
            "decide", "1", "", "nonexistent.object", "method", "1", "luci", "getFeatures", "0"
        )
        self.assertEqual(unknown_object.stdout.strip(), "ERROR_OBJECT")


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        bundle = build_artifacts()
        committed = json.loads(
            (REPO / "policy" / "no_ubusauth_decisions.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed, bundle)
        self.assertEqual(committed["grants"], [])

    def test_canonical_grants_json_unchanged_by_this_profile(self) -> None:
        luci_grants, _bundle = luci_build_artifacts()
        committed = json.loads((REPO / "policy" / "grants.json").read_text(encoding="utf-8"))
        for grant in luci_grants:
            self.assertIn(grant, committed)
        blob = json.dumps(committed)
        self.assertNotIn(PROFILE, blob)
        self.assertNotIn("policy:no-ubusauth-v1", blob)
        self.assertNotIn(
            "policy:grant:unauthenticated:ubus_http:luci.setPassword", blob
        )


if __name__ == "__main__":
    unittest.main()
