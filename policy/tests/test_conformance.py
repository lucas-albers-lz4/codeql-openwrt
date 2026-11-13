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
    ANALYSIS_REVISION,
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    EMITTED_METHODS,
    ERROR_ACCESS,
    ERROR_PARSE,
    EXEC_METHODS,
    FIXED_EXEC_METHODS,
    MOUNTS_FIXTURE_SID,
    NETWORK_FIXTURE_SID,
    PRODUCER,
    PROCESSES_FIXTURE_SID,
    REQUEST_ARGS_EXEC_METHODS,
    ROOT_FIXTURE_SID,
    STATUS_FIXTURE_SID,
    SYSTEM_FIXTURE_SID,
    SYNTHETIC_SESSION_CLASSES,
    acl_match,
    build_artifacts,
    corpus_revision,
    emit_artifacts,
    evaluate_call,
    evaluate_expected_case,
    grant_record,
    load_acl_catalog,
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
        self.assertNotIn("policy:grant:unauthenticated:ubus_http:luci.setPassword", grant_ids)

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

    def test_unauthenticated_exec_methods_deny(self) -> None:
        for method in EXEC_METHODS:
            case_id = f"unauthenticated-{method}-deny"
            with self.subTest(method=method):
                result = self._result(case_id)
                self.assertEqual(result.outcome, "deny")
                self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
                self.assertIsNone(result.matched)
                self.assertFalse(self.cases[case_id]["expect_grant"])
                grant_ids = [row["record_id"] for row in self.grants]
                self.assertNotIn(
                    f"policy:grant:unauthenticated:ubus_http:luci.{method}", grant_ids
                )

    def test_delegated_exec_methods_allow(self) -> None:
        expected = {
            "getSwconfigFeatures": (
                "luci-mod-network-config",
                NETWORK_FIXTURE_SID,
                "luci-mod-network.json",
            ),
            "getSwconfigPortState": (
                "luci-mod-network-config",
                NETWORK_FIXTURE_SID,
                "luci-mod-network.json",
            ),
            "getRealtimeStats": (
                "luci-mod-status-realtime",
                STATUS_FIXTURE_SID,
                "luci-mod-status.json",
            ),
            "setPassword": (
                "luci-mod-system-config",
                SYSTEM_FIXTURE_SID,
                "luci-mod-system.json",
            ),
            "setLocaltime": (
                "luci-mod-system-config",
                SYSTEM_FIXTURE_SID,
                "luci-mod-system.json",
            ),
            "getBlockDevices": (
                "luci-mod-system-mounts",
                MOUNTS_FIXTURE_SID,
                "luci-mod-system.json",
            ),
            "setBlockDetect": (
                "luci-mod-system-mounts",
                MOUNTS_FIXTURE_SID,
                "luci-mod-system.json",
            ),
            "getConntrackList": (
                "luci-mod-status-realtime",
                STATUS_FIXTURE_SID,
                "luci-mod-status.json",
            ),
            "getProcessList": (
                "luci-mod-status-processes",
                PROCESSES_FIXTURE_SID,
                "luci-mod-status.json",
            ),
        }
        for method, (session_class, sid, source) in expected.items():
            with self.subTest(method=method):
                result = self._result(f"{session_class}-{method}-allow")
                self.assertEqual(result.outcome, "allow")
                self.assertEqual(result.session_class, session_class)
                self.assertEqual(result.sid, sid)
                self.assertIsNotNone(result.matched)
                self.assertEqual(result.matched.object, "luci")
                self.assertEqual(result.matched.function, method)
                self.assertEqual(result.matched.group, session_class)
                self.assertEqual(result.matched.source, source)
                self.assertEqual(
                    self.cases[f"{session_class}-{method}-allow"]["assessment"],
                    "intended_access",
                )

    def test_root_exec_methods_allow_not_violation(self) -> None:
        for method in EXEC_METHODS:
            with self.subTest(method=method):
                case = self.cases[f"root-star-{method}-allow"]
                result = self._result(case["id"])
                self.assertEqual(result.outcome, "allow")
                self.assertEqual(result.session_class, "root")
                self.assertEqual(result.sid, ROOT_FIXTURE_SID)
                self.assertIsNotNone(result.matched)
                self.assertEqual(result.matched.function, method)
                self.assertEqual(case["assessment"], "intended_access")
                self.assertEqual(case["expectation_id"], "root-administration")
                self.assertIn("not a violation", case["note"])
                self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_delegated_sessions_do_not_cross_grant(self) -> None:
        network = self.sessions[NETWORK_FIXTURE_SID]
        status = self.sessions[STATUS_FIXTURE_SID]
        system = self.sessions[SYSTEM_FIXTURE_SID]
        mounts = self.sessions[MOUNTS_FIXTURE_SID]
        processes = self.sessions[PROCESSES_FIXTURE_SID]
        self.assertEqual(
            evaluate_call(
                sid=network.sid, object="luci", function="setPassword", data={}, sessions=self.sessions
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=status.sid,
                object="luci",
                function="getSwconfigFeatures",
                data={},
                sessions=self.sessions,
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=system.sid,
                object="luci",
                function="getRealtimeStats",
                data={},
                sessions=self.sessions,
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=network.sid, object="luci", function="getFeatures", data={}, sessions=self.sessions
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=mounts.sid, object="luci", function="setPassword", data={}, sessions=self.sessions
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=system.sid,
                object="luci",
                function="getBlockDevices",
                data={},
                sessions=self.sessions,
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=processes.sid,
                object="luci",
                function="getRealtimeStats",
                data={},
                sessions=self.sessions,
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=status.sid,
                object="luci",
                function="getProcessList",
                data={},
                sessions=self.sessions,
            ).outcome,
            "deny",
        )
        self.assertEqual(
            evaluate_call(
                sid=processes.sid,
                object="file",
                function="exec",
                data={},
                sessions=self.sessions,
            ).outcome,
            "deny",
        )

    def test_supplied_class_must_match_known_sid(self) -> None:
        for supplied, sid in (
            ("unauthenticated", ROOT_FIXTURE_SID),
            ("root", NETWORK_FIXTURE_SID),
            ("luci-mod-network-config", STATUS_FIXTURE_SID),
            ("luci-mod-system-config", DEFAULT_SID),
        ):
            with self.subTest(supplied=supplied, sid=sid):
                with self.assertRaisesRegex(ValueError, "does not match SID session"):
                    evaluate_call(session_class=supplied, sid=sid, data={}, sessions=self.sessions)

        unknown = evaluate_call(session_class="root", sid="f" * 32, data={}, sessions=self.sessions)
        self.assertEqual(unknown.outcome, "deny")
        self.assertIsNone(unknown.session_class)
        missing = evaluate_call(session_class="root", sid=None, data={}, sessions=self.sessions)
        self.assertEqual(missing.outcome, "jsonrpc_parse_error")

    def test_grant_rejects_case_identity_not_evaluated_identity(self) -> None:
        case = dict(self.cases["root-star-setPassword-allow"])
        result = self._result(case["id"])
        case["session_class"] = "unauthenticated"
        with self.assertRaisesRegex(ValueError, "does not match evaluated SID session"):
            grant_record(case, result)

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
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotEqual(row["analysis_revision"], "policy:ubus-getfeatures-v1")
            self.assertIn(row["record_type"], SCHEMA["properties"]["record_type"]["enum"])
            self.assertIn(row["evidence_status"], SCHEMA["properties"]["evidence_status"]["enum"])

    def test_grants_keep_getfeatures_and_emit_inventoried_exec_methods(self) -> None:
        methods = {row["method"] for row in self.grants}
        self.assertEqual(methods, set(EMITTED_METHODS))
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(
            classes,
            {
                "unauthenticated",
                "root",
                "luci-mod-network-config",
                "luci-mod-status-realtime",
                "luci-mod-system-config",
                "luci-mod-system-mounts",
                "luci-mod-status-processes",
            },
        )
        getfeatures = [row for row in self.grants if row["method"] == "getFeatures"]
        self.assertEqual(len(getfeatures), 2)
        self.assertEqual({row["session_class"] for row in getfeatures}, {"unauthenticated", "root"})
        delegated_ids = {
            "policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigFeatures",
            "policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigPortState",
            "policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats",
            "policy:grant:luci-mod-system-config:ubus_http:luci.setPassword",
            "policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime",
            "policy:grant:luci-mod-system-mounts:ubus_http:luci.getBlockDevices",
            "policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect",
            "policy:grant:luci-mod-status-realtime:ubus_http:luci.getConntrackList",
            "policy:grant:luci-mod-status-processes:ubus_http:luci.getProcessList",
        }
        record_ids = {row["record_id"] for row in self.grants}
        self.assertTrue(delegated_ids <= record_ids)
        self.assertEqual(set(REQUEST_ARGS_EXEC_METHODS) | set(FIXED_EXEC_METHODS), set(EXEC_METHODS))
        blob = json.dumps(self.grants)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("cgi-io", blob)
        self.assertNotIn("hostapd", blob)
        self.assertNotIn("setInitAction", blob)
        self.assertNotIn('"ubus_object": "file"', blob)
        for row in self.grants:
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["evidence_status"], "fact")
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertEqual(row["ubus_object"], "luci")
            self.assertIn(row["method"], EMITTED_METHODS)
            self.assertEqual(row["op"], "invoke")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["target_id"], f"ubus:luci.{row['method']}")
            self.assertEqual(row["entrypoint_id"], f"ubus_http:luci.{row['method']}")
            if row["method"] in EXEC_METHODS:
                self.assertNotEqual(row["session_class"], "unauthenticated")

    def test_decisions_cover_handwritten_cases(self) -> None:
        ids = [row["record_id"] for row in self.bundle["decisions"]]
        expected = [f"policy:decision:{case['id']}" for case in load_expected_cases()]
        self.assertEqual(ids, expected)
        parse = next(row for row in self.bundle["decisions"] if row["outcome"] == "jsonrpc_parse_error")
        self.assertEqual(parse["jsonrpc_error"]["code"], -32700)
        self.assertIn("unauthenticated_allow", parse["not"])
        self.assertIn(UNKNOWN_SNIPPET, " ".join(parse["unknowns"]))
        assessments = {row.get("assessment") for row in self.bundle["decisions"]}
        self.assertNotIn("authorization_violation", assessments)

    def test_fixture_roles_are_marked_synthetic(self) -> None:
        for row in self.grants + self.bundle["decisions"]:
            with self.subTest(record_id=row["record_id"]):
                self.assertEqual(
                    row.get("synthetic_session", False),
                    row.get("session_class") in SYNTHETIC_SESSION_CLASSES,
                )
        findings = json.loads((REPO / "reports" / "m4-findings.json").read_text())
        for row in findings:
            with self.subTest(record_id=row["record_id"]):
                self.assertIn(row["method"], REQUEST_ARGS_EXEC_METHODS)
                self.assertIn(row["session_class"], SYNTHETIC_SESSION_CLASSES)
                self.assertIs(row.get("synthetic_session"), True)

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

    def test_no_ubusauth_one_rewrites_empty_sid(self) -> None:
        sid, *_rest, rewritten, err = parse_call_params("", "luci", "getFeatures", {}, 1)
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

    def test_literal_exec_methods_match_own_grant_only(self) -> None:
        for method in EXEC_METHODS:
            with self.subTest(method=method):
                self.assertTrue(acl_match("luci", method, "luci", method))
                self.assertFalse(acl_match("luci", "getFeatures", "luci", method))

    def test_uci_set_does_not_match_luci_grant(self) -> None:
        self.assertFalse(acl_match("luci", "getFeatures", "uci", "set"))

    def test_root_star_matches_unauthenticated_group(self) -> None:
        from policy.oracle import Login

        root = Login(username="root", read=["*"], write=["*"])
        self.assertTrue(login_test_permission(root, "read", "unauthenticated"))
        self.assertTrue(login_test_permission(None, "read", "unauthenticated"))
        self.assertFalse(login_test_permission(None, "read", "luci-base"))
        self.assertTrue(login_test_permission(root, "read", "luci-mod-network-config"))
        self.assertTrue(login_test_permission(root, "write", "luci-mod-system-config"))
        self.assertTrue(login_test_permission(root, "write", "luci-mod-system-mounts"))
        network = Login(username="luci-mod-network-config", read=["luci-mod-network-config"])
        self.assertTrue(login_test_permission(network, "read", "luci-mod-network-config"))
        self.assertFalse(login_test_permission(network, "write", "luci-mod-system-config"))
        mounts = Login(
            username="luci-mod-system-mounts",
            read=["luci-mod-system-mounts"],
            write=["luci-mod-system-mounts"],
        )
        self.assertTrue(login_test_permission(mounts, "read", "luci-mod-system-mounts"))
        self.assertTrue(login_test_permission(mounts, "write", "luci-mod-system-mounts"))
        self.assertFalse(login_test_permission(mounts, "write", "luci-mod-system-config"))
        processes = Login(
            username="luci-mod-status-processes",
            read=["luci-mod-status-processes"],
        )
        self.assertTrue(login_test_permission(processes, "read", "luci-mod-status-processes"))
        self.assertFalse(login_test_permission(processes, "write", "luci-mod-status-processes"))

    def test_acl_catalog_loads_module_files_without_setinitaction(self) -> None:
        catalog = load_acl_catalog()
        by_fun = {(entry.group, entry.object, entry.function): entry for entry in catalog}
        self.assertIn(("luci-mod-network-config", "luci", "getSwconfigFeatures"), by_fun)
        self.assertIn(("luci-mod-network-config", "luci", "getSwconfigPortState"), by_fun)
        self.assertIn(("luci-mod-status-realtime", "luci", "getRealtimeStats"), by_fun)
        self.assertIn(("luci-mod-system-config", "luci", "setPassword"), by_fun)
        self.assertIn(("luci-mod-system-config", "luci", "setLocaltime"), by_fun)
        self.assertIn(("luci-mod-system-mounts", "luci", "getBlockDevices"), by_fun)
        self.assertIn(("luci-mod-system-mounts", "luci", "setBlockDetect"), by_fun)
        self.assertIn(("luci-mod-status-realtime", "luci", "getConntrackList"), by_fun)
        self.assertIn(("luci-mod-status-processes", "luci", "getProcessList"), by_fun)
        self.assertTrue(any(entry.object == "file" and entry.function == "exec" for entry in catalog))
        self.assertTrue(any(entry.scope == "cgi-io" for entry in catalog))
        self.assertTrue(any(entry.object == "hostapd.*" for entry in catalog))
        self.assertFalse(any(entry.function == "setInitAction" for entry in catalog))

    def test_ubus_wildcard_object_hostapd_dot_star(self) -> None:
        """Pinned luci-mod-network write ubus hostapd.* / del_client (FNM_NOESCAPE)."""
        self.assertTrue(
            acl_match("hostapd.*", "del_client", "hostapd.wlan0", "del_client")
        )
        self.assertFalse(acl_match("hostapd.*", "del_client", "hostapd", "del_client"))
        self.assertFalse(acl_match("hostapd.*", "del_client", "hostapd.wlan0", "scan"))

    def test_uh_id_len_prefix_rejects_before_fnmatch(self) -> None:
        self.assertFalse(acl_match("lucix*", "getFeatures", "luci", "getFeatures"))


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

    def test_match_and_decide_exec_methods(self) -> None:
        for method in EXEC_METHODS:
            with self.subTest(method=method):
                own = self._run("match", "luci", method, "luci", method)
                unauth_grant = self._run("match", "luci", "getFeatures", "luci", method)
                self.assertEqual(own.stdout.strip(), "ALLOW")
                self.assertEqual(unauth_grant.stdout.strip(), "DENY")
                deny = self._run(
                    "decide", "0", DEFAULT_SID, "luci", method, "1", "luci", "getFeatures"
                )
                allow = self._run(
                    "decide", "0", DEFAULT_SID, "luci", method, "1", "luci", method
                )
                self.assertEqual(deny.stdout.strip(), "DENY")
                self.assertEqual(allow.stdout.strip(), "ALLOW")

    def test_match_ubus_wildcard_object(self) -> None:
        allow = self._run("match", "hostapd.*", "del_client", "hostapd.wlan0", "del_client")
        deny_obj = self._run("match", "hostapd.*", "del_client", "hostapd", "del_client")
        deny_fun = self._run("match", "hostapd.*", "del_client", "hostapd.wlan0", "scan")
        prefix = self._run("match", "lucix*", "getFeatures", "luci", "getFeatures")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(deny_obj.stdout.strip(), "DENY")
        self.assertEqual(deny_fun.stdout.strip(), "DENY")
        self.assertEqual(prefix.stdout.strip(), "DENY")

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
        network = self._run("group", "*", "luci-mod-network-config")
        exact = self._run("group", "luci-mod-network-config", "luci-mod-network-config")
        miss = self._run("group", "luci-mod-network-config", "luci-mod-system-config")
        self.assertEqual(network.stdout.strip(), "MATCH")
        self.assertEqual(exact.stdout.strip(), "MATCH")
        self.assertEqual(miss.stdout.strip(), "NO_MATCH")

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
        self.assertEqual(committed_grants[: len(grants)], grants)
        self.assertEqual(committed_decisions, bundle)
        tail = committed_grants[len(grants) :]
        cgi_rows = [row for row in tail if row.get("ingress") == "cgi_io"]
        file_exec_rows = [
            row for row in tail if row.get("ubus_object") == "file" and row.get("method") == "exec"
        ]
        self.assertEqual(len(cgi_rows) + len(file_exec_rows), len(tail))
        cgi_endpoints = {row["cgi_endpoint"] for row in cgi_rows}
        for row in cgi_rows:
            self.assertEqual(row["ingress"], "cgi_io")
            self.assertIn(
                row["cgi_endpoint"],
                {"cgi-backup", "cgi-upload", "cgi-download", "cgi-exec"},
            )
        self.assertEqual(
            cgi_endpoints,
            {"cgi-backup", "cgi-upload", "cgi-download", "cgi-exec"},
        )
        self.assertTrue(file_exec_rows)
        for row in file_exec_rows:
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertIn(
                row["analysis_revision"],
                {
                    "policy:ubus-file-exec-v1",
                    "policy:ubus-file-exec-ifup-v1",
                    "policy:ubus-file-exec-kill-v1",
                    "policy:ubus-file-exec-mounts-v1",
                    "policy:ubus-file-exec-list-backup-v1",
                },
            )
            self.assertNotIn("cgi_endpoint", row)

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
