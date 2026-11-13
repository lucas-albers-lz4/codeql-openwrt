#!/usr/bin/env python3
"""ubus file.exec luci-mod-status iptables -Z / routes ip vs evaluator vs C double."""

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

from policy.cgi_exec_file import LOGS_SESSION_CLASS  # noqa: E402
from policy.cgi_exec_status import (  # noqa: E402
    FIREWALL_READ_SESSION_CLASS,
    FIREWALL_SESSION_CLASS,
)
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    ERROR_ACCESS,
    ERROR_PARSE,
    NETWORK_FIXTURE_SID,
    PRODUCER,
    build_artifacts as luci_build_artifacts,
    corpus_revision,
)
from policy.ubus_file_exec import (  # noqa: E402
    ANALYSIS_REVISION,
    COMMANDS,
    FILE_FUNCTION,
    IP,
    IPTABLES,
    RPCD_SHA,
    ROUTES_JSON_SESSION_CLASS,
    ROUTES_SESSION_CLASS,
    UBUS_METHOD,
    UBUS_OBJECT,
    UBUS_STATUS_INVALID_ARGUMENT,
    UBUS_STATUS_NOT_FOUND,
    UBUS_STATUS_OK,
    UBUS_STATUS_PERMISSION_DENIED,
    build_artifacts,
    evaluate_expected_case,
    evaluate_file_exec,
    grant_id,
    load_expected_cases,
    load_file_exec_world,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "ubus_file_exec.c"


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
        cls.sessions = load_file_exec_world()
        cls.grants, cls.bundle, cls.effects = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_iptables_z_deny(self) -> None:
        result = self._result("unauthenticated-iptables-z-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
        self.assertIsNone(result.ubus_matched)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn(grant_id("unauthenticated", "iptables"), grant_ids)

    def test_missing_sid_is_parse_error(self) -> None:
        result = self._result("missing-sid-parse-error")
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertIn("execv", self.cases["missing-sid-parse-error"]["not"])
        self.assertIn("path_found", self.cases["missing-sid-parse-error"]["not"])

    def test_firewall_iptables_z_allow_exact_cmdline(self) -> None:
        case = self.cases["luci-mod-status-firewall-iptables-z-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.ubus_status, UBUS_STATUS_OK)
        self.assertEqual(result.session_class, FIREWALL_SESSION_CLASS)
        self.assertEqual(result.command_id, "iptables")
        self.assertEqual(result.match_stage, "cmdline")
        self.assertEqual(result.file_matched.object, "/usr/sbin/iptables -Z")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")
        self.assertIn("not a PoC", case["note"])

    def test_extra_argv_and_bare_exe_are_denied(self) -> None:
        extra = self._result("luci-mod-status-firewall-iptables-z-extra-denied")
        self.assertEqual(extra.outcome, "command_denied")
        self.assertEqual(extra.ubus_status, UBUS_STATUS_PERMISSION_DENIED)
        self.assertIsNone(extra.match_stage)
        bare = self._result("luci-mod-status-firewall-iptables-bare-denied")
        self.assertEqual(bare.outcome, "command_denied")

    def test_ubus_file_exec_is_not_enough_without_file_acl(self) -> None:
        network = self._result("luci-mod-network-config-iptables-z-command-denied")
        self.assertEqual(network.outcome, "command_denied")
        self.assertIsNotNone(network.ubus_matched)
        self.assertEqual(network.ubus_matched.object, UBUS_OBJECT)
        self.assertIsNone(network.file_matched)
        routes = self._result("luci-mod-status-routes-iptables-z-command-denied")
        self.assertEqual(routes.outcome, "command_denied")
        self.assertEqual(network.sid, NETWORK_FIXTURE_SID)

    def test_read_firewall_and_logs_denied_at_http_gate(self) -> None:
        read = self._result("luci-mod-status-firewall-read-iptables-z-deny")
        self.assertEqual(read.outcome, "deny")
        self.assertEqual(read.session_class, FIREWALL_READ_SESSION_CLASS)
        self.assertEqual(read.jsonrpc_error, ERROR_ACCESS)
        logs = self._result("luci-mod-status-logs-iptables-z-deny")
        self.assertEqual(logs.outcome, "deny")
        self.assertEqual(logs.session_class, LOGS_SESSION_CLASS)

    def test_routes_ip_glob_is_intended_access(self) -> None:
        neigh = self._result("luci-mod-status-routes-ip-neigh-allow")
        self.assertEqual(neigh.outcome, "allow")
        self.assertEqual(neigh.match_stage, "cmdline")
        self.assertEqual(neigh.session_class, ROUTES_SESSION_CLASS)
        self.assertEqual(
            neigh.file_matched.object,
            "/sbin/ip -[46] neigh show",
        )
        route = self._result("luci-mod-status-routes-ip-route-allow")
        self.assertEqual(route.outcome, "allow")
        rule = self._result("luci-mod-status-routes-ip-rule-allow")
        self.assertEqual(rule.outcome, "allow")
        self.assertEqual(
            rule.file_matched.object,
            "/sbin/ip -[46] rule show",
        )
        case = self.cases["luci-mod-status-routes-ip-neigh-allow"]
        self.assertEqual(case["assessment"], "intended_access")
        self.assertIn("not a PoC", case["note"])

    def test_routes_and_routes_json_acls_do_not_cover_each_other(self) -> None:
        denied = self._result("luci-mod-status-routes-ip-json-command-denied")
        self.assertEqual(denied.outcome, "command_denied")
        allowed = self._result("luci-mod-status-routes-json-ip-json-allow")
        self.assertEqual(allowed.outcome, "allow")
        self.assertEqual(allowed.session_class, ROUTES_JSON_SESSION_CLASS)
        self.assertEqual(allowed.match_stage, "cmdline")
        plain = self._result("luci-mod-status-routes-json-plain-ip-command-denied")
        self.assertEqual(plain.outcome, "command_denied")

    def test_legacy_path_is_not_found(self) -> None:
        result = self._result("iptables-legacy-not-found")
        self.assertEqual(result.outcome, "not_found")
        self.assertEqual(result.ubus_status, UBUS_STATUS_NOT_FOUND)

    def test_env_with_sid_is_denied(self) -> None:
        result = self._result("env-with-sid-permission-denied")
        self.assertEqual(result.outcome, "command_denied")
        self.assertEqual(result.ubus_status, UBUS_STATUS_PERMISSION_DENIED)

    def test_empty_env_is_present_and_denied_before_lookup(self) -> None:
        result = self._result("empty-env-with-sid-permission-denied")
        self.assertEqual(result.outcome, "command_denied")
        self.assertEqual(result.ubus_status, UBUS_STATUS_PERMISSION_DENIED)
        self.assertEqual(result.steps[-1]["reason"], "sid_and_env")
        self.assertFalse(any(step["step"] == "rpc_file_exec_lookup" for step in result.steps))
        sid = self.cases["env-with-sid-permission-denied"]["sid"]
        not_a_table = evaluate_file_exec(sid=sid, command=IPTABLES, params=["-Z"], env=[])
        self.assertEqual(not_a_table.outcome, "allow")

    def test_rpc_exec_policy_and_string_argument_filtering(self) -> None:
        sid = self.cases["luci-mod-status-firewall-iptables-z-allow"]["sid"]
        for command in (None, 123, [IPTABLES], {"command": IPTABLES}):
            result = evaluate_file_exec(sid=sid, command=command, params=["-Z"])
            self.assertEqual(result.outcome, "invalid_argument")
            self.assertEqual(result.ubus_status, UBUS_STATUS_INVALID_ARGUMENT)
        empty = evaluate_file_exec(sid=sid, command="", params=["-Z"])
        self.assertEqual(empty.outcome, "not_found")
        self.assertEqual(empty.ubus_status, UBUS_STATUS_NOT_FOUND)
        filtered = evaluate_file_exec(
            sid=sid, command=IPTABLES, params=[None, "-Z", 42, {}, [], False]
        )
        self.assertEqual(filtered.outcome, "allow")
        self.assertEqual(filtered.params, ["-Z"])
        self.assertEqual(filtered.cmdline, "/usr/sbin/iptables -Z")

    def test_root_iptables_z_allow_not_violation(self) -> None:
        case = self.cases["root-star-iptables-z-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertEqual(case["expectation_id"], "root-administration")
        self.assertIn("not a violation", case["note"])

    def test_evaluator_matches_every_handwritten_outcome(self) -> None:
        for case in self.cases.values():
            result = self._result(case["id"])
            self.assertEqual(result.outcome, case["expected_outcome"], case["id"])
            self.assertEqual(
                bool(case["expect_grant"] and result.outcome == "allow"),
                case["expect_grant"],
                case["id"],
            )


class TestGrantsAndEffects(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grants, cls.bundle, cls.effects = build_artifacts()
        cls.luci_grants, cls.luci_bundle = luci_build_artifacts()

    def test_custom_root_revision_is_shared_by_all_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "corpus").mkdir()
            (root / "corpus" / "lock.json").write_bytes(
                (REPO / "corpus" / "lock.json").read_bytes() + b"\n"
            )
            grants, bundle, effects = build_artifacts(REPO / "policy" / "fixtures", root)
            revision = corpus_revision(root)
            self.assertNotEqual(revision, corpus_revision(REPO))
            self.assertEqual(bundle["corpus_revision"], revision)
            for row in [*grants, *bundle["decisions"], *effects]:
                self.assertEqual(row["corpus_revision"], revision, row["record_id"])

    def test_luci_emitter_is_unchanged(self) -> None:
        methods = {row["method"] for row in self.luci_grants}
        self.assertEqual(
            methods,
            {
                "getFeatures",
                "getSwconfigFeatures",
                "getSwconfigPortState",
                "getRealtimeStats",
                "setPassword",
                "setLocaltime",
                "getBlockDevices",
                "setBlockDetect",
                "getConntrackList",
                "getProcessList",
            },
        )
        blob = json.dumps(self.luci_grants)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("setInitAction", blob)
        self.assertNotIn("step4", json.dumps(self.luci_bundle))
        for row in self.luci_grants:
            self.assertEqual(row["ubus_object"], "luci")
            self.assertNotEqual(row["method"], UBUS_METHOD)
            self.assertFalse(row["entrypoint_id"].startswith("ubus_http:file.exec:"))

    def test_file_exec_grants_are_ubus_file_only(self) -> None:
        self.assertEqual(len(self.grants), 8)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(
            classes,
            {FIREWALL_SESSION_CLASS, ROUTES_SESSION_CLASS, ROUTES_JSON_SESSION_CLASS, "root"},
        )
        self.assertNotIn(FIREWALL_READ_SESSION_CLASS, classes)
        entrypoints = {row["entrypoint_id"] for row in self.grants}
        self.assertEqual(entrypoints, {spec["entrypoint_id"] for spec in COMMANDS.values()})
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertEqual(row["ubus_object"], UBUS_OBJECT)
            self.assertEqual(row["method"], UBUS_METHOD)
            self.assertEqual(row["op"], "exec")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotIn("cgi_endpoint", row)
            self.assertNotEqual(row["assessment"], "authorization_violation")
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-backup", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("path_found", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))
        self.assertNotIn("/usr/libexec/syslog-wrapper", blob)

    def test_effects_are_synthetic_file_exec(self) -> None:
        self.assertEqual(len(self.effects), 4)
        by_id = {row["record_id"].rsplit(":", 1)[-1]: row for row in self.effects}
        self.assertEqual(set(by_id), set(COMMANDS))
        for command_id, effect in by_id.items():
            spec = COMMANDS[command_id]
            for key in REQUIRED:
                self.assertIn(key, effect, key)
            self.assertEqual(effect["producer"], PRODUCER)
            self.assertEqual(effect["record_type"], "handler_effect")
            self.assertEqual(effect["evidence_status"], "fact")
            self.assertNotEqual(effect["evidence_status"], "path_found")
            self.assertEqual(effect["ingress"], "ubus_http")
            self.assertEqual(effect["ubus_object"], UBUS_OBJECT)
            self.assertEqual(effect["method"], UBUS_METHOD)
            self.assertEqual(effect["sink_kind"], "file_exec")
            self.assertEqual(effect["op"], "exec")
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertIn(grant_id(spec["delegated"], command_id), effect["evidence_refs"])
            self.assertIn(grant_id("root", command_id), effect["evidence_refs"])
            text = " ".join(effect["assumptions"]).lower()
            self.assertIn("shellquote", text)
            self.assertIn("basename", text)
            self.assertIn("not sanitizers", text)
            self.assertIn("execv", text)
            self.assertNotIn("path_found", json.dumps(effect))
            self.assertNotIn("cgi_endpoint", effect)


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "ubus_file_exec")

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

    def test_parse_and_canon(self) -> None:
        missing = self._run("parse", "-", UBUS_OBJECT, UBUS_METHOD, "{}")
        self.assertEqual(missing.stdout.strip(), "ERROR_PARSE")
        ok = self._run("parse", "55555555555555555555555555555555", UBUS_OBJECT, UBUS_METHOD, "{}")
        self.assertEqual(ok.stdout.strip(), "PARSE_OK")
        canon = self._run("canon", "/usr/sbin/../sbin/iptables")
        self.assertEqual(canon.stdout.strip(), IPTABLES)

    def test_decide_conjunctive_file_acl(self) -> None:
        allow = self._run(
            "decide",
            "55555555555555555555555555555555",
            IPTABLES,
            "-Z",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "/usr/sbin/iptables -Z",
            FILE_FUNCTION,
        )
        glob_allow = self._run(
            "decide",
            "77777777777777777777777777777777",
            IP,
            "-4 neigh show",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "/sbin/ip -[46] neigh show",
            FILE_FUNCTION,
        )
        no_ubus = self._run(
            "decide",
            "00000000000000000000000000000000",
            IPTABLES,
            "-Z",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
        )
        denied = self._run(
            "decide",
            NETWORK_FIXTURE_SID,
            IPTABLES,
            "-Z",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "-",
            "-",
        )
        missing = self._run(
            "decide",
            "55555555555555555555555555555555",
            "/usr/sbin/iptables-legacy",
            "-Z",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "-",
            "-",
        )
        extra = self._run(
            "decide",
            "55555555555555555555555555555555",
            IPTABLES,
            "-Z extra",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "/usr/sbin/iptables -Z",
            FILE_FUNCTION,
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(glob_allow.stdout.strip(), "ALLOW")
        self.assertEqual(no_ubus.stdout.strip(), "ERROR_ACCESS")
        self.assertEqual(denied.stdout.strip(), "UBUS_PERMISSION_DENIED")
        self.assertEqual(missing.stdout.strip(), "UBUS_NOT_FOUND")
        self.assertEqual(extra.stdout.strip(), "UBUS_PERMISSION_DENIED")

    def test_empty_env_presence_is_denied(self) -> None:
        args = (
            "decide", "55555555555555555555555555555555", IPTABLES, "-Z",
            UBUS_OBJECT, UBUS_METHOD, "-", "-", "/usr/sbin/iptables -Z", FILE_FUNCTION,
        )
        self.assertEqual(self._run(*args, "1").stdout.strip(), "UBUS_PERMISSION_DENIED")
        self.assertEqual(self._run(*args, "0").stdout.strip(), "ALLOW")
        # The HTTP ingress rejects a missing SID before the rpcd env guard.
        no_sid_args = (args[0], "-", *args[2:])
        self.assertEqual(self._run(*no_sid_args, "1").stdout.strip(), "ERROR_PARSE")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"RPCD_SHA={RPCD_SHA}", proc.stdout)
        self.assertIn("UBUS_OBJECT=file", proc.stdout)
        self.assertIn("UBUS_METHOD=exec", proc.stdout)
        self.assertIn("FILE_FUNCTION=exec", proc.stdout)
        self.assertNotIn("cgi-backup", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effects = build_artifacts()
        committed = json.loads((REPO / "policy" / "ubus_file_exec_decisions.json").read_text(encoding="utf-8"))
        committed_effect = json.loads(
            (REPO / "reports" / "m2-ubus-file-exec-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed, {"grants": grants, **bundle})
        self.assertEqual(committed_effect, effects)

    def test_canonical_grants_json_includes_file_exec_grants(self) -> None:
        grants, _, effects = build_artifacts()
        committed = json.loads((REPO / "policy" / "grants.json").read_text(encoding="utf-8"))
        catalog = json.loads((REPO / "reports" / "handler_effects.json").read_text(encoding="utf-8"))
        for grant in grants:
            self.assertIn(grant, committed)
        for effect in effects:
            catalog_effect = next(row for row in catalog if row["record_id"] == effect["record_id"])
            self.assertEqual(catalog_effect, effect)
        self.assertNotIn("path_found", json.dumps(grants))


if __name__ == "__main__":
    unittest.main()
