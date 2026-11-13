#!/usr/bin/env python3
"""cgi-exec luci-mod-status file.exec conformance vs evaluator vs C double."""

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

from policy.cgi_exec_file import (  # noqa: E402
    CGI_FUNCTION,
    CGI_OBJECT,
    CGI_SCOPE,
    CONTENT_TYPE_PREFIX,
    FILE_FUNCTION,
    LOGS_FIXTURE_SID,
    LOGS_SESSION_CLASS,
    parse_command,
)
from policy.cgi_exec_status import (  # noqa: E402
    ANALYSIS_REVISION,
    CGI_ENDPOINT,
    CGI_IO_SHA,
    COMMANDS,
    DMESG,
    FIREWALL_FIXTURE_SID,
    FIREWALL_INIT,
    FIREWALL_READ_SESSION_CLASS,
    FIREWALL_READ_SID,
    FIREWALL_SESSION_CLASS,
    IPTABLES,
    NFT,
    build_artifacts,
    evaluate_expected_case,
    grant_id,
    load_expected_cases,
    load_status_world,
)
from policy.cgi_upload import canonicalize_path  # noqa: E402
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    NETWORK_FIXTURE_SID,
    PRODUCER,
    build_artifacts as luci_build_artifacts,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "cgi_exec_status.c"


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
        cls.sessions = load_status_world()
        cls.grants, cls.bundle, cls.effects = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_dmesg_deny(self) -> None:
        result = self._result("unauthenticated-dmesg-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertIsNone(result.cgi_matched)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn(grant_id("unauthenticated", DMESG), grant_ids)

    def test_missing_sessionid_is_forbidden_not_bad_request(self) -> None:
        result = self._result("missing-sessionid-nft-forbidden")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertNotEqual(result.http_status, 400)
        self.assertIn("execv", self.cases["missing-sessionid-nft-forbidden"]["not"])
        self.assertIn("path_found", self.cases["missing-sessionid-nft-forbidden"]["not"])

    def test_logs_dmesg_allow_exact_cmdline(self) -> None:
        case = self.cases["luci-mod-status-logs-dmesg-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.session_class, LOGS_SESSION_CLASS)
        self.assertEqual(result.helper, DMESG)
        self.assertEqual(result.match_stage, "cmdline")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_dmesg_extra_argv_is_denied_without_bare_exe(self) -> None:
        result = self._result("luci-mod-status-logs-dmesg-extra-argv-denied")
        self.assertEqual(result.outcome, "command_denied")
        self.assertIsNone(result.match_stage)
        extra = self._result("luci-mod-status-firewall-iptables-bare-denied")
        self.assertEqual(extra.outcome, "command_denied")

    def test_cgi_io_exec_is_not_enough_without_file_acl(self) -> None:
        logs_nft = self._result("luci-mod-status-logs-nft-command-denied")
        self.assertEqual(logs_nft.outcome, "command_denied")
        self.assertIsNotNone(logs_nft.cgi_matched)
        self.assertEqual(logs_nft.cgi_matched.scope, CGI_SCOPE)
        self.assertIsNone(logs_nft.file_matched)
        network = self._result("luci-mod-network-config-dmesg-command-denied")
        self.assertEqual(network.outcome, "command_denied")

    def test_iptables_glob_is_intended_access(self) -> None:
        case = self.cases["luci-mod-status-firewall-iptables-glob-extra-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.match_stage, "cmdline")
        self.assertEqual(
            result.file_matched.object,
            "/usr/sbin/iptables --line-numbers -w -nvxL -t *",
        )
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")
        self.assertIn("not a PoC", case["note"])

    def test_read_fixture_cannot_restart_firewall(self) -> None:
        denied = self._result("luci-mod-status-firewall-read-restart-command-denied")
        self.assertEqual(denied.outcome, "command_denied")
        self.assertEqual(denied.session_class, FIREWALL_READ_SESSION_CLASS)
        allowed = self._result("luci-mod-status-firewall-restart-allow")
        self.assertEqual(allowed.outcome, "allow")
        self.assertEqual(allowed.session_class, FIREWALL_SESSION_CLASS)
        self.assertEqual(allowed.helper, FIREWALL_INIT)

    def test_legacy_save_is_not_found(self) -> None:
        result = self._result("iptables-legacy-save-not-found")
        self.assertEqual(result.outcome, "not_found")
        self.assertEqual(result.http_status, 404)

    def test_root_nft_allow_not_violation(self) -> None:
        case = self.cases["root-star-nft-allow"]
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
            self.assertEqual(result.http_status, case["http_status"], case["id"])
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
        self.assertNotIn("dmesg", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("setInitAction", blob)
        self.assertNotIn("step4", json.dumps(self.luci_bundle))

    def test_status_grants_are_file_exec_only(self) -> None:
        self.assertEqual(len(self.grants), 14)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(
            classes,
            {LOGS_SESSION_CLASS, FIREWALL_SESSION_CLASS, "root"},
        )
        self.assertNotIn(FIREWALL_READ_SESSION_CLASS, classes)
        helpers = {row["fs_path"] for row in self.grants}
        self.assertEqual(helpers, set(COMMANDS))
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["ingress"], "cgi_io")
            self.assertEqual(row["cgi_endpoint"], CGI_ENDPOINT)
            self.assertTrue(row["entrypoint_id"].startswith(f"cgi_io:{CGI_ENDPOINT}:"))
            self.assertEqual(row["op"], "exec")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotIn("ubus_object", row)
            self.assertNotIn("method", row)
            self.assertNotEqual(row["assessment"], "authorization_violation")
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-backup", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("path_found", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))
        self.assertNotIn("/usr/libexec/syslog-wrapper", blob)

    def test_effects_are_synthetic_file_exec(self) -> None:
        self.assertEqual(len(self.effects), 7)
        by_path = {row["fs_path"]: row for row in self.effects}
        self.assertEqual(set(by_path), set(COMMANDS))
        for fs_path, effect in by_path.items():
            spec = COMMANDS[fs_path]
            for key in REQUIRED:
                self.assertIn(key, effect, key)
            self.assertEqual(effect["producer"], PRODUCER)
            self.assertEqual(effect["record_type"], "handler_effect")
            self.assertEqual(effect["evidence_status"], "fact")
            self.assertNotEqual(effect["evidence_status"], "path_found")
            self.assertEqual(effect["ingress"], "cgi_io")
            self.assertEqual(effect["cgi_endpoint"], CGI_ENDPOINT)
            self.assertEqual(effect["sink_kind"], "file_exec")
            self.assertEqual(effect["op"], "exec")
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertIn(grant_id(spec["delegated"], fs_path), effect["evidence_refs"])
            self.assertIn(grant_id("root", fs_path), effect["evidence_refs"])
            text = " ".join(effect["assumptions"]).lower()
            self.assertIn("shellquote", text)
            self.assertIn("basename", text)
            self.assertIn("not sanitizers", text)
            self.assertIn("execv", text)
            self.assertNotIn("path_found", json.dumps(effect))

    def test_parse_command_and_canonicalize(self) -> None:
        self.assertEqual(parse_command("/bin/dmesg -r"), [DMESG, "-r"])
        self.assertEqual(
            parse_command("/usr/sbin/iptables --line-numbers -w -nvxL -t filter"),
            [IPTABLES, "--line-numbers", "-w", "-nvxL", "-t", "filter"],
        )
        self.assertEqual(
            canonicalize_path("/usr/sbin/../sbin/nft"),
            NFT,
        )


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "cgi_exec_status")

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
        bad = self._run("parse", "application/json", LOGS_FIXTURE_SID)
        self.assertEqual(bad.stdout.strip(), "HTTP_400")
        missing = self._run("parse", CONTENT_TYPE_PREFIX, "-")
        self.assertEqual(missing.stdout.strip(), "HTTP_403")
        ok = self._run("parse", CONTENT_TYPE_PREFIX, LOGS_FIXTURE_SID)
        self.assertEqual(ok.stdout.strip(), "PARSE_OK")
        canon = self._run("canon", "/usr/sbin/../sbin/nft")
        self.assertEqual(canon.stdout.strip(), NFT)

    def test_decide_conjunctive_file_acl(self) -> None:
        allow = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            LOGS_FIXTURE_SID,
            "/bin/dmesg -r",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            "/bin/dmesg -r",
            FILE_FUNCTION,
            "-",
            "-",
        )
        glob_allow = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            FIREWALL_FIXTURE_SID,
            "/usr/sbin/iptables --line-numbers -w -nvxL -t filter extra",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            "/usr/sbin/iptables --line-numbers -w -nvxL -t *",
            FILE_FUNCTION,
            "-",
            "-",
        )
        denied = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            LOGS_FIXTURE_SID,
            "/usr/sbin/nft --terse --json list ruleset",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            "-",
            "-",
            "-",
            "-",
        )
        missing = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            FIREWALL_FIXTURE_SID,
            "/usr/sbin/iptables-legacy-save",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            "-",
            "-",
            "-",
            "-",
        )
        restart_denied = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            FIREWALL_READ_SID,
            "/etc/init.d/firewall restart",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            "-",
            "-",
            "-",
            "-",
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(glob_allow.stdout.strip(), "ALLOW")
        self.assertEqual(denied.stdout.strip(), "HTTP_403")
        self.assertEqual(missing.stdout.strip(), "HTTP_404")
        self.assertEqual(restart_denied.stdout.strip(), "HTTP_403")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"CGI_IO_SHA={CGI_IO_SHA}", proc.stdout)
        self.assertIn("FILE_SCOPE=file", proc.stdout)
        self.assertIn("FILE_FUNCTION=exec", proc.stdout)
        self.assertNotIn("cgi-backup", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effects = build_artifacts()
        committed = json.loads((REPO / "policy" / "cgi_exec_status_decisions.json").read_text(encoding="utf-8"))
        committed_effect = json.loads(
            (REPO / "reports" / "m2-cgi-exec-status-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed, {"grants": grants, **bundle})
        self.assertEqual(committed_effect, effects)

    def test_canonical_grants_json_includes_status_grants(self) -> None:
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
