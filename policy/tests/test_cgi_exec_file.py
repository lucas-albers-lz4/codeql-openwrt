#!/usr/bin/env python3
"""cgi-exec file.exec conformance: handwritten cases vs evaluator vs C double."""

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
    ANALYSIS_REVISION,
    CGI_ENDPOINT,
    CGI_FUNCTION,
    CGI_IO_SHA,
    CGI_OBJECT,
    CGI_SCOPE,
    CONTENT_TYPE_PREFIX,
    FILE_FUNCTION,
    FILE_SCOPE,
    HELPERS,
    LOGS_FIXTURE_SID,
    LOGS_SESSION_CLASS,
    NETWORK_SESSION_CLASS,
    PACKAGE_MANAGER_CALL,
    PKGMGR_FIXTURE_SID,
    PKGMGR_SESSION_CLASS,
    SYSLOG_WRAPPER,
    build_artifacts,
    evaluate_expected_case,
    evaluate_file_exec,
    grant_id,
    load_expected_cases,
    load_helper_world,
    parse_command,
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
C_SRC = REPO / "policy" / "c_double" / "cgi_exec_file.c"


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
        cls.sessions = load_helper_world()
        cls.grants, cls.bundle, cls.effects = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_helper_deny(self) -> None:
        result = self._result("unauthenticated-syslog-wrapper-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertIsNone(result.cgi_matched)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn(grant_id("unauthenticated", SYSLOG_WRAPPER), grant_ids)

    def test_missing_sessionid_is_forbidden_not_bad_request(self) -> None:
        result = self._result("missing-sessionid-syslog-wrapper-forbidden")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertNotEqual(result.http_status, 400)
        self.assertIn("execv", self.cases["missing-sessionid-syslog-wrapper-forbidden"]["not"])
        self.assertIn("path_found", self.cases["missing-sessionid-syslog-wrapper-forbidden"]["not"])

    def test_cgi_io_exec_is_not_enough_without_file_acl(self) -> None:
        result = self._result("luci-mod-network-config-syslog-wrapper-command-denied")
        self.assertEqual(result.outcome, "command_denied")
        self.assertEqual(result.http_status, 403)
        self.assertIsNotNone(result.cgi_matched)
        self.assertEqual(result.cgi_matched.scope, CGI_SCOPE)
        self.assertIsNone(result.file_matched)
        self.assertEqual(result.message, "Access to command denied by ACL")

    def test_logs_syslog_wrapper_allow(self) -> None:
        case = self.cases["luci-mod-status-logs-syslog-wrapper-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.session_class, LOGS_SESSION_CLASS)
        self.assertEqual(result.helper, SYSLOG_WRAPPER)
        self.assertEqual(result.match_stage, "cmdline")
        self.assertEqual(result.file_matched.scope, FILE_SCOPE)
        self.assertEqual(result.file_matched.function, FILE_FUNCTION)
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_executable_fallback_versus_exact_cmdline(self) -> None:
        extra = self._result("luci-mod-status-logs-syslog-wrapper-extra-argv-allow")
        self.assertEqual(extra.outcome, "allow")
        self.assertEqual(extra.match_stage, "executable")
        denied = self._result("luci-app-package-manager-list-installed-extra-denied")
        self.assertEqual(denied.outcome, "command_denied")
        self.assertIsNone(denied.match_stage)

    def test_install_glob_is_intended_access(self) -> None:
        case = self.cases["luci-app-package-manager-install-glob-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.match_stage, "cmdline")
        self.assertEqual(result.file_matched.object, f"{PACKAGE_MANAGER_CALL} install *")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")
        self.assertIn("not a PoC", case["note"])

    def test_root_helper_allow_not_violation(self) -> None:
        case = self.cases["root-star-syslog-wrapper-allow"]
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
        self.assertNotIn("syslog-wrapper", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("setInitAction", blob)
        self.assertNotIn("step4", json.dumps(self.luci_bundle))

    def test_helper_grants_are_file_exec_only(self) -> None:
        self.assertEqual(len(self.grants), 6)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(
            classes,
            {LOGS_SESSION_CLASS, NETWORK_SESSION_CLASS, PKGMGR_SESSION_CLASS, "root"},
        )
        helpers = {row["fs_path"] for row in self.grants}
        self.assertEqual(helpers, set(HELPERS))
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["ingress"], "cgi_io")
            self.assertEqual(row["cgi_endpoint"], CGI_ENDPOINT)
            self.assertTrue(row["entrypoint_id"].startswith(f"cgi_io:{CGI_ENDPOINT}:/usr/libexec/"))
            self.assertEqual(row["op"], "exec")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotIn("ubus_object", row)
            self.assertNotIn("method", row)
            self.assertNotEqual(row["assessment"], "authorization_violation")
            self.assertIn("session.access scope=cgi-io object=exec function=read", row["requirements"])
            self.assertIn("session.access scope=file", " ".join(row["requirements"]))
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-backup", blob)
        self.assertNotIn("cgi-upload", blob)
        self.assertNotIn("cgi-download", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("path_found", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))
        self.assertNotIn("luci-mod-status-firewall", blob)

    def test_effects_are_synthetic_file_exec(self) -> None:
        self.assertEqual(len(self.effects), 3)
        by_path = {row["fs_path"]: row for row in self.effects}
        self.assertEqual(set(by_path), set(HELPERS))
        for fs_path, effect in by_path.items():
            spec = HELPERS[fs_path]
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
        self.assertEqual(
            parse_command("/usr/libexec/package-manager-call list-installed"),
            [PACKAGE_MANAGER_CALL, "list-installed"],
        )
        self.assertEqual(
            parse_command(r"/usr/libexec/syslog-wrapper\ ignored"),
            [f"{SYSLOG_WRAPPER} ignored"],
        )
        self.assertIsNone(parse_command(""))
        self.assertEqual(
            canonicalize_path("/usr/libexec/../libexec/syslog-wrapper"),
            SYSLOG_WRAPPER,
        )


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "cgi_exec_file")

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
        canon = self._run("canon", "/usr/libexec/../libexec/syslog-wrapper")
        self.assertEqual(canon.stdout.strip(), SYSLOG_WRAPPER)

    def test_parse_command_splits_helper_argv(self) -> None:
        proc = self._run("parse_command", f"{PACKAGE_MANAGER_CALL} list-installed")
        self.assertEqual(
            proc.stdout.splitlines(),
            [PACKAGE_MANAGER_CALL, "list-installed"],
        )
        self.assertEqual(parse_command(f"{PACKAGE_MANAGER_CALL} list-installed"), proc.stdout.splitlines())

    def test_decide_conjunctive_file_acl(self) -> None:
        allow = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            LOGS_FIXTURE_SID,
            SYSLOG_WRAPPER,
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            SYSLOG_WRAPPER,
            FILE_FUNCTION,
            "-",
            "-",
        )
        extra = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            LOGS_FIXTURE_SID,
            f"{SYSLOG_WRAPPER} ignored",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            SYSLOG_WRAPPER,
            FILE_FUNCTION,
            SYSLOG_WRAPPER,
            FILE_FUNCTION,
        )
        denied = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            NETWORK_FIXTURE_SID,
            SYSLOG_WRAPPER,
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
            NETWORK_FIXTURE_SID,
            "/bin/true",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            "-",
            "-",
            "-",
            "-",
        )
        glob_allow = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            PKGMGR_FIXTURE_SID,
            f"{PACKAGE_MANAGER_CALL} install luci",
            CGI_SCOPE,
            CGI_OBJECT,
            CGI_FUNCTION,
            f"{PACKAGE_MANAGER_CALL} install *",
            FILE_FUNCTION,
            "-",
            "-",
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(extra.stdout.strip(), "ALLOW")
        self.assertEqual(denied.stdout.strip(), "HTTP_403")
        self.assertEqual(missing.stdout.strip(), "HTTP_404")
        self.assertEqual(glob_allow.stdout.strip(), "ALLOW")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"CGI_IO_SHA={CGI_IO_SHA}", proc.stdout)
        self.assertIn("FILE_SCOPE=file", proc.stdout)
        self.assertIn("FILE_FUNCTION=exec", proc.stdout)
        self.assertNotIn("cgi-backup", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effects = build_artifacts()
        committed = json.loads((REPO / "policy" / "cgi_exec_file_decisions.json").read_text(encoding="utf-8"))
        committed_effect = json.loads(
            (REPO / "reports" / "m2-cgi-exec-file-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed, {"grants": grants, **bundle})
        self.assertEqual(committed_effect, effects)

    def test_canonical_grants_json_includes_helper_grants(self) -> None:
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
