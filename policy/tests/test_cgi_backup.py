#!/usr/bin/env python3
"""cgi-backup conformance: handwritten cases vs evaluator vs C double."""

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

from policy import cgi_backup  # noqa: E402
from policy.cgi_backup import (  # noqa: E402
    ANALYSIS_REVISION,
    CGI_ENDPOINT,
    CGI_FUNCTION,
    CGI_IO_SHA,
    CGI_OBJECT,
    CGI_SCOPE,
    CONTENT_TYPE_PREFIX,
    EFFECT_RECORD_ID,
    ENTRYPOINT_ID,
    FLASH_FIXTURE_SID,
    FLASH_SESSION_CLASS,
    TARGET_ID,
    build_artifacts,
    evaluate_backup,
    evaluate_expected_case,
    load_cgi_world,
    load_expected_cases,
)
from policy.cgi_download import build_artifacts as download_build_artifacts  # noqa: E402
from policy.cgi_exec import build_artifacts as exec_build_artifacts  # noqa: E402
from policy.cgi_exec_file import build_artifacts as helper_build_artifacts  # noqa: E402
from policy.cgi_exec_status import build_artifacts as status_build_artifacts  # noqa: E402
from policy.ubus_file_exec import build_artifacts as file_exec_build_artifacts  # noqa: E402
from policy.ubus_file_exec_ifup import build_artifacts as ifup_build_artifacts  # noqa: E402
from policy.ubus_file_exec_kill import build_artifacts as kill_build_artifacts  # noqa: E402
from policy.ubus_file_exec_mounts import build_artifacts as mounts_build_artifacts  # noqa: E402
from policy.cgi_upload import build_artifacts as upload_build_artifacts  # noqa: E402
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    NETWORK_FIXTURE_SID,
    PRODUCER,
    ROOT_FIXTURE_SID,
    SYSTEM_FIXTURE_SID,
    build_artifacts as luci_build_artifacts,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "cgi_backup.c"


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
        cls.sessions = load_cgi_world()
        cls.grants, cls.bundle, cls.effect = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_backup_deny(self) -> None:
        result = self._result("unauthenticated-cgi-backup-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertIsNone(result.matched)
        self.assertFalse(self.cases["unauthenticated-cgi-backup-deny"]["expect_grant"])
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn("policy:grant:unauthenticated:cgi_io:cgi-backup", grant_ids)

    def test_missing_sessionid_is_forbidden_not_bad_request(self) -> None:
        result = self._result("missing-sessionid-cgi-backup-forbidden")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertNotEqual(result.http_status, 400)
        self.assertIsNone(result.matched)
        self.assertIn("unauthenticated_allow", self.cases["missing-sessionid-cgi-backup-forbidden"]["not"])
        self.assertIn("sysupgrade_exec", self.cases["missing-sessionid-cgi-backup-forbidden"]["not"])

    def test_invalid_content_type_is_bad_request(self) -> None:
        result = self._result("invalid-content-type-cgi-backup-bad-request")
        self.assertEqual(result.outcome, "bad_request")
        self.assertEqual(result.http_status, 400)
        self.assertIsNone(result.matched)
        self.assertFalse(self.cases["invalid-content-type-cgi-backup-bad-request"]["expect_grant"])

    def test_flash_backup_allow(self) -> None:
        case = self.cases["luci-mod-system-flash-cgi-backup-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.session_class, FLASH_SESSION_CLASS)
        self.assertEqual(result.sid, FLASH_FIXTURE_SID)
        self.assertIsNotNone(result.matched)
        self.assertEqual(result.matched.scope, CGI_SCOPE)
        self.assertEqual(result.matched.object, CGI_OBJECT)
        self.assertEqual(result.matched.function, CGI_FUNCTION)
        self.assertEqual(result.matched.group, FLASH_SESSION_CLASS)
        self.assertEqual(result.matched.source, "luci-mod-system.json")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_root_backup_allow_not_violation(self) -> None:
        case = self.cases["root-star-cgi-backup-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(result.sid, ROOT_FIXTURE_SID)
        self.assertEqual(case["assessment"], "intended_access")
        self.assertEqual(case["expectation_id"], "root-administration")
        self.assertIn("not a violation", case["note"])
        self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_system_config_and_network_exec_are_not_backup(self) -> None:
        for case_id, sid in (
            ("luci-mod-system-config-cgi-backup-deny", SYSTEM_FIXTURE_SID),
            ("luci-mod-network-config-cgi-backup-deny", NETWORK_FIXTURE_SID),
        ):
            with self.subTest(case_id=case_id):
                result = self._result(case_id)
                self.assertEqual(result.outcome, "deny")
                self.assertEqual(result.http_status, 403)
                self.assertEqual(result.sid, sid)
                self.assertFalse(self.cases[case_id]["expect_grant"])

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


class TestGrantsAndEffect(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grants, cls.bundle, cls.effect = build_artifacts()
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
        self.assertNotIn("cgi-backup", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("step4", json.dumps(self.luci_bundle))

    def test_cgi_grants_are_backup_only(self) -> None:
        self.assertEqual(len(self.grants), 2)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(classes, {FLASH_SESSION_CLASS, "root"})
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["ingress"], "cgi_io")
            self.assertEqual(row["cgi_endpoint"], CGI_ENDPOINT)
            self.assertEqual(row["entrypoint_id"], ENTRYPOINT_ID)
            self.assertEqual(row["target_id"], TARGET_ID)
            self.assertEqual(row["op"], "read")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotIn("ubus_object", row)
            self.assertNotIn("method", row)
            self.assertNotEqual(row["assessment"], "authorization_violation")
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-exec", blob)
        self.assertNotIn("cgi-upload", blob)
        self.assertNotIn("cgi-download", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))

    def test_synthetic_flash_session_is_marked(self) -> None:
        flash = next(row for row in self.grants if row["session_class"] == FLASH_SESSION_CLASS)
        root = next(row for row in self.grants if row["session_class"] == "root")
        self.assertTrue(flash["synthetic_session"])
        self.assertNotIn("synthetic_session", root)

    def test_effect_is_synthetic_sensitive_backup_read(self) -> None:
        effect = self.effect
        for key in REQUIRED:
            self.assertIn(key, effect, key)
        self.assertEqual(effect["record_id"], EFFECT_RECORD_ID)
        self.assertEqual(effect["producer"], PRODUCER)
        self.assertNotEqual(effect["producer"], "step3")
        self.assertEqual(effect["record_type"], "handler_effect")
        self.assertEqual(effect["evidence_status"], "fact")
        self.assertEqual(effect["ingress"], "cgi_io")
        self.assertEqual(effect["cgi_endpoint"], CGI_ENDPOINT)
        self.assertEqual(effect["sink_kind"], "sensitive_backup_read")
        self.assertEqual(effect["op"], "read")
        self.assertEqual(effect["assessment"], "intended_access")
        self.assertNotEqual(effect["assessment"], "authorization_violation")
        self.assertIn(f"policy:grant:{FLASH_SESSION_CLASS}:cgi_io:cgi-backup", effect["evidence_refs"])
        self.assertIn("policy:grant:root:cgi_io:cgi-backup", effect["evidence_refs"])
        self.assertFalse(any("unauthenticated" in ref for ref in effect["evidence_refs"] if ref.startswith("policy:grant:")))
        text = " ".join(effect["assumptions"]).lower()
        self.assertIn("sysupgrade", text)
        self.assertIn("shellquote", text)
        self.assertIn("basename", text)
        self.assertIn("not sanitizers", text)

    def test_decisions_cover_handwritten_cases(self) -> None:
        ids = [row["record_id"] for row in self.bundle["decisions"]]
        expected = [f"policy:decision:{case['id']}" for case in load_expected_cases()]
        self.assertEqual(ids, expected)
        assessments = {row.get("assessment") for row in self.bundle["decisions"]}
        self.assertNotIn("authorization_violation", assessments)
        self.assertEqual(self.bundle["pins"]["cgi-io"], CGI_IO_SHA)
        self.assertFalse(self.bundle["harness"]["live_cgi_io"])
        self.assertFalse(self.bundle["harness"]["live_sysupgrade"])

    def test_empty_sid_is_forbidden(self) -> None:
        result = evaluate_backup(sid="", content_type=CONTENT_TYPE_PREFIX)
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)

    def test_content_type_prefix_allows_charset(self) -> None:
        result = evaluate_backup(
            sid=FLASH_FIXTURE_SID,
            content_type="application/x-www-form-urlencoded; charset=UTF-8",
            sessions=load_cgi_world(),
        )
        self.assertEqual(result.outcome, "allow")


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "cgi_backup")

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

    def test_parse_invalid_content_type(self) -> None:
        proc = self._run("parse", "application/json", FLASH_FIXTURE_SID)
        self.assertEqual(proc.stdout.strip(), "HTTP_400")
        self.assertNotEqual(proc.returncode, 0)

    def test_parse_missing_sessionid(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_PREFIX, "-")
        self.assertEqual(proc.stdout.strip(), "HTTP_403")
        self.assertNotEqual(proc.returncode, 0)

    def test_parse_ok(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_PREFIX, FLASH_FIXTURE_SID)
        self.assertEqual(proc.stdout.strip(), "PARSE_OK")
        self.assertEqual(proc.returncode, 0)
        charset = self._run(
            "parse",
            "application/x-www-form-urlencoded; charset=UTF-8",
            FLASH_FIXTURE_SID,
        )
        self.assertEqual(charset.stdout.strip(), "PARSE_OK")

    def test_match_backup_read_only(self) -> None:
        allow = self._run("match", "cgi-io", "backup", "read", "cgi-io", "backup", "read")
        exec_grant = self._run("match", "cgi-io", "exec", "read", "cgi-io", "backup", "read")
        upload = self._run("match", "cgi-io", "upload", "write", "cgi-io", "backup", "read")
        download = self._run("match", "cgi-io", "download", "read", "cgi-io", "backup", "read")
        wrong_scope = self._run("match", "ubus", "backup", "read", "cgi-io", "backup", "read")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(exec_grant.stdout.strip(), "DENY")
        self.assertEqual(upload.stdout.strip(), "DENY")
        self.assertEqual(download.stdout.strip(), "DENY")
        self.assertEqual(wrong_scope.stdout.strip(), "DENY")

    def test_decide_four_cases(self) -> None:
        allow = self._run(
            "decide", CONTENT_TYPE_PREFIX, FLASH_FIXTURE_SID, "cgi-io", "backup", "read"
        )
        deny_exec = self._run(
            "decide", CONTENT_TYPE_PREFIX, DEFAULT_SID, "cgi-io", "exec", "read"
        )
        forbidden = self._run("decide", CONTENT_TYPE_PREFIX, "-", "cgi-io", "backup", "read")
        bad = self._run("decide", "text/plain", FLASH_FIXTURE_SID, "cgi-io", "backup", "read")
        root = self._run(
            "decide", CONTENT_TYPE_PREFIX, ROOT_FIXTURE_SID, "cgi-io", "backup", "read"
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(deny_exec.stdout.strip(), "HTTP_403")
        self.assertEqual(forbidden.stdout.strip(), "HTTP_403")
        self.assertEqual(bad.stdout.strip(), "HTTP_400")
        self.assertEqual(root.stdout.strip(), "ALLOW")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"CGI_IO_SHA={CGI_IO_SHA}", proc.stdout)
        self.assertIn("REQ_SCOPE=cgi-io", proc.stdout)
        self.assertIn("REQ_OBJECT=backup", proc.stdout)
        self.assertIn("REQ_FUNCTION=read", proc.stdout)
        self.assertNotIn("cgi-exec", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_emit_matches_committed_files(self) -> None:
        cgi_grants, cgi_bundle, effect = build_artifacts()
        luci_grants, luci_bundle = luci_build_artifacts()
        committed_grants = json.loads((REPO / "policy" / "grants.json").read_text(encoding="utf-8"))
        committed_luci = json.loads(
            (REPO / "policy" / "policy_decisions.json").read_text(encoding="utf-8")
        )
        committed_cgi = json.loads(
            (REPO / "policy" / "cgi_backup_decisions.json").read_text(encoding="utf-8")
        )
        committed_effects = json.loads(
            (REPO / "reports" / "handler_effects.json").read_text(encoding="utf-8")
        )
        upload_grants, _, _ = upload_build_artifacts()
        download_grants, _, _ = download_build_artifacts()
        exec_grants, _, _ = exec_build_artifacts()
        helper_grants, _, _ = helper_build_artifacts()
        status_grants, _, _ = status_build_artifacts()
        file_exec_grants, _, _ = file_exec_build_artifacts()
        ifup_grants, _, _ = ifup_build_artifacts()
        kill_grants, _, _ = kill_build_artifacts()
        mounts_grants, _, _ = mounts_build_artifacts()
        self.assertEqual(
            committed_grants,
            luci_grants
            + cgi_grants
            + upload_grants
            + download_grants
            + exec_grants
            + helper_grants
            + status_grants
            + file_exec_grants
            + ifup_grants
            + kill_grants
            + mounts_grants,
        )
        self.assertEqual(committed_luci, luci_bundle)
        self.assertEqual(committed_cgi, cgi_bundle)
        committed_effect = next(row for row in committed_effects if row["record_id"] == EFFECT_RECORD_ID)
        self.assertEqual(committed_effect, effect)


if __name__ == "__main__":
    unittest.main()
