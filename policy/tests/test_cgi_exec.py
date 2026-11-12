#!/usr/bin/env python3
"""cgi-exec conformance: handwritten cases vs evaluator vs C double."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.cgi_backup import FLASH_FIXTURE_SID, load_cgi_world  # noqa: E402
from policy.cgi_exec import (  # noqa: E402
    ANALYSIS_REVISION,
    CGI_ENDPOINT,
    CGI_FUNCTION,
    CGI_IO_SHA,
    CGI_OBJECT,
    CGI_SCOPE,
    CONTENT_TYPE_PREFIX,
    EFFECT_RECORD_ID,
    ENTRYPOINT_ID,
    NETWORK_SESSION_CLASS,
    TARGET_ID,
    build_artifacts,
    evaluate_exec,
    evaluate_expected_case,
    load_expected_cases,
    write_artifacts,
)
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    NETWORK_FIXTURE_SID,
    PRODUCER,
    ROOT_FIXTURE_SID,
    STATUS_FIXTURE_SID,
    SYSTEM_FIXTURE_SID,
    build_artifacts as luci_build_artifacts,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "cgi_exec.c"


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

    def test_unauthenticated_exec_deny(self) -> None:
        result = self._result("unauthenticated-cgi-exec-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertIsNone(result.matched)
        self.assertFalse(self.cases["unauthenticated-cgi-exec-deny"]["expect_grant"])
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn("policy:grant:unauthenticated:cgi_io:cgi-exec", grant_ids)

    def test_missing_sessionid_is_forbidden_not_bad_request(self) -> None:
        result = self._result("missing-sessionid-cgi-exec-forbidden")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertNotEqual(result.http_status, 400)
        self.assertIsNone(result.matched)
        self.assertIn("unauthenticated_allow", self.cases["missing-sessionid-cgi-exec-forbidden"]["not"])
        self.assertIn("execv", self.cases["missing-sessionid-cgi-exec-forbidden"]["not"])
        self.assertIn("path_found", self.cases["missing-sessionid-cgi-exec-forbidden"]["not"])

    def test_invalid_content_type_is_bad_request(self) -> None:
        result = self._result("invalid-content-type-cgi-exec-bad-request")
        self.assertEqual(result.outcome, "bad_request")
        self.assertEqual(result.http_status, 400)
        self.assertIsNone(result.matched)
        self.assertFalse(self.cases["invalid-content-type-cgi-exec-bad-request"]["expect_grant"])

    def test_network_config_exec_allow(self) -> None:
        case = self.cases["luci-mod-network-config-cgi-exec-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.session_class, NETWORK_SESSION_CLASS)
        self.assertEqual(result.sid, NETWORK_FIXTURE_SID)
        self.assertIsNotNone(result.matched)
        self.assertEqual(result.matched.scope, CGI_SCOPE)
        self.assertEqual(result.matched.object, CGI_OBJECT)
        self.assertEqual(result.matched.function, CGI_FUNCTION)
        self.assertEqual(result.matched.group, NETWORK_SESSION_CLASS)
        self.assertEqual(result.matched.source, "luci-mod-network.json")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_root_exec_allow_not_violation(self) -> None:
        case = self.cases["root-star-cgi-exec-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(result.sid, ROOT_FIXTURE_SID)
        self.assertEqual(case["assessment"], "intended_access")
        self.assertEqual(case["expectation_id"], "root-administration")
        self.assertIn("not a violation", case["note"])
        self.assertNotEqual(case["assessment"], "authorization_violation")

    def test_other_fixture_roles_are_not_exec(self) -> None:
        for case_id, sid in (
            ("luci-mod-system-config-cgi-exec-deny", SYSTEM_FIXTURE_SID),
            ("luci-mod-system-flash-cgi-exec-deny", FLASH_FIXTURE_SID),
            ("luci-mod-status-realtime-cgi-exec-deny", STATUS_FIXTURE_SID),
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
        self.assertNotIn("cgi-exec", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("setInitAction", blob)
        self.assertNotIn("step4", json.dumps(self.luci_bundle))
        getfeatures = [row for row in self.luci_grants if row["method"] == "getFeatures"]
        self.assertEqual(len(getfeatures), 2)

    def test_cgi_grants_are_exec_only(self) -> None:
        self.assertEqual(len(self.grants), 2)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(classes, {NETWORK_SESSION_CLASS, "root"})
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["ingress"], "cgi_io")
            self.assertEqual(row["cgi_endpoint"], CGI_ENDPOINT)
            self.assertEqual(row["entrypoint_id"], ENTRYPOINT_ID)
            self.assertEqual(row["target_id"], TARGET_ID)
            self.assertEqual(row["op"], "exec")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotIn("ubus_object", row)
            self.assertNotIn("method", row)
            self.assertNotEqual(row["assessment"], "authorization_violation")
            self.assertIn("session.access scope=cgi-io object=exec function=read", row["requirements"])
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-backup", blob)
        self.assertNotIn("cgi-upload", blob)
        self.assertNotIn("cgi-download", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("path_found", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))
        self.assertNotIn("luci-app-package-manager", blob)
        self.assertNotIn("luci-mod-status-logs", blob)
        self.assertNotIn("luci-mod-status-firewall", blob)

    def test_synthetic_network_session_is_marked(self) -> None:
        network = next(row for row in self.grants if row["session_class"] == NETWORK_SESSION_CLASS)
        root = next(row for row in self.grants if row["session_class"] == "root")
        self.assertTrue(network["synthetic_session"])
        self.assertNotIn("synthetic_session", root)

    def test_effect_is_synthetic_exec_gate(self) -> None:
        effect = self.effect
        for key in REQUIRED:
            self.assertIn(key, effect, key)
        self.assertEqual(effect["record_id"], EFFECT_RECORD_ID)
        self.assertEqual(effect["producer"], PRODUCER)
        self.assertNotEqual(effect["producer"], "step3")
        self.assertEqual(effect["record_type"], "handler_effect")
        self.assertEqual(effect["evidence_status"], "fact")
        self.assertNotEqual(effect["evidence_status"], "path_found")
        self.assertEqual(effect["ingress"], "cgi_io")
        self.assertEqual(effect["cgi_endpoint"], CGI_ENDPOINT)
        self.assertEqual(effect["sink_kind"], "exec")
        self.assertEqual(effect["op"], "exec")
        self.assertEqual(effect["assessment"], "intended_access")
        self.assertNotEqual(effect["assessment"], "authorization_violation")
        self.assertIn(f"policy:grant:{NETWORK_SESSION_CLASS}:cgi_io:cgi-exec", effect["evidence_refs"])
        self.assertIn("policy:grant:root:cgi_io:cgi-exec", effect["evidence_refs"])
        self.assertFalse(
            any("unauthenticated" in ref for ref in effect["evidence_refs"] if ref.startswith("policy:grant:"))
        )
        text = " ".join(effect["assumptions"]).lower()
        self.assertIn("shellquote", text)
        self.assertIn("basename", text)
        self.assertIn("not sanitizers", text)
        self.assertIn("execv", text)
        self.assertNotIn("path_found", json.dumps(effect))

    def test_decisions_cover_handwritten_cases(self) -> None:
        ids = [row["record_id"] for row in self.bundle["decisions"]]
        expected = [f"policy:decision:{case['id']}" for case in load_expected_cases()]
        self.assertEqual(ids, expected)
        assessments = {row.get("assessment") for row in self.bundle["decisions"]}
        self.assertNotIn("authorization_violation", assessments)
        self.assertEqual(self.bundle["pins"]["cgi-io"], CGI_IO_SHA)
        self.assertFalse(self.bundle["harness"]["live_cgi_io"])
        self.assertFalse(self.bundle["harness"]["live_execv"])

    def test_empty_sid_is_forbidden(self) -> None:
        result = evaluate_exec(sid="", content_type=CONTENT_TYPE_PREFIX)
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)

    def test_content_type_prefix_allows_charset(self) -> None:
        result = evaluate_exec(
            sid=NETWORK_FIXTURE_SID,
            content_type="application/x-www-form-urlencoded; charset=UTF-8",
            sessions=load_cgi_world(),
        )
        self.assertEqual(result.outcome, "allow")


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "cgi_exec")

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
        proc = self._run("parse", "application/json", NETWORK_FIXTURE_SID)
        self.assertEqual(proc.stdout.strip(), "HTTP_400")
        self.assertNotEqual(proc.returncode, 0)

    def test_parse_missing_sessionid(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_PREFIX, "-")
        self.assertEqual(proc.stdout.strip(), "HTTP_403")
        self.assertNotEqual(proc.returncode, 0)

    def test_parse_ok(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_PREFIX, NETWORK_FIXTURE_SID)
        self.assertEqual(proc.stdout.strip(), "PARSE_OK")
        self.assertEqual(proc.returncode, 0)
        charset = self._run(
            "parse",
            "application/x-www-form-urlencoded; charset=UTF-8",
            NETWORK_FIXTURE_SID,
        )
        self.assertEqual(charset.stdout.strip(), "PARSE_OK")

    def test_match_exec_read_only(self) -> None:
        allow = self._run("match", "cgi-io", "exec", "read", "cgi-io", "exec", "read")
        backup = self._run("match", "cgi-io", "backup", "read", "cgi-io", "exec", "read")
        upload = self._run("match", "cgi-io", "upload", "write", "cgi-io", "exec", "read")
        download = self._run("match", "cgi-io", "download", "read", "cgi-io", "exec", "read")
        wrong_scope = self._run("match", "ubus", "exec", "read", "cgi-io", "exec", "read")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(backup.stdout.strip(), "DENY")
        self.assertEqual(upload.stdout.strip(), "DENY")
        self.assertEqual(download.stdout.strip(), "DENY")
        self.assertEqual(wrong_scope.stdout.strip(), "DENY")

    def test_decide_four_cases(self) -> None:
        allow = self._run(
            "decide", CONTENT_TYPE_PREFIX, NETWORK_FIXTURE_SID, "cgi-io", "exec", "read"
        )
        deny_backup = self._run(
            "decide", CONTENT_TYPE_PREFIX, DEFAULT_SID, "cgi-io", "backup", "read"
        )
        forbidden = self._run("decide", CONTENT_TYPE_PREFIX, "-", "cgi-io", "exec", "read")
        bad = self._run("decide", "text/plain", NETWORK_FIXTURE_SID, "cgi-io", "exec", "read")
        root = self._run(
            "decide", CONTENT_TYPE_PREFIX, ROOT_FIXTURE_SID, "cgi-io", "exec", "read"
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(deny_backup.stdout.strip(), "HTTP_403")
        self.assertEqual(forbidden.stdout.strip(), "HTTP_403")
        self.assertEqual(bad.stdout.strip(), "HTTP_400")
        self.assertEqual(root.stdout.strip(), "ALLOW")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"CGI_IO_SHA={CGI_IO_SHA}", proc.stdout)
        self.assertIn("REQ_SCOPE=cgi-io", proc.stdout)
        self.assertIn("REQ_OBJECT=exec", proc.stdout)
        self.assertIn("REQ_FUNCTION=read", proc.stdout)
        self.assertNotIn("cgi-backup", proc.stdout)
        self.assertNotIn("cgi-upload", proc.stdout)
        self.assertNotIn("cgi-download", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effect = build_artifacts()
        committed = json.loads((REPO / "policy" / "cgi_exec_decisions.json").read_text(encoding="utf-8"))
        committed_effect = json.loads(
            (REPO / "reports" / "m2-cgi-exec-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed, {"grants": grants, **bundle})
        self.assertEqual(committed_effect, effect)

    def test_writer_preserves_canonical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(REPO / "policy" / "fixtures", root / "policy" / "fixtures")
            (root / "corpus").mkdir()
            shutil.copy2(REPO / "corpus" / "lock.json", root / "corpus" / "lock.json")
            (root / "reports").mkdir()
            canonical_paths = (Path("policy/grants.json"), Path("reports/handler_effects.json"))
            before = {}
            for relative_path in canonical_paths:
                shutil.copy2(REPO / relative_path, root / relative_path)
                before[relative_path] = (root / relative_path).read_bytes()

            paths = write_artifacts(root)

            self.assertEqual(
                paths,
                (root / "policy" / "cgi_exec_decisions.json", root / "reports" / "m2-cgi-exec-effect.json"),
            )
            for relative_path in canonical_paths:
                self.assertEqual((root / relative_path).read_bytes(), before[relative_path], str(relative_path))
            for path in paths:
                self.assertTrue(path.is_file(), str(path))


if __name__ == "__main__":
    unittest.main()
