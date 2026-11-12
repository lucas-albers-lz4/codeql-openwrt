#!/usr/bin/env python3
"""cgi-download conformance: handwritten cases vs evaluator vs C double."""

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

from policy.cgi_backup import FLASH_FIXTURE_SID, FLASH_SESSION_CLASS, load_cgi_world  # noqa: E402
from policy.cgi_download import (  # noqa: E402
    ANALYSIS_REVISION,
    CGI_ENDPOINT,
    CGI_FUNCTION,
    CGI_IO_SHA,
    CGI_OBJECT,
    CGI_SCOPE,
    CONTENT_TYPE_PREFIX,
    EFFECT_RECORD_ID,
    ENTRYPOINT_ID,
    FILE_FUNCTION,
    FILE_SCOPE,
    FLASH_PATH,
    TARGET_ID,
    build_artifacts,
    canonicalize_path,
    evaluate_download,
    evaluate_expected_case,
    load_expected_cases,
    write_artifacts,
)
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    PRODUCER,
    ROOT_FIXTURE_SID,
    SYSTEM_FIXTURE_SID,
    build_artifacts as luci_build_artifacts,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "cgi_download.c"


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

    def test_unauthenticated_download_deny(self) -> None:
        result = self._result("unauthenticated-cgi-download-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertIsNone(result.cgi_matched)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn("policy:grant:unauthenticated:cgi_io:cgi-download", grant_ids)

    def test_missing_sessionid_is_forbidden_not_bad_request(self) -> None:
        result = self._result("missing-sessionid-cgi-download-forbidden")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.http_status, 403)
        self.assertNotEqual(result.http_status, 400)

    def test_invalid_content_type_is_bad_request(self) -> None:
        result = self._result("invalid-content-type-cgi-download-bad-request")
        self.assertEqual(result.outcome, "bad_request")
        self.assertEqual(result.http_status, 400)

    def test_flash_download_allow(self) -> None:
        result = self._result("luci-mod-system-flash-cgi-download-allow")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.canon, FLASH_PATH)
        self.assertEqual(result.cgi_matched.object, CGI_OBJECT)
        self.assertEqual(result.file_matched.function, FILE_FUNCTION)
        self.assertEqual(self.cases["luci-mod-system-flash-cgi-download-allow"]["assessment"], "intended_access")
        self.assertNotEqual(
            self.cases["luci-mod-system-flash-cgi-download-allow"]["assessment"],
            "authorization_violation",
        )

    def test_root_download_allow_not_violation(self) -> None:
        result = self._result("root-star-cgi-download-allow")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(self.cases["root-star-cgi-download-allow"]["assessment"], "intended_access")

    def test_cgi_io_grant_without_file_grant_is_denied(self) -> None:
        result = self._result("luci-mod-system-flash-cgi-download-passwd-deny")
        self.assertEqual(result.outcome, "path_denied")
        self.assertIsNotNone(result.cgi_matched)
        self.assertIsNone(result.file_matched)

    def test_dotdot_is_canonicalized_before_file_acl(self) -> None:
        result = self._result("luci-mod-system-flash-cgi-download-dotdot-deny")
        self.assertEqual(result.outcome, "path_denied")
        self.assertEqual(result.canon, "/etc/passwd")

    def test_system_config_is_not_download(self) -> None:
        result = self._result("luci-mod-system-config-cgi-download-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.sid, SYSTEM_FIXTURE_SID)

    def test_evaluator_matches_every_handwritten_outcome(self) -> None:
        for case in self.cases.values():
            result = self._result(case["id"])
            self.assertEqual(result.outcome, case["expected_outcome"], case["id"])
            self.assertEqual(result.http_status, case["http_status"], case["id"])


class TestGrantsAndEffect(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grants, cls.bundle, cls.effect = build_artifacts()
        cls.luci_grants, cls.luci_bundle = luci_build_artifacts()

    def test_luci_emitter_is_unchanged(self) -> None:
        blob = json.dumps(self.luci_grants)
        self.assertNotIn("cgi-download", blob)
        self.assertNotIn("cgi-upload", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("step4", json.dumps(self.luci_bundle))

    def test_cgi_grants_are_download_only(self) -> None:
        self.assertEqual(len(self.grants), 2)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(classes, {FLASH_SESSION_CLASS, "root"})
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["cgi_endpoint"], CGI_ENDPOINT)
            self.assertEqual(row["op"], "read")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertIn("session.access scope=file object=canonicalize_path(path) function=read", row["requirements"])
            self.assertNotEqual(row["assessment"], "authorization_violation")
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-exec", blob)
        self.assertNotIn("cgi-upload", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))

    def test_effect_is_synthetic_file_read(self) -> None:
        effect = self.effect
        for key in REQUIRED:
            self.assertIn(key, effect, key)
        self.assertEqual(effect["record_id"], EFFECT_RECORD_ID)
        self.assertEqual(effect["sink_kind"], "file_read")
        self.assertEqual(effect["op"], "read")
        self.assertEqual(effect["assessment"], "intended_access")
        self.assertNotEqual(effect["evidence_status"], "path_found")
        self.assertIn(f"policy:grant:{FLASH_SESSION_CLASS}:cgi_io:cgi-download", effect["evidence_refs"])
        self.assertIn("policy:grant:root:cgi_io:cgi-download", effect["evidence_refs"])
        text = " ".join(effect["assumptions"]).lower()
        self.assertIn("shellquote", text)
        self.assertIn("basename", text)
        self.assertIn("not sanitizers", text)

    def test_canonical_grants_json_includes_download_grants(self) -> None:
        grants, _, effect = build_artifacts()
        committed = json.loads((REPO / "policy" / "grants.json").read_text(encoding="utf-8"))
        catalog = json.loads((REPO / "reports" / "handler_effects.json").read_text(encoding="utf-8"))
        for grant in grants:
            self.assertIn(grant, committed)
        catalog_effect = next(row for row in catalog if row["record_id"] == EFFECT_RECORD_ID)
        self.assertEqual(catalog_effect, effect)
        self.assertNotIn("cgi-exec", json.dumps(grants))


class TestCanonicalize(unittest.TestCase):
    def test_python_matches_documented_vectors(self) -> None:
        self.assertEqual(canonicalize_path("/dev/mtdblock0"), "/dev/mtdblock0")
        self.assertEqual(canonicalize_path("/dev/mtdblock0/../../../etc/passwd"), "/etc/passwd")
        self.assertEqual(canonicalize_path("/tmp/../dev/mtdblock0"), "/dev/mtdblock0")
        self.assertEqual(canonicalize_path("/etc/luci-uploads//foo"), "/etc/luci-uploads/foo")
        self.assertIsNone(canonicalize_path(""))
        self.assertIsNone(canonicalize_path(None))


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "cgi_download")

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

    def test_parse_missing_sessionid(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_PREFIX, "-")
        self.assertEqual(proc.stdout.strip(), "HTTP_403")

    def test_canon_dotdot(self) -> None:
        proc = self._run("canon", "/dev/mtdblock0/../../../etc/passwd")
        self.assertEqual(proc.stdout.strip(), "/etc/passwd")
        stay = self._run("canon", "/tmp/../dev/mtdblock0")
        self.assertEqual(stay.stdout.strip(), "/dev/mtdblock0")

    def test_match_download_read_only(self) -> None:
        allow = self._run("match", "cgi-io", "download", "read", "cgi-io", "download", "read")
        backup = self._run("match", "cgi-io", "backup", "read", "cgi-io", "download", "read")
        upload = self._run("match", "cgi-io", "upload", "write", "cgi-io", "download", "read")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(backup.stdout.strip(), "DENY")
        self.assertEqual(upload.stdout.strip(), "DENY")

    def test_decide_flash_path_and_dotdot(self) -> None:
        allow = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            FLASH_FIXTURE_SID,
            FLASH_PATH,
            "cgi-io",
            "download",
            "read",
            "/dev/mtdblock[0-9]*",
            "read",
        )
        passwd = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            FLASH_FIXTURE_SID,
            "/etc/passwd",
            "cgi-io",
            "download",
            "read",
            "/dev/mtdblock[0-9]*",
            "read",
        )
        dotdot = self._run(
            "decide",
            CONTENT_TYPE_PREFIX,
            FLASH_FIXTURE_SID,
            "/dev/mtdblock0/../../../etc/passwd",
            "cgi-io",
            "download",
            "read",
            "/dev/mtdblock[0-9]*",
            "read",
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(passwd.stdout.strip(), "HTTP_403")
        self.assertEqual(dotdot.stdout.strip(), "HTTP_403")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"CGI_IO_SHA={CGI_IO_SHA}", proc.stdout)
        self.assertIn("REQ_OBJECT=download", proc.stdout)
        self.assertNotIn("cgi-exec", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effect = build_artifacts()
        committed = json.loads(
            (REPO / "policy" / "cgi_download_decisions.json").read_text(encoding="utf-8")
        )
        committed_effect = json.loads(
            (REPO / "reports" / "m2-cgi-download-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed["grants"], grants)
        self.assertEqual(committed["decisions"], bundle["decisions"])
        self.assertEqual(committed_effect, effect)


if __name__ == "__main__":
    unittest.main()
