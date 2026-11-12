#!/usr/bin/env python3
"""cgi-upload conformance: handwritten cases vs evaluator vs C double."""

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

from policy.cgi_upload import (  # noqa: E402
    ANALYSIS_REVISION,
    BASE_FIXTURE_SID,
    BASE_SESSION_CLASS,
    CGI_ENDPOINT,
    CGI_IO_SHA,
    CGI_OBJECT,
    CONTENT_TYPE_EXAMPLE,
    CONTENT_TYPE_PREFIX,
    EFFECT_RECORD_ID,
    FLASH_FIXTURE_SID,
    FLASH_SESSION_CLASS,
    UPLOAD_PATH,
    build_artifacts,
    canonicalize_path,
    evaluate_expected_case,
    evaluate_upload,
    load_expected_cases,
    load_upload_world,
)
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    DEFAULT_SID,
    PRODUCER,
    ROOT_FIXTURE_SID,
    build_artifacts as luci_build_artifacts,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "cgi_upload.c"


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
        cls.sessions = load_upload_world()
        cls.grants, cls.bundle, cls.effect = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_upload_deny(self) -> None:
        result = self._result("unauthenticated-cgi-upload-deny")
        self.assertEqual(result.outcome, "upload_denied")
        self.assertEqual(result.http_status, 200)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn("policy:grant:unauthenticated:cgi_io:cgi-upload", grant_ids)

    def test_missing_sessionid_is_response_200_not_403(self) -> None:
        result = self._result("missing-sessionid-with-filedata")
        self.assertEqual(result.outcome, "missing_session")
        self.assertEqual(result.message, "File data without session")
        self.assertFalse(any(step["step"] == "session_access" for step in result.steps))
        self.assertEqual(result.http_status, 200)
        self.assertNotEqual(result.http_status, 403)

    def test_absent_sessionid_without_filedata_has_no_response(self) -> None:
        result = self._result("missing-sessionid-without-filedata")
        self.assertEqual(result.outcome, "no_response")
        self.assertIsNone(result.http_status)
        self.assertIsNone(result.message)
        self.assertFalse(any(step["step"] == "session_access" for step in result.steps))

    def test_empty_sessionid_part_is_outside_slice(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty sessionid"):
            evaluate_upload(sid="")

    def test_authorized_sessionid_without_filedata_has_no_file_acl_check(self) -> None:
        result = self._result("luci-base-without-filedata")
        self.assertEqual(result.outcome, "no_response")
        self.assertIsNone(result.http_status)
        self.assertIsNotNone(result.cgi_matched)
        self.assertFalse(any(step.get("scope") == "file" for step in result.steps))

    def test_urlencoded_content_type_is_invalid_request(self) -> None:
        result = self._result("invalid-content-type-cgi-upload-invalid-request")
        self.assertEqual(result.outcome, "invalid_request")
        self.assertEqual(result.http_status, 200)

    def test_luci_base_upload_allow(self) -> None:
        result = self._result("luci-base-cgi-upload-allow")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.canon, UPLOAD_PATH)
        self.assertEqual(result.cgi_matched.object, CGI_OBJECT)
        self.assertEqual(self.cases["luci-base-cgi-upload-allow"]["assessment"], "intended_access")
        self.assertNotEqual(
            self.cases["luci-base-cgi-upload-allow"]["assessment"],
            "authorization_violation",
        )

    def test_root_upload_allow_not_violation(self) -> None:
        result = self._result("root-star-cgi-upload-allow")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")

    def test_cgi_io_grant_without_file_grant_is_denied(self) -> None:
        result = self._result("luci-base-cgi-upload-passwd-deny")
        self.assertEqual(result.outcome, "path_denied")
        self.assertIsNotNone(result.cgi_matched)
        self.assertIsNone(result.file_matched)

    def test_dotdot_is_canonicalized_before_file_acl(self) -> None:
        result = self._result("luci-base-cgi-upload-dotdot-deny")
        self.assertEqual(result.outcome, "path_denied")
        self.assertEqual(result.canon, "/etc/passwd")

    def test_flash_read_login_does_not_get_upload_write(self) -> None:
        result = self._result("luci-mod-system-flash-cgi-upload-deny")
        self.assertEqual(result.outcome, "upload_denied")
        self.assertEqual(result.sid, FLASH_FIXTURE_SID)

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

    def test_no_response_decisions_have_no_status_or_grant(self) -> None:
        decisions = {row["record_id"]: row for row in self.bundle["decisions"]}
        for case_id in ("missing-sessionid-without-filedata", "luci-base-without-filedata"):
            row = decisions[f"policy:decision:{case_id}"]
            self.assertEqual(row["outcome"], "no_response")
            self.assertIsNone(row["http_status"])
            self.assertFalse(row["response_emitted"])
            self.assertFalse(row["grant_emitted"])
            self.assertFalse(row["filedata_present"])

    def test_luci_emitter_is_unchanged(self) -> None:
        blob = json.dumps(self.luci_grants)
        self.assertNotIn("cgi-upload", blob)
        self.assertNotIn("authorization_violation", blob)

    def test_cgi_grants_are_upload_only(self) -> None:
        self.assertEqual(len(self.grants), 2)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(classes, {BASE_SESSION_CLASS, "root"})
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["cgi_endpoint"], CGI_ENDPOINT)
            self.assertEqual(row["op"], "write")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotEqual(row["assessment"], "authorization_violation")
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-exec", blob)
        self.assertNotIn("cgi-download", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))

    def test_effect_is_synthetic_file_write(self) -> None:
        effect = self.effect
        for key in REQUIRED:
            self.assertIn(key, effect, key)
        self.assertEqual(effect["record_id"], EFFECT_RECORD_ID)
        self.assertEqual(effect["sink_kind"], "file_write")
        self.assertEqual(effect["op"], "write")
        self.assertEqual(effect["assessment"], "intended_access")
        self.assertNotEqual(effect["evidence_status"], "path_found")
        self.assertIn(f"policy:grant:{BASE_SESSION_CLASS}:cgi_io:cgi-upload", effect["evidence_refs"])
        self.assertIn("policy:grant:root:cgi_io:cgi-upload", effect["evidence_refs"])
        text = " ".join(effect["assumptions"]).lower()
        self.assertIn("shellquote", text)
        self.assertIn("basename", text)
        self.assertIn("not sanitizers", text)
        self.assertIn("status 200", text)


class TestCanonicalize(unittest.TestCase):
    def test_python_matches_documented_vectors(self) -> None:
        self.assertEqual(canonicalize_path(UPLOAD_PATH), UPLOAD_PATH)
        self.assertEqual(canonicalize_path("/etc/luci-uploads/../passwd"), "/etc/passwd")
        self.assertEqual(canonicalize_path("/etc/luci-uploads//foo"), "/etc/luci-uploads/foo")
        self.assertIsNone(canonicalize_path(""))


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "cgi_upload")

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

    def test_parse_urlencoded_is_invalid_request(self) -> None:
        proc = self._run("parse", "application/x-www-form-urlencoded", BASE_FIXTURE_SID)
        self.assertEqual(proc.stdout.strip(), "INVALID_REQUEST")

    def test_parse_does_not_require_sessionid(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_EXAMPLE, "-")
        self.assertEqual(proc.stdout.strip(), "PARSE_OK")

    def test_parse_ok(self) -> None:
        proc = self._run("parse", CONTENT_TYPE_EXAMPLE, BASE_FIXTURE_SID)
        self.assertEqual(proc.stdout.strip(), "PARSE_OK")

    def test_canon_dotdot(self) -> None:
        proc = self._run("canon", "/etc/luci-uploads/../passwd")
        self.assertEqual(proc.stdout.strip(), "/etc/passwd")

    def test_match_upload_write_only(self) -> None:
        allow = self._run("match", "cgi-io", "upload", "write", "cgi-io", "upload", "write")
        download = self._run("match", "cgi-io", "download", "read", "cgi-io", "upload", "write")
        backup = self._run("match", "cgi-io", "backup", "read", "cgi-io", "upload", "write")
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(download.stdout.strip(), "DENY")
        self.assertEqual(backup.stdout.strip(), "DENY")

    def test_decide_path_and_dotdot(self) -> None:
        allow = self._run(
            "decide",
            CONTENT_TYPE_EXAMPLE,
            BASE_FIXTURE_SID,
            UPLOAD_PATH,
            "cgi-io",
            "upload",
            "write",
            "/etc/luci-uploads/*",
            "write",
            "1",
        )
        passwd = self._run(
            "decide",
            CONTENT_TYPE_EXAMPLE,
            BASE_FIXTURE_SID,
            "/etc/passwd",
            "cgi-io",
            "upload",
            "write",
            "/etc/luci-uploads/*",
            "write",
            "1",
        )
        dotdot = self._run(
            "decide",
            CONTENT_TYPE_EXAMPLE,
            BASE_FIXTURE_SID,
            "/etc/luci-uploads/../passwd",
            "cgi-io",
            "upload",
            "write",
            "/etc/luci-uploads/*",
            "write",
            "1",
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(passwd.stdout.strip(), "PATH_DENIED")
        self.assertEqual(dotdot.stdout.strip(), "PATH_DENIED")

    def test_decide_absent_session_and_filedata_controls(self) -> None:
        for sid, filedata, cgi_object, expected in [
            ("-", "1", "upload", "FILE_DATA_WITHOUT_SESSION"),
            ("-", "0", "upload", "NO_RESPONSE"),
            (BASE_FIXTURE_SID, "1", "download", "UPLOAD_DENIED"),
            (BASE_FIXTURE_SID, "0", "download", "UPLOAD_DENIED"),
            (BASE_FIXTURE_SID, "0", "upload", "NO_RESPONSE"),
        ]:
            with self.subTest(sid=sid, filedata=filedata, cgi_object=cgi_object):
                proc = self._run(
                    "decide", CONTENT_TYPE_EXAMPLE, sid, UPLOAD_PATH,
                    "cgi-io", cgi_object, "write", "/etc/luci-uploads/*", "write", filedata,
                )
                self.assertEqual(proc.stdout.strip(), expected)
                self.assertEqual(proc.returncode, 0 if expected == "NO_RESPONSE" else 1)

    def test_decide_empty_sessionid_is_outside_slice(self) -> None:
        proc = self._run(
            "decide", CONTENT_TYPE_EXAMPLE, "", UPLOAD_PATH,
            "cgi-io", "upload", "write", "/etc/luci-uploads/*", "write", "1",
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("empty sessionid", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"CGI_IO_SHA={CGI_IO_SHA}", proc.stdout)
        self.assertIn("REQ_OBJECT=upload", proc.stdout)
        self.assertNotIn("cgi-exec", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effect = build_artifacts()
        committed = json.loads(
            (REPO / "policy" / "cgi_upload_decisions.json").read_text(encoding="utf-8")
        )
        committed_effect = json.loads(
            (REPO / "reports" / "m2-cgi-upload-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed["grants"], grants)
        self.assertEqual(committed["decisions"], bundle["decisions"])
        self.assertEqual(committed_effect, effect)

    def test_does_not_rewrite_canonical_grants_json(self) -> None:
        committed = json.loads((REPO / "policy" / "grants.json").read_text(encoding="utf-8"))
        blob = json.dumps(committed)
        self.assertNotIn("cgi-upload", blob)


if __name__ == "__main__":
    unittest.main()
