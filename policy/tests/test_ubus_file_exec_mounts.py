#!/usr/bin/env python3
"""ubus file.exec luci-mod-system-mounts umount/block vs evaluator vs C double."""

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

from policy.cgi_backup import FLASH_FIXTURE_SID, FLASH_SESSION_CLASS  # noqa: E402
from policy.cgi_exec_file import LOGS_SESSION_CLASS  # noqa: E402
from policy.cgi_exec_status import FIREWALL_FIXTURE_SID, FIREWALL_SESSION_CLASS  # noqa: E402
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    ERROR_ACCESS,
    ERROR_PARSE,
    MOUNTS_FIXTURE_SID,
    NETWORK_FIXTURE_SID,
    PRODUCER,
    build_artifacts as luci_build_artifacts,
    corpus_revision,
)
from policy.ubus_file_exec import (  # noqa: E402
    FILE_FUNCTION,
    UBUS_METHOD,
    UBUS_OBJECT,
    UBUS_STATUS_NOT_FOUND,
    UBUS_STATUS_OK,
    UBUS_STATUS_PERMISSION_DENIED,
)
from policy.ubus_file_exec_ifup import NETWORK_READ_SESSION_CLASS  # noqa: E402
from policy.ubus_file_exec_mounts import (  # noqa: E402
    ANALYSIS_REVISION,
    BLOCK,
    COMMANDS,
    MOUNTS_SESSION_CLASS,
    RPCD_SHA,
    UMOUNT,
    build_artifacts,
    evaluate_expected_case,
    evaluate_mounts_exec,
    grant_id,
    load_expected_cases,
    load_mounts_world,
)

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "ubus_file_exec_mounts.c"


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
        cls.sessions = load_mounts_world()
        cls.grants, cls.bundle, cls.effects = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_umount_deny(self) -> None:
        result = self._result("unauthenticated-umount-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
        self.assertIsNone(result.ubus_matched)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn(grant_id("unauthenticated", "umount"), grant_ids)

    def test_missing_sid_is_parse_error(self) -> None:
        result = self._result("missing-sid-parse-error")
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertIn("execv", self.cases["missing-sid-parse-error"]["not"])
        self.assertIn("path_found", self.cases["missing-sid-parse-error"]["not"])

    def test_mounts_umount_allow_bare_executable(self) -> None:
        case = self.cases["luci-mod-system-mounts-umount-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.ubus_status, UBUS_STATUS_OK)
        self.assertEqual(result.session_class, MOUNTS_SESSION_CLASS)
        self.assertEqual(result.sid, MOUNTS_FIXTURE_SID)
        self.assertEqual(result.command_id, "umount")
        self.assertEqual(result.match_stage, "executable")
        self.assertEqual(result.file_matched.object, UMOUNT)
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")
        self.assertIn("not a PoC", case["note"])

    def test_extra_argv_is_intended_access_not_poc(self) -> None:
        extra = self._result("luci-mod-system-mounts-umount-extra-argv-allow")
        self.assertEqual(extra.outcome, "allow")
        self.assertEqual(extra.match_stage, "executable")
        case = self.cases["luci-mod-system-mounts-umount-extra-argv-allow"]
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")
        self.assertIn("not a PoC", case["note"])
        self.assertFalse(case["expect_grant"])

    def test_mounts_block_allow(self) -> None:
        case = self.cases["luci-mod-system-mounts-block-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.match_stage, "executable")
        self.assertEqual(result.session_class, MOUNTS_SESSION_CLASS)
        self.assertEqual(result.file_matched.object, BLOCK)
        self.assertEqual(case["assessment"], "intended_access")
        self.assertIn("not a PoC", case["note"])

    def test_flash_has_ubus_exec_without_umount_file_acl(self) -> None:
        flash = self._result("luci-mod-system-flash-umount-command-denied")
        self.assertEqual(flash.outcome, "command_denied")
        self.assertEqual(flash.session_class, FLASH_SESSION_CLASS)
        self.assertEqual(flash.sid, FLASH_FIXTURE_SID)
        self.assertIsNotNone(flash.ubus_matched)
        self.assertEqual(flash.ubus_matched.object, UBUS_OBJECT)
        self.assertIsNone(flash.file_matched)

    def test_ubus_exec_without_umount_file_acl_is_command_denied(self) -> None:
        firewall = self._result("luci-mod-status-firewall-umount-command-denied")
        self.assertEqual(firewall.outcome, "command_denied")
        self.assertEqual(firewall.session_class, FIREWALL_SESSION_CLASS)
        self.assertIsNotNone(firewall.ubus_matched)
        self.assertEqual(firewall.ubus_matched.object, UBUS_OBJECT)
        self.assertIsNone(firewall.file_matched)
        network = self._result("luci-mod-network-config-umount-command-denied")
        self.assertEqual(network.outcome, "command_denied")
        self.assertEqual(network.session_class, NETWORK_READ_SESSION_CLASS)
        self.assertEqual(network.sid, NETWORK_FIXTURE_SID)

    def test_logs_denied_at_http_gate(self) -> None:
        logs = self._result("luci-mod-status-logs-umount-deny")
        self.assertEqual(logs.outcome, "deny")
        self.assertEqual(logs.session_class, LOGS_SESSION_CLASS)
        self.assertEqual(logs.jsonrpc_error, ERROR_ACCESS)

    def test_unstaffed_paths_are_not_found(self) -> None:
        for case_id in ("kill-not-found", "ping-not-found", "sysupgrade-not-found"):
            result = self._result(case_id)
            self.assertEqual(result.outcome, "not_found", case_id)
            self.assertEqual(result.ubus_status, UBUS_STATUS_NOT_FOUND, case_id)

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
        not_a_table = evaluate_mounts_exec(
            sid=MOUNTS_FIXTURE_SID, command=UMOUNT, params=["/mnt/sda1"], env=[]
        )
        self.assertEqual(not_a_table.outcome, "allow")

    def test_root_umount_allow_not_violation(self) -> None:
        case = self.cases["root-star-umount-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(case["assessment"], "intended_access")
        self.assertEqual(case["expectation_id"], "root-administration")
        self.assertIn("not a violation", case["note"])
        block = self._result("root-star-block-allow")
        self.assertEqual(block.outcome, "allow")
        self.assertEqual(block.command_id, "block")

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
        self.assertEqual(len(self.grants), 4)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(classes, {MOUNTS_SESSION_CLASS, "root"})
        self.assertNotIn(FLASH_SESSION_CLASS, classes)
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
        self.assertNotIn("/bin/kill", blob)
        self.assertNotIn("/sbin/sysupgrade", blob)
        self.assertNotIn("/sbin/firstboot", blob)

    def test_effects_are_synthetic_file_exec(self) -> None:
        self.assertEqual(len(self.effects), 2)
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
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "ubus_file_exec_mounts")

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
        ok = self._run("parse", MOUNTS_FIXTURE_SID, UBUS_OBJECT, UBUS_METHOD, "{}")
        self.assertEqual(ok.stdout.strip(), "PARSE_OK")
        canon = self._run("canon", "/bin/../bin/umount")
        self.assertEqual(canon.stdout.strip(), UMOUNT)
        block = self._run("canon", "/sbin/../sbin/block")
        self.assertEqual(block.stdout.strip(), BLOCK)

    def test_decide_conjunctive_file_acl(self) -> None:
        allow = self._run(
            "decide",
            MOUNTS_FIXTURE_SID,
            UMOUNT,
            "/mnt/sda1",
            UBUS_OBJECT,
            UBUS_METHOD,
            UMOUNT,
            FILE_FUNCTION,
            "-",
            "-",
        )
        extra = self._run(
            "decide",
            MOUNTS_FIXTURE_SID,
            UMOUNT,
            "/mnt/sda1 extra",
            UBUS_OBJECT,
            UBUS_METHOD,
            UMOUNT,
            FILE_FUNCTION,
            "-",
            "-",
        )
        block = self._run(
            "decide",
            MOUNTS_FIXTURE_SID,
            BLOCK,
            "mount",
            UBUS_OBJECT,
            UBUS_METHOD,
            BLOCK,
            FILE_FUNCTION,
            "-",
            "-",
        )
        no_ubus = self._run(
            "decide",
            "00000000000000000000000000000000",
            UMOUNT,
            "/mnt/sda1",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
        )
        denied = self._run(
            "decide",
            FIREWALL_FIXTURE_SID,
            UMOUNT,
            "/mnt/sda1",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "-",
            "-",
        )
        missing = self._run(
            "decide",
            MOUNTS_FIXTURE_SID,
            "/sbin/sysupgrade",
            "--list-backup",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "-",
            "-",
        )
        ping = self._run(
            "decide",
            MOUNTS_FIXTURE_SID,
            "/bin/ping",
            "-c 5 openwrt.org",
            UBUS_OBJECT,
            UBUS_METHOD,
            "-",
            "-",
            "-",
            "-",
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(extra.stdout.strip(), "ALLOW")
        self.assertEqual(block.stdout.strip(), "ALLOW")
        self.assertEqual(no_ubus.stdout.strip(), "ERROR_ACCESS")
        self.assertEqual(denied.stdout.strip(), "UBUS_PERMISSION_DENIED")
        self.assertEqual(missing.stdout.strip(), "UBUS_NOT_FOUND")
        self.assertEqual(ping.stdout.strip(), "UBUS_NOT_FOUND")

    def test_empty_env_presence_is_denied(self) -> None:
        args = (
            "decide", MOUNTS_FIXTURE_SID, UMOUNT, "/mnt/sda1",
            UBUS_OBJECT, UBUS_METHOD, UMOUNT, FILE_FUNCTION, "-", "-",
        )
        self.assertEqual(self._run(*args, "1").stdout.strip(), "UBUS_PERMISSION_DENIED")
        self.assertEqual(self._run(*args, "0").stdout.strip(), "ALLOW")
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
        committed = json.loads(
            (REPO / "policy" / "ubus_file_exec_mounts_decisions.json").read_text(encoding="utf-8")
        )
        committed_effect = json.loads(
            (REPO / "reports" / "m2-ubus-file-exec-mounts-effect.json").read_text(encoding="utf-8")
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
