#!/usr/bin/env python3
"""ubus luci.getConntrackHelpers luci-app-firewall vs evaluator vs C double."""

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
from policy.cgi_exec_file import PKGMGR_FIXTURE_SID, PKGMGR_SESSION_CLASS  # noqa: E402
from policy.oracle import (  # noqa: E402
    C_DOUBLE_FLAGS,
    ERROR_ACCESS,
    ERROR_PARSE,
    MOUNTS_FIXTURE_SID,
    PRODUCER,
    ROOT_FIXTURE_SID,
    STATUS_FIXTURE_SID,
    build_artifacts as luci_build_artifacts,
    corpus_revision,
)
from policy.ubus_file_exec_mounts import MOUNTS_SESSION_CLASS  # noqa: E402
from policy.ubus_rc_list import (  # noqa: E402
    INIT_READ_FIXTURE_SID,
    INIT_READ_SESSION_CLASS,
)
from policy.ubus_system_reboot import (  # noqa: E402
    REBOOT_FIXTURE_SID,
    REBOOT_SESSION_CLASS,
)
from policy.ubus_luci_getbuiltinethernetports import (  # noqa: E402
    PORTS_FIXTURE_SID,
    PORTS_SESSION_CLASS,
)
from policy.ubus_luci_getmountpoints import (  # noqa: E402
    STORAGE_FIXTURE_SID,
    STORAGE_SESSION_CLASS,
)
from policy.ubus_luci_getconntrackhelpers import (  # noqa: E402
    ANALYSIS_REVISION,
    EFFECT_RECORD_ID,
    ENTRYPOINT_ID,
    INDEX_SESSION_CLASS,
    REALTIME_SESSION_CLASS,
    RPCD_SHA,
    FIREWALL_FIXTURE_SID,
    FIREWALL_SESSION_CLASS,
    UBUS_METHOD,
    UBUS_OBJECT,
    build_artifacts,
    evaluate_expected_case,
    evaluate_luci_getconntrackhelpers,
    grant_id,
    load_expected_cases,
    load_luci_getconntrackhelpers_world,
)
from policy.ubus_system_board import INDEX_FIXTURE_SID  # noqa: E402

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
C_SRC = REPO / "policy" / "c_double" / "ubus_luci_getconntrackhelpers.c"


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
        cls.sessions = load_luci_getconntrackhelpers_world()
        cls.grants, cls.bundle, cls.effects = build_artifacts()

    def _result(self, case_id: str):
        return evaluate_expected_case(self.cases[case_id], self.sessions)

    def test_unauthenticated_luci_getConntrackHelpers_deny(self) -> None:
        result = self._result("unauthenticated-luci-getConntrackHelpers-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
        self.assertIsNone(result.matched)
        grant_ids = [row["record_id"] for row in self.grants]
        self.assertNotIn(grant_id("unauthenticated"), grant_ids)

    def test_missing_sid_is_parse_error(self) -> None:
        result = self._result("missing-sid-parse-error")
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertIn("path_found", self.cases["missing-sid-parse-error"]["not"])
        self.assertIn("setInitAction", self.cases["missing-sid-parse-error"]["not"])

    def test_null_data_is_parse_error_but_omitted_data_defaults_to_table(self) -> None:
        result = self._result("null-data-parse-error")
        self.assertEqual(result.outcome, "jsonrpc_parse_error")
        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
        self.assertEqual(evaluate_luci_getconntrackhelpers(sid=FIREWALL_FIXTURE_SID).outcome, "allow")

    def test_ports_fixture_allow(self) -> None:
        case = self.cases["luci-app-firewall-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, FIREWALL_SESSION_CLASS)
        self.assertEqual(result.sid, FIREWALL_FIXTURE_SID)
        self.assertEqual(result.object, UBUS_OBJECT)
        self.assertEqual(result.function, UBUS_METHOD)
        self.assertEqual(result.matched.object, UBUS_OBJECT)
        self.assertEqual(result.matched.function, UBUS_METHOD)
        self.assertEqual(case["assessment"], "intended_access")
        self.assertNotEqual(case["assessment"], "authorization_violation")
        self.assertIn("not a PoC", case["note"])
        self.assertIn("rpc.declare", case["note"])

    def test_storage_mounts_and_package_manager_denied(self) -> None:
        storage = self._result("luci-mod-status-index-storage-luci-getConntrackHelpers-deny")
        self.assertEqual(storage.outcome, "deny")
        self.assertEqual(storage.session_class, STORAGE_SESSION_CLASS)
        self.assertEqual(storage.sid, STORAGE_FIXTURE_SID)
        mounts = self._result("luci-mod-system-mounts-luci-getConntrackHelpers-deny")
        self.assertEqual(mounts.outcome, "deny")
        self.assertEqual(mounts.session_class, MOUNTS_SESSION_CLASS)
        self.assertEqual(mounts.sid, MOUNTS_FIXTURE_SID)
        pkgmgr = self._result("luci-app-package-manager-luci-getConntrackHelpers-deny")
        self.assertEqual(pkgmgr.outcome, "deny")
        self.assertEqual(pkgmgr.session_class, PKGMGR_SESSION_CLASS)
        self.assertEqual(pkgmgr.sid, PKGMGR_FIXTURE_SID)

    def test_index_fixture_denied_at_http_gate(self) -> None:
        result = self._result("luci-mod-status-index-luci-getConntrackHelpers-deny")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.session_class, INDEX_SESSION_CLASS)
        self.assertEqual(result.sid, INDEX_FIXTURE_SID)
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)

    def test_other_fixtures_denied_at_http_gate(self) -> None:
        realtime = self._result("luci-mod-status-realtime-luci-getConntrackHelpers-deny")
        self.assertEqual(realtime.outcome, "deny")
        self.assertEqual(realtime.session_class, REALTIME_SESSION_CLASS)
        self.assertEqual(realtime.sid, STATUS_FIXTURE_SID)
        self.assertEqual(realtime.jsonrpc_error, ERROR_ACCESS)
        reboot = self._result("luci-mod-system-reboot-luci-getConntrackHelpers-deny")
        self.assertEqual(reboot.outcome, "deny")
        self.assertEqual(reboot.sid, REBOOT_FIXTURE_SID)
        self.assertEqual(reboot.session_class, REBOOT_SESSION_CLASS)
        flash = self._result("luci-mod-system-flash-luci-getConntrackHelpers-deny")
        self.assertEqual(flash.outcome, "deny")
        self.assertEqual(flash.session_class, FLASH_SESSION_CLASS)
        self.assertEqual(flash.sid, FLASH_FIXTURE_SID)
        self.assertEqual(flash.jsonrpc_error, ERROR_ACCESS)
        self.assertIn("write flash", self.cases["luci-mod-system-flash-luci-getConntrackHelpers-deny"]["note"])
        init_read = self._result("luci-mod-system-init-read-luci-getConntrackHelpers-deny")
        self.assertEqual(init_read.outcome, "deny")
        self.assertEqual(init_read.session_class, INIT_READ_SESSION_CLASS)
        self.assertEqual(init_read.sid, INIT_READ_FIXTURE_SID)

    def test_system_board_is_allowed_not_granted(self) -> None:
        result = self._result("system-board-not-this-slice")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.function, "board")
        self.assertFalse(self.cases["system-board-not-this-slice"]["expect_grant"])
        blob = json.dumps(self.grants)
        self.assertNotIn("system.board", blob)

    def test_system_info_is_allowed_not_granted(self) -> None:
        result = self._result("system-info-not-this-slice")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.function, "info")
        self.assertEqual(result.session_class, INDEX_SESSION_CLASS)
        self.assertFalse(self.cases["system-info-not-this-slice"]["expect_grant"])
        blob = json.dumps(self.grants)
        self.assertNotIn("system.info", blob)

    def test_system_reboot_is_denied_not_granted(self) -> None:
        result = self._result("system-reboot-not-this-slice")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
        self.assertEqual(result.function, "reboot")
        self.assertFalse(self.cases["system-reboot-not-this-slice"]["expect_grant"])

    def test_luci_getVersion_is_allowed_not_granted(self) -> None:
        result = self._result("luci-getVersion-not-this-slice")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.object, "luci")
        self.assertEqual(result.function, "getVersion")
        self.assertFalse(self.cases["luci-getVersion-not-this-slice"]["expect_grant"])
        methods = [row["method"] for row in self.grants]
        self.assertNotIn("getVersion", methods)

    def test_luci_getUnixtime_is_allowed_not_granted(self) -> None:
        result = self._result("luci-getUnixtime-not-this-slice")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.object, "luci")
        self.assertEqual(result.function, "getUnixtime")
        self.assertFalse(self.cases["luci-getUnixtime-not-this-slice"]["expect_grant"])
        methods = [row["method"] for row in self.grants]
        self.assertNotIn("getUnixtime", methods)

    def test_luci_getOdhcp6cStats_is_allowed_not_granted(self) -> None:
        result = self._result("luci-getOdhcp6cStats-not-this-slice")
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.object, "luci")
        self.assertEqual(result.function, "getOdhcp6cStats")
        self.assertFalse(self.cases["luci-getOdhcp6cStats-not-this-slice"]["expect_grant"])
        methods = [row["method"] for row in self.grants]
        self.assertNotIn("getOdhcp6cStats", methods)

    def test_luci_mod_system_config_is_denied(self) -> None:
        result = self._result("luci-mod-system-config-not-this-slice")
        self.assertEqual(result.outcome, "deny")
        self.assertEqual(result.object, "luci")
        self.assertEqual(result.function, "getConntrackHelpers")
        self.assertEqual(result.session_class, "luci-mod-system-config")
        self.assertEqual(result.jsonrpc_error, ERROR_ACCESS)
        self.assertFalse(self.cases["luci-mod-system-config-not-this-slice"]["expect_grant"])
        classes = {row["session_class"] for row in self.grants}
        self.assertNotIn("luci-mod-system-config", classes)

    def test_root_luci_getConntrackHelpers_allow_not_violation(self) -> None:
        case = self.cases["root-star-luci-getConntrackHelpers-allow"]
        result = self._result(case["id"])
        self.assertEqual(result.outcome, "allow")
        self.assertEqual(result.session_class, "root")
        self.assertEqual(result.sid, ROOT_FIXTURE_SID)
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

    def test_luci_getConntrackHelpers_grants_are_getConntrackHelpers_only(self) -> None:
        self.assertEqual(len(self.grants), 2)
        classes = {row["session_class"] for row in self.grants}
        self.assertEqual(
            classes,
            {FIREWALL_SESSION_CLASS, "root"},
        )
        self.assertNotIn(FLASH_SESSION_CLASS, classes)
        self.assertNotIn(REBOOT_SESSION_CLASS, classes)
        self.assertNotIn(REALTIME_SESSION_CLASS, classes)
        self.assertNotIn(INDEX_SESSION_CLASS, classes)
        for row in self.grants:
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["record_type"], "policy_grant")
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertEqual(row["ubus_object"], UBUS_OBJECT)
            self.assertEqual(row["method"], UBUS_METHOD)
            self.assertEqual(row["op"], "invoke")
            self.assertEqual(row["entrypoint_id"], ENTRYPOINT_ID)
            self.assertEqual(row["assessment"], "intended_access")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertNotIn("cgi_endpoint", row)
            self.assertNotEqual(row["assessment"], "authorization_violation")
        blob = json.dumps(self.grants)
        self.assertNotIn("cgi-backup", blob)
        self.assertNotIn("dispatcher", blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("path_found", blob)
        self.assertNotIn("setInitAction", blob)
        self.assertNotIn("step4", json.dumps(self.bundle))

    def test_effects_are_synthetic_ubus_call(self) -> None:
        self.assertEqual(len(self.effects), 1)
        effect = self.effects[0]
        for key in REQUIRED:
            self.assertIn(key, effect, key)
        self.assertEqual(effect["record_id"], EFFECT_RECORD_ID)
        self.assertEqual(effect["producer"], PRODUCER)
        self.assertEqual(effect["record_type"], "handler_effect")
        self.assertEqual(effect["evidence_status"], "fact")
        self.assertNotEqual(effect["evidence_status"], "path_found")
        self.assertEqual(effect["ingress"], "ubus_http")
        self.assertEqual(effect["ubus_object"], UBUS_OBJECT)
        self.assertEqual(effect["method"], UBUS_METHOD)
        self.assertEqual(effect["sink_kind"], "ubus_call")
        self.assertEqual(effect["op"], "invoke")
        self.assertEqual(effect["assessment"], "intended_access")
        self.assertIn(grant_id(FIREWALL_SESSION_CLASS), effect["evidence_refs"])
        self.assertIn(grant_id("root"), effect["evidence_refs"])
        self.assertNotIn(grant_id(MOUNTS_SESSION_CLASS), effect["evidence_refs"])
        self.assertNotIn(grant_id(PKGMGR_SESSION_CLASS), effect["evidence_refs"])
        text = " ".join(effect["assumptions"]).lower()
        self.assertIn("shellquote", text)
        self.assertIn("basename", text)
        self.assertIn("not sanitizers", text)
        self.assertIn("getversion", text)
        self.assertIn("getunixtime", text)
        self.assertIn("getodhcp6cstats", text)
        self.assertIn("system.info", text)
        self.assertNotIn("path_found", json.dumps(effect))
        self.assertNotIn("cgi_endpoint", effect)


class TestCDouble(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.tmp.name) / "ubus_luci_getconntrackhelpers")

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

    def test_parse_requires_sid_object_method_table(self) -> None:
        missing = self._run("parse", "-", UBUS_OBJECT, UBUS_METHOD, "{}")
        self.assertEqual(missing.stdout.strip(), "ERROR_PARSE")
        ok = self._run("parse", FIREWALL_FIXTURE_SID, UBUS_OBJECT, UBUS_METHOD, "{}")
        self.assertEqual(ok.stdout.strip(), "PARSE_OK")
        not_table = self._run(
            "parse", FIREWALL_FIXTURE_SID, UBUS_OBJECT, UBUS_METHOD, "string"
        )
        self.assertEqual(not_table.stdout.strip(), "ERROR_PARSE")
        null_data = self._run("parse", FIREWALL_FIXTURE_SID, UBUS_OBJECT, UBUS_METHOD, "null")
        self.assertEqual(null_data.stdout.strip(), "ERROR_PARSE")

    def test_decide_http_gate(self) -> None:
        allow = self._run(
            "decide",
            FIREWALL_FIXTURE_SID,
            UBUS_OBJECT,
            UBUS_METHOD,
            "{}",
            UBUS_OBJECT,
            UBUS_METHOD,
        )
        no_ubus = self._run(
            "decide",
            "00000000000000000000000000000000",
            UBUS_OBJECT,
            UBUS_METHOD,
            "{}",
            "-",
            "-",
        )
        flash = self._run(
            "decide",
            FLASH_FIXTURE_SID,
            UBUS_OBJECT,
            UBUS_METHOD,
            "{}",
            "file",
            "exec",
        )
        getversion = self._run(
            "decide",
            INDEX_FIXTURE_SID,
            UBUS_OBJECT,
            "getVersion",
            "{}",
            UBUS_OBJECT,
            UBUS_METHOD,
        )
        getodhcp = self._run(
            "decide",
            INDEX_FIXTURE_SID,
            UBUS_OBJECT,
            "getOdhcp6cStats",
            "{}",
            UBUS_OBJECT,
            UBUS_METHOD,
        )
        info = self._run(
            "decide",
            FIREWALL_FIXTURE_SID,
            "system",
            "info",
            "{}",
            UBUS_OBJECT,
            UBUS_METHOD,
        )
        self.assertEqual(allow.stdout.strip(), "ALLOW")
        self.assertEqual(no_ubus.stdout.strip(), "ERROR_ACCESS")
        self.assertEqual(flash.stdout.strip(), "ERROR_ACCESS")
        self.assertEqual(getversion.stdout.strip(), "NOT_THIS_SLICE")
        self.assertEqual(getodhcp.stdout.strip(), "NOT_THIS_SLICE")
        self.assertEqual(info.stdout.strip(), "NOT_THIS_SLICE")

    def test_match_luci_getConntrackHelpers_literal(self) -> None:
        hit = self._run("match", UBUS_OBJECT, UBUS_METHOD, UBUS_OBJECT, UBUS_METHOD)
        miss = self._run("match", UBUS_OBJECT, "getVersion", UBUS_OBJECT, UBUS_METHOD)
        self.assertEqual(hit.stdout.strip(), "ALLOW")
        self.assertEqual(miss.stdout.strip(), "DENY")

    def test_flags_record_pin(self) -> None:
        proc = self._run("flags")
        self.assertIn(f"RPCD_SHA={RPCD_SHA}", proc.stdout)
        self.assertIn("UBUS_OBJECT=luci", proc.stdout)
        self.assertIn("UBUS_METHOD=getConntrackHelpers", proc.stdout)
        self.assertNotIn("cgi-backup", proc.stdout)
        self.assertNotIn("setInitAction", proc.stdout)


class TestCommittedArtifacts(unittest.TestCase):
    def test_write_artifacts_roundtrip(self) -> None:
        grants, bundle, effects = build_artifacts()
        committed = json.loads(
            (REPO / "policy" / "ubus_luci_getconntrackhelpers_decisions.json").read_text(encoding="utf-8")
        )
        committed_effect = json.loads(
            (REPO / "reports" / "m2-ubus-luci-getconntrackhelpers-effect.json").read_text(encoding="utf-8")
        )
        self.assertEqual(committed, {"grants": grants, **bundle})
        self.assertEqual(committed_effect, effects)

    def test_canonical_grants_json_includes_getConntrackHelpers_grants(self) -> None:
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
