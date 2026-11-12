#!/usr/bin/env python3
"""Grant ↔ handler_effect joins against committed reports/handler_effects.json."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.oracle import EXEC_METHODS, REQUEST_ARGS_EXEC_METHODS  # noqa: E402

JOIN_KEYS = (
    "corpus_revision",
    "profile",
    "ingress",
    "entrypoint_id",
    "ubus_object",
    "method",
)
CGI_JOIN_KEYS = (
    "corpus_revision",
    "profile",
    "ingress",
    "entrypoint_id",
    "cgi_endpoint",
)
CGI_EFFECT_ID = "policy:effect:cgi-backup-sensitive-read"
CGI_EXEC_EFFECT_ID = "policy:effect:cgi-exec-session-access"
COPIED_EFFECT_SNAPSHOTS = (
    "reports/findings.json",
    "reports/m4-getfeatures-direct-exec.json",
    "reports/m4-luci-sys-init-action-findings.json",
    "reports/m4-block-device-exec.json",
    "reports/m4-luci-sys-status-exec.json",
)
PROJECTED_PATH_SNAPSHOT = "reports/m4-findings.json"
LUCI_EFFECT_COUNT = 17
COPIED_EFFECT_COUNT = 12
SOURCE_FIELDS = (
    "corpus_revision",
    "profile",
    "analysis_revision",
    "ingress",
    "entrypoint_id",
    "ubus_object",
    "method",
    "target_id",
    "op",
    "sink_kind",
    "assessment",
)
SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestHandlerEffectJoins(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.effects = _load(REPO / "reports" / "handler_effects.json")
        cls.grants = _load(REPO / "policy" / "grants.json")
        cls.taint_paths = _load(REPO / "reports" / "m4-findings.json")

    def test_catalog_is_handler_effects_only(self) -> None:
        self.assertIsInstance(self.effects, list)
        self.assertGreaterEqual(len(self.effects), LUCI_EFFECT_COUNT + 1)
        ids = [row["record_id"] for row in self.effects]
        effect_ids = [row["effect_id"] for row in self.effects]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(effect_ids), len(set(effect_ids)))
        luci_rows = [row for row in self.effects if row.get("ingress") == "ubus_http"]
        cgi_rows = [row for row in self.effects if row.get("ingress") == "cgi_io"]
        self.assertEqual(len(luci_rows), LUCI_EFFECT_COUNT)
        self.assertEqual(len(cgi_rows), 2)
        for row in luci_rows:
            for key in REQUIRED:
                self.assertIn(key, row, key)
            self.assertEqual(row["record_type"], "handler_effect")
            self.assertEqual(row["evidence_status"], "fact")
            self.assertEqual(row["producer"], "step3")
            self.assertEqual(row["profile"], "luci-ssl-25.12")
            self.assertEqual(row["ubus_object"], "luci")
            self.assertEqual(row["op"], "exec")
            self.assertIn(row["sink_kind"], ("popen", "system"))
            self.assertIn(row["assessment"], ("intended_access", "unassessed"))
            self.assertNotEqual(row["assessment"], "authorization_violation")
            self.assertNotIn("cgi_endpoint", row)
            self.assertNotIn("route_path", row)
            self.assertIn(row["record_type"], SCHEMA["properties"]["record_type"]["enum"])
            self.assertIn(row["sink_kind"], SCHEMA["properties"]["sink_kind"]["enum"])
        by_endpoint = {row["cgi_endpoint"]: row for row in cgi_rows}
        self.assertEqual(set(by_endpoint), {"cgi-backup", "cgi-exec"})
        backup = by_endpoint["cgi-backup"]
        self.assertEqual(backup["record_id"], CGI_EFFECT_ID)
        self.assertEqual(backup["producer"], "policy_facts")
        self.assertEqual(backup["sink_kind"], "sensitive_backup_read")
        self.assertEqual(backup["op"], "read")
        self.assertEqual(backup["assessment"], "intended_access")
        self.assertNotEqual(backup["assessment"], "authorization_violation")
        exec_row = by_endpoint["cgi-exec"]
        self.assertEqual(exec_row["record_id"], CGI_EXEC_EFFECT_ID)
        self.assertEqual(exec_row["producer"], "policy_facts")
        self.assertEqual(exec_row["sink_kind"], "exec")
        self.assertEqual(exec_row["op"], "exec")
        self.assertEqual(exec_row["assessment"], "intended_access")
        self.assertNotEqual(exec_row["evidence_status"], "path_found")
        self.assertNotEqual(exec_row["assessment"], "authorization_violation")

    def test_every_grant_joins_an_effect(self) -> None:
        for grant in self.grants:
            keys = CGI_JOIN_KEYS if grant.get("ingress") == "cgi_io" else JOIN_KEYS
            matches = [
                effect
                for effect in self.effects
                if all(effect.get(key) == grant[key] for key in keys)
                and grant["record_id"] in effect.get("evidence_refs", [])
            ]
            self.assertTrue(
                matches,
                f"grant {grant['record_id']} has no joining handler_effect",
            )

    def test_exec_method_effects_join_delegated_and_root_grants(self) -> None:
        by_method = {}
        for row in self.effects:
            if row.get("method") in EXEC_METHODS:
                by_method.setdefault(row["method"], []).append(row)
        self.assertEqual(set(by_method), set(EXEC_METHODS))
        for method, effects in by_method.items():
            delegated = next(
                grant
                for grant in self.grants
                if grant.get("method") == method and grant["session_class"] != "root"
            )
            root = next(
                grant
                for grant in self.grants
                if grant.get("method") == method and grant["session_class"] == "root"
            )
            for effect in effects:
                refs = effect["evidence_refs"]
                self.assertIn(delegated["record_id"], refs)
                self.assertIn(root["record_id"], refs)
                self.assertEqual(effect["assessment"], "intended_access")
            unauth_grants = [
                grant
                for grant in self.grants
                if grant.get("method") == method and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth_grants, [])

    def test_getfeatures_effects_join_unauthenticated_and_root(self) -> None:
        effects = [row for row in self.effects if row.get("method") == "getFeatures"]
        self.assertEqual(len(effects), 6)
        for effect in effects:
            self.assertIn(
                "policy:grant:unauthenticated:ubus_http:luci.getFeatures",
                effect["evidence_refs"],
            )
            self.assertIn(
                "policy:grant:root:ubus_http:luci.getFeatures",
                effect["evidence_refs"],
            )
            self.assertEqual(effect["assessment"], "intended_access")

    def test_setinitaction_has_effect_without_grant(self) -> None:
        effects = [row for row in self.effects if row.get("method") == "setInitAction"]
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["assessment"], "unassessed")
        self.assertFalse(any("policy:grant:" in ref for ref in effects[0]["evidence_refs"]))
        self.assertEqual([row for row in self.grants if row.get("method") == "setInitAction"], [])

    def test_projected_effects_cite_existing_taint_paths(self) -> None:
        taint_ids = {row["record_id"] for row in self.taint_paths}
        for method in REQUEST_ARGS_EXEC_METHODS:
            effect = next(
                row
                for row in self.effects
                if row.get("method") == method
                and any(ref in taint_ids for ref in row.get("evidence_refs", []))
            )
            cited = [ref for ref in effect["evidence_refs"] if ref in taint_ids]
            self.assertEqual(len(cited), 1, method)
            source = next(row for row in self.taint_paths if row["record_id"] == cited[0])
            self.assertEqual(source["record_type"], "taint_path")
            self.assertEqual(source["entrypoint_id"], effect["entrypoint_id"])
            self.assertEqual(source["sink_kind"], effect["sink_kind"])
            self.assertEqual(source["target_id"], effect["target_id"])

    def test_every_catalog_effect_resolves_to_its_producer_snapshot(self) -> None:
        """Catalog rows must be copied effects or projections of retained paths."""
        copied_sources = []
        for relative_path in COPIED_EFFECT_SNAPSHOTS:
            for row in _load(REPO / relative_path):
                if (
                    row.get("record_type") == "handler_effect"
                    and row.get("evidence_status") == "fact"
                ):
                    copied_sources.append((relative_path, row))

        path_sources = [
            (PROJECTED_PATH_SNAPSHOT, row)
            for row in _load(REPO / PROJECTED_PATH_SNAPSHOT)
            if row.get("record_type") == "taint_path"
            and row.get("evidence_status") == "path_found"
        ]
        self.assertEqual(len(copied_sources), COPIED_EFFECT_COUNT)
        self.assertEqual(len(path_sources), len(REQUEST_ARGS_EXEC_METHODS))

        luci_effects = [row for row in self.effects if row.get("ingress") == "ubus_http"]
        resolved_source_keys = []
        for effect in luci_effects:
            copied = [
                (path, source)
                for path, source in copied_sources
                if source["record_id"] == effect["record_id"]
            ]
            projected = [
                (path, source)
                for path, source in path_sources
                if source["record_id"] in effect.get("evidence_refs", [])
            ]
            matches = copied + projected
            self.assertEqual(
                len(matches),
                1,
                f"{effect['record_id']} must resolve uniquely to a retained source row",
            )
            source_path, source = matches[0]
            resolved_source_keys.append((source_path, source["record_id"]))

            if source_path == PROJECTED_PATH_SNAPSHOT:
                self.assertEqual(source["record_type"], "taint_path")
                self.assertEqual(source["evidence_status"], "path_found")
                self.assertIn(effect["method"], REQUEST_ARGS_EXEC_METHODS)
            else:
                self.assertEqual(source["record_type"], "handler_effect")
                self.assertEqual(source["record_id"], effect["record_id"])

            for field in SOURCE_FIELDS:
                self.assertEqual(
                    effect.get(field),
                    source.get(field),
                    f"{effect['record_id']} drifted from {source_path} in {field}",
                )

        self.assertEqual(len(resolved_source_keys), LUCI_EFFECT_COUNT)
        self.assertEqual(
            len(resolved_source_keys),
            len(set(resolved_source_keys)),
            "catalog effects must resolve one-to-one to retained producer rows",
        )

    def test_shellquote_and_basename_are_not_sanitizers(self) -> None:
        quoted = [
            "m4:effect:luci-getSwconfigFeatures-popen",
            "m4:effect:luci-getSwconfigPortState-popen",
            "m4:effect:luci-getRealtimeStats-popen",
            "m4:effect:luci-setPassword-system",
        ]
        by_id = {row["record_id"]: row for row in self.effects}
        for record_id in quoted:
            text = " ".join(by_id[record_id]["assumptions"]).lower()
            self.assertIn("shellquote", text)
            self.assertIn("not", text)
            self.assertIn("sanitizer", text)
        init_text = " ".join(by_id["m4:luci-sys-init-action-system"]["assumptions"]).lower()
        self.assertIn("basename is not a modeled sanitizer", init_text)
        localtime = " ".join(by_id["m4:effect:luci-setLocaltime-system"]["assumptions"]).lower()
        self.assertIn("not treat localtime or sprintf %d as sanitizers", localtime)
        for record_id in (
            "m4:effect:luci-getBlockDevices-popen",
            "m4:effect:luci-setBlockDetect-system",
            "m4:effect:luci-setLocaltime-sysfixtime-system",
            "m4:effect:luci-getConntrackList-popen",
            "m4:effect:luci-getProcessList-popen",
        ):
            text = " ".join(by_id[record_id]["assumptions"]).lower()
            self.assertIn("not a taint path", text)
            self.assertNotIn("path_found", text)
        process_text = " ".join(by_id["m4:effect:luci-getProcessList-popen"]["assumptions"]).lower()
        self.assertIn("file.exec", process_text)
        self.assertIn("not", process_text)
        cgi_text = " ".join(by_id[CGI_EFFECT_ID]["assumptions"]).lower()
        self.assertIn("shellquote", cgi_text)
        self.assertIn("basename", cgi_text)
        self.assertIn("not sanitizers", cgi_text)
        exec_text = " ".join(by_id[CGI_EXEC_EFFECT_ID]["assumptions"]).lower()
        self.assertIn("shellquote", exec_text)
        self.assertIn("basename", exec_text)
        self.assertIn("not sanitizers", exec_text)
        self.assertNotIn("path_found", json.dumps(by_id[CGI_EXEC_EFFECT_ID]))

    def test_cgi_backup_joins_flash_and_root(self) -> None:
        effect = next(row for row in self.effects if row["record_id"] == CGI_EFFECT_ID)
        flash = next(
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-backup"
            and grant["session_class"] == "luci-mod-system-flash"
        )
        root = next(
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-backup" and grant["session_class"] == "root"
        )
        refs = effect["evidence_refs"]
        self.assertIn(flash["record_id"], refs)
        self.assertIn(root["record_id"], refs)
        self.assertEqual(effect["assessment"], "intended_access")
        unauth = [
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-backup"
            and grant["session_class"] == "unauthenticated"
        ]
        self.assertEqual(unauth, [])

    def test_cgi_exec_joins_network_and_root(self) -> None:
        effect = next(row for row in self.effects if row["record_id"] == CGI_EXEC_EFFECT_ID)
        network = next(
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-exec"
            and grant["session_class"] == "luci-mod-network-config"
        )
        root = next(
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-exec" and grant["session_class"] == "root"
        )
        refs = effect["evidence_refs"]
        self.assertIn(network["record_id"], refs)
        self.assertIn(root["record_id"], refs)
        self.assertEqual(effect["assessment"], "intended_access")
        self.assertNotEqual(effect["evidence_status"], "path_found")
        unauth = [
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-exec"
            and grant["session_class"] == "unauthenticated"
        ]
        self.assertEqual(unauth, [])
        invented = [
            grant
            for grant in self.grants
            if grant.get("cgi_endpoint") == "cgi-exec"
            and grant["session_class"]
            in ("luci-mod-status-logs", "luci-mod-status-firewall", "luci-app-package-manager")
        ]
        self.assertEqual(invented, [])

    def test_catalog_does_not_invent_forbidden_claims(self) -> None:
        allowed_cgi = {
            "cgi-backup": "sensitive_backup_read",
            "cgi-exec": "exec",
        }
        for row in self.effects:
            self.assertNotEqual(row.get("assessment"), "authorization_violation")
            self.assertNotEqual(row.get("ingress"), "dispatcher")
            self.assertNotEqual(row.get("evidence_status"), "path_found")
            if row.get("ingress") == "cgi_io":
                self.assertIn(row.get("cgi_endpoint"), allowed_cgi)
                self.assertEqual(row.get("sink_kind"), allowed_cgi[row["cgi_endpoint"]])
            else:
                self.assertNotIn("cgi_endpoint", row)


if __name__ == "__main__":
    unittest.main()
