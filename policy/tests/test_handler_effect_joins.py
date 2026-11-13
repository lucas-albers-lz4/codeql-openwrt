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

from policy.oracle import (  # noqa: E402
    EXEC_METHODS,
    REQUEST_ARGS_EXEC_METHODS,
    corpus_revision,
)

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
CGI_BACKUP_EFFECT_ID = "policy:effect:cgi-backup-sensitive-read"
CGI_UPLOAD_EFFECT_ID = "policy:effect:cgi-upload-file-write"
CGI_DOWNLOAD_EFFECT_ID = "policy:effect:cgi-download-file-read"
CGI_EXEC_EFFECT_ID = "policy:effect:cgi-exec-session-access"
CGI_EXEC_FILE_SNAPSHOT = "reports/m2-cgi-exec-file-effect.json"
CGI_CATALOG = {
    CGI_BACKUP_EFFECT_ID: {
        "cgi_endpoint": "cgi-backup",
        "sink_kind": "sensitive_backup_read",
        "op": "read",
        "snapshot": None,
        "delegated_class": "luci-mod-system-flash",
    },
    CGI_UPLOAD_EFFECT_ID: {
        "cgi_endpoint": "cgi-upload",
        "sink_kind": "file_write",
        "op": "write",
        "snapshot": "reports/m2-cgi-upload-effect.json",
        "delegated_class": "luci-base",
    },
    CGI_DOWNLOAD_EFFECT_ID: {
        "cgi_endpoint": "cgi-download",
        "sink_kind": "file_read",
        "op": "read",
        "snapshot": "reports/m2-cgi-download-effect.json",
        "delegated_class": "luci-mod-system-flash",
    },
    CGI_EXEC_EFFECT_ID: {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-effect.json",
        "delegated_class": "luci-mod-network-config",
    },
    "policy:effect:cgi-exec-file:syslog-wrapper": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": CGI_EXEC_FILE_SNAPSHOT,
        "delegated_class": "luci-mod-status-logs",
    },
    "policy:effect:cgi-exec-file:luci-peeraddr": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": CGI_EXEC_FILE_SNAPSHOT,
        "delegated_class": "luci-mod-network-config",
    },
    "policy:effect:cgi-exec-file:package-manager-call": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": CGI_EXEC_FILE_SNAPSHOT,
        "delegated_class": "luci-app-package-manager",
    },
    "policy:effect:cgi-exec-status:dmesg": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-logs",
    },
    "policy:effect:cgi-exec-status:nft": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:iptables": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:ip6tables": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:iptables-save": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:ip6tables-save": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:firewall-init": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
}
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
        self.assertEqual(len(cgi_rows), len(CGI_CATALOG))
        self.assertEqual({row["record_id"] for row in cgi_rows}, set(CGI_CATALOG))
        self.assertEqual(
            {row["cgi_endpoint"] for row in cgi_rows},
            {spec["cgi_endpoint"] for spec in CGI_CATALOG.values()},
        )
        lock_hash = corpus_revision()
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
            self.assertEqual(row["corpus_revision"], lock_hash)
        for cgi in cgi_rows:
            spec = CGI_CATALOG[cgi["record_id"]]
            self.assertEqual(cgi["cgi_endpoint"], spec["cgi_endpoint"])
            self.assertEqual(cgi["producer"], "policy_facts")
            self.assertEqual(cgi["sink_kind"], spec["sink_kind"])
            self.assertEqual(cgi["op"], spec["op"])
            self.assertEqual(cgi["assessment"], "intended_access")
            self.assertNotEqual(cgi["assessment"], "authorization_violation")
            self.assertEqual(cgi["corpus_revision"], lock_hash)
            self.assertEqual(cgi["evidence_status"], "fact")
            self.assertNotEqual(cgi["evidence_status"], "path_found")

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
        for record_id in (
            CGI_BACKUP_EFFECT_ID,
            CGI_UPLOAD_EFFECT_ID,
            CGI_DOWNLOAD_EFFECT_ID,
            CGI_EXEC_EFFECT_ID,
            "policy:effect:cgi-exec-file:syslog-wrapper",
            "policy:effect:cgi-exec-file:luci-peeraddr",
            "policy:effect:cgi-exec-file:package-manager-call",
            "policy:effect:cgi-exec-status:dmesg",
            "policy:effect:cgi-exec-status:nft",
            "policy:effect:cgi-exec-status:iptables",
            "policy:effect:cgi-exec-status:firewall-init",
        ):
            cgi_text = " ".join(by_id[record_id]["assumptions"]).lower()
            self.assertIn("shellquote", cgi_text)
            self.assertIn("basename", cgi_text)
            self.assertIn("not sanitizers", cgi_text)

    def test_cgi_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in CGI_CATALOG.values():
            if spec["snapshot"]:
                loaded = _load(REPO / spec["snapshot"])
                snapshots[spec["snapshot"]] = loaded if isinstance(loaded, list) else [loaded]
        for record_id, spec in CGI_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            if spec["snapshot"]:
                snapshot_rows = snapshots[spec["snapshot"]]
                snapshot = next(row for row in snapshot_rows if row["record_id"] == record_id)
                self.assertEqual(effect, snapshot)

    def test_catalog_does_not_invent_forbidden_claims(self) -> None:
        for row in self.effects:
            self.assertNotEqual(row.get("assessment"), "authorization_violation")
            self.assertNotEqual(row.get("ingress"), "dispatcher")
            if row.get("ingress") == "cgi_io":
                spec = CGI_CATALOG[row["record_id"]]
                self.assertEqual(row.get("sink_kind"), spec["sink_kind"])
            else:
                self.assertNotIn("cgi_endpoint", row)
        exec_effect = next(row for row in self.effects if row["record_id"] == CGI_EXEC_EFFECT_ID)
        exec_text = " ".join(exec_effect.get("assumptions", [])).lower()
        self.assertIn("execv", exec_text)
        self.assertIn("file.exec", " ".join(exec_effect.get("unknowns", [])).lower())
        self.assertNotIn("path_found", json.dumps(exec_effect))


if __name__ == "__main__":
    unittest.main()
