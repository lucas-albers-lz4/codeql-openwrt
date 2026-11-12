#!/usr/bin/env python3
"""Grant ↔ handler_effect joins against committed reports/handler_effects.json."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
JOIN_KEYS = (
    "corpus_revision",
    "profile",
    "ingress",
    "entrypoint_id",
    "ubus_object",
    "method",
)
EXEC_METHODS = (
    "getSwconfigFeatures",
    "getSwconfigPortState",
    "getRealtimeStats",
    "setPassword",
    "setLocaltime",
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
        self.assertGreaterEqual(len(self.effects), 12)
        ids = [row["record_id"] for row in self.effects]
        effect_ids = [row["effect_id"] for row in self.effects]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(effect_ids), len(set(effect_ids)))
        for row in self.effects:
            for key in REQUIRED:
                self.assertIn(key, row, key)
            self.assertEqual(row["record_type"], "handler_effect")
            self.assertEqual(row["evidence_status"], "fact")
            self.assertEqual(row["producer"], "step3")
            self.assertEqual(row["profile"], "luci-ssl-25.12")
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertEqual(row["ubus_object"], "luci")
            self.assertEqual(row["op"], "exec")
            self.assertIn(row["sink_kind"], ("popen", "system"))
            self.assertIn(row["assessment"], ("intended_access", "unassessed"))
            self.assertNotEqual(row["assessment"], "authorization_violation")
            self.assertNotIn("cgi_endpoint", row)
            self.assertNotIn("route_path", row)
            self.assertIn(row["record_type"], SCHEMA["properties"]["record_type"]["enum"])
            self.assertIn(row["sink_kind"], SCHEMA["properties"]["sink_kind"]["enum"])

    def test_every_grant_joins_an_effect(self) -> None:
        for grant in self.grants:
            matches = [
                effect
                for effect in self.effects
                if all(effect.get(key) == grant[key] for key in JOIN_KEYS)
                and grant["record_id"] in effect.get("evidence_refs", [])
            ]
            self.assertTrue(
                matches,
                f"grant {grant['record_id']} has no joining handler_effect",
            )

    def test_exec_method_effects_join_delegated_and_root_grants(self) -> None:
        by_method = {row["method"]: row for row in self.effects if row["method"] in EXEC_METHODS}
        self.assertEqual(set(by_method), set(EXEC_METHODS))
        for method, effect in by_method.items():
            delegated = next(
                grant
                for grant in self.grants
                if grant["method"] == method and grant["session_class"] != "root"
            )
            root = next(
                grant
                for grant in self.grants
                if grant["method"] == method and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertTrue(any(ref.startswith("m4:luci-") for ref in refs))
            self.assertEqual(effect["assessment"], "intended_access")
            unauth_grants = [
                grant
                for grant in self.grants
                if grant["method"] == method and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth_grants, [])

    def test_getfeatures_effects_join_unauthenticated_and_root(self) -> None:
        effects = [row for row in self.effects if row["method"] == "getFeatures"]
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
        effects = [row for row in self.effects if row["method"] == "setInitAction"]
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["assessment"], "unassessed")
        self.assertFalse(any("policy:grant:" in ref for ref in effects[0]["evidence_refs"]))
        self.assertEqual([row for row in self.grants if row["method"] == "setInitAction"], [])

    def test_projected_effects_cite_existing_taint_paths(self) -> None:
        taint_ids = {row["record_id"] for row in self.taint_paths}
        for method in EXEC_METHODS:
            effect = next(row for row in self.effects if row["method"] == method)
            cited = [ref for ref in effect["evidence_refs"] if ref in taint_ids]
            self.assertEqual(len(cited), 1, method)
            source = next(row for row in self.taint_paths if row["record_id"] == cited[0])
            self.assertEqual(source["record_type"], "taint_path")
            self.assertEqual(source["entrypoint_id"], effect["entrypoint_id"])
            self.assertEqual(source["sink_kind"], effect["sink_kind"])
            self.assertEqual(source["target_id"], effect["target_id"])

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

    def test_catalog_does_not_invent_forbidden_claims(self) -> None:
        for row in self.effects:
            self.assertNotEqual(row.get("assessment"), "authorization_violation")
            self.assertNotEqual(row.get("ingress"), "cgi_io")
            self.assertNotEqual(row.get("ingress"), "dispatcher")
            self.assertNotIn("cgi_endpoint", row)


if __name__ == "__main__":
    unittest.main()
