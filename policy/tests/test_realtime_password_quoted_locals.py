#!/usr/bin/env python3
"""M4 inventory: preserved runtime quoting and analyzer coverage through locals."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.oracle import corpus_revision  # noqa: E402

JOIN_KEYS = (
    "corpus_revision",
    "profile",
    "ingress",
    "entrypoint_id",
    "ubus_object",
    "method",
)
INVENTORY = REPO / "reports" / "m4-realtime-password-quoted-locals.json"
BARRIER = REPO / "reports" / "m4-shellquote-findings.json"
GRANTS = REPO / "policy" / "grants.json"
SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
ANALYSIS_REVISION = "inventory:realtime-password-quoted-locals-v1"
ROWS = {
    "getRealtimeStats": {
        "record_id": "m4:inventory:luci-getRealtimeStats-flags-quoted-locals",
        "delegated": "policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats",
        "root": "policy:grant:root:ubus_http:luci.getRealtimeStats",
        "deny": "policy:decision:unauthenticated-getRealtimeStats-deny",
        "local": "flags",
        "sink_kind": "popen",
        "target_id": "command:luci-bwc",
        "taint_path": "m4:luci-getRealtimeStats-request-args-popen",
    },
    "setPassword": {
        "record_id": "m4:inventory:luci-setPassword-u-p-quoted-locals",
        "delegated": "policy:grant:luci-mod-system-config:ubus_http:luci.setPassword",
        "root": "policy:grant:root:ubus_http:luci.setPassword",
        "deny": "policy:decision:unauthenticated-setPassword-deny",
        "local": "u/p",
        "sink_kind": "system",
        "target_id": "command:busybox-passwd",
        "taint_path": "m4:luci-setPassword-request-args-system",
    },
}


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestRealtimePasswordQuotedLocals(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = _load(INVENTORY)
        cls.grants = _load(GRANTS)
        cls.barrier = _load(BARRIER)
        cls.lock_hash = corpus_revision()

    def test_inventory_has_exactly_the_two_methods(self) -> None:
        self.assertEqual(len(self.rows), 2)
        self.assertEqual(
            [row["method"] for row in self.rows],
            ["getRealtimeStats", "setPassword"],
        )
        ids = [row["record_id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_schema_join_keys_and_producer_fields(self) -> None:
        for row in self.rows:
            for key in REQUIRED:
                self.assertIn(key, row, key)
            for key in JOIN_KEYS:
                self.assertIn(key, row, key)
            spec = ROWS[row["method"]]
            self.assertEqual(row["record_type"], "taint_path")
            self.assertEqual(row["evidence_status"], "fact")
            self.assertNotEqual(row["evidence_status"], "path_found")
            self.assertEqual(row["producer"], "step3")
            self.assertEqual(row["profile"], "luci-ssl-25.12")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertEqual(row["corpus_revision"], self.lock_hash)
            self.assertEqual(row["ingress"], "ubus_http")
            self.assertEqual(row["ubus_object"], "luci")
            self.assertEqual(row["op"], "exec")
            self.assertEqual(row["assessment"], "intended_access")
            self.assertNotEqual(row["assessment"], "authorization_violation")
            self.assertEqual(row["record_id"], spec["record_id"])
            self.assertEqual(row["sink_kind"], spec["sink_kind"])
            self.assertEqual(row["target_id"], spec["target_id"])
            self.assertEqual(row["entrypoint_id"], f"ubus_http:luci.{row['method']}")
            self.assertNotIn("cgi_endpoint", row)
            self.assertNotIn("route_path", row)
            blob = json.dumps(row)
            self.assertNotIn('"path_found"', blob)
            self.assertNotEqual(row.get("assessment"), "authorization_violation")
            self.assertNotIn("dispatcher", blob)

    def test_rows_join_existing_grants_and_unauth_deny(self) -> None:
        by_id = {grant["record_id"]: grant for grant in self.grants}
        for row in self.rows:
            spec = ROWS[row["method"]]
            refs = row["evidence_refs"]
            self.assertIn(spec["delegated"], refs)
            self.assertIn(spec["root"], refs)
            self.assertIn(spec["deny"], refs)
            self.assertIn(spec["taint_path"], refs)
            for grant_id in (spec["delegated"], spec["root"]):
                grant = by_id[grant_id]
                self.assertTrue(
                    all(row[key] == grant[key] for key in JOIN_KEYS),
                    f"{row['record_id']} does not join {grant_id}",
                )
                self.assertEqual(grant["analysis_revision"], "policy:ubus-luci-exec-methods-v2")
                self.assertEqual(grant["assessment"], "intended_access")
            unauth = [
                grant
                for grant in self.grants
                if grant.get("method") == row["method"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])

    def test_runtime_quoting_and_analyzer_coverage_are_distinct(self) -> None:
        barrier_methods = {
            row["method"]
            for row in self.barrier
            if row.get("evidence_status") == "no_path" and row.get("method")
        }
        self.assertIn("getSwconfigFeatures", barrier_methods)
        self.assertIn("getSwconfigPortState", barrier_methods)
        self.assertNotIn("getRealtimeStats", barrier_methods)
        self.assertNotIn("setPassword", barrier_methods)
        for row in self.rows:
            spec = ROWS[row["method"]]
            assumptions = " ".join(row["assumptions"]).lower()
            conditions = " ".join(row["conditions"]).lower()
            self.assertIn("shellquote", assumptions)
            self.assertIn("does not treat shellquote as a global sanitizer", assumptions)
            self.assertIn("quote characters are preserved", assumptions)
            self.assertIn("local storage and template interpolation", assumptions)
            self.assertIn("model coverage gap", assumptions)
            self.assertIn("runtime command safety is unassessed", assumptions)
            self.assertIn("basename is not a sanitizer", assumptions)
            self.assertIn("same-function quoted locals", assumptions)
            self.assertIn("not a new query", assumptions)
            self.assertIn("not a query path result", assumptions)
            self.assertIn("does not invent a grant" if row["method"] == "getRealtimeStats" else "not a new unauthenticated grant", assumptions)
            self.assertIn("root-administration", assumptions)
            self.assertIn(spec["local"].split("/")[0], conditions)
            self.assertIn("not", conditions)
            self.assertIn("${shellquote", conditions)

    def test_luci_emitter_is_unchanged(self) -> None:
        methods = {
            row["method"]
            for row in self.grants
            if row.get("ubus_object") == "luci"
            and row.get("analysis_revision") == "policy:ubus-luci-exec-methods-v2"
        }
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
        getversion = [
            row
            for row in self.grants
            if row.get("ubus_object") == "luci" and row.get("method") == "getVersion"
        ]
        self.assertTrue(getversion)
        self.assertTrue(
            all(row["analysis_revision"] == "policy:ubus-luci-getversion-v1" for row in getversion)
        )
        getunixtime = [
            row
            for row in self.grants
            if row.get("ubus_object") == "luci" and row.get("method") == "getUnixtime"
        ]
        self.assertTrue(getunixtime)
        self.assertTrue(
            all(row["analysis_revision"] == "policy:ubus-luci-getunixtime-v1" for row in getunixtime)
        )
        getodhcp6cstats = [
            row
            for row in self.grants
            if row.get("ubus_object") == "luci" and row.get("method") == "getOdhcp6cStats"
        ]
        self.assertTrue(getodhcp6cstats)
        self.assertTrue(
            all(row["analysis_revision"] == "policy:ubus-luci-getodhcp6cstats-v1" for row in getodhcp6cstats)
        )
        gettimezones = [
            row
            for row in self.grants
            if row.get("ubus_object") == "luci" and row.get("method") == "getTimezones"
        ]
        self.assertTrue(gettimezones)
        self.assertTrue(
            all(row["analysis_revision"] == "policy:ubus-luci-gettimezones-v1" for row in gettimezones)
        )
        blob = json.dumps(self.grants)
        self.assertNotIn(ANALYSIS_REVISION, blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("setInitAction", blob)


if __name__ == "__main__":
    unittest.main()
