#!/usr/bin/env python3
"""M4 inventory: luci-ssl files[] via luci.mk routing classification."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from corpus.luci_ssl_files import (  # noqa: E402
    ANALYSIS_REVISION,
    C_NOT_ANALYZED,
    INVENTORY,
    LUCI_SSL_LUCI_PACKAGES,
    PLAN_SEVEN_CASES,
    PRODUCER,
    build_records,
    classify_installed,
    corpus_revision,
    luci_mk_installed,
)
from policy.oracle import corpus_revision as lock_revision  # noqa: E402

SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]
GRANTS = REPO / "policy" / "grants.json"
HANDLER = REPO / "reports" / "handler_effects.json"
PROFILE = REPO / "corpus" / "profiles" / "luci-ssl-25.12" / "profile.json"
GRANT_METHODS = {
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
}


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestLuciSslFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = _load(INVENTORY)
        cls.built = build_records(REPO)
        cls.grants = _load(GRANTS)
        cls.effects = _load(HANDLER)
        cls.profile = _load(PROFILE)
        cls.lock_hash = corpus_revision(REPO)

    def test_committed_inventory_matches_builder(self) -> None:
        self.assertEqual(self.rows, self.built)
        self.assertEqual(self.lock_hash, lock_revision(REPO))
        self.assertEqual(
            self.lock_hash,
            "sha256:b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a",
        )

    def test_schema_counts_and_disjoint_union(self) -> None:
        routing = [row for row in self.rows if row["record_type"] == "routing"]
        helpers = [row for row in self.rows if row["record_type"] == "exec_helper_inventory"]
        self.assertEqual(len(self.rows), 27)
        self.assertEqual(len(routing), 24)
        self.assertEqual(len(helpers), 3)
        classes = {row["classification"] for row in routing}
        self.assertEqual(classes, {"plain", "markup", "uncertain"})
        self.assertEqual(sum(1 for row in routing if row["classification"] == "plain"), 10)
        self.assertEqual(sum(1 for row in routing if row["classification"] == "markup"), 12)
        self.assertEqual(sum(1 for row in routing if row["classification"] == "uncertain"), 2)
        paths = [row["fs_path"] for row in self.rows]
        self.assertEqual(len(paths), len(set(paths)))
        ids = [row["record_id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        for row in self.rows:
            for key in REQUIRED:
                self.assertIn(key, row, key)
            self.assertEqual(row["producer"], PRODUCER)
            self.assertEqual(row["profile"], "luci-ssl-25.12")
            self.assertEqual(row["analysis_revision"], ANALYSIS_REVISION)
            self.assertEqual(row["corpus_revision"], self.lock_hash)
            self.assertNotEqual(row["evidence_status"], "path_found")
            self.assertNotIn("ingress", row)
            self.assertNotIn("route_path", row)
            self.assertNotIn("ubus_object", row)
            self.assertNotIn("method", row)
            blob = json.dumps(row)
            self.assertNotIn('"path_found"', blob)
            self.assertNotIn("authorization_violation", blob)
            self.assertNotIn("step4", blob)
            self.assertNotEqual(row.get("method"), "setInitAction")
            self.assertNotIn("ubus_http:luci.setInitAction", blob)

    def test_classifier_matches_each_routing_row(self) -> None:
        for row in self.rows:
            if row["record_type"] != "routing":
                continue
            classification, reason, rule = classify_installed(
                row["fs_path"],
                shebang=row.get("shebang"),
                content_prefix=row.get("content_prefix") or "",
            )
            self.assertEqual(classification, row["classification"], row["fs_path"])
            self.assertEqual(reason, row["reason"], row["fs_path"])
            self.assertEqual(rule, row["rule"], row["fs_path"])
            if classification == "plain":
                self.assertEqual(row["evidence_status"], "fact")
            else:
                self.assertEqual(row["evidence_status"], "inconclusive")
        self.assertEqual(
            classify_installed("/usr/share/rpcd/ucode/luci", None, "// Copyright")[0],
            "plain",
        )
        self.assertEqual(
            classify_installed("/usr/share/ucode/luci/uhttpd.uc", None, "{%")[0],
            "markup",
        )
        self.assertEqual(
            classify_installed("/www/cgi-bin/luci", "#!/usr/bin/env ucode", "#!/usr/bin/env ucode")[0],
            "plain",
        )
        self.assertEqual(
            classify_installed(
                "/usr/share/ucode/luci/template/themes/bootstrap-dark", None, ""
            )[0],
            "uncertain",
        )
        self.assertEqual(
            luci_mk_installed("ucode", "sys.uc"),
            "/usr/share/ucode/luci/sys.uc",
        )
        self.assertEqual(
            luci_mk_installed("htdocs", "cgi-bin/luci"),
            "/www/cgi-bin/luci",
        )
        self.assertEqual(
            luci_mk_installed("root", "usr/share/rpcd/ucode/luci"),
            "/usr/share/rpcd/ucode/luci",
        )

    def test_plan_seven_cases_are_honest_about_absence(self) -> None:
        by_path = {row["fs_path"]: row for row in self.rows}
        for name, spec in PLAN_SEVEN_CASES.items():
            if spec["present"]:
                self.assertIn(spec["fs_path"], by_path, name)
            else:
                self.assertIsNone(spec["fs_path"], name)
        self.assertFalse(PLAN_SEVEN_CASES["shebang-libexec-ucode"]["present"])
        self.assertFalse(PLAN_SEVEN_CASES["dot-uc-rpcd-plugin"]["present"])
        self.assertFalse(PLAN_SEVEN_CASES["ut-under-rpcd"]["present"])
        for helper in (
            "/usr/libexec/syslog-wrapper",
            "/usr/libexec/luci-peeraddr",
            "/usr/libexec/package-manager-call",
        ):
            row = by_path[helper]
            self.assertEqual(row["record_type"], "exec_helper_inventory")
            self.assertEqual(row["shebang"], "#!/bin/sh")
            self.assertEqual(row["evidence_status"], "inconclusive")
            self.assertIn("shell_not_analyzed", " ".join(row["assumptions"]))
        cgi = by_path["/www/cgi-bin/luci"]
        self.assertEqual(cgi["shebang"], "#!/usr/bin/env ucode")
        self.assertEqual(cgi["classification"], "plain")
        self.assertEqual(cgi["rule"], 3)
        uhttpd = by_path["/usr/share/ucode/luci/uhttpd.uc"]
        self.assertEqual(uhttpd["classification"], "markup")
        self.assertEqual(uhttpd["rule"], 4)
        self.assertTrue(uhttpd["content_prefix"].startswith("{%"))

    def test_package_closure_and_profile_preview(self) -> None:
        self.assertEqual(
            LUCI_SSL_LUCI_PACKAGES,
            (
                "luci-ssl",
                "luci-light",
                "luci-app-package-manager",
                "luci-mod-admin-full",
                "luci-app-firewall",
                "luci-theme-bootstrap",
                "luci-proto-ppp",
                "luci-proto-ipv6",
                "luci-base",
                "luci-mod-status",
                "luci-mod-system",
                "luci-mod-network",
            ),
        )
        for name in C_NOT_ANALYZED:
            self.assertTrue(name)
        self.assertEqual(
            self.profile["files_inventory"],
            "reports/m4-luci-ssl-files.json",
        )
        preview_paths = {item["installed"] for item in self.profile["files_preview"]}
        inventory_paths = {row["fs_path"] for row in self.rows if row["record_type"] == "routing"}
        self.assertTrue(preview_paths <= inventory_paths)
        self.assertIn("/usr/share/rpcd/ucode/luci", preview_paths)
        self.assertIn("/www/cgi-bin/luci", preview_paths)
        self.assertIn("/usr/share/ucode/luci/uhttpd.uc", preview_paths)
        unknowns = " ".join(self.profile["unknowns"])
        self.assertNotIn("not in wave 1", unknowns)
        self.assertIn("c_plugin_not_analyzed", unknowns)

    def test_luci_emitter_and_handler_effects_are_unchanged(self) -> None:
        methods = {row["method"] for row in self.grants if row.get("ingress") == "ubus_http"}
        self.assertEqual(methods, GRANT_METHODS)
        blob = json.dumps(self.grants)
        self.assertNotIn(ANALYSIS_REVISION, blob)
        self.assertNotIn("authorization_violation", blob)
        self.assertNotIn("setInitAction", blob)
        effect_blob = json.dumps(self.effects)
        self.assertNotIn(ANALYSIS_REVISION, effect_blob)
        self.assertNotIn("m4:routing:luci-ssl:", effect_blob)


if __name__ == "__main__":
    unittest.main()
