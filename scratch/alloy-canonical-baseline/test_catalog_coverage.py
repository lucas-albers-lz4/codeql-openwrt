from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from policy.oracle import (
    AclEntry,
    acl_match,
    parse_rpcd_logins,
    Session,
)
from policy import ubus_luci_getmountpoints as points
from run_baseline import (
    ALL_ACL_FILES,
    EXPECTED_GETMOUNTPOINTS_GROUPS,
    ROOT,
    load_complete_acl_catalog,
    matrix_cell,
    session_for_gate,
    validate_acl_fixture_sources,
)


class CompleteAclCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = ROOT / "policy" / "fixtures"
        cls.lock = json.loads((ROOT / "corpus" / "lock.json").read_text())
        cls.catalog, cls.groups = load_complete_acl_catalog(cls.fixtures)
        cls.logins = {
            login.username: login
            for login in parse_rpcd_logins((cls.fixtures / "rpcd.config").read_text())
        }

    def test_provenance_covers_all_eight_acl_files_and_hashes(self):
        hashes = validate_acl_fixture_sources(self.fixtures, self.lock)
        self.assertEqual(len(ALL_ACL_FILES), 8)
        self.assertEqual(
            set(ALL_ACL_FILES),
            {path.name for path in self.fixtures.glob("luci-*.json")}
            | {"unauthenticated.json"},
        )
        self.assertTrue(all(f"policy/fixtures/{name}" in hashes for name in ALL_ACL_FILES))
        referenced = {
            group
            for login in self.logins.values()
            if login.username != "root"
            for group in login.read + login.write
            if group and group != "*" and not group.startswith("!")
        }
        self.assertEqual(referenced - self.groups, set())
        self.assertEqual(len(referenced), 18)

    def test_getmountpoints_source_overlap_includes_package_manager(self):
        entries = [
            entry
            for entry in self.catalog
            if entry.perm == "read"
            and acl_match(entry.object, entry.function, "luci", "getMountPoints")
        ]
        source_groups = {entry.group for entry in entries}
        self.assertEqual(source_groups, EXPECTED_GETMOUNTPOINTS_GROUPS)
        actual_roles = {
            role
            for role, login in self.logins.items()
            if role != "root"
            and any(
                entry.group in (login.read + login.write)
                for entry in entries
            )
        }
        self.assertEqual(
            actual_roles,
            {
                "luci-mod-status-index-storage",
                "luci-mod-system-mounts",
                "luci-app-package-manager",
            },
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "canonical evaluator requires Linux glibc/musl fnmatch")
    def test_package_manager_native_session_is_preserved_and_allows_mounts_read(self):
        login = self.logins["luci-app-package-manager"]
        native_world = points.load_luci_getmountpoints_world()
        sessions, sid, detail = session_for_gate(
            login.username, "00000000000000000000000000000099", login,
            native_world, self.catalog, self.groups,
        )
        self.assertEqual(detail["session_source"], "native_gate_world")
        self.assertTrue(detail["native_acl_matches_full_catalog"])
        cell = matrix_cell(
            login.username, sid, points.evaluate_luci_getmountpoints,
            sessions, {"object": "luci", "function": "getMountPoints"}, detail,
        )
        self.assertTrue(cell["scope_complete"])
        self.assertEqual(cell["relation_outcome"], "allow")
        self.assertEqual(cell["acl_match"]["group"], "luci-app-package-manager")

    def test_native_session_is_preserved_and_scope_diff_becomes_unknown(self):
        login = self.logins["luci-mod-system-mounts"]
        expected = [AclEntry("luci-mod-system-mounts", "read", "ubus", "luci", "getMountPoints", "fixture")]
        native = Session(login.username, "native-sid", login, expected)
        world = {native.sid: native}
        with patch("run_baseline.session_acls", return_value=expected):
            sessions, sid, detail = session_for_gate(
                login.username, "other-sid", login, world, self.catalog, self.groups
            )
        self.assertEqual(detail["session_source"], "native_gate_world")
        self.assertTrue(detail["native_acl_matches_full_catalog"])
        self.assertEqual(sid, "native-sid")
        self.assertIs(sessions[sid], native)
        self.assertIs(world[native.sid], native)

        incomplete_world = {
            native.sid: Session(login.username, native.sid, login, [])
        }
        with patch("run_baseline.session_acls", return_value=expected):
            sessions, sid, detail = session_for_gate(
                login.username, "other-sid", login, incomplete_world,
                self.catalog, self.groups,
            )
        self.assertEqual(detail["scope_reason"], "native_session_acl_scope_differs_from_full_pinned_catalog")
        fake_result = SimpleNamespace(
            outcome="allow", matched=object(), jsonrpc_error=None, steps=[]
        )
        cell = matrix_cell(
            login.username, sid, lambda **_: fake_result, sessions,
            {"object": "luci", "function": "getMountPoints"}, detail,
        )
        self.assertFalse(cell["scope_complete"])
        self.assertEqual(cell["raw_relation_outcome"], "allow")
        self.assertEqual(cell["http_gate"], "unknown")
        self.assertEqual(cell["relation_outcome"], "unknown")

    def test_unmapped_login_group_stays_unknown_without_evaluation(self):
        login = self.logins["luci-app-package-manager"]
        sessions, sid, detail = session_for_gate(
            login.username, "new-sid", login, {}, self.catalog,
            self.groups - {"luci-app-package-manager"},
        )
        self.assertIsNone(sessions)
        self.assertIsNone(sid)
        cell = matrix_cell(
            login.username, sid, lambda **_: self.fail("must not evaluate incomplete scope"),
            sessions, {"object": "luci", "function": "getMountPoints"}, detail,
        )
        self.assertEqual(cell["http_gate"], "unknown")
        self.assertEqual(cell["relation_outcome"], "unknown")


if __name__ == "__main__":
    unittest.main()
