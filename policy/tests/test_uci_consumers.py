"""UCI consumer inventory and synthetic, independent policy gate controls."""
import json
import unittest
from pathlib import Path

from policy.oracle import AclEntry, Session, corpus_revision, session_access
from policy.uci_consumers import PROFILE, build_artifacts

ROOT = Path(__file__).resolve().parents[2]


def synthetic_session(*entries):
    """Use only explicit test grants; these are not deployment logins."""
    return Session("synthetic", "test", None, [
        AclEntry("test", "write", scope, obj, fun, "synthetic")
        for scope, obj, fun in entries
    ])


def uci_set_gate(session, config):
    # uhttpd ubus method gate and rpcd's separate config-scope write gate.
    return bool(session_access(session, "ubus", "uci", "set") and
                session_access(session, "uci", config, "write"))


def file_gate(session, method, path):
    # For a regular file, file.write and file.remove both require file/write.
    return bool(session_access(session, "ubus", "file", method) and
                session_access(session, "file", path, "write"))


class ConsumerCatalogTests(unittest.TestCase):
    def setUp(self):
        self.rows = build_artifacts()
        self.assets = json.loads((ROOT / "corpus/profiles/luci-ssl-25.12/assets.json").read_text())

    def test_rows_conform_to_schema(self):
        # The schema has no required condition for fact rows beyond its top-level
        # required properties. Check every emitted property against its declared
        # type/enum, including array item types, without an external dependency.
        schema = json.loads((ROOT / "schemas/finding.schema.json").read_text())
        for row in self.rows:
            self.assertTrue(set(schema["required"]) <= row.keys())
            for key, value in row.items():
                spec = schema["properties"][key]
                if "enum" in spec:
                    self.assertIn(value, spec["enum"])
                if spec.get("type") == "string":
                    self.assertIsInstance(value, str)
                if spec.get("type") == "array":
                    self.assertIsInstance(value, list)
                    self.assertTrue(all(isinstance(item, str) for item in value))
            self.assertEqual(row["evidence_status"], "fact")
            self.assertTrue(row["evidence_refs"])
            self.assertTrue(row["consumer_id"])

    def test_known_assets_and_emitted_artifact(self):
        configs = {a["uci_config"] for a in self.assets["assets"] if a["kind"] == "uci_config"}
        self.assertEqual(configs, {"dropbear", "rpcd", "uhttpd", "system", "firewall", "network"})
        self.assertEqual(configs, {r["uci_config"] for r in self.rows})
        self.assertEqual(len(self.rows), len({r["record_id"] for r in self.rows}))
        for row in self.rows:
            self.assertEqual(row["asset_id"], "uci:" + row["uci_config"])
            self.assertEqual(row["profile"], PROFILE)
            self.assertEqual(row["corpus_revision"], corpus_revision())
            self.assertNotIn("fs_path", row)
        self.assertEqual(self.rows, json.loads((ROOT / "policy/uci_consumers.json").read_text()))

    def test_future_join_exact_keys_and_unknown(self):
        def matches(revision, profile, config):
            return [r for r in self.rows if (r["corpus_revision"], r["profile"], r["uci_config"]) == (revision, profile, config)]
        rev = corpus_revision()
        self.assertEqual(len(matches(rev, PROFILE, "system")), 1)
        for args in ((rev, PROFILE, "unknown"), (rev, PROFILE, None),
                     ("other", PROFILE, "system"), (rev, "other", "system")):
            self.assertEqual(matches(*args), [])  # unresolved, not proof of absence


class SyntheticDualPathControls(unittest.TestCase):
    def test_independent_gates_for_each_uci_asset(self):
        assets = json.loads((ROOT / "corpus/profiles/luci-ssl-25.12/assets.json").read_text())
        configs = [a for a in assets["assets"] if a["kind"] == "uci_config"]
        self.assertEqual(len(configs), 6)
        for asset in configs:
            config = asset["uci_config"]
            path = asset["backing_file"]
            self.assertEqual(asset["asset_id"], "uci:" + config)
            self.assertEqual(path, "/etc/config/" + config)
            uci_only = synthetic_session(("ubus", "uci", "set"), ("uci", config, "write"))
            file_only = synthetic_session(("ubus", "file", "write"), ("ubus", "file", "remove"),
                                          ("file", path, "write"))
            with self.subTest(config=config):
                self.assertTrue(uci_set_gate(uci_only, config))
                self.assertFalse(uci_set_gate(file_only, config))
                for method in ("write", "remove"):
                    self.assertFalse(file_gate(uci_only, method, path))
                    self.assertTrue(file_gate(file_only, method, path))
                for other in configs:
                    if other is asset:
                        continue
                    self.assertFalse(uci_set_gate(uci_only, other["uci_config"]))
                    for method in ("write", "remove"):
                        self.assertFalse(file_gate(file_only, method, other["backing_file"]))
                self.assertFalse(uci_set_gate(synthetic_session(("uci", config, "write")), config))
                self.assertFalse(file_gate(synthetic_session(("file", path, "write")), "write", path))
                self.assertFalse(file_gate(synthetic_session(("ubus", "file", "remove")), "remove", path))

    def test_bounded_system_option_expectation(self):
        # Synthetic intended operation: set system.@system[0].hostname only.
        # A UCI config grant itself is not option-limited; this bound is an
        # expectation about the operation, not an ACL-enforced restriction.
        uci_only = synthetic_session(("ubus", "uci", "set"), ("uci", "system", "write"))
        def intended_operation(config, section, option):
            return (config, section, option) == ("system", "@system[0]", "hostname")

        self.assertTrue(uci_set_gate(uci_only, "system") and
                        intended_operation("system", "@system[0]", "hostname"))
        self.assertTrue(uci_set_gate(uci_only, "system"))
        self.assertFalse(intended_operation("system", "@system[0]", "timezone"))


if __name__ == "__main__":
    unittest.main()
