"""Fail-closed source-table import and exact setBlockDetect policy checks."""
import csv
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from policy.setblock_table import (CATALOG, COLUMNS, DECISIONS, EFFECT_ID, EFFECT_NAME,
                                   EXPECTED, GRANT_IDS, JOIN_KEYS, SNAPSHOT, import_table)

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "policy/fixtures/setblock-observation.csv"
SOURCE = ROOT / "policy/fixtures/getblock-source"


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        for path in ("corpus/lock.json", "corpus/profiles/luci-ssl-25.12/expected-capabilities.json",
                     "policy/grants.json", str(DECISIONS), str(SNAPSHOT), str(CATALOG)):
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        self.csv = Path(self.temp.name) / "observation.csv"
        shutil.copyfile(CSV, self.csv)
        self.source = Path(self.temp.name) / "source"
        shutil.copytree(SOURCE, self.source)

    def artifacts(self):
        return tuple((self.repo / p).read_bytes()
                     for p in (SNAPSHOT, CATALOG, Path("policy/grants.json"), DECISIONS))

    def write_csv(self, header=COLUMNS, rows=(EXPECTED,)):
        with self.csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)

    def rejected_unchanged(self):
        before = self.artifacts()
        with self.assertRaises((ValueError, OSError, KeyError, csv.Error)):
            import_table(self.csv, self.source, self.repo)
        self.assertEqual(self.artifacts(), before)

    def test_valid_replaces_only_effect_and_preserves_policy_context(self):
        grants_before = (self.repo / "policy/grants.json").read_bytes()
        decisions_before = (self.repo / DECISIONS).read_bytes()
        original_effect = next(row for row in json.loads((self.repo / CATALOG).read_text())
                               if row.get("record_id") == EFFECT_ID)
        original_unrelated = {}
        for path in (SNAPSHOT, CATALOG):
            file = self.repo / path
            rows = json.loads(file.read_text())
            original_unrelated[path] = [r for r in rows if r.get("record_id") != EFFECT_ID]
            rows.append(next(r for r in rows if r.get("record_id") == EFFECT_ID))
            file.write_text(json.dumps(rows))

        import_table(self.csv, self.source, self.repo)
        for path in (SNAPSHOT, CATALOG):
            rows = json.loads((self.repo / path).read_text())
            self.assertEqual([r for r in rows if r.get("record_id") != EFFECT_ID], original_unrelated[path])
            matches = [r for r in rows if r.get("record_id") == EFFECT_ID]
            self.assertEqual(len(matches), 1)
            effect = matches[0]
            self.assertEqual(effect["effect_id"], EFFECT_NAME)
            self.assertEqual(effect["target_id"], "command:block-detect")
            self.assertEqual(effect["entrypoint_id"], "ubus_http:luci.setBlockDetect")
            self.assertEqual(effect["profile"], original_effect["profile"])
            self.assertEqual(effect["corpus_revision"], original_effect["corpus_revision"])
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["expectation_id"], "luci-mod-system-mounts")
            self.assertEqual(effect["conditions"], original_effect["conditions"])
            self.assertEqual(effect["sink_kind"], "system")
            self.assertEqual(effect["op"], "exec")
            self.assertEqual(effect["source_location"], {
                "path": "usr/share/rpcd/ucode/luci", "start_line": 532,
                "start_column": 21, "end_line": 532, "end_column": 68,
            })
            self.assertTrue(set(GRANT_IDS.values()) <= set(effect["evidence_refs"]))
            self.assertIn("ql/src/m4/SetBlockDetectEffectTable.ql", effect["evidence_refs"])
            self.assertIn("Fixed argv", " ".join(effect["assumptions"]))
            self.assertNotIn("path_found", json.dumps(effect))
            self.assertNotIn("authorization_violation", json.dumps(effect))

        grants = json.loads((self.repo / "policy/grants.json").read_text())
        self.assertFalse(any(g.get("session_class") == "unauthenticated"
                             and g.get("method") == "setBlockDetect" for g in grants))
        decisions = json.loads((self.repo / DECISIONS).read_text())
        self.assertTrue(any(d.get("record_id") == "policy:decision:unauthenticated-setBlockDetect-deny"
                            and d.get("outcome") == "deny" for d in decisions["decisions"]))
        self.assertEqual((self.repo / "policy/grants.json").read_bytes(), grants_before)
        self.assertEqual((self.repo / DECISIONS).read_bytes(), decisions_before)
        once = self.artifacts()
        import_table(self.csv, self.source, self.repo)
        self.assertEqual(self.artifacts(), once)

    def test_malformed_and_wrong_rows_fail_without_artifact_mutation(self):
        self.csv.unlink()
        self.rejected_unchanged()
        invalid = [
            (COLUMNS[:-1], [EXPECTED]),
            (("method",) + COLUMNS[1:], [EXPECTED]),
            (COLUMNS, []),
            (COLUMNS, [EXPECTED, EXPECTED]),
        ]
        for header, rows in invalid:
            with self.subTest(header=header, row_count=len(rows)):
                self.write_csv(header, rows)
                self.rejected_unchanged()
        for i, column in enumerate(COLUMNS):
            with self.subTest(column=column):
                row = list(EXPECTED)
                row[i] = "unexpected"
                self.write_csv(rows=[row])
                self.rejected_unchanged()

    def test_wrong_source_bytes_or_lock_fail_without_writes(self):
        source = self.source / "usr/share/rpcd/ucode/luci"
        source.write_bytes(source.read_bytes() + b"\n")
        self.rejected_unchanged()
        shutil.copyfile(SOURCE / "usr/share/rpcd/ucode/luci", source)
        lock = self.repo / "corpus/lock.json"
        data = json.loads(lock.read_text())
        data["repos"]["luci"]["sha"] = "other"
        lock.write_text(json.dumps(data))
        self.rejected_unchanged()

    def test_grant_expectation_or_unauthenticated_gate_mismatch_fails_closed(self):
        grants_path = self.repo / "policy/grants.json"
        original = json.loads(grants_path.read_text())
        for record_id in GRANT_IDS.values():
            with self.subTest(record_id=record_id):
                grants_path.write_text(json.dumps([g for g in original if g.get("record_id") != record_id]))
                self.rejected_unchanged()
                grants_path.write_text(json.dumps(original))
                grant = next(g for g in original if g.get("record_id") == record_id)
                grants_path.write_text(json.dumps(original + [grant]))
                self.rejected_unchanged()
                grants_path.write_text(json.dumps(original))
                changed = json.loads(json.dumps(original))
                next(g for g in changed if g.get("record_id") == record_id)["assessment"] = "other"
                grants_path.write_text(json.dumps(changed))
                self.rejected_unchanged()
        grants_path.write_text(json.dumps(original))

        unauth = json.loads(json.dumps(next(
            g for g in original if g.get("record_id") == GRANT_IDS["luci-mod-system-mounts"]
        )))
        unauth["record_id"] = "policy:grant:unauthenticated:ubus_http:luci.setBlockDetect"
        unauth["session_class"] = "unauthenticated"
        grants_path.write_text(json.dumps(original + [unauth]))
        self.rejected_unchanged()
        grants_path.write_text(json.dumps(original))

        decisions_path = self.repo / DECISIONS
        decisions = json.loads(decisions_path.read_text())
        deny_id = "policy:decision:unauthenticated-setBlockDetect-deny"
        decisions["decisions"] = [d for d in decisions["decisions"] if d.get("record_id") != deny_id]
        decisions_path.write_text(json.dumps(decisions))
        self.rejected_unchanged()
        decisions_path.write_text(json.dumps(decisions))
        decisions["decisions"].append(next(
            d for d in json.loads((ROOT / DECISIONS).read_text())["decisions"]
            if d.get("record_id") == deny_id
        ))
        next(d for d in decisions["decisions"] if d.get("record_id") == deny_id)["outcome"] = "allow"
        decisions_path.write_text(json.dumps(decisions))
        self.rejected_unchanged()
        decisions_path.write_text((ROOT / DECISIONS).read_text())

        expectations_path = self.repo / "corpus/profiles/luci-ssl-25.12/expected-capabilities.json"
        expectations = json.loads(expectations_path.read_text())
        expectations["expectations"] = [e for e in expectations["expectations"]
                                        if e.get("expectation_id") != "luci-mod-system-mounts"]
        expectations_path.write_text(json.dumps(expectations))
        self.rejected_unchanged()

    def test_missing_or_conflicting_effect_fails_without_writes(self):
        path = self.repo / CATALOG
        rows = json.loads(path.read_text())
        path.write_text(json.dumps([r for r in rows if r.get("record_id") != EFFECT_ID]))
        self.rejected_unchanged()
        path.write_text(json.dumps(rows))
        rows.append({"record_id": "other", "effect_id": EFFECT_NAME})
        path.write_text(json.dumps(rows))
        self.rejected_unchanged()

    def test_second_replace_failure_restores_both_artifacts(self):
        before = self.artifacts()
        real_replace = os.replace
        calls = []

        def fail_second(src, dst):
            calls.append((src, dst))
            if len(calls) == 2:
                raise OSError("injected second replace failure")
            return real_replace(src, dst)

        with patch("policy.setblock_table.os.replace", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "injected second replace"):
                import_table(self.csv, self.source, self.repo)
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.artifacts(), before)


if __name__ == "__main__":
    unittest.main()
