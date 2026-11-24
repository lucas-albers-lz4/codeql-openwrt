"""Controls for source-derived event corpus oracle construction."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import event_corpus_manifest as generator
from tools.event_corpus_manifest import (POLICY_SHA256, build, changed_paths,
                                         relevant_recipe_changes, source_route)
from tools.full_tree_candidates import SelectorError


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


class EventCorpusManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", self.repo], check=True)
        for key, value in (("user.email", "test@example.invalid"),
                           ("user.name", "Event Manifest Test")):
            subprocess.run(["git", "-C", self.repo, "config", key, value], check=True)
        self.selected = "package/example/files/scan.uc"
        self.excluded = "package/example/tests/fixture.uc"
        self.put(self.selected, b"return 1\n")
        self.put(self.excluded, b"excluded\n")
        self.commit()
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.put(self.selected, b"return 2\n")
        self.commit()
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        self.policy = {
            "schema": "mvp-bounded-corpus-v0.6",
            "pins": {"openwrt": self.base, "luci": "a" * 40, "packages": "b" * 40},
            "selected": [{"repo": "openwrt", "source_path": self.selected,
                          "source_commit": self.base,
                          "proposed_installed_path": "usr/share/ucode/scan.uc",
                          "expected_route": {"classification": "plain", "reason": "ucode_extension"},
                          "source_sha256": hashlib.sha256(b"return 1\n").hexdigest(),
                          "prior_local_extraction": "old observation",
                          "git_blob": git(self.repo, "rev-parse", f"{self.base}:{self.selected}")}],
            "excluded": [{"repo": "openwrt", "source_path": self.excluded,
                          "source_commit": self.base,
                          "sha256": hashlib.sha256(b"excluded\n").hexdigest(),
                          "git_blob": git(self.repo, "rev-parse", f"{self.base}:{self.excluded}")}],
            "counts": {"selected": 1, "route_classes": {"plain": 1}},
        }
        self.receipt = {"status": "identities_resolved_only", "repository": "openwrt",
                        "pr_number": 17, "base": {"commit": self.base},
                        "source": {"commit": self.head, "tree": self.tree}}
        entries = []
        for path, status, events in ((self.selected, "selected", ["selected_content_changed_scan_eligible"]),
                                     (self.excluded, "excluded", [])):
            contents = (self.repo / path).read_bytes()
            entries.append({"source_path": path, "status": status, "events": events,
                            "head": {"source_path": path,
                                     "git_blob": git(self.repo, "rev-parse", f"{self.head}:{path}"),
                                     "sha256": hashlib.sha256(contents).hexdigest()}})
        self.inventory = {"status": "inventory_ready", "fail_closed": False,
                          "repository": "openwrt", "base_commit": self.base,
                          "head_commit": self.head, "head_tree": self.tree,
                          "policy_sha256": POLICY_SHA256, "events": entries}

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path: str, data: bytes):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def commit(self):
        subprocess.run(["git", "-C", self.repo, "add", "-A"], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-qm", "fixture"], check=True)

    def test_selected_edit_refreshes_exact_source_identity(self):
        result = build(self.policy, self.receipt, self.inventory, self.repo)
        row = result["selected"][0]
        self.assertEqual(row["source_commit"], self.head)
        self.assertEqual(row["source_sha256"], hashlib.sha256(b"return 2\n").hexdigest())
        self.assertEqual(row["git_blob"], git(self.repo, "rev-parse", f"{self.head}:{self.selected}"))
        self.assertEqual(result["pins"]["openwrt"], self.head)
        self.assertEqual(result["event"]["head_tree"], self.tree)
        self.assertEqual(result["excluded"][0]["source_commit"], self.head)
        self.assertNotIn("prior_local_extraction", row)
        self.assertNotIn("plain_route_observed", result["counts"])

    def test_route_precedence_controls(self):
        self.assertEqual(source_route("x.ut", "usr/share/ucode/x.ut", b"return 1\n"),
                         {"classification": "markup", "reason": "ut_markup_extension"})
        self.assertEqual(source_route("x.uc", "usr/share/rpcd/ucode/x.uc", b"{% tag %}\n"),
                         {"classification": "plain", "reason": "rpcd_raw_mode_full_path"})
        self.assertEqual(source_route("x.uc", "usr/share/ucode/x.uc", b"#!/usr/bin/env -S ucode -f\n{% tag %}\n"),
                         {"classification": "plain", "reason": "ucode_shebang"})
        self.assertEqual(source_route("x.uc", "usr/share/ucode/x.uc", b"{{ markup }}\n"),
                         {"classification": "markup", "reason": "markup_tag_content"})
        self.assertEqual(source_route("x.uc", "usr/share/ucode/x.uc", b"return 1\r{{ not_a_new_line }}\n"),
                         {"classification": "plain", "reason": "ucode_extension"})
        self.assertEqual(source_route("x.uc", "usr/share/ucode/x.uc", "return 1\u0085{{ not_a_new_line }}\n".encode()),
                         {"classification": "plain", "reason": "ucode_extension"})
        self.assertEqual(source_route("x.uc", "usr/share/ucode/x.uc", b"\x1c{{ not_rust_whitespace }}\n"),
                         {"classification": "plain", "reason": "ucode_extension"})
        self.assertEqual(source_route("source.uc", "usr/share/ucode/staged.ut", b"return 1\n"),
                         {"classification": "markup", "reason": "ut_markup_extension"})

    def test_inventory_identity_and_content_tampering_rejected(self):
        bad = json.loads(json.dumps(self.inventory))
        bad["head_tree"] = "0" * 40
        with self.assertRaisesRegex(SelectorError, "identities differ"):
            build(self.policy, self.receipt, bad, self.repo)
        bad = json.loads(json.dumps(self.inventory))
        bad["events"][0]["head"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(SelectorError, "blob/content mismatch"):
            build(self.policy, self.receipt, bad, self.repo)

    def test_unreviewed_and_removed_candidates_rejected(self):
        for mutation in ("unreviewed", "candidate_removed_or_signal_lost"):
            bad = json.loads(json.dumps(self.inventory))
            if mutation == "unreviewed":
                bad["events"][0]["status"] = "unreviewed"
            else:
                bad["events"][0]["events"] = [mutation]
            with self.assertRaisesRegex(SelectorError, "needs review"):
                build(self.policy, self.receipt, bad, self.repo)

    def test_changed_route_rejected_before_extraction(self):
        bad = json.loads(json.dumps(self.policy))
        bad["selected"][0]["expected_route"] = {"classification": "markup",
                                                   "reason": "markup_tag_content"}
        with self.assertRaisesRegex(SelectorError, "source route changed"):
            build(bad, self.receipt, self.inventory, self.repo)

    def test_selected_owner_recipe_drift_is_separate_from_unrelated_recipe(self):
        paths = ["package/example/Makefile", "package/other/Makefile",
                 "include/package.mk", "package/example/files/readme.txt"]
        self.assertEqual(relevant_recipe_changes(self.policy, "openwrt", paths),
                         ["include/package.mk", "package/example/Makefile"])
        self.put("package/example/Makefile", b"# changed install rule\n")
        self.commit()
        new_head = git(self.repo, "rev-parse", "HEAD")
        self.receipt["source"] = {"commit": new_head,
                                  "tree": git(self.repo, "rev-parse", "HEAD^{tree}")}
        self.inventory["head_commit"] = new_head
        self.inventory["head_tree"] = self.receipt["source"]["tree"]
        with self.assertRaisesRegex(SelectorError, "reviewed recipe/config input changed"):
            build(self.policy, self.receipt, self.inventory, self.repo)

    def test_recipe_rename_exposes_old_and_new_paths(self):
        self.put("package/example/Makefile", b"# owner recipe\n")
        self.commit()
        before = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "package/other").mkdir(parents=True)
        (self.repo / "package/example/Makefile").rename(self.repo / "package/other/README")
        self.commit()
        after = git(self.repo, "rev-parse", "HEAD")
        paths = changed_paths(self.repo, before, after)
        self.assertEqual(paths, ["package/example/Makefile", "package/other/README"])
        self.assertEqual(relevant_recipe_changes(self.policy, "openwrt", paths),
                         ["package/example/Makefile"])

    def test_cli_pins_policy_and_rechecks_candidate_report(self):
        root = Path(self.temp.name)
        policy_path, receipt_path = root / "policy.json", root / "receipt.json"
        inventory_path, output_path = root / "inventory.json", root / "out.json"
        policy_bytes = json.dumps(self.policy).encode()
        policy_digest = hashlib.sha256(policy_bytes).hexdigest()
        self.inventory["policy_sha256"] = policy_digest
        policy_path.write_bytes(policy_bytes)
        receipt_path.write_text(json.dumps(self.receipt))
        inventory_path.write_text(json.dumps(self.inventory))
        arguments = ["event_corpus_manifest.py", str(policy_path), str(receipt_path),
                     str(inventory_path), str(self.repo), str(output_path)]
        with patch.object(generator, "POLICY_SHA256", policy_digest), \
             patch.object(generator, "compare", return_value=self.inventory), \
             patch("sys.argv", arguments):
            self.assertEqual(generator.main(), 0)
        output = json.loads(output_path.read_text())
        self.assertEqual(output["event"]["candidate_inventory_sha256"],
                         hashlib.sha256(inventory_path.read_bytes()).hexdigest())
        output_path.unlink()
        with patch.object(generator, "POLICY_SHA256", "0" * 64), \
             patch.object(generator, "compare", return_value=self.inventory), \
             patch("sys.argv", arguments):
            self.assertEqual(generator.main(), 2)
        self.assertFalse(output_path.exists())
        changed = json.loads(inventory_path.read_text())
        changed["head_candidate_count"] = 999
        inventory_path.write_text(json.dumps(changed))
        with patch.object(generator, "POLICY_SHA256", policy_digest), \
             patch.object(generator, "compare", return_value=self.inventory), \
             patch("sys.argv", arguments):
            self.assertEqual(generator.main(), 2)
        self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
