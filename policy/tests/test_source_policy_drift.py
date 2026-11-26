from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest
from tools.source_policy_drift import analyze, DriftError

class SourcePolicyDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.remote = self.root / "remote"; self.remote.mkdir()
        self.git("init", "-q", "--bare", str(self.remote))
        work = self.root / "work"; work.mkdir(); self.work = work
        self.git("init", "-q", str(work)); self.git("-C", str(work), "config", "user.email", "test@example.invalid"); self.git("-C", str(work), "config", "user.name", "Test")
        self.git("-C", str(work), "remote", "add", "origin", str(self.remote))
        source = work / "applications" / "pkg" / "known.uc"; source.parent.mkdir(parents=True); source.write_text("let a=1;\n"); self.git("-C", str(work), "add", "."); self.git("-C", str(work), "commit", "-qm", "base")
        self.base = self.git("-C", str(work), "rev-parse", "HEAD"); self.git("-C", str(work), "push", "-q", "origin", "HEAD:main")
        blob = self.git("-C", str(work), "rev-parse", f"{self.base}:applications/pkg/known.uc")
        self.manifest = {"schema": "mvp-bounded-corpus-v0.4", "pins": {"luci": self.base}, "selected": [{"repo": "luci", "source_path": "applications/pkg/known.uc", "git_blob": blob, "source_sha256": hashlib.sha256(b"let a=1;\n").hexdigest(), "source_commit": self.base, "expected_route": {"classification": "plain"}}], "excluded": []}
        self.raw = json.dumps(self.manifest, sort_keys=True).encode()
        self.manifest_sha = hashlib.sha256(self.raw).hexdigest()
    def tearDown(self): self.tmp.cleanup()
    @staticmethod
    def git(*args): return subprocess.check_output(["git", *args], text=True).strip()
    def commit_event(self, add_candidate=True):
        if add_candidate: (self.work / "new.uc").write_text("let b=2;\n")
        else: (self.work / "note.txt").write_text("non-candidate change\n")
        self.git("-C", str(self.work), "add", "-A"); self.git("-C", str(self.work), "commit", "-qm", "incoming")
        self.event = self.git("-C", str(self.work), "rev-parse", "HEAD")
        self.git("-C", str(self.work), "push", "-q", "origin", "HEAD:main")
        return self.event
    def test_shallow_repository_added_candidate_fails_closed(self):
        event = self.commit_event()
        shallow = self.root / "shallow"
        self.git("clone", "-q", "--depth=1", f"file://{self.remote}", "-b", "main", str(shallow))
        self.assertEqual(self.git("-C", str(shallow), "rev-parse", "HEAD"), event)
        self.assertEqual(self.git("-C", str(shallow), "rev-parse", "--is-shallow-repository"), "true")
        # Simulate workflow's explicit fetch of the exact API base commit.
        self.git("-C", str(shallow), "fetch", "-q", "--no-tags", "--depth=1", "origin", self.base)
        result = analyze(self.manifest, self.raw, "luci", shallow, event, self.base, self.manifest_sha)
        self.assertTrue(result["fail_closed"]); self.assertEqual(result["drift"][0]["class"], "new_candidate")
        self.assertEqual(result["base_commit"], self.base); self.assertEqual(result["event_commit"], event)
    def test_dotted_suffixless_rpc_backend_is_new_candidate(self):
        source = self.work / "applications/pkg/root/usr/share/rpcd/ucode/luci.mtk_hqos"
        source.parent.mkdir(parents=True)
        source.write_text("'use strict';\nreturn {};\n")
        outside = self.work / "applications/pkg/root/usr/share/rpcd/other/luci.mtk_hqos"
        outside.parent.mkdir(parents=True)
        outside.write_text("not a Ucode root\n")
        event = self.commit_event(False)
        result = analyze(self.manifest, self.raw, "luci", self.work, event, self.base, self.manifest_sha)
        self.assertTrue(result["fail_closed"])
        paths = {row["path"] for row in result["drift"] if row["class"] == "new_candidate"}
        self.assertIn("applications/pkg/root/usr/share/rpcd/ucode/luci.mtk_hqos", paths)
        self.assertNotIn("applications/pkg/root/usr/share/rpcd/other/luci.mtk_hqos", paths)

    def test_changed_selected_content_recalculates_blob_and_hash(self):
        (self.work / "applications" / "pkg" / "known.uc").write_text("let a=3;\n"); event = self.commit_event(False)
        result = analyze(self.manifest, self.raw, "luci", self.work, event, self.base, self.manifest_sha)
        row = result["changed_selected_or_excluded"][0]
        self.assertFalse(result["fail_closed"]); self.assertEqual(result["drift"], [])
        self.assertEqual(result["status"], "content_changes_observed")
        self.assertNotEqual(row["event_identity"]["git_blob"], row["baseline_git_blob"])
        self.assertEqual(row["event_identity"]["sha256"], hashlib.sha256(b"let a=3;\n").hexdigest())
    def test_package_policy_input_change_fails_closed(self):
        (self.work / "applications" / "pkg" / "Makefile").write_text("# changed package routing condition\n")
        event = self.commit_event(False)
        result = analyze(self.manifest, self.raw, "luci", self.work, event, self.base, self.manifest_sha)
        self.assertTrue(result["fail_closed"])
        self.assertEqual(result["drift"][0]["class"], "policy_condition_or_routing_input_changed")

    def test_unrelated_package_makefile_is_reported_without_failing(self):
        unrelated = self.work / "package" / "utils" / "bzip2" / "Makefile"
        unrelated.parent.mkdir(parents=True); unrelated.write_text("# unrelated package\n")
        event = self.commit_event(False)
        result = analyze(self.manifest, self.raw, "luci", self.work, event, self.base, self.manifest_sha)
        self.assertFalse(result["fail_closed"])
        self.assertEqual(result["drift"], [])
        self.assertEqual(result["unrelated_policy_files"][0]["path"], "package/utils/bzip2/Makefile")

    def test_manifest_hash_mismatch_fails_closed(self):
        event = self.commit_event(False)
        with self.assertRaisesRegex(DriftError, "manifest SHA-256 mismatch"):
            analyze(self.manifest, self.raw, "luci", self.work, event, self.base, "0" * 64)
    def test_duplicate_or_unsafe_source_paths_fail_closed(self):
        event = self.commit_event(False)
        duplicate = dict(self.manifest); duplicate["excluded"] = [dict(self.manifest["selected"][0])]
        raw = json.dumps(duplicate, sort_keys=True).encode()
        with self.assertRaisesRegex(DriftError, "duplicate"):
            analyze(duplicate, raw, "luci", self.work, event, self.base, hashlib.sha256(raw).hexdigest())
        unsafe = dict(self.manifest); unsafe["selected"] = [dict(self.manifest["selected"][0], source_path="../known.uc")]
        raw = json.dumps(unsafe, sort_keys=True).encode()
        with self.assertRaisesRegex(DriftError, "unsafe"):
            analyze(unsafe, raw, "luci", self.work, event, self.base, hashlib.sha256(raw).hexdigest())
    def test_checked_in_v04_manifest_hash_and_pins_validate(self):
        manifest_path = Path(__file__).parents[2] / "docs" / "current-corpus-source-v0.4.json"
        raw = manifest_path.read_bytes(); manifest = json.loads(raw)
        for repo, selected_count, excluded_count in (("luci", 65, 4), ("openwrt", 34, 1)):
            selected, excluded, _pin = __import__("tools.source_policy_drift", fromlist=["validate_manifest"]).validate_manifest(manifest, raw, repo)
            self.assertEqual((len(selected), len(excluded)), (selected_count, excluded_count))

    def test_bad_manifest_pin_fails_closed(self):
        event = self.commit_event(False)
        bad = dict(self.manifest); bad["pins"] = {"luci": "f" * 40}
        raw = json.dumps(bad, sort_keys=True).encode()
        with self.assertRaisesRegex(DriftError, "source_commit does not match"):
            analyze(bad, raw, "luci", self.work, event, self.base, hashlib.sha256(raw).hexdigest())
