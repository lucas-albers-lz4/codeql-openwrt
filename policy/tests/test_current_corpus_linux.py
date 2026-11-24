"""Source-first manifest and fail-closed current-corpus preflight checks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.current_corpus_linux import (MANIFEST_SHA256, digest, run_current,
                                        validate_manifest, index_with_retained_routing)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/current-corpus-source-v0.6.json"


def null_lock(path: Path) -> Path:
    lock = json.loads((ROOT / "docs/r3-release-lock.json").read_text())
    for key in ("tag", "commit", "asset_url", "asset_sha256", "manifest_sha256",
                "verifier_sha256", "extractor_sha256", "library_lock_sha256",
                "query_lock_sha256", "suite_sha256", "codeql_binary_sha256"):
        lock["release"][key] = None
    for part in ("library", "queries"):
        lock["release"]["packs"][part]["version"] = None
    path.write_text(json.dumps(lock))
    return path


class CurrentCorpusLinuxTests(unittest.TestCase):
    def manifest(self):
        return json.loads(MANIFEST.read_text())

    def test_frozen_manifest_structure_and_digest(self):
        self.assertEqual(digest(MANIFEST), MANIFEST_SHA256)
        validate_manifest(self.manifest())

    def test_duplicate_staged_path_rejected(self):
        manifest = self.manifest()
        manifest["selected"][1]["proposed_installed_path"] = manifest["selected"][0]["proposed_installed_path"]
        with self.assertRaisesRegex(RuntimeError, "duplicate selected identity/stage"):
            validate_manifest(manifest)

    def test_selected_source_traversal_rejected(self):
        manifest = self.manifest()
        manifest["selected"][0]["source_path"] = "../escape.uc"
        with self.assertRaisesRegex(RuntimeError, "unsafe source/stage path"):
            validate_manifest(manifest)

    def test_missing_source_digest_rejected(self):
        manifest = self.manifest()
        manifest["selected"][0]["source_sha256"] = "0"
        with self.assertRaisesRegex(RuntimeError, "missing selected source digest/blob"):
            validate_manifest(manifest)

    def test_null_release_lock_fails_before_new_run_root(self):
        with tempfile.TemporaryDirectory() as temp:
            prior = Path(temp) / "r3"
            lock = null_lock(Path(temp) / "null-lock.json")
            with self.assertRaisesRegex(RuntimeError, "unpopulated/invalid release commit"):
                run_current(lock, MANIFEST, prior, "test")
            self.assertFalse((prior / "current-corpus").exists())

    def test_workflow_module_entrypoint_reaches_lock_preflight(self):
        with tempfile.TemporaryDirectory() as temp:
            prior = Path(temp) / "r3"
            lock = null_lock(Path(temp) / "null-lock.json")
            process = subprocess.run([sys.executable, "-B", "-m", "tools.current_corpus_linux",
                                      str(lock), "docs/current-corpus-source-v0.6.json",
                                      str(prior), "test"], cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("unpopulated/invalid release commit", process.stderr)
            self.assertFalse(prior.exists())

    def test_index_failure_retains_emitted_routing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            route = Path(temp) / "routing.json"
            retained = Path(temp) / "retained.json"

            class FailingIndex:
                def call(self, label, argv, *, env):
                    if label != "db-index":
                        raise AssertionError(label)
                    route.write_text('{"decisions": []}')
                    raise RuntimeError("index failed after routing")

            with self.assertRaisesRegex(RuntimeError, "index failed after routing"):
                index_with_retained_routing(FailingIndex(), ["codeql"], {}, route, retained)
            self.assertEqual(retained.read_bytes(), route.read_bytes())


if __name__ == "__main__":
    unittest.main()
