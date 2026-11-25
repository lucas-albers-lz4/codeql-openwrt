"""Preflight rejection checks for the unpopulated released-producer gate."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.r3_linux_handoff import pinned, run_handoff, safe_unzip


ROOT = Path(__file__).resolve().parents[2]


class R3LinuxHandoffTests(unittest.TestCase):
    def test_unpopulated_release_lock_fails_before_run_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            run_root = Path(temp) / "run"
            lock = json.loads((ROOT / "docs/r3-release-lock.json").read_text())
            lock["release"]["commit"] = None
            lock_path = Path(temp) / "empty-lock.json"
            lock_path.write_text(json.dumps(lock))
            with self.assertRaisesRegex(RuntimeError, "unpopulated/invalid release commit"):
                run_handoff(lock_path, run_root, "test")
            self.assertFalse(run_root.exists())

    def test_candidate_kind_cannot_satisfy_release_lock(self):
        lock = json.loads((ROOT / "docs/r3-release-lock.json").read_text())
        lock["release"].update(commit="a" * 40, asset_sha256="b" * 64,
                               manifest_sha256="c" * 64, verifier_sha256="d" * 64,
                               suite_sha256="e" * 64, extractor_sha256="f" * 64,
                               library_lock_sha256="0" * 64, query_lock_sha256="1" * 64,
                               codeql_binary_sha256="2" * 64,
                               tag="v1.2.3", artifact_kind="ci-candidate",
                               asset_url="https://github.com/lucas-albers-lz4/codeql-ucode/releases/download/v1.2.3/codeql-ucode-linux-x64.tar.gz")
        lock["release"]["packs"]["library"]["version"] = "0.1.0"
        lock["release"]["packs"]["queries"]["version"] = "0.1.0"
        lock["source_oracle_sha256"] = "3" * 64
        with self.assertRaisesRegex(RuntimeError, "versioned release kind"):
            pinned(lock)

    def test_zip_traversal_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "cli.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("codeql/../escape", "bad")
            output = Path(temp) / "cli"
            with self.assertRaisesRegex(RuntimeError, "unsafe CLI archive member"):
                safe_unzip(archive, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
