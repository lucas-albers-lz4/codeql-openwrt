"""Synthetic portable archive controls; no network or build."""

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import check
import package


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "output"
        self.root.mkdir()
        (self.root / "log").write_bytes(b"phase output\n")
        value = {
            "status": "failed",
            "process_group_quiescent": True,
            "output_sha256": {"log": check.digest(b"phase output\n")},
        }
        (self.root / "manifest.json").write_text(json.dumps(value))

    def test_valid_partial_evidence_archive(self):
        target = self.base / "evidence.tar"
        digest = package.create(self.root, target)
        self.assertEqual(digest, check.digest(target.read_bytes()))
        with tarfile.open(target) as archive:
            self.assertEqual(archive.getnames(), ["metadata/log", "metadata/manifest.json"])
            self.assertTrue(all(row.isfile() and row.mode == 0o644 for row in archive))

    def test_size_rejected_before_payload_read(self):
        original = check.physical_file
        calls = []

        def tracked(path, root, nonempty=False):
            calls.append(Path(path).name)
            return original(path, root, nonempty)

        with patch.object(package, "MAX_TOTAL", 1), patch.object(
            check, "physical_file", side_effect=tracked
        ):
            with self.assertRaisesRegex(ValueError, "size limit"):
                package.collect(self.root)
        self.assertEqual(calls, ["manifest.json"])

    def test_gnu_tar_roundtrip(self):
        tar = shutil.which("gtar") or shutil.which("tar")
        if not tar or b"GNU tar" not in subprocess.check_output([tar, "--version"]):
            self.skipTest("GNU tar unavailable")
        archive = self.base / "evidence.tar"
        package.create(self.root, archive)
        dest = self.base / "extracted"
        dest.mkdir()
        subprocess.run([tar, "-xf", str(archive), "-C", str(dest)], cwd="/", check=True)
        self.assertEqual((dest / "metadata/log").read_bytes(), b"phase output\n")
        self.assertEqual(
            json.loads((dest / "metadata/manifest.json").read_text())["status"], "failed"
        )

    def test_symlink_hardlink_and_extra_rejected(self):
        (self.root / "alias").symlink_to(self.root / "log")
        with self.assertRaisesRegex(ValueError, "symlink"):
            package.collect(self.root)
        (self.root / "alias").unlink()
        os.link(self.root / "log", self.root / "alias")
        with self.assertRaisesRegex(ValueError, "unsafe file"):
            package.collect(self.root)
        (self.root / "alias").unlink()
        (self.root / "extra").write_text("extra")
        with self.assertRaisesRegex(ValueError, "output inventory differs"):
            package.collect(self.root)

    def test_changed_and_missing_payload_rejected(self):
        (self.root / "log").write_text("changed")
        with self.assertRaisesRegex(ValueError, "output digest differs"):
            package.collect(self.root)
        (self.root / "log").unlink()
        with self.assertRaisesRegex(ValueError, "output inventory differs"):
            package.collect(self.root)

    def test_nonquiescent_or_unsafe_manifest_withheld(self):
        value = json.loads((self.root / "manifest.json").read_text())
        value["process_group_quiescent"] = False
        (self.root / "manifest.json").write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "not quiescent"):
            package.collect(self.root)
        value["process_group_quiescent"] = True
        value["output_capture_errors"] = ["unsafe entry"]
        (self.root / "manifest.json").write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "unsafe output inventory"):
            package.collect(self.root)

    def test_duplicate_manifest_and_existing_archive_rejected(self):
        (self.root / "manifest.json").write_text('{"output_sha256":{},"output_sha256":{}}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            package.collect(self.root)
        target = self.base / "evidence.tar"
        target.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "archive path not fresh"):
            package.create(self.root, target)
        self.assertEqual(target.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
