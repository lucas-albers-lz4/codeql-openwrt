"""Preflight rejection checks for the unpopulated released-producer gate."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.r3_linux_handoff import historical_event_manifest, pinned, run_handoff, safe_unzip, validate_release_state


ROOT = Path(__file__).resolve().parents[2]


def populated_lock(expected_prerelease=True, artifact_kind="versioned-release"):
    lock = json.loads((ROOT / "docs/r3-release-lock.json").read_text())
    release = lock["release"]
    release.update(commit="a" * 40, asset_sha256="b" * 64,
                   manifest_sha256="c" * 64, verifier_sha256="d" * 64,
                   suite_sha256="e" * 64, extractor_sha256="f" * 64,
                   library_lock_sha256="0" * 64, query_lock_sha256="1" * 64,
                   codeql_binary_sha256="2" * 64,
                   tag="v1.2.3-rc.1", artifact_kind=artifact_kind,
                   expected_prerelease=expected_prerelease,
                   asset_url="https://github.com/lucas-albers-lz4/codeql-ucode/releases/download/v1.2.3-rc.1/codeql-ucode-linux-x64.tar.gz")
    release["packs"]["library"]["version"] = "0.1.0"
    release["packs"]["queries"]["version"] = "0.1.0"
    lock["source_oracle_sha256"] = "3" * 64
    return lock


class R3LinuxHandoffTests(unittest.TestCase):
    def test_historical_event_manifest_is_source_first_without_result_expectation(self):
        acceptance = {"schema": "ucode-sarif-acceptance-v1",
                      "producer": {"sha": "a" * 40},
                      "sources": [{"uri": "usr/share/rpcd/ucode/luci.openvpn.uc", "sha256": "b" * 64}],
                      "expected_extracted": ["usr/share/rpcd/ucode/luci.openvpn.uc"],
                      "expected_rules": ["ucode/m4/direct-rpc-shell-word"],
                      "expected_sarif_descriptors": ["ucode/m4/direct-rpc-shell-word"],
                      "expected_results": [{"rule_id": "ucode/m4/direct-rpc-shell-word"}]}
        event = historical_event_manifest(acceptance)
        self.assertEqual(event["schema"], "ucode-sarif-event-triage-v1")
        self.assertNotIn("expected_results", event)
        self.assertEqual(event["sources"], acceptance["sources"])
        self.assertEqual(event["producer"], acceptance["producer"])
        self.assertIn("expected_results", acceptance)

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
        lock = populated_lock(artifact_kind="ci-candidate")
        with self.assertRaisesRegex(RuntimeError, "versioned release kind"):
            pinned(lock)

    def test_lock_accepts_versioned_prerelease_pin(self):
        pinned(populated_lock())

    def test_lock_requires_explicit_boolean_prerelease_status(self):
        lock = populated_lock(expected_prerelease=1)
        with self.assertRaisesRegex(RuntimeError, "expected prerelease status"):
            pinned(lock)

    def test_matching_immutable_prerelease_is_accepted(self):
        validate_release_state(
            {"expected_prerelease": True},
            {"draft": False, "prerelease": True},
            {"isImmutable": True},
        )

    def test_release_status_must_match_lock(self):
        with self.assertRaisesRegex(RuntimeError, "prerelease status mismatch"):
            validate_release_state(
                {"expected_prerelease": True},
                {"draft": False, "prerelease": False},
                {"isImmutable": True},
            )

    def test_mutable_prerelease_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "release is mutable"):
            validate_release_state(
                {"expected_prerelease": True},
                {"draft": False, "prerelease": True},
                {"isImmutable": False},
            )

    def test_draft_prerelease_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "release is draft"):
            validate_release_state(
                {"expected_prerelease": True},
                {"draft": True, "prerelease": True},
                {"isImmutable": True},
            )

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
