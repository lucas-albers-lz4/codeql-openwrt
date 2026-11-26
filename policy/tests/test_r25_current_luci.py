"""Offline controls for the explicitly separate current-LuCI R2.5 profile."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import r25_current_luci_handoff as current
from tools import r25_package_stage as stage

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "docs/r25-current-luci-package-lock.json"


class CurrentLuciLaneTests(unittest.TestCase):
    def test_allowlist_and_historical_profile_set_remain_separate(self):
        lock, raw = current.load_current_lock(LOCK)
        self.assertEqual(set(lock["packages"]), current.PROFILE_IDS)
        historical, _ = stage._load_lock(ROOT / "docs/r25-package-lock.json")
        self.assertEqual(set(historical["packages"]), {"luci-base", "wifi-scripts-ucode-y"})
        self.assertEqual(json.loads(raw), lock)
        with self.assertRaisesRegex(ValueError, "unsupported R2.5 package lock/profile set"):
            stage._load_lock(LOCK, profile_set="historical")

    def test_r3_release_lock_is_exactly_pinned_before_bootstrap(self):
        lock, raw = current.load_pinned_release_lock(ROOT / "docs/r3-release-lock.json")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), current.RELEASE_LOCK_SHA256)
        self.assertEqual(lock["release"]["tag"], "v0.1.0-rc.1")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "release-lock.json"
            altered = json.loads(raw)
            altered["release"]["expected_prerelease"] = not altered["release"]["expected_prerelease"]
            path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, "reviewed immutable producer pin"):
                current.load_pinned_release_lock(path)

    def test_current_profile_requires_reviewed_artifact_pins(self):
        lock = json.loads(LOCK.read_text())
        lock["packages"]["luci-mod-status"]["ipk"]["artifact_id"] += 1
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "lock.json"
            path.write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError, "artifact/control identity differs"):
                current.load_current_lock(path)

    def test_actual_pinned_status_ipk_stages_with_current_profile(self):
        lock, _raw_lock = current.load_current_lock(LOCK)
        package_id = "luci-mod-status"
        profile = lock["packages"][package_id]
        oracle_raw = (ROOT / profile["oracle"]["path"]).read_bytes()
        ipk_path = ROOT / "evidence/issue173-core-packages-20261126/raw/luci-mod-status.ipk"
        raw_ipk = ipk_path.read_bytes()
        self.assertEqual(hashlib.sha256(raw_ipk).hexdigest(), profile["ipk"]["sha256"])
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp).resolve()
            (workspace / "incoming").mkdir()
            (workspace / "stages").mkdir()
            (workspace / "receipts").mkdir()
            input_ipk = workspace / "incoming/luci-mod-status.ipk"
            input_ipk.write_bytes(raw_ipk)
            staged = stage.stage_locked_package(
                package_id, input_ipk, workspace,
                workspace / "stages/luci-mod-status",
                workspace / "receipts/luci-mod-status.json",
                lock_path=LOCK, profile_set="current-luci")
            self.assertEqual(staged["regular_member_count"], 33)
            self.assertEqual(staged["route_counts"], {"plain": 0, "markup": 1, "excluded": 32})
            row = next(row for row in staged["files"] if row["path"].endswith("index.ut"))
            self.assertEqual(row["sha256"], next(
                item["sha256"] for item in json.loads(oracle_raw)["files"]
                if item["path"] == row["path"]))
            staged_path = workspace / "stages/luci-mod-status/usr/share/ucode/luci/template/admin_status/index.ut"
            self.assertTrue(staged_path.is_file())
            self.assertEqual(staged_path.stat().st_mode & 0o777, 0o600)
            member_inventory = json.loads((ROOT / lock["member_inventory"]["path"]).read_text())
            status_rows = member_inventory["packages"]["luci-mod-status"]["observed_members"]
            original_mode = next(row["mode"] for row in status_rows
                                 if row["path"] == "usr/share/ucode/luci/template/admin_status/index.ut")
            self.assertEqual(original_mode, "0644")

    def test_stage_archive_retains_hidden_files_and_analysis_modes_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "r25-package"
            stage_root = root / "stages" / "fixture"
            stage_root.mkdir(parents=True)
            visible = stage_root / "visible.uc"
            visible.write_bytes(b"visible")
            visible.chmod(0o600)
            hidden = stage_root / "etc/luci-uploads/.placeholder"
            hidden.parent.mkdir(parents=True)
            hidden.write_bytes(b"")
            hidden.chmod(0o600)
            oracle_path = Path(temp) / "oracle.json"
            oracle_path.write_text(json.dumps({"files": [
                {"path": "visible.uc", "sha256": hashlib.sha256(b"visible").hexdigest()},
                {"path": "etc/luci-uploads/.placeholder", "sha256": hashlib.sha256(b"").hexdigest()},
            ]}))
            row = current.preserve_stage_archive(root, "fixture", {"oracle": {"path": str(oracle_path)}})
            self.assertEqual(row["hidden_paths"], ["etc/luci-uploads/.placeholder"])
            self.assertEqual(row["analysis_stage_mode_by_path"], {
                "visible.uc": "0600", "etc/luci-uploads/.placeholder": "0600"})
            self.assertTrue((root / row["archive"]).is_file())

    def test_raw_success_errors_and_resolved_suite_are_rebound(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lane = root / "r25-package"
            stage_root = lane / "stages" / "fixture"
            run_root = lane / "producer-runs/fixture"
            output = run_root / "output"
            (run_root / "bundle/ql/src/diagnostics").mkdir(parents=True)
            output.mkdir(parents=True)
            stage_root.mkdir(parents=True)
            source = stage_root / "service.uc"
            source.write_text("return 1;\n")
            oracle = {"schema": "ucode-installed-stage-v1", "files": [{
                "path": "service.uc", "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "expect_success": True,
                "route": {"classification": "plain", "inconclusive_reason": None,
                          "reason": "test", "status": "plain_route_selected"}}]}
            oracle_path = root / "oracle.json"
            oracle_path.write_text(json.dumps(oracle))
            uri = source.resolve().as_uri()
            suite_file = run_root / "bundle/ql/src/diagnostics/ExtractionErrors.ql"
            suite_file.write_text("query fixture\n")
            (output / "success.json").write_text(json.dumps({"#select": {"tuples": [[{"url": {"uri": uri}}, ""]]}}))
            (output / "errors.json").write_text(json.dumps({"#select": {"tuples": []}}))
            suite_paths = ["diagnostics/ExtractionErrors.ql"]
            resolved_raw = json.dumps([str(suite_file.resolve())]) + "\n"
            (output / "resolved-suite.json").write_text(resolved_raw)
            resolved_sha = hashlib.sha256(resolved_raw.encode()).hexdigest()
            (output / "coverage-manifest.json").write_text(json.dumps({"resolved_suite_sha256": resolved_sha}))
            (lane / "producer-runs/fixture/receipt.json").write_text(json.dumps({
                "successful_files": {"service.uc": 1}, "extraction_errors": [],
                "resolved_suite_sha256": resolved_sha,
                "coverage_manifest_sha256": hashlib.sha256((output / "coverage-manifest.json").read_bytes()).hexdigest()}))
            profile = {"oracle": {"path": str(oracle_path)}}
            accepted = current.audit_raw_producer_outputs(lane, {"packages": {"fixture": profile}}, suite_paths)
            self.assertEqual(accepted["fixture"]["success_row_count"], 1)
            self.assertEqual(accepted["fixture"]["error_row_count"], 0)
            alias = stage_root / "alias.uc"
            alias.symlink_to(source.name)
            alias_uri = alias.absolute().as_uri()
            (output / "success.json").write_text(json.dumps({"#select": {"tuples": [[{"url": {"uri": alias_uri}}, ""]]}}))
            with self.assertRaisesRegex(ValueError, "aliased or escapes"):
                current.audit_raw_producer_outputs(lane, {"packages": {"fixture": profile}}, suite_paths)
            alias.unlink()
            (output / "success.json").write_text(json.dumps({"#select": {"tuples": [[{"url": {"uri": uri}}]]}}))
            with self.assertRaisesRegex(ValueError, "malformed successful-file row"):
                current.audit_raw_producer_outputs(lane, {"packages": {"fixture": profile}}, suite_paths)
            (output / "success.json").write_text(json.dumps({"#select": {"tuples": [[{"url": {"uri": uri}}, ""]]}}))
            suite_alias = run_root / "bundle/ql/src/diagnostics/alias.ql"
            suite_alias.symlink_to(suite_file.name)
            (output / "resolved-suite.json").write_text(json.dumps([str(suite_alias.absolute())]) + "\n")
            with self.assertRaisesRegex(ValueError, "escapes the producer-private"):
                current.audit_raw_producer_outputs(lane, {"packages": {"fixture": profile}}, suite_paths)
            suite_alias.unlink()
            (output / "resolved-suite.json").write_text(resolved_raw)
            (output / "errors.json").write_text(json.dumps({"#select": {"tuples": [["unexpected"]]}}))
            with self.assertRaisesRegex(ValueError, "raw diagnostic tuples disagree"):
                current.audit_raw_producer_outputs(lane, {"packages": {"fixture": profile}}, suite_paths)

    def test_unexpected_symlink_is_rejected_before_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "r25-package"
            stage_root = root / "stages" / "fixture"
            stage_root.mkdir(parents=True)
            (stage_root / "link").symlink_to("/etc/passwd")
            oracle_path = Path(temp) / "oracle.json"
            oracle_path.write_text(json.dumps({"files": []}))
            with self.assertRaisesRegex(ValueError, "unsafe stage entry"):
                current.preserve_stage_archive(root, "fixture", {"oracle": {"path": str(oracle_path)}})
            self.assertFalse((root / "stage-archives/fixture.tar").exists())


if __name__ == "__main__":
    unittest.main()
