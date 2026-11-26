from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools import r25_package_handoff as handoff
from tools import r25_package_stage as stage


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


class PackageHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_bundle_cli_archive_executable_and_runner_hashes_are_independently_checked(self):
        r3 = self.root / "r3"
        bundle = r3 / "bundle/codeql-ucode-linux"
        runner = bundle / "runner/run-installed-stage.py"
        runner.parent.mkdir(parents=True)
        runner.write_text("#!/usr/bin/env python3\n")
        runner.chmod(0o755)
        archive = r3 / "downloads/codeql-linux64.zip"
        binary = r3 / "cli/codeql/codeql"
        archive.parent.mkdir(parents=True)
        binary.parent.mkdir(parents=True)
        archive.write_bytes(b"cli zip")
        binary.write_bytes(b"locked CLI binary")
        file_row = {"path": "runner/run-installed-stage.py",
                    "sha256": handoff.sha_file(runner), "bytes": runner.stat().st_size,
                    "mode": stat.S_IMODE(runner.stat().st_mode)}
        manifest = {"schema_version": 1, "artifact_kind": "versioned-release",
                    "producer_commit": "a" * 40, "release_tag": "v0.1.0",
                    "files": [file_row]}
        manifest_path = bundle / "bundle-manifest.json"
        write_json(manifest_path, manifest)
        lock = {"release": {"manifest_sha256": handoff.sha_file(manifest_path),
                             "commit": "a" * 40, "tag": "v0.1.0",
                             "codeql_binary_sha256": handoff.sha_file(binary)},
                "codeql": {"sha256": handoff.sha_file(archive)}}
        self.assertEqual(handoff.verify_bundle_inputs(r3, lock), (bundle, binary, archive))
        lock["release"]["codeql_binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "executable differs from release lock"):
            handoff.verify_bundle_inputs(r3, lock)

    def test_artifact_id_name_and_expiry_are_checked_before_download(self):
        input_root = self.root / "inputs"
        input_root.mkdir()
        logs = self.root / "logs"
        logs.mkdir()
        profile = {"ipk": {"run_id": 45548269425, "artifact_id": 14997815607,
                           "artifact_name": "wifi-ipk-byte-45548269425-1",
                           "filename": "y-wifi-scripts.ipk"}}
        metadata = {"artifacts": [{"id": 14997815607,
                                   "name": "wifi-ipk-byte-45548269425-1",
                                   "expired": False,
                                   "workflow_run": {"id": 45548269425}}]}
        calls = []

        def fake_run(label, argv, cwd, env, log_root, records):
            calls.append((label, argv, env.copy()))
            if label.endswith("artifact-list"):
                return json.dumps(metadata)
            dest = Path(argv[-1])
            (dest / "y-wifi-scripts.ipk").write_bytes(b"verified later by lock")
            return ""

        with patch.dict(os.environ, {"GH_TOKEN": "artifact-read-token"}):
            with patch.object(handoff, "run_checked", side_effect=fake_run):
                result = handoff.download_pinned_artifact(
                    "lucas-albers-lz4/codeql-openwrt", "wifi-scripts-ucode-y",
                    profile, input_root, logs, [])
        self.assertEqual(result, input_root / "wifi-scripts-ucode-y/y-wifi-scripts.ipk")
        self.assertEqual(len(calls), 2)
        self.assertIn("GH_TOKEN", calls[0][2])
        self.assertEqual(calls[0][1][2], "/repos/lucas-albers-lz4/codeql-openwrt/actions/runs/45548269425/artifacts?per_page=100")

        expired = {"artifacts": [{**metadata["artifacts"][0], "expired": True}]}
        calls.clear()
        with patch.dict(os.environ, {"GH_TOKEN": "artifact-read-token"}):
            with patch.object(handoff, "run_checked", side_effect=[json.dumps(expired)]):
                with self.assertRaisesRegex(ValueError, "missing, changed or expired"):
                    handoff.download_pinned_artifact(
                        "lucas-albers-lz4/codeql-openwrt", "wifi-scripts-ucode-y",
                        profile, input_root, logs, [])
        self.assertEqual(len(calls), 0)

    def test_producer_child_environment_does_not_receive_download_token(self):
        with patch.dict(os.environ, {"GH_TOKEN": "artifact-read-token",
                                     "GITHUB_TOKEN": "other-token",
                                     "ACTIONS_RUNTIME_TOKEN": "runtime-token"}):
            env = handoff.clean_environment()
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", env)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "GH_TOKEN is required"):
                handoff.clean_environment(include_gh=True)

    def test_source_oracles_bind_complete_coverage_routes_diagnostics_and_zero_result_sarif(self):
        lock, _ = stage._load_lock(stage.LOCK_PATH)
        package_id = "wifi-scripts-ucode-y"
        profile = lock["packages"][package_id]
        oracle_raw = (stage.ROOT / profile["oracle"]["path"]).read_bytes()
        oracle, _ = stage.validate_oracle(oracle_raw, profile["oracle"]["sha256"], profile)
        r3 = self.root / "r3"
        r25 = r3 / "r25-package"
        producer_output = r25 / "producer-runs" / package_id
        stage_root = r25 / "stages" / package_id
        (producer_output / "output").mkdir(parents=True)
        stage_root.mkdir(parents=True)
        for entry in oracle["files"]:
            target = stage_root / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"unit-test placeholder; digest supplied through an isolated mock")
        release_lock = {"release": {"manifest_sha256": "1" * 64, "commit": "2" * 40,
                                     "tag": "v0.1.0", "expected_rules": [
                                         "ucode/m4/direct-rpc-shell-word",
                                         "ucode/diagnostics/extraction-errors",
                                         "ucode/diagnostics/successfully-extracted-files"]},
                        "codeql": {"sha256": "3" * 64, "version": "2.27.4"}}
        files = [{"path": entry["path"], "sha256": entry["sha256"],
                  "route": entry["route"],
                  "successful_count": int(entry["expect_success"]),
                  "extraction_error_count": 0} for entry in oracle["files"]]
        successful = {entry["path"]: 1 for entry in oracle["files"] if entry["expect_success"]}
        sarif_path = producer_output / "output/default-suite.sarif"
        sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"rules": [{"id": "ucode/m4/direct-rpc-shell-word"}]}},
            "results": []}]}
        write_json(sarif_path, sarif)
        routing = {"input_count": len(files), "duplicate_input_count": 0,
                   "decisions": [{"path": str(stage_root / entry["path"]),
                                  "installed_path": entry["path"], **entry["route"]}
                                 for entry in oracle["files"]]}
        routing_path = producer_output / "output/routing.json"
        write_json(routing_path, routing)
        coverage = {"schema": "ucode-installed-stage-coverage-v1",
                    "bundle_manifest_sha256": release_lock["release"]["manifest_sha256"],
                    "producer_commit": release_lock["release"]["commit"],
                    "release_tag": release_lock["release"]["tag"],
                    "codeql_archive_sha256": release_lock["codeql"]["sha256"],
                    "codeql_version": "CodeQL command-line toolchain release 2.27.4.",
                    "oracle_sha256": profile["oracle"]["sha256"],
                    "routing_sha256": handoff.sha_file(routing_path),
                    "files": files,
                    "resolved_queries": ["DirectRpcShellWord.ql", "ExtractionErrors.ql",
                                         "SuccessfullyExtractedFiles.ql"],
                    "sarif": {"sha256": handoff.sha_file(sarif_path),
                              "rule_ids": ["ucode/m4/direct-rpc-shell-word"],
                              "result_count": 0},
                    "commands": [{"label": "database-index", "exit_status": 0}]}
        coverage_path = producer_output / "output/coverage-manifest.json"
        write_json(coverage_path, coverage)
        receipt = {"bundle_manifest_sha256": coverage["bundle_manifest_sha256"],
                   "producer_commit": coverage["producer_commit"], "release_tag": coverage["release_tag"],
                   "oracle_sha256": profile["oracle"]["sha256"], "sarif": coverage["sarif"],
                   "codeql_version": coverage["codeql_version"],
                   "codeql_archive_sha256": coverage["codeql_archive_sha256"],
                   "routing_sha256": coverage["routing_sha256"],
                   "coverage_manifest_sha256": handoff.sha_file(coverage_path),
                   "stage_files": {entry["path"]: entry["sha256"] for entry in oracle["files"]},
                   "extraction_errors": [], "successful_files": successful,
                   "resolved_queries": coverage["resolved_queries"]}
        write_json(producer_output / "receipt.json", receipt)
        real_sha = handoff.sha_file

        def sha_with_stage_oracle(path):
            try:
                rel = path.relative_to(stage_root).as_posix()
            except ValueError:
                return real_sha(path)
            return next(entry["sha256"] for entry in oracle["files"] if entry["path"] == rel)

        with patch.object(handoff, "sha_file", side_effect=sha_with_stage_oracle):
            summary = handoff.verify_coverage(package_id, profile, oracle, producer_output, release_lock)
        self.assertEqual(summary["successful_file_count"], 17)
        self.assertEqual(summary["sarif_result_count"], 0)

        sarif["runs"][0]["results"] = [{"ruleId": "ucode/m4/direct-rpc-shell-word"}]
        write_json(sarif_path, sarif)
        coverage["sarif"]["sha256"] = handoff.sha_file(sarif_path)
        coverage["sarif"]["result_count"] = 1
        write_json(coverage_path, coverage)
        receipt["sarif"] = coverage["sarif"]
        write_json(producer_output / "receipt.json", receipt)
        with patch.object(handoff, "sha_file", side_effect=sha_with_stage_oracle):
            with self.assertRaisesRegex(ValueError, "unexpected default-suite package SARIF result"):
                handoff.verify_coverage(package_id, profile, oracle, producer_output, release_lock)

    def test_runner_output_missing_coverage_rows_fails_closed(self):
        lock, _ = stage._load_lock(stage.LOCK_PATH)
        package_id = "luci-base"
        profile = lock["packages"][package_id]
        oracle, _ = stage.validate_oracle(
            (stage.ROOT / profile["oracle"]["path"]).read_bytes(),
            profile["oracle"]["sha256"], profile)
        output = self.root / "r3/r25-package/producer-runs/luci-base"
        (output / "output").mkdir(parents=True)
        for path in (output / "output/coverage-manifest.json", output / "receipt.json",
                     output / "output/default-suite.sarif", output / "output/routing.json"):
            path.write_text("{}")
        release_lock = {"release": {"manifest_sha256": "1" * 64, "commit": "2" * 40,
                                     "tag": "v0.1.0", "expected_rules": []},
                        "codeql": {"sha256": "3" * 64, "version": "2.27.4"}}
        profile = lock["packages"][package_id]
        write_json(output / "output/coverage-manifest.json", {
            "schema": "ucode-installed-stage-coverage-v1",
            "bundle_manifest_sha256": release_lock["release"]["manifest_sha256"],
            "producer_commit": release_lock["release"]["commit"],
            "release_tag": release_lock["release"]["tag"],
            "codeql_archive_sha256": release_lock["codeql"]["sha256"],
            "oracle_sha256": profile["oracle"]["sha256"], "files": []})
        with self.assertRaisesRegex(ValueError, "coverage file count mismatch"):
            handoff.verify_coverage(package_id, profile, oracle, output, release_lock)


if __name__ == "__main__":
    unittest.main()
