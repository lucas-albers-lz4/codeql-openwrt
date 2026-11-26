from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import warnings
from zipfile import ZipFile

from tools import default_branch_consumer_replay as replay
from tools import default_branch_final_proof as final_proof


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sarif(result_rows: list[dict]) -> bytes:
    value = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeQL", "semanticVersion": "2.0",
                "rules": [{"id": "test/rule",
                           "defaultConfiguration": {"level": "warning"}}],
            }},
            "columnKind": "utf16CodeUnits",
            "invocations": [{"executionSuccessful": True}],
            "results": result_rows,
        }],
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _result() -> dict:
    return {
        "ruleId": "test/rule",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uriBaseId": "%SRCROOT%", "uri": "usr/a.uc"},
            "region": {"startLine": 1, "startColumn": 1,
                       "endLine": 1, "endColumn": 2},
        }}],
    }


def _fixture(base: Path, result_rows: list[dict]) -> dict:
    base.mkdir(parents=True, exist_ok=True)
    scratch = base / "scratch"
    payload = scratch / "payload"
    out = payload / "out"
    stage = payload / "stage"
    for path in (scratch, scratch / "home", scratch / "tmp", payload,
                 out, stage, stage / "usr"):
        path.mkdir(mode=0o700)
    source = stage / "usr" / "a.uc"
    source_raw = b"x\n"
    source.write_bytes(source_raw)
    producer = {"codeql_version": "2.0", "producer_id": "fixture"}
    manifest = {
        "schema": "ucode-sarif-event-triage-v1",
        "producer": producer,
        "expected_extracted": ["usr/a.uc"],
        "sources": [{"uri": "usr/a.uc", "sha256": _sha(source_raw)}],
        "expected_rules": ["test/rule"],
        "expected_sarif_descriptors": ["test/rule"],
    }
    sarif_raw = _sarif(result_rows)
    receipt = {
        "schema": "ucode-sarif-run-v1", "run_id": "9-1",
        "producer": producer, "sarif_sha256": _sha(sarif_raw),
        "commands": [{"exit": 0, "argv": ["codeql", "database", "finalize"]}],
        "extraction_errors": [], "successful_files": ["usr/a.uc"],
        "resolved_rules": ["test/rule"],
    }
    manifest_raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    receipt_raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (out / "default-suite.sarif").write_bytes(sarif_raw)
    (out / "event-triage-input.json").write_bytes(manifest_raw)
    (out / "producer-receipt.json").write_bytes(receipt_raw)
    return {
        "scratch": scratch, "out": out, "stage": stage,
        "manifest": manifest, "receipt": receipt,
        "manifest_raw": manifest_raw, "receipt_raw": receipt_raw,
        "sarif_raw": sarif_raw,
    }


class ConsumerReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="consumer-replay-contract-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def _invoke(self, fixture: dict) -> dict:
        result = replay._invoke_consumer(
            replay.ROOT / "tools" / "sarif_accept.py", fixture["scratch"],
            run_id=9, attempt=1,
        )
        stdout = result["stdout"]
        stderr = result["stderr"]
        fixture["invocation"] = {key: value for key, value in result.items()
                                  if key not in ("stdout", "stderr")}
        fixture["stdout"] = stdout
        fixture["stderr"] = stderr
        return fixture

    def test_actual_consumer_preserves_duplicate_tuple_multiplicity_and_clean_control(self):
        positive = self._invoke(_fixture(self.base / "positive", [_result(), _result()]))
        self.assertEqual(positive["invocation"]["exit"], 0, positive["stderr"])
        packet = replay._parse_object(positive["stdout"], "positive output")
        self.assertEqual(packet["status"], "triage_required")
        self.assertEqual(packet["result_count"], 2)
        counts = replay._tuple_counter(packet, "positive output")
        self.assertEqual(len(counts), 1)
        self.assertEqual(next(iter(counts.values())), 2)
        compared = replay._assert_output_equal(
            positive["stdout"], positive["stdout"], positive["sarif_raw"],
            positive["manifest"], Counter({"usr/a.uc": 1}), "9-1",
        )
        self.assertEqual(compared["tuple_multiplicity"][0]["count"], 2)

        clean = self._invoke(_fixture(self.base / "clean", []))
        self.assertEqual(clean["invocation"]["exit"], 0, clean["stderr"])
        clean_packet = replay._parse_object(clean["stdout"], "clean output")
        self.assertEqual(clean_packet["status"], "clean_scan")
        self.assertEqual(clean_packet["result_count"], 0)
        self.assertEqual(clean_packet["results_for_triage"], [])

    def test_actual_consumer_rejects_stale_sarif_digest_and_changed_input(self):
        fixture = _fixture(self.base / "sarif-mutated", [_result()])
        changed = json.loads(fixture["sarif_raw"])
        changed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["endColumn"] = 1
        (fixture["out"] / "default-suite.sarif").write_text(json.dumps(changed), encoding="utf-8")
        rejected = self._invoke(fixture)
        self.assertNotEqual(rejected["invocation"]["exit"], 0)
        self.assertIn(b"SARIF bytes differ from producer receipt", rejected["stderr"])

        fixture2 = _fixture(self.base / "input-mutated", [_result()])
        changed_manifest = dict(fixture2["manifest"])
        changed_manifest["expected_extracted"] = ["usr/a.uc", "usr/a.uc"]
        (fixture2["out"] / "event-triage-input.json").write_text(
            json.dumps(changed_manifest), encoding="utf-8")
        rejected_input = self._invoke(fixture2)
        self.assertNotEqual(rejected_input["invocation"]["exit"], 0)

    def test_output_comparison_rejects_whitespace_and_duplicate_tuple_mismatch(self):
        fixture = self._invoke(_fixture(self.base / "output", [_result(), _result()]))
        self.assertEqual(fixture["invocation"]["exit"], 0)
        with self.assertRaisesRegex(replay.ReplayError, "stdout bytes"):
            replay._assert_output_equal(
                fixture["stdout"], fixture["stdout"] + b" ", fixture["sarif_raw"],
                fixture["manifest"], Counter({"usr/a.uc": 1}), "9-1",
            )
        hosted = json.loads(fixture["stdout"])
        hosted["results_for_triage"].pop()
        hosted["result_count"] = 1
        hosted_raw = (json.dumps(hosted, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self.assertRaises(replay.ReplayError):
            replay._assert_output_equal(
                fixture["stdout"], hosted_raw, fixture["sarif_raw"],
                fixture["manifest"], Counter({"usr/a.uc": 1}), "9-1",
            )

    def test_safe_zip_rejects_duplicate_names_and_malformed_nested_json(self):
        from io import BytesIO

        archive = BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with ZipFile(archive, "w") as output:
                output.writestr("same.json", b"{}")
                output.writestr("same.json", b"{\"x\":1}")
        with self.assertRaises(final_proof.FinalProofError):
            final_proof._read_zip(archive.getvalue(), "mutated fixture")

        nested = b'{"x":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
        with self.assertRaises(replay.ReplayError):
            replay._parse_object(nested, "nested SARIF fixture")

    def test_unsafe_stage_path_and_aliased_output_are_rejected(self):
        for value in ("../escape.uc", "/absolute.uc", "usr\\escape.uc", "usr//escape.uc"):
            with self.subTest(value=value), self.assertRaises(replay.ReplayError):
                replay._validate_installed_path(value)

        target = self.base / "sentinel.txt"
        target.write_bytes(b"unchanged")
        alias = self.base / "alias.txt"
        try:
            alias.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaises(OSError):
            replay._write_exclusive(alias, b"replacement")
        self.assertEqual(target.read_bytes(), b"unchanged")

    def test_source_materialization_checks_pinned_git_blob_and_sha(self):
        roots = {}
        rows = []
        for repo in ("luci", "openwrt", "packages"):
            root = self.base / (repo + "-repo")
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Replay Test"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "replay@example.invalid"], check=True)
            source_path = f"src/{repo}.uc"
            installed_path = f"usr/share/ucode/{repo}.uc"
            data = f"{repo}\n".encode()
            source = root / source_path
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
            commit = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            blob = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", f"HEAD:{source_path}"], text=True).strip()
            roots[repo] = root
            rows.append({
                "repo": repo, "source_path": source_path,
                "source_commit": commit, "git_blob": blob,
                "source_sha256": _sha(data),
                "proposed_installed_path": installed_path,
            })
        manifest = {
            "pins": {row["repo"]: row["source_commit"] for row in rows},
            "selected": rows,
        }
        stage = self.base / "stage"
        stage.mkdir()
        observed = replay._materialize_selected_sources(manifest, roots, stage)
        self.assertEqual(len(observed), 3)
        self.assertEqual((stage / "usr/share/ucode/openwrt.uc").read_bytes(), b"openwrt\n")

        wrong_sha = json.loads(json.dumps(manifest))
        wrong_sha["selected"][0]["source_sha256"] = "0" * 64
        wrong_sha_stage = self.base / "wrong-sha"
        wrong_sha_stage.mkdir()
        with self.assertRaisesRegex(replay.ReplayError, "SHA-256 differs"):
            replay._materialize_selected_sources(wrong_sha, roots, wrong_sha_stage)

        wrong_pin = json.loads(json.dumps(manifest))
        wrong_pin["pins"]["openwrt"] = "f" * 40
        wrong_pin_stage = self.base / "wrong-pin"
        wrong_pin_stage.mkdir()
        with self.assertRaises(replay.ReplayError):
            replay._materialize_selected_sources(wrong_pin, roots, wrong_pin_stage)


if __name__ == "__main__":
    unittest.main()
