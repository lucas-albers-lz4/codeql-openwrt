"""Event-runner lock and source-first manifest binding controls."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.current_corpus_linux import run_current, validate_event_manifest


ROOT = Path(__file__).resolve().parents[2]


class EventCorpusLinuxTests(unittest.TestCase):
    def test_null_release_lock_fails_before_event_run_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = json.loads((ROOT / "docs/r3-release-lock.json").read_text())
            for key in ("tag", "commit", "asset_url", "asset_sha256", "manifest_sha256",
                        "verifier_sha256", "extractor_sha256", "library_lock_sha256",
                        "query_lock_sha256", "suite_sha256", "codeql_binary_sha256"):
                lock["release"][key] = None
            for part in ("library", "queries"):
                lock["release"]["packs"][part]["version"] = None
            lock_path = root / "null-lock.json"
            lock_path.write_text(json.dumps(lock))
            with self.assertRaisesRegex(RuntimeError, "unpopulated/invalid release commit"):
                run_current(lock_path, root / "event.json", root,
                            "ci-test", event_context=(root / "receipt.json",
                                                      root / "inventory.json", root / "source"))
            self.assertFalse((root / "event-corpus").exists())

    def test_event_manifest_must_match_fresh_inventory_and_receipt_digests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            receipt = root / "receipt.json"
            inventory = root / "inventory.json"
            output = root / "event.json"
            receipt.write_text('{"repository":"openwrt"}')
            report = {"base_commit": "a" * 40, "head_commit": "b" * 40}
            inventory.write_text(json.dumps(report))
            expected = {"schema": "mvp-incoming-event-corpus-v1",
                        "event": {"policy_sha256": hashlib.sha256(
                            (ROOT / "docs/current-corpus-source-v0.6.json").read_bytes()).hexdigest(),
                                  "identity_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
                                  "candidate_inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
                                  "route_oracle_script_sha256": hashlib.sha256(
                                      (ROOT / "tools/event_corpus_manifest.py").read_bytes()).hexdigest()}}
            output.write_text(json.dumps(expected))
            with patch("tools.current_corpus_linux.compare_candidates", return_value=report), \
                 patch("tools.current_corpus_linux.build_event_manifest", return_value={
                     "schema": expected["schema"], "event": {"policy_sha256": expected["event"]["policy_sha256"]}}):
                self.assertEqual(validate_event_manifest(output, receipt, inventory, root), expected)
                inventory.write_text(json.dumps({**report, "head_candidate_count": 999}))
                with self.assertRaisesRegex(RuntimeError, "fresh Git objects"):
                    validate_event_manifest(output, receipt, inventory, root)


if __name__ == "__main__":
    unittest.main()
