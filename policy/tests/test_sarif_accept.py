"""Rejection controls for the proposed SARIF acceptance boundary."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.sarif_accept import accept


class SarifAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.uri = "usr/share/rpcd/ucode/luci.openvpn.uc"
        staged = self.source / self.uri
        staged.parent.mkdir(parents=True)
        staged.write_text("const raw = request.args.cl_meta;\n", encoding="utf-8")
        self.producer = {"sha": "a" * 40, "pack_sha256": "b" * 64,
                         "codeql_version": "2.27.4", "suite_sha256": "c" * 64}
        self.rule = "ucode/m4/openvpn-raw-metadata-command"
        self.location = {"rule_id": self.rule, "uri": self.uri,
                         "start_line": 1, "start_column": 13,
                         "end_line": 1, "end_column": 33, "level": "warning"}
        self.manifest = {"schema": "ucode-sarif-acceptance-v1", "producer": self.producer,
                         "sources": [{"uri": self.uri,
                                      "sha256": hashlib.sha256(staged.read_bytes()).hexdigest()}],
                         "expected_extracted": [self.uri], "expected_rules": [self.rule],
                         "expected_sarif_descriptors": [self.rule],
                         "expected_results": [self.location]}
        self.sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.4",
                                "rules": [{"id": self.rule,
                                           "defaultConfiguration": {"level": "warning"}}]}},
            "columnKind": "utf16CodeUnits",
            "invocations": [{"executionSuccessful": True}],
            "results": [self.result()]}]}
        self.receipt = {"schema": "ucode-sarif-run-v1", "producer": self.producer,
                        "run_id": "ci-123", "sarif_sha256": "",
                        "successful_files": [self.uri], "extraction_errors": [],
                        "resolved_rules": [self.rule],
                        "commands": [{"argv": ["codeql", "database", "analyze"], "exit": 0}]}

    def result(self):
        return {"ruleId": self.rule, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": self.uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 1, "startColumn": 13, "endColumn": 33}}}]}

    def verify(self, update_hash=True):
        paths = [self.root / name for name in ("sarif.json", "manifest.json", "receipt.json")]
        paths[0].write_text(json.dumps(self.sarif), encoding="utf-8")
        paths[1].write_text(json.dumps(self.manifest), encoding="utf-8")
        if update_hash:
            self.receipt["sarif_sha256"] = hashlib.sha256(paths[0].read_bytes()).hexdigest()
        paths[2].write_text(json.dumps(self.receipt), encoding="utf-8")
        return accept(*paths, self.source)

    def test_exact_alert_and_fixed_zero(self):
        self.assertEqual(len(self.verify()["accepted_results"]), 1)
        self.sarif["runs"][0]["results"] = []
        self.manifest["expected_results"] = []
        self.assertEqual(self.verify()["accepted_results"], [])

    def test_duplicate_alert_rejected(self):
        self.sarif["runs"][0]["results"].append(copy.deepcopy(self.result()))
        with self.assertRaisesRegex(ValueError, "multiset mismatch"):
            self.verify()

    def test_wrong_location_and_unknown_rule_rejected(self):
        result = self.sarif["runs"][0]["results"][0]
        result["locations"][0]["physicalLocation"]["region"]["startColumn"] = 14
        with self.assertRaisesRegex(ValueError, "multiset mismatch"):
            self.verify()
        result["ruleId"] = "unexpected-rule"
        with self.assertRaisesRegex(ValueError, "unknown SARIF rule"):
            self.verify()

    def test_missing_or_duplicate_extraction_rejected(self):
        self.receipt["successful_files"] = []
        with self.assertRaisesRegex(ValueError, "successful-file multiset"):
            self.verify()
        self.receipt["successful_files"] = [self.uri, self.uri]
        with self.assertRaisesRegex(ValueError, "successful-file multiset"):
            self.verify()

    def test_source_and_sarif_hash_rejected(self):
        self.manifest["sources"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source-byte mismatch"):
            self.verify()
        self.manifest["sources"][0]["sha256"] = hashlib.sha256(
            (self.source / self.uri).read_bytes()).hexdigest()
        self.verify()
        self.sarif["runs"][0]["results"] = []
        with self.assertRaisesRegex(ValueError, "SARIF bytes differ"):
            self.verify(update_hash=False)

    def test_failed_command_and_extraction_error_rejected(self):
        self.receipt["commands"][0]["exit"] = 1
        with self.assertRaisesRegex(ValueError, "failed producer command"):
            self.verify()
        self.receipt["commands"][0]["exit"] = 0
        self.receipt["extraction_errors"] = ["syntax error"]
        with self.assertRaisesRegex(ValueError, "extraction errors"):
            self.verify()

    def test_unsafe_uri_and_missing_rule_rejected(self):
        result = self.sarif["runs"][0]["results"][0]
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "../escape.uc"
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.verify()
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = self.uri
        self.sarif["runs"][0]["tool"]["driver"]["rules"] = []
        with self.assertRaisesRegex(ValueError, "rule descriptors differ"):
            self.verify()

    def test_unexpected_or_unexecuted_suite_rule_rejected(self):
        self.receipt["resolved_rules"].append("ucode/m4/extra")
        with self.assertRaisesRegex(ValueError, "resolved suite rule set differs"):
            self.verify()
        self.receipt["resolved_rules"] = [self.rule]
        self.sarif["runs"][0]["tool"]["driver"]["rules"].append(
            {"id": "ucode/m4/extra", "defaultConfiguration": {"level": "warning"}})
        with self.assertRaisesRegex(ValueError, "rule descriptors differ"):
            self.verify()

    def test_resolved_diagnostic_without_sarif_descriptor(self):
        diagnostic = "ucode/diagnostics/extraction-errors"
        self.manifest["expected_rules"].append(diagnostic)
        self.receipt["resolved_rules"].append(diagnostic)
        self.assertEqual(len(self.verify()["accepted_results"]), 1)
        self.manifest["expected_sarif_descriptors"].append(diagnostic)
        with self.assertRaisesRegex(ValueError, "rule descriptors differ"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
