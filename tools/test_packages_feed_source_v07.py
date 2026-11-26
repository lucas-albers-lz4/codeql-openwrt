import copy
import hashlib
import unittest

from tools import current_corpus_linux as current_corpus
from tools import packages_feed_source_v07 as verifier


class PackagesFeedV07PolicyTests(unittest.TestCase):
    EXPECTED_POLICY_SHA256 = "2ef4dc10e78b6c3aef873e3f0652b5102698cedb317c9cf96587806941c61d2e"

    def setUp(self):
        self.policy, self.raw, self.baseline = verifier.load_policy()

    def test_frozen_policy_digest_counts_and_v06_rows(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.EXPECTED_POLICY_SHA256)
        self.assertEqual(verifier.POLICY_SHA256, self.EXPECTED_POLICY_SHA256)
        summary = verifier.validate_policy(self.policy, self.baseline)
        self.assertEqual(summary["selected"], 142)
        self.assertEqual(summary["excluded"], 16)
        self.assertEqual(summary["new_package_selected"], 14)
        self.assertEqual(summary["new_package_excluded"], 3)
        self.assertEqual(summary["route_classes"], {"markup": 38, "plain": 104})
        self.assertEqual(self.policy["pins"], self.baseline["pins"])
        self.assertNotIn("mvp-bounded-corpus-v0.7", verifier.candidates.EXPECTED_MANIFESTS)

    def test_v07_source_route_and_stage_oracle(self):
        new_selected = {
            row["source_path"]: row for row in self.policy["selected"]
            if row["repo"] == "packages" and row["route_support"] == verifier.SUPPORT
        }
        self.assertEqual(set(new_selected), verifier.NEW_SELECTED_PATHS)
        for path, route in verifier.EXPECTED_ROUTES.items():
            row = new_selected[path]
            self.assertEqual((row["expected_route"]["classification"],
                              row["expected_route"]["reason"]), route)
            self.assertEqual(row["source_mode"], verifier.EXPECTED_SOURCE_MODES[path])
            self.assertEqual(row["proposed_installed_path"],
                             verifier.EXPECTED_INSTALLED_PATHS[path])
            self.assertRegex(row["git_blob"], r"^[0-9a-f]{40}$")
            self.assertRegex(row["source_sha256"], r"^[0-9a-f]{64}$")
            self.assertIs(row["installed_bytes_verified"], False)
            self.assertTrue(row["install_recipe"])
            self.assertTrue(row["install_recipe_git_blob"])
            self.assertTrue(row["install_recipe_source_sha256"])

        snort_rows = [row for path, row in new_selected.items()
                      if path.startswith("net/snort3/")]
        self.assertEqual(len(snort_rows), 3)
        self.assertTrue(all(row["route_qualification"] == "provisional markup route"
                            for row in snort_rows))

        route_basis = self.policy["route_expectation_basis"]
        self.assertEqual(route_basis["implementation"],
                         "tools/event_corpus_manifest.py:source_route")
        self.assertEqual(route_basis["implementation_sha256"],
                         verifier.ROUTE_ORACLE_SHA256)
        self.assertEqual(route_basis["producer_pr_head"],
                         verifier.route_oracle.ROUTE_PRODUCER_PR_HEAD)
        self.assertFalse(route_basis["release_equivalence_verified"])

    def test_route_verifier_recomputes_precedence_and_line_start(self):
        extension = next(row for row in self.policy["selected"]
                         if row.get("source_path") ==
                         "net/adblock-fast/files/lib/adblock-fast/cli.uc")
        with self.assertRaisesRegex(verifier.SourcePolicyError,
                                    "source-derived route differs"):
            verifier._verify_expected_route(extension,
                                            b"#!/usr/bin/env ucode\nreturn 1\n")

        markup = next(row for row in self.policy["selected"]
                      if row.get("source_path") == "net/snort3/files/main.uc")
        non_qualifying = b"// {% this is not a template line\nreturn 1\n"
        actual = verifier.route_oracle.source_route(
            markup["source_path"], markup["proposed_installed_path"], non_qualifying)
        self.assertEqual(actual, {"classification": "plain", "reason": "ucode_extension"})
        with self.assertRaisesRegex(verifier.SourcePolicyError,
                                    "source-derived route differs"):
            verifier._verify_expected_route(markup, non_qualifying)

    def test_three_test_mocks_are_explicit_near_miss_exclusions(self):
        mocks = {
            row["source_path"]: row for row in self.policy["excluded"]
            if row["repo"] == "packages" and row["source_path"] in verifier.NEW_EXCLUDED_PATHS
        }
        self.assertEqual(set(mocks), verifier.NEW_EXCLUDED_PATHS)
        for path, row in mocks.items():
            self.assertEqual(row["package_owner"], "adblock-fast")
            self.assertEqual(row["source_mode"], "100644")
            self.assertRegex(row["git_blob"], r"^[0-9a-f]{40}$")
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(row["reason"], "test mock; no product package install mapping")

    def test_validator_rejects_mutated_v06_row_and_provisional_route(self):
        changed = copy.deepcopy(self.policy)
        changed["selected"][0]["proposed_installed_path"] += ".changed"
        with self.assertRaisesRegex(verifier.SourcePolicyError, "v0.6 selected rows changed"):
            verifier.validate_policy(changed, self.baseline)

        changed = copy.deepcopy(self.policy)
        row = next(item for item in changed["selected"]
                   if item.get("source_path") == "net/snort3/files/main.uc")
        row["route_support"] = "markup_route_observed"
        with self.assertRaisesRegex(verifier.SourcePolicyError, "source route expectation differs"):
            verifier.validate_policy(changed, self.baseline)

    def test_v06_runner_remains_the_default_128_by_13_contract(self):
        self.assertEqual(current_corpus.MANIFEST_SHA256, verifier.BASELINE_SHA256)
        self.assertEqual(len(self.baseline["selected"]), 128)
        self.assertEqual(len(self.baseline["excluded"]), 13)
        current_corpus.validate_manifest(self.baseline)
        with self.assertRaisesRegex(RuntimeError, "unreviewed corpus schema"):
            current_corpus.validate_manifest(self.policy)


if __name__ == "__main__":
    unittest.main()
