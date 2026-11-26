from __future__ import annotations

from collections import Counter
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import default_branch_source_truth as verifier
from tools import event_corpus_manifest as routes
from tools import full_tree_candidates as selector


class SourceTruthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="source-truth-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.roots: dict[str, Path] = {}
        self.selected_specs = {
            "luci": (
                "modules/demo/root/usr/share/ucode/demo.ut",
                "usr/share/ucode/demo.ut",
                b"#!/usr/bin/ucode\n{% print('markup') %}\n",
            ),
            "openwrt": (
                "package/demo/files/usr/share/rpcd/ucode/demo.ut",
                "usr/share/rpcd/ucode/demo.ut",
                b"{{ rpcd raw mode wins }}\n",
            ),
            "packages": (
                "net/demo/files/usr/share/ucode/demo.uc",
                "usr/share/ucode/demo.uc",
                b"export function main() { return 1; }\n",
            ),
        }
        self.excluded_specs = {
            "luci": ("modules/demo/tests/fixture.uc", b"// excluded source-shaped lookalike\n"),
            "openwrt": ("package/demo/tests/near-miss.uc", b"// excluded candidate\n"),
            "packages": ("net/demo/tests/mock.uc", b"// test helper\n"),
        }
        pins: dict[str, str] = {}
        for repo in verifier.REPOSITORIES:
            root = self.base / (repo + "-checkout")
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Source Truth Test"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "source-truth@example.invalid"], check=True)
            for path, data in (self.selected_specs[repo][0], self.selected_specs[repo][2]), self.excluded_specs[repo]:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
            pins[repo] = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            self.roots[repo] = root

        self.manifest: dict = {
            "schema": "mvp-default-branch-commit-corpus-v1",
            "pins": pins,
            "selected": [],
            "excluded": [],
            "event": {
                "kind": "default_branch_commit",
                "source_role": "incoming_default_branch_first_parent",
                "repository": "openwrt",
                "base_commit": "a" * 40,
                "base_tree": "b" * 40,
                "first_parent_commit": "a" * 40,
                "control_commit": "c" * 40,
                "head_commit": pins["openwrt"],
                "head_tree": subprocess.check_output(
                    ["git", "-C", str(self.roots["openwrt"]), "rev-parse", "HEAD^{tree}"],
                    text=True).strip(),
                "policy_base_commit": "d" * 40,
                "route_oracle_script_sha256": hashlib.sha256(
                    Path(routes.__file__).read_bytes()).hexdigest(),
                "selector_script_sha256": hashlib.sha256(
                    Path(selector.__file__).read_bytes()).hexdigest(),
                "policy_sha256": selector.EXPECTED_MANIFESTS["mvp-bounded-corpus-v0.6"],
                "route_oracle_basis": {
                    "producer_pr_head": routes.ROUTE_PRODUCER_PR_HEAD,
                    "extractor_source_sha256": routes.ROUTE_EXTRACTOR_SOURCE_SHA256,
                    "release_equivalence_verified": False,
                },
            },
            "counts": {},
        }
        for repo in verifier.REPOSITORIES:
            source_path, installed_path, data = self.selected_specs[repo]
            git_blob = self._git_blob(repo, source_path)
            self.manifest["selected"].append({
                "repo": repo,
                "source_commit": pins[repo],
                "source_path": source_path,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "git_blob": git_blob,
                "proposed_installed_path": installed_path,
                "expected_route": routes.source_route(source_path, installed_path, data),
            })
            excluded_path, excluded_data = self.excluded_specs[repo]
            self.manifest["excluded"].append({
                "repo": repo,
                "source_path": excluded_path,
                "sha256": hashlib.sha256(excluded_data).hexdigest(),
                "reason": "test fixture; no install mapping",
            })
            if repo == "openwrt":
                self.manifest["excluded"][-1].update(
                    source_commit=pins[repo],
                    git_blob=self._git_blob(repo, excluded_path),
                )
        self.policy = self._make_policy()
        self.policy_raw = (json.dumps(self.policy, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.manifest["event"]["policy_sha256"] = hashlib.sha256(self.policy_raw).hexdigest()
        repo_selected = Counter(row["repo"] for row in self.manifest["selected"])
        classes = Counter(row["expected_route"]["classification"] for row in self.manifest["selected"])
        self.manifest["counts"] = {
            "selected": 3, "excluded": 3,
            "repo_selected": dict(repo_selected),
            "route_classes": dict(classes),
        }
        self._write_inputs()

    def _make_policy(self) -> dict:
        pins = dict(self.manifest["pins"])
        pins["openwrt"] = self.manifest["event"]["policy_base_commit"]
        selected = []
        excluded = []
        for row in self.manifest["selected"]:
            base = dict(row)
            if row["repo"] == "openwrt":
                base["source_commit"] = pins["openwrt"]
            else:
                base["prior_claims"] = ["fixture-history"]
            selected.append(base)
        for row in self.manifest["excluded"]:
            base = dict(row)
            if row["repo"] == "openwrt":
                base["source_commit"] = pins["openwrt"]
            excluded.append(base)
        return {"schema": "mvp-bounded-corpus-v0.6", "pins": pins,
                "selected": selected, "excluded": excluded}

    def _git_blob(self, repo: str, path: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.roots[repo]), "rev-parse", f"HEAD:{path}"],
            text=True).strip()

    def _write_inputs(self) -> None:
        self.manifest_path = self.base / "manifest.json"
        self.coverage_path = self.base / "coverage.json"
        self.routing_path = self.base / "routing.json"
        manifest_raw = (json.dumps(self.manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.manifest_path.write_bytes(manifest_raw)
        covered_selected = []
        for row in self.manifest["selected"]:
            route = row["expected_route"]
            covered_selected.append({
                "repo": row["repo"],
                "source_commit": row["source_commit"],
                "source_path": row["source_path"],
                "source_sha256": row["source_sha256"],
                "git_blob": row["git_blob"],
                "staged_path": row["proposed_installed_path"],
                "route_classification": route["classification"],
                "route_reason": route["reason"],
                "route_status": "plain_route_selected" if route["classification"] == "plain" else "inconclusive",
            })
        decisions = [{
            "installed_path": row["proposed_installed_path"],
            "classification": row["expected_route"]["classification"],
            "reason": row["expected_route"]["reason"],
            "status": "plain_route_selected" if row["expected_route"]["classification"] == "plain" else "inconclusive",
        } for row in self.manifest["selected"]]
        classes = Counter(row["expected_route"]["classification"] for row in self.manifest["selected"])
        self.coverage_path.write_text(json.dumps({
            "schema": "ucode-default-branch-corpus-coverage-v1",
            "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "source_pins": self.manifest["pins"],
            "event": self.manifest["event"],
            "selected": covered_selected,
            "excluded": self.manifest["excluded"],
        }, sort_keys=True), encoding="utf-8")
        self.routing_path.write_text(json.dumps({
            "input_count": len(decisions),
            "plain_count": classes["plain"],
            "markup_count": classes["markup"],
            "markup_inconclusive_count": classes["markup"],
            "uncertain_count": 0,
            "excluded_count": 0,
            "duplicate_input_count": 0,
            "decisions": decisions,
        }, sort_keys=True), encoding="utf-8")

    def _verify(self) -> dict:
        original_read = verifier._read_json

        def read(path: Path, label: str):
            if label == "frozen v0.6 policy":
                return self.policy_raw, self.policy
            return original_read(path, label)

        with (mock.patch.object(verifier, "_read_json", side_effect=read),
              mock.patch.dict(selector.EXPECTED_MANIFESTS,
                              {"mvp-bounded-corpus-v0.6": hashlib.sha256(self.policy_raw).hexdigest()}),
              mock.patch.object(verifier, "_tracked_candidate_census",
                                side_effect=self._fixture_census)):
            return verifier.verify(self.manifest_path, self.coverage_path,
                                   self.routing_path, self.roots)

    def _fixture_census(self, root: Path, pin: str, policy: dict, repo: str):
        del root, pin, policy
        rows = []
        for row in self.manifest["selected"]:
            if row["repo"] != repo:
                continue
            path = row["source_path"]
            data = self.selected_specs[repo][2]
            rows.append({"source_path": path, "git_blob": self._git_blob(repo, path),
                         "sha256": hashlib.sha256(data).hexdigest(), "mode": "100644",
                         "status": "selected", "policy": row})
        seen = set()
        for row in self.manifest["excluded"]:
            if row["repo"] != repo or row["source_path"] in seen:
                continue
            seen.add(row["source_path"])
            path = row["source_path"]
            data = self.excluded_specs[repo][1]
            rows.append({"source_path": path, "git_blob": self._git_blob(repo, path),
                         "sha256": hashlib.sha256(data).hexdigest(), "mode": "100644",
                         "status": "excluded", "policy": row})
        return rows, {"tracked_paths": 4, "tracked_candidate_paths": len(rows),
                      "source_signal_paths": len(rows),
                      "selected_policy_paths": sum(row["status"] == "selected" for row in rows),
                      "excluded_policy_paths": sum(row["status"] == "excluded" for row in rows),
                      "outside_frozen_denominator": 0}

    def test_rederives_three_repo_bytes_and_route_precedence(self) -> None:
        result = self._verify()
        self.assertEqual(result["status"], "bounded_selected_excluded_match")
        self.assertEqual(result["selected_by_repo"], {"luci": 1, "openwrt": 1, "packages": 1})
        self.assertEqual(result["excluded_by_repo"], {"luci": 1, "openwrt": 1, "packages": 1})
        self.assertEqual(result["route_classes"], {"markup": 1, "plain": 2})
        self.assertTrue(result["tracked_candidate_signals_accounted_for"])
        self.assertEqual(result["roots"]["luci"]["observed_blobs"][0]["mode"], "100644")
        self.assertFalse(result["canonical_git_provenance_verified"])
        self.assertFalse(result["signed_live_completion_verified"])

    def test_source_route_is_not_accepted_from_matching_receipts_alone(self) -> None:
        blobs = {}
        for row in self.manifest["selected"]:
            blobs[(row["repo"], row["source_path"])] = self.selected_specs[row["repo"]][2]
        self.manifest["selected"][0]["expected_route"] = {
            "classification": "plain", "reason": "ucode_extension"}
        self._write_inputs()  # Keep coverage and routing mutually consistent with the lie.
        with self.assertRaisesRegex(verifier.SourceTruthError, "source-derived route differs"):
            verifier._verify_routes(self.manifest, json.loads(self.coverage_path.read_text()),
                                    json.loads(self.routing_path.read_text()), blobs)

    def test_hash_mutation_in_source_identity_is_rejected(self) -> None:
        row = next(row for row in self.manifest["selected"] if row["repo"] == "openwrt")
        row["source_sha256"] = "0" * 64
        self._write_inputs()
        with self.assertRaisesRegex(verifier.SourceTruthError, "selector selected source bytes differ"):
            self._verify()

    def test_synchronized_alternate_candidate_cannot_change_frozen_selection(self) -> None:
        row = dict(self.manifest["selected"][0])
        row["source_path"] = "modules/demo/root/usr/share/ucode/alternate.uc"
        self.manifest["selected"].append(row)
        self.manifest["counts"]["selected"] += 1
        self._write_inputs()  # Coverage and route tables now agree with the alternate path.
        with self.assertRaisesRegex(verifier.SourceTruthError, "manifest selected identities differ"):
            self._verify()

    def test_synchronized_ut_rpcd_route_swap_cannot_change_projection(self) -> None:
        row = self.manifest["selected"][0]
        row["proposed_installed_path"] = "usr/share/rpcd/ucode/demo.ut"
        row["expected_route"] = routes.source_route(
            row["source_path"], row["proposed_installed_path"], self.selected_specs["luci"][2])
        self._write_inputs()  # Route/coverage outputs now agree with the swap.
        with self.assertRaisesRegex(verifier.SourceTruthError, "manifest selected policy row differs"):
            self._verify()

    def test_synchronized_exclusion_promotion_cannot_change_frozen_lists(self) -> None:
        excluded = self.manifest["excluded"].pop(0)
        source_path = excluded["source_path"]
        source_data = self.excluded_specs["luci"][1]
        installed = "usr/share/ucode/fixture.uc"
        self.manifest["selected"].append({
            "repo": "luci", "source_commit": self.manifest["pins"]["luci"],
            "source_path": source_path, "source_sha256": excluded["sha256"],
            "git_blob": self._git_blob("luci", source_path),
            "proposed_installed_path": installed,
            "expected_route": routes.source_route(source_path, installed, source_data),
        })
        self.manifest["counts"]["selected"] += 1
        self.manifest["counts"]["excluded"] -= 1
        self._write_inputs()  # Coverage now treats the frozen exclusion as selected.
        with self.assertRaisesRegex(verifier.SourceTruthError, "manifest selected identities differ"):
            self._verify()

    def test_frozen_excluded_near_miss_cannot_be_added_to_coverage(self) -> None:
        self._write_inputs()
        coverage = json.loads(self.coverage_path.read_text())
        excluded = self.manifest["excluded"][0]
        coverage["selected"].append({
            "repo": excluded["repo"], "source_commit": self.manifest["pins"][excluded["repo"]],
            "source_path": excluded["source_path"], "source_sha256": excluded["sha256"],
            "git_blob": self._git_blob(excluded["repo"], excluded["source_path"]),
            "staged_path": "usr/share/ucode/test-near-miss.uc",
        })
        self.coverage_path.write_text(json.dumps(coverage), encoding="utf-8")
        with self.assertRaisesRegex(verifier.SourceTruthError, "selected identity multiplicity differs"):
            self._verify()

    def test_excluded_coverage_compares_optional_commit_and_blob_fields(self) -> None:
        self._write_inputs()
        coverage = json.loads(self.coverage_path.read_text())
        row = next(row for row in coverage["excluded"] if row["repo"] == "openwrt")
        row["git_blob"] = "e" * 40
        self.coverage_path.write_text(json.dumps(coverage), encoding="utf-8")
        with self.assertRaisesRegex(verifier.SourceTruthError, "excluded identity multiplicity differs"):
            self._verify()

    def test_duplicate_excluded_path_is_rejected(self) -> None:
        self.manifest["excluded"].append(dict(self.manifest["excluded"][0]))
        self.manifest["counts"]["excluded"] += 1
        self._write_inputs()
        with self.assertRaisesRegex(verifier.SourceTruthError, "duplicate frozen policy row"):
            self._verify()

    def test_fifo_json_input_is_rejected_without_blocking(self) -> None:
        fifo = self.base / "manifest.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(verifier.SourceTruthError, "not a regular file"):
            verifier._read_json(fifo, "manifest")

    def test_dirty_worktree_does_not_change_pinned_object_observation(self) -> None:
        (self.roots["luci"] / "untracked.txt").write_text("dirty", encoding="utf-8")
        receipt = self._verify()
        self.assertFalse(receipt["roots"]["luci"]["worktree_clean_checked"])
        self.assertEqual(receipt["status"], "bounded_selected_excluded_match")

    def test_routing_tuple_mutation_is_rejected(self) -> None:
        self._write_inputs()
        routing = json.loads(self.routing_path.read_text())
        routing["decisions"][0]["reason"] = "wrong reason"
        self.routing_path.write_text(json.dumps(routing), encoding="utf-8")
        with self.assertRaisesRegex(verifier.SourceTruthError, "routing decision multiplicity differs"):
            self._verify()

    def test_new_unreviewed_candidate_stays_outside_frozen_denominator(self) -> None:
        current, _counts = self._fixture_census(self.roots["luci"], "", {}, "luci")
        near_miss = {
            "source_path": "modules/demo/extra/eligible.uc",
            "git_blob": "1" * 40,
            "sha256": "2" * 64,
            "status": "unreviewed",
        }
        current.append(near_miss)
        counts, unreviewed = verifier._compare_candidate_universe(
            "luci", current, self.manifest["selected"], self.manifest["excluded"])
        self.assertEqual(counts, {"selected": 1, "excluded": 1, "unreviewed": 1})
        self.assertEqual([row["source_path"] for row in unreviewed], [near_miss["source_path"]])

    def test_new_package_tree_candidate_is_reported_without_installability_claim(self) -> None:
        root = self.roots["packages"]
        new_path = "net/demo/newcandidate.uc"
        new_data = b"// tracked source-shaped near miss\n"
        target = root / new_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(new_data)
        subprocess.run(["git", "-C", str(root), "add", new_path], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "new candidate"], check=True)
        pin = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        policy = {"selected": self.manifest["selected"], "excluded": self.manifest["excluded"]}
        inventory, counts = verifier._tracked_candidate_census(root, pin, policy, "packages")
        self.assertEqual(counts["outside_frozen_denominator"], 1)
        candidate = next(row for row in inventory if row["source_path"] == new_path)
        self.assertEqual(candidate["sha256"], hashlib.sha256(new_data).hexdigest())
        self.assertIn("ucode_suffix", candidate["signals"])
        self.assertEqual(candidate["status"], "unreviewed")

    def test_cli_exit_codes_distinguish_match_rejection_and_partial(self) -> None:
        argv = ["--manifest", str(self.manifest_path), "--coverage", str(self.coverage_path),
                "--routing", str(self.routing_path)]
        for repo in verifier.REPOSITORIES:
            argv.extend([f"--{repo}-checkout", str(self.roots[repo])])
        for result, expected in (({"tracked_candidate_signals_accounted_for": True}, 0),
                                 ({"tracked_candidate_signals_accounted_for": False}, 3)):
            with self.subTest(expected=expected), \
                 mock.patch.object(verifier, "verify", return_value=result), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verifier.main(argv), expected)
        with mock.patch.object(verifier, "verify",
                               side_effect=verifier.SourceTruthError("bad input")), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(verifier.main(argv), 2)


if __name__ == "__main__":
    unittest.main()
