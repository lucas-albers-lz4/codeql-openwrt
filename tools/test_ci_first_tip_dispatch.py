"""Source-first controls for the scheduled tip-only dispatch plan."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.ci_first_tip_dispatch import prepare, read_small, selected_tips

A, B, C = "a" * 40, "b" * 40, "c" * 40
P, Q, R = "1" * 64, "2" * 64, "3" * 64


def fixture():
    run = {
        "schema": "incoming-discovery-run-input-v2", "event": "schedule",
        "genesis": False, "scan_dispatched": False,
        "run_id": "20", "run_attempt": "1", "previous_run_id": "19",
        "previous_run_attempt": "1", "previous_run_event": "workflow_dispatch",
        "previous_sha256": P,
    }
    gap = {
        "schema": "default-branch-gap-preflight-v1", "status": "complete",
        "previous_sha256": P, "current_sha256": Q, "http_errors": [],
        "intervals": [
            {"repository": "openwrt/openwrt", "state": "bounded_fast_forward",
             "prior": {"commit": A, "tree": A},
             "observed": {"commit": C, "tree": C},
             "first_parent_commits": [
                 {"commit": B, "tree": B, "first_parent": A},
                 {"commit": C, "tree": C, "first_parent": B},
             ]},
            {"repository": "openwrt/luci", "state": "unchanged",
             "prior": {"commit": B, "tree": B},
             "observed": {"commit": B, "tree": B},
             "first_parent_commits": []},
        ],
    }
    return run, gap


def choose(run, gap):
    return selected_tips(run, gap, previous_sha256=P, current_sha256=Q,
                         gap_sha256=R, current_run_id="20", current_attempt="1")


class TipDispatchTests(unittest.TestCase):
    def test_latest_tip_only_and_parent_control(self):
        run, gap = fixture()
        result = choose(run, gap)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["scans"], [{
            "repository": "openwrt/openwrt", "source_sha": C,
            "control_sha": B, "previous_run_id": "19",
            "previous_run_attempt": "1", "previous_sha256": P,
            "current_run_id": "20", "current_run_attempt": "1",
            "current_sha256": Q, "gap_sha256": R,
        }])

    def test_unchanged_pair_has_no_dispatch(self):
        run, gap = fixture()
        gap["intervals"][0] = copy.deepcopy(gap["intervals"][1])
        gap["intervals"][0]["repository"] = "openwrt/openwrt"
        self.assertEqual(choose(run, gap)["status"], "no_changed_tips")

    def test_manual_discovery_is_ineligible(self):
        run, gap = fixture()
        run["event"] = "workflow_dispatch"
        with self.assertRaisesRegex(ValueError, "discovery run identity"):
            choose(run, gap)

    def test_changed_checkpoint_digest_rejects(self):
        run, gap = fixture()
        gap["current_sha256"] = R
        with self.assertRaisesRegex(ValueError, "checkpoint digests"):
            choose(run, gap)

    def test_truncated_parent_chain_rejects(self):
        run, gap = fixture()
        gap["intervals"][0]["first_parent_commits"].pop(0)
        with self.assertRaisesRegex(ValueError, "first-parent"):
            choose(run, gap)

    def test_unobserved_tip_rejects(self):
        run, gap = fixture()
        gap["intervals"][0]["observed"]["commit"] = A
        with self.assertRaisesRegex(ValueError, "selected tip"):
            choose(run, gap)

    def test_duplicate_repository_rejects(self):
        run, gap = fixture()
        gap["intervals"][1]["repository"] = "openwrt/openwrt"
        with self.assertRaisesRegex(ValueError, "both upstream"):
            choose(run, gap)

    def test_unverified_dispatch_claim_rejects(self):
        run, gap = fixture()
        run["scan_dispatched"] = True
        with self.assertRaisesRegex(ValueError, "discovery run identity"):
            choose(run, gap)

    def test_retained_checkpoint_digest_and_symlink_controls(self):
        run, gap = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, previous = root / "current", root / "previous"
            (current / "gap").mkdir(parents=True)
            previous.mkdir()
            current_decisions, previous_decisions = b'{"current":true}\n', b'{"previous":true}\n'
            current_sha = hashlib.sha256(current_decisions).hexdigest()
            previous_sha = hashlib.sha256(previous_decisions).hexdigest()
            run["previous_sha256"] = previous_sha
            gap["previous_sha256"], gap["current_sha256"] = previous_sha, current_sha
            gap_raw = (json.dumps(gap, sort_keys=True) + "\n").encode()
            gap_sha = hashlib.sha256(gap_raw).hexdigest()
            (current / "run-input.json").write_text(json.dumps(run) + "\n")
            (current / "decisions.json").write_bytes(current_decisions)
            (previous / "decisions.json").write_bytes(previous_decisions)
            (current / "gap/gap.json").write_bytes(gap_raw)
            (current / "decisions.sha256").write_text(
                f"{current_sha}  discovery-output/decisions.json\n")
            (current / "gap/gap.sha256").write_text(
                f"{gap_sha}  discovery-output/gap/gap.json\n")
            result = prepare(current, previous, "20", "1")
            self.assertEqual(result["scans"][0]["source_sha"], C)
            (current / "decisions.sha256").write_text(
                f"{previous_sha}  discovery-output/decisions.json\n")
            with self.assertRaisesRegex(ValueError, "digest files differ"):
                prepare(current, previous, "20", "1")
            (current / "decisions.sha256").write_text(
                f"{current_sha}  discovery-output/decisions.json\n")
            (current / "decisions.json").unlink()
            (current / "decisions.json").symlink_to(previous / "decisions.json")
            with self.assertRaisesRegex(ValueError, "absent or oversized"):
                prepare(current, previous, "20", "1")

    def test_duplicate_run_input_field_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "run-input.json"
            path.write_text('{"event":"schedule","event":"workflow_dispatch"}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                read_small(path)


if __name__ == "__main__":
    unittest.main()
