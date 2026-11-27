"""Select bounded default-branch tip scans from a completed discovery artifact.

This module does not authenticate GitHub execution or dispatch a workflow.
The caller must verify both run APIs and replay the retained gap first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
POSITIVE = re.compile(r"[1-9][0-9]*\Z")
REPOSITORIES = ("openwrt/openwrt", "openwrt/luci")
MAX_SMALL = 2_000_000


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        require(name not in result, f"duplicate JSON field: {name}")
        result[name] = value
    return result


def read_small(path: Path) -> tuple[bytes, dict]:
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size <= MAX_SMALL,
            f"missing or oversized regular input: {path}")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SMALL + 1)
    require(len(raw) <= MAX_SMALL, f"oversized input: {path}")
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(type(value) is dict, f"input is not an object: {path}")
    return raw, value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_line(path: Path, expected_name: str) -> str:
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 200,
            f"missing or oversized digest file: {path}")
    line = path.read_text().strip()
    match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(expected_name), line)
    require(match is not None, f"invalid digest file: {path}")
    return match.group(1)


def selected_tips(run_input: dict, gap: dict, *, previous_sha256: str,
                  current_sha256: str, gap_sha256: str,
                  current_run_id: str, current_attempt: str) -> dict:
    """Return at most one observed tip per changed upstream repository."""
    require(run_input.get("schema") == "incoming-discovery-run-input-v2" and
            run_input.get("event") == "schedule" and
            run_input.get("genesis") is False and
            run_input.get("scan_dispatched") is False and
            run_input.get("run_id") == current_run_id and
            run_input.get("run_attempt") == current_attempt and
            type(run_input.get("previous_run_id")) is str and
            POSITIVE.fullmatch(run_input["previous_run_id"]) is not None and
            type(run_input.get("previous_run_attempt")) is str and
            POSITIVE.fullmatch(run_input["previous_run_attempt"]) is not None and
            run_input.get("previous_run_event") in ("schedule", "workflow_dispatch") and
            run_input.get("previous_sha256") == previous_sha256 and
            SHA64.fullmatch(previous_sha256) is not None and
            POSITIVE.fullmatch(current_run_id) is not None and
            POSITIVE.fullmatch(current_attempt) is not None,
            "discovery run identity or predecessor differs")
    require(gap.get("schema") == "default-branch-gap-preflight-v1" and
            gap.get("status") == "complete" and
            gap.get("previous_sha256") == previous_sha256 and
            gap.get("current_sha256") == current_sha256 and
            SHA64.fullmatch(gap_sha256) is not None and
            gap.get("http_errors") == [],
            "retained gap status or checkpoint digests differ")
    intervals = gap.get("intervals")
    require(type(intervals) is list and len(intervals) == 2 and
            {row.get("repository") for row in intervals if type(row) is dict}
            == set(REPOSITORIES), "gap does not contain both upstream repositories once")
    scans = []
    for interval in intervals:
        prior, observed = interval.get("prior"), interval.get("observed")
        commits = interval.get("first_parent_commits")
        require(type(prior) is dict and type(observed) is dict and
                type(commits) is list and len(commits) <= 100 and
                type(prior.get("commit")) is str and SHA40.fullmatch(prior["commit"]) and
                type(observed.get("commit")) is str and SHA40.fullmatch(observed["commit"]),
                "invalid observed tip interval")
        if interval.get("state") == "unchanged":
            require(not commits and prior == observed,
                    "unchanged interval has commits or changed tip")
            continue
        require(interval.get("state") == "bounded_fast_forward" and commits and
                prior != observed, "changed tip lacks a bounded first-parent interval")
        previous = prior["commit"]
        for commit in commits:
            require(type(commit) is dict and set(commit) == {"commit", "tree", "first_parent"} and
                    all(type(commit.get(name)) is str and SHA40.fullmatch(commit[name])
                        for name in ("commit", "tree", "first_parent")) and
                    commit["first_parent"] == previous and
                    commit["commit"] != previous,
                    "first-parent gap chain differs")
            previous = commit["commit"]
        tip = commits[-1]
        require(tip["commit"] == observed["commit"] and
                tip["tree"] == observed.get("tree"),
                "selected tip differs from observed source")
        scans.append({
            "repository": interval["repository"],
            "source_sha": tip["commit"],
            "control_sha": tip["first_parent"],
            "previous_run_id": run_input["previous_run_id"],
            "previous_run_attempt": run_input["previous_run_attempt"],
            "previous_sha256": previous_sha256,
            "current_run_id": current_run_id,
            "current_run_attempt": current_attempt,
            "current_sha256": current_sha256,
            "gap_sha256": gap_sha256,
        })
    return {
        "schema": "ci-first-scheduled-tip-dispatch-plan-v1",
        "status": "planned" if scans else "no_changed_tips",
        "scope": "latest observed default-branch tip per changed repository only",
        "scans": scans,
        "limits": [
            "Only scheduled, completed discovery artifacts are eligible.",
            "Intermediate commits are not scanned separately by this plan.",
            "The downstream released scan must independently revalidate every input.",
        ],
    }


def prepare(current: Path, previous: Path, current_run_id: str,
            current_attempt: str) -> dict:
    run_raw, run_input = read_small(current / "run-input.json")
    gap_raw, gap = read_small(current / "gap/gap.json")
    decision_paths = (current / "decisions.json", previous / "decisions.json")
    require(all(path.is_file() and not path.is_symlink() and
                path.stat().st_size <= 64_000_000 for path in decision_paths),
            "discovery checkpoint is absent or oversized")
    current_decisions, previous_decisions = (path.read_bytes() for path in decision_paths)
    require(len(current_decisions) <= 64_000_000 and
            len(previous_decisions) <= 64_000_000,
            "discovery checkpoint exceeds byte bound")
    current_sha = sha256(current_decisions)
    previous_sha = sha256(previous_decisions)
    gap_sha = sha256(gap_raw)
    require(digest_line(current / "decisions.sha256",
                        "discovery-output/decisions.json") == current_sha and
            digest_line(current / "gap/gap.sha256",
                        "discovery-output/gap/gap.json") == gap_sha and
            run_input["previous_sha256"] == previous_sha,
            "retained checkpoint digest files differ")
    result = selected_tips(run_input, gap, previous_sha256=previous_sha,
                           current_sha256=current_sha, gap_sha256=gap_sha,
                           current_run_id=current_run_id,
                           current_attempt=current_attempt)
    result["run_input_sha256"] = sha256(run_raw)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        plan = prepare(args.current, args.previous, args.run_id, args.attempt)
        with args.output.open("x") as stream:
            json.dump(plan, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print(json.dumps({"status": plan["status"], "scan_count": len(plan["scans"])}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print(f"scheduled-tip plan rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
