#!/usr/bin/env python3
"""Resolve an explicitly pinned upstream event and clean control checkout.

This is an identity/preflight check only. It does not discover PRs, select a
dynamic source corpus, or run CodeQL.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import sys

REPOSITORIES = {
    "openwrt": "https://github.com/openwrt/openwrt.git",
    "luci": "https://github.com/openwrt/luci.git",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")


class InvalidEvent(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidEvent(message)


def git(path: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), *args], text=True, stderr=subprocess.PIPE
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise InvalidEvent(f"git {' '.join(args)} failed: {exc.stderr.strip()}") from exc


def canonical_repository(path: Path, expected: str) -> None:
    urls = git(path, "remote", "get-url", "--all", "origin").splitlines()
    normalized = {u.removesuffix("/").removesuffix(".git") for u in urls}
    canonical = expected.removesuffix(".git")
    require(normalized == {canonical}, f"checkout origin does not match {expected}")


def commit_identity(path: Path, sha: str) -> dict[str, str]:
    require(bool(SHA.fullmatch(sha)), "commit must be a full 40-character lowercase SHA")
    commit = git(path, "rev-parse", "--verify", f"{sha}^{{commit}}")
    require(commit == sha, "resolved commit differs from requested SHA")
    require(git(path, "rev-parse", "HEAD") == sha, "checkout HEAD differs from requested SHA")
    require(not git(path, "status", "--porcelain=v1"), "checkout is dirty")
    return {"commit": commit, "tree": git(path, "rev-parse", f"{commit}^{{tree}}")}


def validate(event: dict, api_pr: dict, source_checkout: Path,
             control_checkout: Path) -> dict:
    require(event.get("schema") == "incoming-event-v1", "unsupported event schema")
    repo = event.get("repository")
    require(repo in REPOSITORIES, "repository must be openwrt or luci")
    require(event.get("event_type") == "manual_sha_drill", "unsupported event type")
    pr = event.get("pr_number")
    require(isinstance(pr, int) and not isinstance(pr, bool) and pr > 0,
            "pr_number must be a positive integer")
    require(isinstance(api_pr, dict), "GitHub pull API response must be an object")
    require(api_pr.get("number") == pr, "GitHub pull response number mismatch")
    require(api_pr.get("state") == "open", "GitHub pull request is not open")
    base = api_pr.get("base")
    head = api_pr.get("head")
    require(isinstance(base, dict) and isinstance(base.get("repo"), dict),
            "GitHub pull response has no base repository")
    require(isinstance(head, dict) and isinstance(head.get("repo"), dict),
            "GitHub pull response has no head repository")
    base_repo = base["repo"].get("full_name")
    head_repo = head["repo"].get("full_name")
    head_fork = head["repo"].get("fork")
    head_sha = head.get("sha")
    expected_full_name = REPOSITORIES[repo].removeprefix("https://github.com/").removesuffix(".git")
    require(isinstance(base_repo, str) and base_repo.lower() == expected_full_name,
            "GitHub pull base repository does not match selected upstream")
    require(isinstance(head_repo, str) and head_repo and isinstance(head_fork, bool),
            "GitHub pull head repository identity is missing or malformed")
    require(head_repo.lower() == expected_full_name or head_fork,
            "cross-repository PR head is not identified as a fork")
    require(isinstance(head_sha, str) and bool(SHA.fullmatch(head_sha)),
            "GitHub pull response head SHA is not a full commit SHA")
    require(event.get("source_sha") == head_sha,
            "event source SHA disagrees with GitHub pull response")
    event_time = event.get("event_time")
    require(isinstance(event_time, str), "event_time must be an ISO-8601 timestamp")
    try:
        parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidEvent("event_time must be an ISO-8601 timestamp") from exc
    require(parsed_time.tzinfo is not None, "event_time must include a timezone")
    control_sha = event.get("control_sha", "")
    require(head_sha != control_sha, "source and clean control must differ")
    canonical_repository(source_checkout, REPOSITORIES[repo])
    canonical_repository(control_checkout, REPOSITORIES[repo])
    source = commit_identity(source_checkout, head_sha)
    control = commit_identity(control_checkout, control_sha)
    return {
        "schema": "incoming-event-receipt-v1",
        "repository": repo,
        "repository_url": REPOSITORIES[repo],
        "pr_number": pr,
        "base_repository": base_repo,
        "head_repository": head_repo,
        "head_repository_is_fork": head_fork,
        "event_type": event["event_type"],
        "event_time": event_time,
        "source": source,
        "control": control,
        "status": "identities_resolved_only",
        "limitations": [
            "PR membership is bound to the captured GitHub pull response and fetched PR head ref; it is not a scan result.",
            "No source-policy discovery, CodeQL execution, SARIF, or consumer handoff is performed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path, help="pinned event JSON")
    parser.add_argument("pull_api_response", type=Path, help="exact GitHub pull API JSON")
    parser.add_argument("source_checkout", type=Path,
                        help="checkout of refs/pull/<number>/head from canonical upstream")
    parser.add_argument("control_checkout", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    try:
        event = json.loads(args.event.read_text())
        api_pr = json.loads(args.pull_api_response.read_text())
        receipt = validate(event, api_pr, args.source_checkout, args.control_checkout)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, InvalidEvent) as exc:
        print(f"incoming event rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
