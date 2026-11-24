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


def validate(event: dict, source_checkout: Path, control_checkout: Path) -> dict:
    require(event.get("schema") == "incoming-event-v1", "unsupported event schema")
    repo = event.get("repository")
    require(repo in REPOSITORIES, "repository must be openwrt or luci")
    require(event.get("event_type") == "manual_sha_drill", "unsupported event type")
    pr = event.get("pr_number")
    require(isinstance(pr, int) and not isinstance(pr, bool) and pr > 0,
            "pr_number must be a positive integer")
    event_time = event.get("event_time")
    require(isinstance(event_time, str), "event_time must be an ISO-8601 timestamp")
    try:
        parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidEvent("event_time must be an ISO-8601 timestamp") from exc
    require(parsed_time.tzinfo is not None, "event_time must include a timezone")
    source_sha, control_sha = event.get("source_sha", ""), event.get("control_sha", "")
    require(source_sha != control_sha, "source and clean control must differ")
    canonical_repository(source_checkout, REPOSITORIES[repo])
    canonical_repository(control_checkout, REPOSITORIES[repo])
    source = commit_identity(source_checkout, source_sha)
    control = commit_identity(control_checkout, control_sha)
    return {
        "schema": "incoming-event-receipt-v1",
        "repository": repo,
        "repository_url": REPOSITORIES[repo],
        "pr_number": pr,
        "event_type": event["event_type"],
        "event_time": event_time,
        "source": source,
        "control": control,
        "status": "identities_resolved_only",
        "limitations": [
            "PR membership is not authenticated by this offline resolver.",
            "No source-policy discovery, CodeQL execution, SARIF, or consumer handoff is performed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path, help="pinned event JSON")
    parser.add_argument("source_checkout", type=Path)
    parser.add_argument("control_checkout", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    try:
        event = json.loads(args.event.read_text())
        receipt = validate(event, args.source_checkout, args.control_checkout)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, InvalidEvent) as exc:
        print(f"incoming event rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
