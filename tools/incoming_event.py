#!/usr/bin/env python3
"""Resolve an explicitly pinned upstream event and clean control checkout.

This is an identity/preflight check only. It does not discover PRs, select a
dynamic source corpus, or run CodeQL.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPOSITORIES = {
    "openwrt": "https://github.com/openwrt/openwrt.git",
    "luci": "https://github.com/openwrt/luci.git",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
FETCH_TIMEOUT_SECONDS = 60


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


def _fetch_commit_identity(url: str, sha: str, protocol: str) -> dict[str, str]:
    """Fetch one object in an empty repository with no inherited Git config.

    The caller chooses the URL and allowed transport. Production passes only
    REPOSITORIES[repo] and HTTPS; tests exercise the same commands with file://.
    """
    require(bool(SHA.fullmatch(sha)), "base commit must be a full 40-character lowercase SHA")
    with tempfile.TemporaryDirectory(prefix="incoming-base-") as temporary:
        root = Path(temporary)
        repository = root / "objects.git"
        template = root / "empty-template"
        template.mkdir()
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TEMPLATE_DIR": str(template),
            "GIT_TERMINAL_PROMPT": "0",
        })

        def run(*args: str) -> str:
            command = ["git", "-c", "protocol.allow=never",
                       "-c", f"protocol.{protocol}.allow=always",
                       "-c", "http.followRedirects=false", *args]
            try:
                result = subprocess.run(command, env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        check=True, timeout=FETCH_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as exc:
                raise InvalidEvent("canonical base Git lookup timed out") from exc
            except (OSError, subprocess.CalledProcessError) as exc:
                detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
                raise InvalidEvent(f"canonical base Git lookup failed: {detail}") from exc
            return result.stdout.strip()

        run("init", "--bare", "-q", str(repository))
        run("-C", str(repository), "fetch", "--no-tags", "--depth=1", url, sha)
        commit = run("-C", str(repository), "rev-parse", "--verify", f"{sha}^{{commit}}")
        require(commit == sha, "fetched base commit differs from requested SHA")
        tree = run("-C", str(repository), "rev-parse", "--verify", f"{sha}^{{tree}}")
        require(bool(SHA.fullmatch(tree)), "fetched base tree is not a full SHA")
        return {"commit": commit, "tree": tree}


def fetch_base_identity(repo: str, sha: str) -> dict[str, str]:
    return _fetch_commit_identity(REPOSITORIES[repo], sha, "https")


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
    base_sha = base.get("sha")
    expected_full_name = REPOSITORIES[repo].removeprefix("https://github.com/").removesuffix(".git")
    require(isinstance(base_repo, str) and base_repo.lower() == expected_full_name,
            "GitHub pull base repository does not match selected upstream")
    require(isinstance(head_repo, str) and head_repo and isinstance(head_fork, bool),
            "GitHub pull head repository identity is missing or malformed")
    # GitHub can report fork=false for a valid cross-repository pull head.
    # PR membership is established by the canonical pull response and fetched
    # refs/pull/<number>/head, not by this repository metadata flag.
    require(isinstance(head_sha, str) and bool(SHA.fullmatch(head_sha)),
            "GitHub pull response head SHA is not a full commit SHA")
    require(event.get("source_sha") == head_sha,
            "event source SHA disagrees with GitHub pull response")
    require(isinstance(base_sha, str) and bool(SHA.fullmatch(base_sha)),
            "GitHub pull response base SHA is not a full commit SHA")
    require(event.get("base_sha") == base_sha,
            "event base SHA disagrees with GitHub pull response")
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
    base_identity = fetch_base_identity(repo, base_sha)
    require(isinstance(base_identity, dict) and base_identity.get("commit") == base_sha and
            isinstance(base_identity.get("tree"), str) and
            bool(SHA.fullmatch(base_identity["tree"])),
            "canonical base commit or tree differs from requested identity")
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
        "base": base_identity,
        "control": control,
        "status": "identities_resolved_only",
        "limitations": [
            "PR membership is bound to the captured GitHub pull response and fetched PR head ref; it is not a scan result.",
            "Base commit and tree were fetched from the canonical upstream URL; this does not re-fetch the PR API response.",
            "No source-policy discovery, CodeQL execution, SARIF, or consumer handoff is performed by this resolver.",
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
