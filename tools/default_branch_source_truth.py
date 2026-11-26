#!/usr/bin/env python3
"""Read-only source-byte and route rederivation for a frozen corpus receipt.

Checkout roots and JSON inputs are supplied observations. This tool checks
their internal consistency and pinned Git tree bytes; it does not attest
canonical Git provenance or authenticate a scan, signature, or completion.
"""
from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import threading
import stat
import subprocess
import sys
from typing import Any

from tools import event_corpus_manifest as route_oracle
from tools import full_tree_candidates as selector


REPOSITORIES = ("luci", "openwrt", "packages")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_GIT_STDOUT = 2 * 1024 * 1024
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR = 128 * 1024
MAX_BLOB_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BLOB_BYTES = 32 * 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 30


class SourceTruthError(ValueError):
    """Input, Git-object, or contract mismatch."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise SourceTruthError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        need(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        if path.is_symlink():
            raise SourceTruthError(f"{label} input is a symlink")
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            need(stat.S_ISREG(info.st_mode), f"{label} input is not a regular file")
            need(info.st_size <= MAX_JSON_BYTES, f"{label} input exceeds byte limit")
            raw = handle.read(MAX_JSON_BYTES + 1)
        need(len(raw) <= MAX_JSON_BYTES, f"{label} input exceeds byte limit")
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except SourceTruthError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SourceTruthError(f"cannot read {label} JSON: {exc}") from exc
    need(isinstance(document, dict), f"{label} JSON is not an object")
    return raw, document


def _git_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env.update({
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_PAGER": "cat",
    })
    return env


def _git(root: Path, *args: str, max_stdout: int = MAX_GIT_STDOUT,
         allowed_returncodes: tuple[int, ...] = (0,)) -> bytes:
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
               "-c", "core.attributesFile=/dev/null", "--no-pager", "-C", str(root), *args]
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=_git_environment())
    except OSError as exc:
        raise SourceTruthError(f"cannot execute local Git command: {exc}") from exc
    assert proc.stdout is not None and proc.stderr is not None
    output: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    overflow: list[str] = []
    limits = {"stdout": max_stdout, "stderr": MAX_GIT_STDERR}

    def drain(name: str, stream: Any) -> None:
        while True:
            remaining = limits[name] + 1 - len(output[name])
            chunk = stream.read(min(64 * 1024, max(1, remaining)))
            if not chunk:
                return
            output[name].extend(chunk)
            if len(output[name]) > limits[name]:
                overflow.append(name)
                try:
                    proc.kill()
                except OSError:
                    pass
                return

    readers = [threading.Thread(target=drain, args=("stdout", proc.stdout), daemon=True),
               threading.Thread(target=drain, args=("stderr", proc.stderr), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        returncode = proc.wait(timeout=GIT_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait()
        for reader in readers:
            reader.join(timeout=1)
        raise SourceTruthError("local Git command exceeded time limit") from exc
    for reader in readers:
        reader.join(timeout=1)
    for stream in (proc.stdout, proc.stderr):
        stream.close()
    if overflow:
        raise SourceTruthError(f"Git {overflow[0]} exceeds verifier byte limit")
    stdout, stderr = bytes(output["stdout"]), bytes(output["stderr"])
    if returncode not in allowed_returncodes:
        detail = stderr.decode("utf-8", "replace").strip()
        raise SourceTruthError(f"local Git command failed ({returncode}): {detail}")
    return stdout


def _git_text(root: Path, *args: str) -> str:
    return _git(root, *args, max_stdout=64 * 1024).decode("utf-8", "strict").strip()


def _validate_source_path(value: Any) -> str:
    need(isinstance(value, str) and value != "", "source path is missing")
    need("\x00" not in value and "\\" not in value and not value.startswith("/"),
         f"unsafe source path: {value!r}")
    need(all(part not in ("", ".", "..") for part in value.split("/")),
         f"unsafe source path: {value!r}")
    PurePosixPath(value)  # Enforce the intended POSIX interpretation.
    return value


def _sha(value: Any, label: str, *, blob: bool = False) -> str:
    pattern = HEX40 if blob else HEX64
    need(isinstance(value, str) and pattern.fullmatch(value) is not None,
         f"invalid {label}")
    return value


def _git_blob_oid(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _counter_equal(left: Counter, right: Counter, label: str) -> None:
    need(left == right, f"{label} multiplicity differs")


def _canonical_row(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compare_candidate_universe(repo: str, candidates: list[dict[str, Any]],
                                selected: list[dict[str, Any]],
                                excluded: list[dict[str, Any]]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """Compare selected/excluded identities and return unreviewed candidates."""
    by_status: dict[str, dict[str, dict[str, Any]]] = {
        "selected": {}, "excluded": {}, "unreviewed": {}}
    for entry in candidates:
        path = _validate_source_path(entry.get("source_path"))
        status = entry.get("status")
        need(status in by_status, f"unknown selector status for {repo}:{path}")
        need(path not in by_status[status], f"duplicate selector path: {repo}:{path}")
        by_status[status][path] = entry
    expected_selected = {row["source_path"]: row for row in selected if row["repo"] == repo}
    expected_excluded = {row["source_path"]: row for row in excluded if row["repo"] == repo}
    need(set(by_status["selected"]) == set(expected_selected),
         f"selected source universe differs for {repo}")
    need(set(by_status["excluded"]) == set(expected_excluded),
         f"excluded source universe differs for {repo}")
    for path, entry in by_status["selected"].items():
        row = expected_selected[path]
        need(entry["git_blob"] == row["git_blob"] and
             entry["sha256"] == row["source_sha256"],
             f"selector selected source bytes differ: {repo}:{path}")
    for path, entry in by_status["excluded"].items():
        row = expected_excluded[path]
        expected_sha = row.get("source_sha256", row.get("sha256"))
        need(entry["sha256"] == expected_sha,
             f"selector excluded source bytes differ: {repo}:{path}")
        if "git_blob" in row:
            need(entry["git_blob"] == row["git_blob"],
                 f"selector excluded Git blob differs: {repo}:{path}")
        policy_row = entry.get("policy")
        if isinstance(policy_row, dict) and "reason" in policy_row:
            need(row.get("reason") == policy_row["reason"],
                 f"excluded policy reason differs: {repo}:{path}")
    unreviewed = [by_status["unreviewed"][path] for path in sorted(by_status["unreviewed"])]
    return ({"selected": len(by_status["selected"]),
             "excluded": len(by_status["excluded"]),
             "unreviewed": len(unreviewed)}, unreviewed)


def _tracked_candidate_census(root: Path, pin: str, policy: dict[str, Any], repo: str
                              ) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Recompute tracked-tree source signals using bounded local Git reads."""
    raw = _git(root, "ls-tree", "-r", "-z", "--full-tree", pin,
               max_stdout=MAX_TREE_BYTES)
    tracked: dict[str, dict[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, path_bytes = record.split(b"\t", 1)
            mode, kind, oid = meta.decode("ascii").split()
            path = path_bytes.decode("utf-8", "surrogateescape")
        except (ValueError, UnicodeError) as exc:
            raise SourceTruthError("malformed tracked-tree record") from exc
        if kind == "commit" and mode == "160000":
            continue
        need(kind == "blob" and HEX40.fullmatch(oid) is not None,
             f"unexpected tracked-tree entry: {path!r}")
        tracked[path] = {"mode": mode, "git_blob": oid, "kind": kind}

    repo_selected = {row["source_path"]: row for row in policy.get("selected", [])
                     if row.get("repo") == repo}
    repo_excluded = {row["source_path"]: row for row in policy.get("excluded", [])
                     if row.get("repo") == repo}
    need(set(repo_selected) | set(repo_excluded) <= set(tracked),
         f"frozen {repo} policy identity is absent from tracked tree")
    grep = _git(root, "grep", "-I", "-l", "-z", "-E", "-e",
                r"^#!.*[Uu][Cc][Oo][Dd][Ee]", pin, "--",
                max_stdout=MAX_TREE_BYTES, allowed_returncodes=(0, 1))
    prefix = pin.encode("ascii") + b":"
    shebang_paths: set[str] = set()
    for record in grep.split(b"\0"):
        if not record:
            continue
        path_bytes = record[len(prefix):] if record.startswith(prefix) else record
        shebang_paths.add(path_bytes.decode("utf-8", "surrogateescape"))

    installed_roots = ("usr/share/ucode/", "usr/share/rpcd/ucode/", "usr/lib/ucode/")
    root_parts = [tuple(value.rstrip("/").split("/")) for value in installed_roots]
    suffixes = (".uc", ".ucode", ".ut")
    candidate_paths: set[str] = set(repo_selected) | set(repo_excluded)
    for path, _entry in tracked.items():
        name = PurePosixPath(path).name
        parts = tuple(PurePosixPath(path).parts)
        suffix = name.endswith(suffixes)
        under_ucode_root = any(
            any(parts[index:index + len(root)] == root
                for index in range(len(parts) - len(root) + 1))
            for root in root_parts)
        if suffix or under_ucode_root or path in shebang_paths:
            candidate_paths.add(path)

    need(candidate_paths <= set(tracked), f"candidate path absent from {repo} tracked tree")
    blobs = _read_blobs(root, [tracked[path]["git_blob"] for path in sorted(candidate_paths)])
    inventory: list[dict[str, Any]] = []
    for path in sorted(candidate_paths):
        entry = tracked[path]
        data = blobs[entry["git_blob"]]
        need(_git_blob_oid(data) == entry["git_blob"],
             f"Git blob ID does not match source bytes: {repo}:{path}")
        name = PurePosixPath(path).name
        signals = []
        if name.endswith(suffixes):
            signals.append("ucode_suffix")
        if entry["mode"] != "120000" and path in shebang_paths:
            first = data.splitlines()[:1]
            if first and first[0].startswith(b"#!") and b"ucode" in first[0].lower():
                signals.append("first_line_ucode_shebang")
        parts = tuple(PurePosixPath(path).parts)
        under_ucode_root = any(
            any(parts[index:index + len(root)] == root
                for index in range(len(parts) - len(root) + 1))
            for root in root_parts)
        if under_ucode_root:
            signals.append("installed_ucode_root" if "." in name
                           else "extensionless_installed_ucode_root")
        baseline = repo_selected.get(path) or repo_excluded.get(path)
        if not signals and baseline is None:
            continue
        status = "selected" if path in repo_selected else "excluded" if path in repo_excluded else "unreviewed"
        reviewed_excluded_link = (entry["mode"] == "120000" and path in repo_excluded and
                                  repo_excluded[path].get("reason") ==
                                  "tracked symlink; target not followed")
        if repo in ("luci", "openwrt"):
            need(entry["mode"] in ("100644", "100755") or reviewed_excluded_link,
                 f"frozen-selector candidate is not a regular file: {repo}:{path}")
        elif status == "selected":
            need(entry["mode"] in ("100644", "100755"),
                 f"selected package source is not a regular file: {path}")
        inventory.append({
            "source_path": path,
            "git_blob": entry["git_blob"],
            "sha256": hashlib.sha256(data).hexdigest(),
            "mode": entry["mode"],
            "signals": signals,
            "explicit_policy": baseline is not None,
            "status": status,
            "policy": baseline,
        })
    counts = {
        "tracked_paths": len(tracked),
        "tracked_candidate_paths": len(inventory),
        "source_signal_paths": sum(bool(row["signals"]) for row in inventory),
        "selected_policy_paths": sum(row["status"] == "selected" for row in inventory),
        "excluded_policy_paths": sum(row["status"] == "excluded" for row in inventory),
        "outside_frozen_denominator": sum(row["status"] == "unreviewed" for row in inventory),
    }
    return inventory, counts


def _prepare_root(repo: str, supplied: Path, pin: str,
                  seen_roots: set[str], seen_common_dirs: set[str]) -> tuple[Path, dict[str, Any]]:
    try:
        if supplied.is_symlink():
            raise SourceTruthError(f"{repo} checkout root is a symlink")
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise SourceTruthError(f"cannot resolve {repo} checkout root: {exc}") from exc
    need(root.is_dir(), f"{repo} checkout root is not a directory")
    root_text = str(root)
    need(root_text not in seen_roots, "checkout roots must be distinct")
    seen_roots.add(root_text)
    top = Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve()
    need(top == root, f"{repo} input is not the checkout root")
    common_dir = Path(_git_text(root, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    common_text = str(common_dir)
    need(common_text not in seen_common_dirs, "checkout Git common directories must be distinct")
    seen_common_dirs.add(common_text)
    head = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    need(HEX40.fullmatch(head) is not None and head == pin,
         f"{repo} checkout HEAD differs from frozen pin")
    tree = _git_text(root, "rev-parse", "--verify", f"{pin}^{{tree}}")
    need(HEX40.fullmatch(tree) is not None, f"{repo} pinned tree is unavailable")
    return root, {
        "checkout_head": head,
        "checkout_tree": tree,
        "worktree_clean_checked": False,
        "root_supplied_by_caller": True,
        "canonical_git_provenance_verified": False,
    }


def _tree_entries(root: Path, pin: str, paths: list[str]) -> dict[str, dict[str, str]]:
    pathspecs = [":(literal)" + path for path in paths]
    raw = _git(root, "ls-tree", "-z", "--full-tree", pin, "--", *pathspecs)
    entries: dict[str, dict[str, str]] = {}
    wanted = set(paths)
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, path_bytes = record.split(b"\t", 1)
            mode, kind, oid = meta.decode("ascii").split()
            path = path_bytes.decode("utf-8", "strict")
        except (ValueError, UnicodeError) as exc:
            raise SourceTruthError("malformed Git tree entry") from exc
        if path not in wanted:
            continue
        need(path not in entries, f"duplicate Git tree path: {path}")
        need(kind == "blob" and HEX40.fullmatch(oid) is not None,
             f"source identity is not a blob: {path}")
        entries[path] = {"mode": mode, "git_blob": oid}
    missing = wanted - set(entries)
    if missing:
        raise SourceTruthError("source path absent from pinned Git tree: " + sorted(missing)[0])
    return entries


def _read_blobs(root: Path, blobs: list[str]) -> dict[str, bytes]:
    unique_blobs = sorted(set(blobs))
    result: dict[str, bytes] = {}
    total = 0
    for oid in unique_blobs:
        need(HEX40.fullmatch(oid) is not None, "invalid Git blob identifier")
        data = _git(root, "cat-file", "blob", oid, max_stdout=MAX_BLOB_BYTES)
        total += len(data)
        need(total <= MAX_TOTAL_BLOB_BYTES, "Git blobs exceed total byte limit")
        result[oid] = data
    return result


def _selected_identity(row: dict[str, Any]) -> tuple[str, ...]:
    return (row["repo"], row["source_commit"], row["source_path"],
            row["source_sha256"], row["git_blob"], row["proposed_installed_path"])


def _coverage_identity(row: dict[str, Any]) -> tuple[str, ...]:
    return (row["repo"], row["source_commit"], row["source_path"],
            row["source_sha256"], row["git_blob"], row["staged_path"])


def _expected_route_tuple(row: dict[str, Any]) -> tuple[str, ...]:
    route = row["expected_route"]
    classification = route["classification"]
    status = "plain_route_selected" if classification == "plain" else "inconclusive"
    return (*_selected_identity(row)[:5], row["proposed_installed_path"],
            classification, route["reason"], status)


def _coverage_route_tuple(row: dict[str, Any]) -> tuple[str, ...]:
    return (*_coverage_identity(row), row["route_classification"],
            row["route_reason"], row["route_status"])


def _excluded_identity(row: dict[str, Any]) -> tuple[str, ...]:
    return (row["repo"], row["source_path"], row["sha256"], row["reason"])


def _policy_row_map(rows: Any, collection: str) -> dict[tuple[str, str], dict[str, Any]]:
    need(isinstance(rows, list), f"frozen policy {collection} rows are missing")
    mapped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        need(isinstance(row, dict) and row.get("repo") in REPOSITORIES,
             f"frozen policy {collection} row is malformed")
        path = _validate_source_path(row.get("source_path"))
        key = (row["repo"], path)
        need(key not in mapped, f"duplicate frozen policy row: {collection}:{key}")
        mapped[key] = row
    return mapped


def _strip_policy_history(row: dict[str, Any]) -> dict[str, Any]:
    historical = {"prior_claims", "prior_local_extraction", "route_support", "source_oracle"}
    return {key: value for key, value in row.items() if key not in historical}


def _bind_manifest_to_policy(policy: dict[str, Any], manifest: dict[str, Any],
                             event: dict[str, Any]) -> str:
    """Bind row selection/projections to v0.6, allowing only builder event deltas."""
    need(policy.get("schema") == "mvp-bounded-corpus-v0.6",
         "unsupported frozen policy schema")
    event_repo = event.get("repository")
    need(event_repo in ("luci", "openwrt"), "unsupported event repository")
    event_head = _sha(event.get("head_commit"), "event head commit", blob=True)
    need(event.get("kind") == "default_branch_commit" and
         event.get("source_role") == "incoming_default_branch_first_parent" and
         event.get("base_commit") == event.get("first_parent_commit"),
         "event kind/source role/first-parent fields are inconsistent")
    _sha(event.get("head_tree"), "event head tree", blob=True)
    _sha(event.get("base_commit"), "event base commit", blob=True)
    _sha(event.get("base_tree"), "event base tree", blob=True)
    _sha(event.get("control_commit"), "event control commit", blob=True)
    need(event.get("policy_base_commit") == policy.get("pins", {}).get(event_repo),
         "event policy base differs from frozen v0.6 pin")
    policy_pins = policy.get("pins")
    need(isinstance(policy_pins, dict) and set(policy_pins) == set(REPOSITORIES),
         "frozen policy pins do not name exactly the three repositories")
    expected_pins = {repo: _sha(policy_pins[repo], f"policy {repo} pin", blob=True)
                     for repo in REPOSITORIES}
    expected_pins[event_repo] = event_head
    need(manifest.get("pins") == expected_pins,
         "manifest source pins differ from frozen policy plus event head")
    basis = event.get("route_oracle_basis")
    need(isinstance(basis, dict) and
         basis.get("producer_pr_head") == route_oracle.ROUTE_PRODUCER_PR_HEAD and
         basis.get("extractor_source_sha256") == route_oracle.ROUTE_EXTRACTOR_SOURCE_SHA256 and
         basis.get("release_equivalence_verified") is False,
         "route oracle basis differs from the pinned source-first contract")

    for collection, event_mutable in (
        ("selected", {"source_commit", "source_sha256", "git_blob"}),
        ("excluded", {"source_commit", "git_blob"}),
    ):
        expected = _policy_row_map(policy.get(collection), collection)
        actual = _policy_row_map(manifest.get(collection), "manifest " + collection)
        need(set(actual) == set(expected),
             f"manifest {collection} identities differ from frozen v0.6 policy")
        for key, policy_row in expected.items():
            repo = key[0]
            actual_row = actual[key]
            if repo == event_repo:
                need(actual_row.get("source_commit") == event_head,
                     f"event {collection} source commit differs from event head: {key[1]}")
                ignored = event_mutable
            else:
                ignored = set()
            expected_shape = {name: value for name, value in _strip_policy_history(policy_row).items()
                              if name not in ignored}
            actual_shape = {name: value for name, value in actual_row.items()
                            if name not in ignored}
            need(actual_shape == expected_shape,
                 f"manifest {collection} policy row differs: {repo}:{key[1]}")
    return event_repo


def _verify_routes(manifest: dict[str, Any], coverage: dict[str, Any],
                   routing: dict[str, Any], source_blobs: dict[tuple[str, str], bytes]
                   ) -> dict[str, Any]:
    selected = manifest["selected"]
    covered = coverage["selected"]
    decisions = routing["decisions"]
    route_counts: Counter[str] = Counter()
    expected_route_rows: Counter[tuple[str, ...]] = Counter()
    coverage_route_rows: Counter[tuple[str, ...]] = Counter()
    expected_decisions: Counter[tuple[str, ...]] = Counter()
    actual_decisions: Counter[tuple[str, ...]] = Counter()
    for row in selected:
        repo, path = row["repo"], row["source_path"]
        actual = route_oracle.source_route(
            path, row["proposed_installed_path"], source_blobs[(repo, path)])
        need(actual == row["expected_route"], f"source-derived route differs: {repo}:{path}")
        classification = actual["classification"]
        need(classification in ("plain", "markup"),
             f"selected route class is outside frozen contract: {classification}")
        route_counts[classification] += 1
        expected_route_rows[_expected_route_tuple(row)] += 1
        expected_decisions[(row["proposed_installed_path"], classification,
                            actual["reason"], "plain_route_selected" if classification == "plain"
                            else "inconclusive")] += 1
    for row in covered:
        coverage_route_rows[_coverage_route_tuple(row)] += 1
    for row in decisions:
        actual_decisions[(row["installed_path"], row["classification"],
                          row["reason"], row["status"])] += 1
    _counter_equal(expected_route_rows, coverage_route_rows,
                   "manifest/coverage route tuple")
    _counter_equal(expected_decisions, actual_decisions, "routing decision")
    for name, expected in (
        ("input_count", len(selected)),
        ("plain_count", route_counts["plain"]),
        ("markup_count", route_counts["markup"]),
        ("markup_inconclusive_count", route_counts["markup"]),
        ("uncertain_count", 0),
        ("excluded_count", 0),
        ("duplicate_input_count", 0),
    ):
        need(type(routing.get(name)) is int and routing[name] == expected,
             f"routing {name} differs")
    need(routing.get("markup_count") == route_counts["markup"] and
         routing.get("markup_inconclusive_count") == route_counts["markup"],
         "routing markup count differs")
    return dict(sorted(route_counts.items()))


def verify(manifest_path: Path, coverage_path: Path, routing_path: Path,
           checkout_roots: dict[str, Path]) -> dict[str, Any]:
    """Re-derive frozen selected/excluded bytes and selected route decisions."""
    need(set(checkout_roots) == set(REPOSITORIES),
         "exactly one supplied checkout root is required per pinned repository")
    manifest_raw, manifest = _read_json(manifest_path, "manifest")
    coverage_raw, coverage = _read_json(coverage_path, "coverage")
    routing_raw, routing = _read_json(routing_path, "routing")
    need(manifest.get("schema") == "mvp-default-branch-commit-corpus-v1",
         "unsupported frozen manifest schema")
    need(isinstance(manifest.get("pins"), dict) and set(manifest["pins"]) == set(REPOSITORIES),
         "frozen manifest pins do not name exactly the three source repositories")
    pins = {repo: _sha(manifest["pins"][repo], f"{repo} commit pin", blob=True)
            for repo in REPOSITORIES}
    need(coverage.get("schema") == "ucode-default-branch-corpus-coverage-v1",
         "unsupported frozen coverage schema")
    need(coverage.get("source_manifest_sha256") == hashlib.sha256(manifest_raw).hexdigest(),
         "coverage does not bind the supplied manifest bytes")
    need(coverage.get("source_pins") == manifest["pins"] and
         coverage.get("event") == manifest.get("event"),
         "coverage pins/event differ from the frozen manifest")
    need(isinstance(manifest.get("selected"), list) and
         isinstance(manifest.get("excluded"), list) and
         isinstance(coverage.get("selected"), list) and
         isinstance(coverage.get("excluded"), list) and
         isinstance(routing.get("decisions"), list),
         "manifest, coverage, or routing rows are missing")

    route_script = Path(route_oracle.__file__)
    route_script_sha = hashlib.sha256(route_script.read_bytes()).hexdigest()
    event = manifest.get("event")
    need(isinstance(event, dict) and event.get("route_oracle_script_sha256") == route_script_sha,
         "route oracle script differs from the frozen manifest")
    route_basis = event.get("route_oracle_basis")
    need(isinstance(route_basis, dict) and
         route_basis.get("extractor_source_sha256") == route_oracle.ROUTE_EXTRACTOR_SOURCE_SHA256,
         "frozen route oracle basis differs from the pinned extractor source digest")
    policy_path = Path(__file__).resolve().parents[1] / "docs/current-corpus-source-v0.6.json"
    policy_raw, policy = _read_json(policy_path, "frozen v0.6 policy")
    policy_sha = hashlib.sha256(policy_raw).hexdigest()
    expected_policy_sha = selector.EXPECTED_MANIFESTS["mvp-bounded-corpus-v0.6"]
    need(policy_sha == expected_policy_sha and event.get("policy_sha256") == policy_sha,
         "frozen v0.6 policy digest differs from the source manifest")
    selector_script_sha = hashlib.sha256(Path(selector.__file__).read_bytes()).hexdigest()
    need(event.get("selector_script_sha256") == selector_script_sha,
         "candidate selector script differs from the frozen manifest")
    event_repo = _bind_manifest_to_policy(policy, manifest, event)

    selected = manifest["selected"]
    excluded = manifest["excluded"]
    covered_selected = coverage["selected"]
    covered_excluded = coverage["excluded"]
    selected_keys: set[tuple[str, str]] = set()
    excluded_keys: set[tuple[str, str]] = set()
    installed_paths: set[str] = set()
    rows_by_repo: dict[str, list[tuple[dict[str, Any], str]]] = {repo: [] for repo in REPOSITORIES}
    for row in selected:
        need(isinstance(row, dict) and row.get("repo") in REPOSITORIES,
             "selected row has unknown repository")
        repo = row["repo"]
        path = _validate_source_path(row.get("source_path"))
        need(row.get("source_commit") == pins[repo], f"selected row source commit differs: {path}")
        _sha(row.get("git_blob"), f"selected Git blob for {path}", blob=True)
        _sha(row.get("source_sha256"), f"selected SHA-256 for {path}")
        need(isinstance(row.get("expected_route"), dict) and
             isinstance(row["expected_route"].get("classification"), str) and
             isinstance(row["expected_route"].get("reason"), str),
             f"selected route is malformed: {path}")
        installed = row.get("proposed_installed_path")
        need(isinstance(installed, str) and installed and "\x00" not in installed,
             f"selected installed path is malformed: {path}")
        key = (repo, path)
        need(key not in selected_keys, f"duplicate selected path: {repo}:{path}")
        need(installed not in installed_paths, f"duplicate selected installed path: {installed}")
        selected_keys.add(key)
        installed_paths.add(installed)
        rows_by_repo[repo].append((row, "selected"))
    for row in excluded:
        need(isinstance(row, dict) and row.get("repo") in REPOSITORIES,
             "excluded row has unknown repository")
        repo = row["repo"]
        path = _validate_source_path(row.get("source_path"))
        digest = row.get("source_sha256", row.get("sha256"))
        _sha(digest, f"excluded SHA-256 for {path}")
        if "sha256" in row:
            need(row["sha256"] == digest, f"excluded SHA fields disagree: {path}")
        if "source_commit" in row:
            need(row["source_commit"] == pins[repo], f"excluded row source commit differs: {path}")
        if "git_blob" in row:
            _sha(row["git_blob"], f"excluded Git blob for {path}", blob=True)
        need(isinstance(row.get("reason"), str) and row["reason"],
             f"excluded reason missing: {path}")
        key = (repo, path)
        need(key not in excluded_keys, f"duplicate excluded path: {repo}:{path}")
        excluded_keys.add(key)
        rows_by_repo[repo].append((row, "excluded"))
    need(not selected_keys.intersection(excluded_keys),
         "a source path is both selected and excluded")
    need(all(any(repo == key[0] for key in selected_keys | excluded_keys)
             for repo in REPOSITORIES), "frozen manifest omits a pinned repository")

    expected_selected = Counter(_selected_identity(row) for row in selected)
    actual_selected = Counter(_coverage_identity(row) for row in covered_selected)
    _counter_equal(expected_selected, actual_selected, "selected identity")
    expected_excluded = Counter(_canonical_row(row) for row in excluded)
    actual_excluded = Counter(_canonical_row(row) for row in covered_excluded)
    _counter_equal(expected_excluded, actual_excluded, "excluded identity")
    need(len(covered_selected) == len(selected) and len(covered_excluded) == len(excluded),
         "coverage row multiplicity differs")

    seen_roots: set[str] = set()
    seen_common_dirs: set[str] = set()
    roots: dict[str, Path] = {}
    root_receipts: dict[str, dict[str, Any]] = {}
    source_blobs: dict[tuple[str, str], bytes] = {}
    byte_counts = {repo: {"selected": 0, "excluded": 0, "outside_candidate": 0}
                   for repo in REPOSITORIES}
    candidate_counts: dict[str, dict[str, int]] = {}
    candidate_census_method: dict[str, str] = {}
    outside_candidates: list[dict[str, Any]] = []
    for repo in REPOSITORIES:
        root, receipt = _prepare_root(repo, checkout_roots[repo], pins[repo],
                                      seen_roots, seen_common_dirs)
        roots[repo] = root
        root_receipts[repo] = receipt
        universe, census_counts = _tracked_candidate_census(root, pins[repo], policy, repo)
        comparison_counts, unreviewed = _compare_candidate_universe(repo, universe, selected, excluded)
        candidate_counts[repo] = {**census_counts, **comparison_counts}
        candidate_census_method[repo] = (
            "independent_tracked_tree_signal_census_no_installability_inference"
            if repo == "packages" else
            "bounded_reimplementation_of_frozen_full_tree_candidate_contract")
        if repo == event_repo:
            need(receipt["checkout_tree"] == event["head_tree"],
                 "event head tree differs from supplied source checkout")
        for entry in unreviewed:
            row = {
                "repo": repo,
                "source_path": entry["source_path"],
                "git_blob": entry["git_blob"],
                "source_sha256": entry["sha256"],
                "_mode": entry.get("mode"),
                "_signals": entry.get("signals", []),
            }
            rows_by_repo[repo].append((row, "outside_frozen_denominator_candidate"))
            outside_candidates.append({
                "repo": repo, "source_path": entry["source_path"],
                "git_blob": entry["git_blob"], "source_sha256": entry["sha256"],
                "mode": entry.get("mode"),
                "signals": entry.get("signals", []),
                "disposition": "outside_frozen_denominator_candidate",
                "route_decision_verified": False,
            })
        rows = rows_by_repo[repo]
        paths = [row["source_path"] for row, _status in rows]
        entries = _tree_entries(root, pins[repo], paths)
        blobs = _read_blobs(root, [entries[path]["git_blob"] for path in paths])
        for row, disposition in rows:
            path = row["source_path"]
            entry = entries[path]
            if disposition == "selected":
                need(entry["mode"] in ("100644", "100755"),
                     f"selected source is not a regular file: {repo}:{path}")
                need(entry["git_blob"] == row["git_blob"],
                     f"selected Git blob differs from manifest: {repo}:{path}")
            elif disposition == "excluded" and "git_blob" in row:
                need(entry["git_blob"] == row["git_blob"],
                     f"excluded Git blob differs from manifest: {repo}:{path}")
            elif disposition not in ("selected", "excluded"):
                need(entry["mode"] in ("100644", "100755", "120000") and
                     entry["git_blob"] == row["git_blob"] and
                     entry["mode"] == row["_mode"],
                     f"outside-denominator candidate differs from pinned tree: {repo}:{path}")
            data = blobs[entry["git_blob"]]
            need(_git_blob_oid(data) == entry["git_blob"],
                 f"Git blob ID does not match source bytes: {repo}:{path}")
            digest = hashlib.sha256(data).hexdigest()
            expected_digest = row.get("source_sha256", row.get("sha256"))
            need(digest == expected_digest,
                 f"source SHA-256 differs from frozen/selector identity: {repo}:{path}")
            source_blobs[(repo, path)] = data
            if disposition in ("selected", "excluded"):
                byte_counts[repo][disposition] += 1
            else:
                byte_counts[repo]["outside_candidate"] += 1
            root_receipts[repo].setdefault("observed_blobs", []).append({
                "source_path": path,
                "git_blob_from_pinned_tree": entry["git_blob"],
                "mode": entry["mode"],
                "sha256_matches_frozen_identity": disposition in ("selected", "excluded"),
                "sha256_matches_tracked_candidate_census": True,
                "disposition": disposition,
            })
            if disposition not in ("selected", "excluded"):
                next(item for item in outside_candidates
                     if item["repo"] == repo and item["source_path"] == path).update(
                         git_blob_from_pinned_tree=entry["git_blob"], source_sha256=digest,
                         selected_or_excluded_identity_in_frozen_manifest=False)

    route_counts = _verify_routes(manifest, coverage, routing, source_blobs)
    selected_by_repo = Counter(row["repo"] for row in selected)
    excluded_by_repo = Counter(row["repo"] for row in excluded)
    manifest_counts = manifest.get("counts")
    need(isinstance(manifest_counts, dict) and
         manifest_counts.get("selected") == len(selected) and
         manifest_counts.get("excluded") == len(excluded) and
         manifest_counts.get("repo_selected") == dict(selected_by_repo) and
         manifest_counts.get("route_classes") == route_counts,
         "manifest summary counts differ from rows")
    candidate_signals_accounted_for = not outside_candidates
    return {
        "schema": "mvp-default-branch-source-truth-verification-v1",
        "status": "bounded_selected_excluded_match",
        "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "route_oracle_script_sha256": route_script_sha,
        "selector_script_sha256": selector_script_sha,
        "frozen_policy_sha256": policy_sha,
        "coverage_sha256": hashlib.sha256(coverage_raw).hexdigest(),
        "routing_sha256": hashlib.sha256(routing_raw).hexdigest(),
        "route_extractor_source_sha256_from_frozen_basis": route_basis["extractor_source_sha256"],
        "git_blob_oid_recomputed_from_bytes": True,
        "git_blob_algorithm": "sha1",
        "release_route_source_bytes_reverified_by_this_tool": False,
        "event_repository": event_repo,
        "event_head_commit": event["head_commit"],
        "event_head_tree": event["head_tree"],
        "event_tree_binding_verified": True,
        "manifest_policy_row_binding_verified": True,
        "selected": len(selected),
        "selected_by_repo": {repo: selected_by_repo[repo] for repo in REPOSITORIES},
        "excluded": len(excluded),
        "excluded_by_repo": {repo: excluded_by_repo[repo] for repo in REPOSITORIES},
        "route_classes": route_counts,
        "selected_identity_multiplicity_exact": True,
        "excluded_identity_multiplicity_exact": True,
        "tracked_candidate_signals_accounted_for": candidate_signals_accounted_for,
        "candidate_universe_counts": candidate_counts,
        "candidate_census_method": candidate_census_method,
        "source_candidates_outside_frozen_denominator": outside_candidates,
        "selected_and_excluded_git_bytes_rederived": byte_counts,
        "source_route_recomputed_from_git_blob_bytes": True,
        "route_decisions_verified_for_outside_candidates": False,
        "manifest_coverage_routing_multiplicity_exact": True,
        "roots": root_receipts,
        "canonical_git_provenance_verified": False,
        "signed_live_completion_verified": False,
        "boundaries": [
            "Checkout roots and JSON documents are caller-supplied and untrusted; this tool reads pinned Git objects and does not inspect worktree cleanliness or attest canonical Git provenance.",
            "Selected route decisions are recomputed from pinned Git blob bytes using the route oracle script whose digest is frozen in the manifest.",
            "Tracked-tree candidate signals were rederived with bounded local Git reads; shebang signals use Git grep with binary blobs omitted, then first-line validation. The packages feed uses an independent signal census rather than the selector CLI/library. Candidate signals do not establish installability.",
            "Source candidate signals outside the frozen selected/excluded denominator are listed with pinned-tree blob/SHA identities. Their presence means all tracked candidate signals are not accounted for in the bounded denominator; they have no verified route because no installed path is frozen.",
            "For excluded rows without a frozen Git blob field, the blob identity is derived from the pinned tree and its bytes are checked against the frozen SHA-256.",
            "This verifies source identities and route consistency only; it does not authenticate a hosted scan, signature, queue action, or live completion.",
            "No network, key, queue, source checkout mutation, extraction, CodeQL query, installed package byte, or runtime claim is involved.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--routing", type=Path, required=True)
    for repo in REPOSITORIES:
        parser.add_argument(f"--{repo}-checkout", type=Path, required=True)
    args = parser.parse_args(argv)
    roots = {repo: getattr(args, f"{repo}_checkout") for repo in REPOSITORIES}
    try:
        result = verify(args.manifest, args.coverage, args.routing, roots)
    except (SourceTruthError, OSError, ValueError, KeyError, TypeError,
            UnicodeError, RecursionError) as exc:
        print("default-branch source truth rejected: " + str(exc), file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result["tracked_candidate_signals_accounted_for"] else 3


if __name__ == "__main__":
    sys.exit(main())
