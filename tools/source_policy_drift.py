#!/usr/bin/env python3
"""Compare a pinned v0.4 source policy with an incoming OpenWrt or LuCI commit."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPOS = {"openwrt", "luci"}
MANIFEST_REPOS = {"openwrt", "luci", "packages"}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_MANIFEST_SHA256 = "1e25cf9c2adc40c854502fed8d1ccc0977a3c4825d6ee4a1c0a543ffe0a76699"

class DriftError(ValueError):
    pass

def git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as e:
        raise DriftError(f"git {' '.join(args)} failed: {e.stderr.strip()}") from e

def git_bytes(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        detail = e.stderr.decode("utf-8", errors="replace").strip()
        raise DriftError(f"git {' '.join(args)} failed: {detail}") from e

def safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise DriftError(f"invalid source path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise DriftError(f"unsafe source path: {value!r}")
    return value

def file_identity(root: Path, commit: str, path: str):
    path = safe_path(path)
    try:
        blob = git(root, "rev-parse", f"{commit}:{path}")
        raw = subprocess.check_output(["git", "-C", str(root), "show", f"{commit}:{path}"])
    except (DriftError, subprocess.CalledProcessError):
        return None
    return {"path": path, "git_blob": blob, "sha256": hashlib.sha256(raw).hexdigest()}

def candidate(path: str) -> bool:
    name = PurePosixPath(path).name
    return PurePosixPath(name).suffix in {".uc", ".ut"} or ("." not in name and name not in {"Makefile", "Config.in"})

def policy_input(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in {"Makefile", "Config.in", "luci.mk"} or name.startswith("Kconfig") or name.endswith(".mk")

def package_roots(repo_name: str, selected: list[dict]) -> set[str]:
    roots = set()
    for row in selected:
        parts = PurePosixPath(row["source_path"]).parts
        if repo_name == "luci" and len(parts) >= 2:
            roots.add("/".join(parts[:2]))
        elif repo_name == "openwrt":
            for index, part in enumerate(parts):
                if part == "files" or part.startswith("files-") or part.startswith("files_"):
                    if index:
                        roots.add("/".join(parts[:index]))
                    break
    return roots

def in_package_roots(path: str, roots: set[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)

def validate_manifest(manifest: dict, raw_bytes: bytes, repo_name: str, expected_sha256: str = EXPECTED_MANIFEST_SHA256) -> tuple[list, list, str]:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    if digest != expected_sha256:
        raise DriftError(f"manifest SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    if manifest.get("schema") != "mvp-bounded-corpus-v0.4":
        raise DriftError("unsupported baseline manifest schema")
    if repo_name not in REPOS:
        raise DriftError("repo must be openwrt or luci")
    pin = manifest.get("pins", {}).get(repo_name)
    if not isinstance(pin, str) or not HEX40.fullmatch(pin):
        raise DriftError(f"manifest has no valid source pin for {repo_name}")
    selected = manifest.get("selected")
    excluded = manifest.get("excluded")
    if not isinstance(selected, list) or not isinstance(excluded, list):
        raise DriftError("manifest selected/excluded entries must be arrays")
    paths = set()
    for classification, rows in (("selected", selected), ("excluded", excluded)):
        for row in rows:
            if not isinstance(row, dict):
                raise DriftError(f"malformed {classification} manifest row")
            if row.get("repo") not in MANIFEST_REPOS:
                raise DriftError(f"unknown repository in {classification} row")
            path = safe_path(row.get("source_path"))
            key = (row["repo"], path)
            if key in paths:
                raise DriftError(f"duplicate selected/excluded source path: {key}")
            paths.add(key)
            if row.get("repo") != repo_name:
                continue
            row_pin = row.get("source_commit")
            if row_pin is not None and row_pin != pin:
                raise DriftError(f"{classification} row source_commit does not match {repo_name} manifest pin: {path}")
            blob = row.get("git_blob")
            sha = row.get("source_sha256", row.get("sha256"))
            if blob is not None and (not isinstance(blob, str) or not HEX40.fullmatch(blob)):
                raise DriftError(f"invalid baseline Git blob for {path}")
            if not isinstance(sha, str) or not HEX64.fullmatch(sha):
                raise DriftError(f"invalid baseline content SHA-256 for {path}")
    return [x for x in selected if x["repo"] == repo_name], [x for x in excluded if x["repo"] == repo_name], pin

def analyze(manifest: dict, manifest_bytes: bytes, repo_name: str, root: Path, event_sha: str, base_sha: str, expected_manifest_sha256: str = EXPECTED_MANIFEST_SHA256) -> dict:
    selected, excluded, baseline_pin = validate_manifest(manifest, manifest_bytes, repo_name, expected_manifest_sha256)
    for label, sha in (("event", event_sha), ("base", base_sha)):
        if not isinstance(sha, str) or not HEX40.fullmatch(sha):
            raise DriftError(f"{label} SHA must be a full 40-character lowercase commit")
        resolved = git(root, "rev-parse", "--verify", f"{sha}^{{commit}}")
        if resolved != sha:
            raise DriftError(f"{label} SHA does not resolve exactly")
    if git(root, "rev-parse", "HEAD") != event_sha:
        raise DriftError("checkout HEAD must equal the full event commit SHA")
    if git(root, "status", "--porcelain=v1"):
        raise DriftError("event checkout must be clean")
    base_tree = git(root, "rev-parse", f"{base_sha}^{{tree}}")
    event_tree = git(root, "rev-parse", f"{event_sha}^{{tree}}")
    names = {x["source_path"]: x for x in selected + excluded}
    owner_roots = package_roots(repo_name, selected)
    resolved_rows, removed, changed = [], [], []
    for path, item in names.items():
        now = file_identity(root, event_sha, path)
        record = {"source_path": path, "baseline_class": "selected" if item in selected else "excluded",
                  "package_owner": item.get("package_owner"), "config_condition": item.get("config_condition"),
                  "reason": item.get("reason"), "expected_route": item.get("expected_route"),
                  "baseline_source_commit": item.get("source_commit"), "baseline_git_blob": item.get("git_blob"),
                  "baseline_sha256": item.get("source_sha256", item.get("sha256")), "event_identity": now}
        if now is None:
            removed.append(record)
        else:
            resolved_rows.append(record)
            baseline_blob = record["baseline_git_blob"]
            if (baseline_blob is not None and now["git_blob"] != baseline_blob) or (baseline_blob is None and now["sha256"] != record["baseline_sha256"]):
                changed.append(record)
    diff_raw = git_bytes(root, "diff", "--name-status", "-z", "--find-renames", base_sha, event_sha)
    diff_fields = diff_raw.decode("utf-8", errors="strict").split("\0")
    if diff_fields and diff_fields[-1] == "":
        diff_fields.pop()
    diffs = []
    index = 0
    while index < len(diff_fields):
        status = diff_fields[index]; index += 1
        if status.startswith("R") and status[1:].isdigit() and index + 1 < len(diff_fields):
            old, new = safe_path(diff_fields[index]), safe_path(diff_fields[index + 1]); index += 2
            diffs.append({"status": "renamed", "old_path": old, "new_path": new})
        elif status in {"A", "D", "M", "T"} and index < len(diff_fields):
            path = safe_path(diff_fields[index]); index += 1
            diffs.append({"status": {"A": "added", "D": "removed", "M": "modified", "T": "type_changed"}[status], "path": path})
        else:
            raise DriftError(f"unrecognized git diff name-status record: {status!r}")
    drift = []
    unrelated_policy_files = []
    for item in diffs:
        path = item.get("new_path", item.get("path", "")); old = item.get("old_path")
        paths = [p for p in (old, path) if p]
        relevant_policy_change = any(policy_input(p) and ((repo_name == "luci" and p == "luci.mk") or in_package_roots(p, owner_roots)) for p in paths)
        if item["status"] == "removed" and path in names:
            drift.append({**item, "class": "removed_baseline_identity"})
        elif item["status"] == "renamed" and (old in names or candidate(path) or candidate(old)):
            drift.append({**item, "class": "renamed_or_candidate_path"})
        elif item["status"] == "added" and candidate(path):
            drift.append({**item, "class": "new_candidate"})
        elif item["status"] == "type_changed" and (path in names or candidate(path)):
            drift.append({**item, "class": "baseline_identity_type_changed" if path in names else "candidate_type_changed"})
        elif any(policy_input(p) for p in paths):
            policy_record = {**item, "class": "policy_condition_or_routing_input_changed"}
            if relevant_policy_change:
                drift.append(policy_record)
            else:
                unrelated_policy_files.append(policy_record)
    fail = bool(drift or removed)
    status = "review_required" if fail else "content_changes_observed" if changed else "no_bounded_drift_observed"
    return {"schema": "source-policy-drift-v1", "baseline_schema": manifest["schema"],
            "baseline_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "baseline_source_commit": baseline_pin,
            "repository": repo_name, "base_commit": base_sha, "base_tree": base_tree,
            "event_commit": event_sha, "event_tree": event_tree,
            "baseline_selected_count_for_repo": len(selected), "baseline_excluded_count_for_repo": len(excluded),
            "selected_and_excluded_identities": resolved_rows, "removed_baseline_identities": removed,
            "changed_selected_or_excluded": changed, "drift": drift,
            "owner_package_roots": sorted(owner_roots), "unrelated_policy_files": unrelated_policy_files,
            "status": status, "fail_closed": fail,
            "limitations": ["Only baseline identities and paths in the explicit base-to-event Git diff are compared.",
                            "Unrelated package build-file changes are reported but do not fail; Makefile-only activation of previously unselected sources is not covered.",
                            "No full-tree discovery, install-path inference, package condition evaluation, extraction, CodeQL, SARIF, or consumer handoff is performed.",
                            "Extensionless candidate heuristic is intentionally broad; unrecognized source layouts may be missed."]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path); parser.add_argument("repository", choices=sorted(REPOS))
    parser.add_argument("checkout", type=Path); parser.add_argument("event_sha"); parser.add_argument("base_sha"); parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        raw = args.manifest.read_bytes(); result = analyze(json.loads(raw), raw, args.repository, args.checkout, args.event_sha, args.base_sha)
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2)); return 1 if result["fail_closed"] else 0
    except (OSError, UnicodeError, json.JSONDecodeError, DriftError) as e:
        print(f"source-policy drift failed closed: {e}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
