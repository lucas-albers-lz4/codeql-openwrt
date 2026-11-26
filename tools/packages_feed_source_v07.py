#!/usr/bin/env python3
"""Verify the opt-in packages-feed v0.7 source policy against a pinned checkout.

This is a source identity and recipe mapping check. It does not build packages,
switch the current v0.6 scan contract, or verify installed bytes or extraction.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any

from tools import event_corpus_manifest as route_oracle
from tools import full_tree_candidates as candidates


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs/current-corpus-source-v0.7.json"
BASELINE_PATH = ROOT / "docs/current-corpus-source-v0.6.json"
POLICY_SHA256 = "2ef4dc10e78b6c3aef873e3f0652b5102698cedb317c9cf96587806941c61d2e"
BASELINE_SHA256 = "9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490"
SUPPORT = "source_expected_not_extracted"
ROUTE_ORACLE_SHA256 = "eba5741635bde7b5719d3e60f3bb8847f6603d91d6939c6c5602c02bcca6be9e"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

NEW_SELECTED_PATHS = {
    "net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc",
    "net/adblock-fast/files/lib/adblock-fast/cli.uc",
    "net/mwan3/files/usr/share/rpcd/ucode/mwan3",
    "net/snort3/files/main.uc",
    "net/snort3/files/nftables.uc",
    "net/snort3/files/snort.uc",
    "net/uneighbord/files/usr/sbin/uneighbord",
    "utils/librespeed-common/files/librespeed-aggregate",
    "utils/librespeed-common/files/librespeed.uc",
    "utils/uvol/files/blockdev_common.uc",
    "utils/uvol/files/lvm.uc",
    "utils/uvol/files/ubi.uc",
    "utils/uvol/files/uci.uc",
    "utils/uvol/files/uvol",
}
NEW_EXCLUDED_PATHS = {
    "net/adblock-fast/tests/lib/mocklib.uc",
    "net/adblock-fast/tests/lib/mocklib/ubus.uc",
    "net/adblock-fast/tests/lib/mocklib/uci.uc",
}
EXPECTED_ROUTES = {
    "net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc": ("plain", "ucode_extension"),
    "net/adblock-fast/files/lib/adblock-fast/cli.uc": ("plain", "ucode_extension"),
    "net/mwan3/files/usr/share/rpcd/ucode/mwan3": ("plain", "rpcd_raw_mode_full_path"),
    "net/snort3/files/main.uc": ("markup", "markup_tag_content"),
    "net/snort3/files/nftables.uc": ("markup", "markup_tag_content"),
    "net/snort3/files/snort.uc": ("markup", "markup_tag_content"),
    "net/uneighbord/files/usr/sbin/uneighbord": ("plain", "ucode_shebang"),
    "utils/librespeed-common/files/librespeed-aggregate": ("plain", "ucode_shebang"),
    "utils/librespeed-common/files/librespeed.uc": ("plain", "rpcd_raw_mode_full_path"),
    "utils/uvol/files/blockdev_common.uc": ("plain", "ucode_extension"),
    "utils/uvol/files/lvm.uc": ("plain", "ucode_extension"),
    "utils/uvol/files/ubi.uc": ("plain", "ucode_extension"),
    "utils/uvol/files/uci.uc": ("plain", "ucode_extension"),
    "utils/uvol/files/uvol": ("plain", "ucode_shebang"),
}
EXPECTED_SOURCE_MODES = {
    **{path: "100644" for path in NEW_SELECTED_PATHS | NEW_EXCLUDED_PATHS},
    "net/uneighbord/files/usr/sbin/uneighbord": "100755",
    "utils/librespeed-common/files/librespeed-aggregate": "100755",
}
EXPECTED_INSTALLED_PATHS = {
    "net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc": "lib/adblock-fast/adblock-fast.uc",
    "net/adblock-fast/files/lib/adblock-fast/cli.uc": "lib/adblock-fast/cli.uc",
    "net/mwan3/files/usr/share/rpcd/ucode/mwan3": "usr/share/rpcd/ucode/mwan3",
    "net/snort3/files/main.uc": "usr/share/snort/main.uc",
    "net/snort3/files/nftables.uc": "usr/share/snort/templates/nftables.uc",
    "net/snort3/files/snort.uc": "usr/share/snort/templates/snort.uc",
    "net/uneighbord/files/usr/sbin/uneighbord": "usr/sbin/uneighbord",
    "utils/librespeed-common/files/librespeed-aggregate": "usr/libexec/librespeed-aggregate",
    "utils/librespeed-common/files/librespeed.uc": "usr/share/rpcd/ucode/librespeed.uc",
    "utils/uvol/files/blockdev_common.uc": "usr/lib/uvol/blockdev_common.uc",
    "utils/uvol/files/lvm.uc": "usr/lib/uvol/backends/lvm.uc",
    "utils/uvol/files/ubi.uc": "usr/lib/uvol/backends/ubi.uc",
    "utils/uvol/files/uci.uc": "usr/lib/uvol/uci.uc",
    "utils/uvol/files/uvol": "usr/sbin/uvol",
}


class SourcePolicyError(ValueError):
    """Raised when the source policy or pinned package checkout differs."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise SourcePolicyError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.PIPE,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        ).strip()
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        raise SourcePolicyError(f"git {' '.join(args)} failed: {detail.strip()}") from exc


def safe_source_path(value: Any) -> str:
    need(isinstance(value, str) and value and "\\" not in value,
         "invalid source path")
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value and
         all(part not in (".", "..") for part in path.parts),
         f"unsafe source path: {value!r}")
    return value


def row_map(rows: Any, label: str) -> dict[tuple[str, str], dict[str, Any]]:
    need(isinstance(rows, list), f"{label} rows are missing")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        need(isinstance(row, dict) and row.get("repo") in ("luci", "openwrt", "packages"),
             f"malformed {label} row")
        key = (row["repo"], safe_source_path(row.get("source_path")))
        need(key not in result, f"duplicate {label} identity: {key}")
        result[key] = row
    return result


def validate_policy(policy: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Check the frozen v0.7 shape and exact v0.6 carry-forward rows."""
    need(policy.get("schema") == "mvp-bounded-corpus-v0.7",
         "unsupported v0.7 policy schema")
    need(baseline.get("schema") == "mvp-bounded-corpus-v0.6",
         "unsupported v0.6 baseline schema")
    need(policy.get("pins") == baseline.get("pins"),
         "v0.7 source pins differ from frozen v0.6 pins")

    selected = row_map(policy.get("selected"), "selected")
    excluded = row_map(policy.get("excluded"), "excluded")
    baseline_selected = row_map(baseline.get("selected"), "v0.6 selected")
    baseline_excluded = row_map(baseline.get("excluded"), "v0.6 excluded")
    need(set(baseline_selected) <= set(selected) and
         all(selected[key] == row for key, row in baseline_selected.items()),
         "v0.6 selected rows changed or were removed")
    need(set(baseline_excluded) <= set(excluded) and
         all(excluded[key] == row for key, row in baseline_excluded.items()),
         "v0.6 excluded rows changed or were removed")
    need(not set(selected).intersection(excluded),
         "selected and excluded identities overlap")
    need(len(selected) == 142 and len(excluded) == 16,
         "v0.7 total selected/excluded counts differ")

    new_selected = {
        path: row for (repo, path), row in selected.items()
        if repo == "packages" and (repo, path) not in baseline_selected
    }
    new_excluded = {
        path: row for (repo, path), row in excluded.items()
        if repo == "packages" and (repo, path) not in baseline_excluded
    }
    need(set(new_selected) == NEW_SELECTED_PATHS,
         "v0.7 package selected path set differs")
    need(set(new_excluded) == NEW_EXCLUDED_PATHS,
         "v0.7 package excluded mock path set differs")

    selected_by_repo = Counter(repo for repo, _ in selected)
    excluded_by_repo = Counter(repo for repo, _ in excluded)
    route_classes: Counter[str] = Counter()
    for row in selected.values():
        route = row.get("expected_route")
        need(isinstance(route, dict) and route.get("classification") in ("plain", "markup"),
             f"selected route class is malformed: {row.get('source_path')}")
        route_classes[route["classification"]] += 1
    need(selected_by_repo == Counter({"luci": 65, "openwrt": 51, "packages": 26}),
         "v0.7 selected repository counts differ")
    need(excluded_by_repo == Counter({"luci": 4, "openwrt": 1, "packages": 11}),
         "v0.7 excluded repository counts differ")
    need(route_classes == Counter({"plain": 104, "markup": 38}),
         "v0.7 route class counts differ")

    pins = policy["pins"]
    expected_routes = Counter()
    expected_owners = Counter()
    for path, row in new_selected.items():
        route = row.get("expected_route")
        expected_route = EXPECTED_ROUTES[path]
        need(row.get("repo") == "packages" and
             row.get("source_commit") == pins["packages"],
             f"v0.7 selected source pin differs: {path}")
        need(row.get("source_mode") == EXPECTED_SOURCE_MODES[path] and
             isinstance(row.get("git_blob"), str) and
             HEX40.fullmatch(row["git_blob"]) is not None and
             isinstance(row.get("source_sha256"), str) and
             HEX64.fullmatch(row["source_sha256"]) is not None,
             f"v0.7 selected source identity is incomplete: {path}")
        need(row.get("installed_bytes_verified") is False,
             f"v0.7 package bytes are overstated: {path}")
        need(row.get("route_support") == SUPPORT and isinstance(route, dict) and
             (route.get("classification"), route.get("reason")) == expected_route,
             f"v0.7 source route expectation differs: {path}")
        owner = row.get("package_owner")
        need(isinstance(owner, str) and owner and
             row.get("package_or_target_condition") == f"package selected: {owner}",
             f"v0.7 package condition is missing or inconsistent: {path}")
        need(row.get("proposed_installed_path") == EXPECTED_INSTALLED_PATHS[path] and
             isinstance(row.get("install_recipe"), str) and
             isinstance(row.get("install_source_expression"), str) and
             isinstance(row.get("install_destination_expression"), str) and
             isinstance(row.get("install_recipe_git_blob"), str) and
             HEX40.fullmatch(row["install_recipe_git_blob"]) is not None and
             isinstance(row.get("install_recipe_source_sha256"), str) and
             HEX64.fullmatch(row["install_recipe_source_sha256"]) is not None,
             f"v0.7 install recipe evidence is incomplete: {path}")
        if expected_route[1] == "markup_tag_content":
            need(row.get("route_qualification") == "provisional markup route",
                 f"snort3 markup route is not marked provisional: {path}")
        expected_routes[expected_route[1]] += 1
        expected_owners[owner] += 1

    need(expected_routes == Counter({"ucode_extension": 6,
                                     "rpcd_raw_mode_full_path": 2,
                                     "ucode_shebang": 3,
                                     "markup_tag_content": 3}),
         "v0.7 route reason counts differ")
    need(expected_owners == Counter({"adblock-fast": 2, "mwan3": 1, "snort3": 3,
                                     "uneighbord": 1, "librespeed-common": 2,
                                     "uvol": 5}),
         "v0.7 package owner counts differ")

    for path, row in new_excluded.items():
        need(row.get("repo") == "packages" and
             row.get("source_commit") == pins["packages"] and
             row.get("source_mode") == EXPECTED_SOURCE_MODES[path] and
             isinstance(row.get("git_blob"), str) and
             HEX40.fullmatch(row["git_blob"]) is not None and
             isinstance(row.get("sha256"), str) and
             HEX64.fullmatch(row["sha256"]) is not None and
             row.get("package_owner") == "adblock-fast" and
             row.get("reason") == "test mock; no product package install mapping",
             f"v0.7 test-mock exclusion identity is incomplete: {path}")

    counts = policy.get("counts", {})
    need(counts.get("selected") == 142 and counts.get("excluded") == 16 and
         counts.get("packages_feed_v0_7_selected") == 14 and
         counts.get("packages_feed_v0_7_excluded_test_mocks") == 3 and
         counts.get("packages_feed_selected") == 26 and
         counts.get("packages_feed_excluded") == 11 and
         counts.get("source_expected_not_extracted") == 14 and
         counts.get("route_classes") == {"plain": 104, "markup": 38},
         "v0.7 policy counts do not match selected/excluded identities")
    return {
        "selected": len(selected),
        "excluded": len(excluded),
        "selected_by_repo": dict(sorted(selected_by_repo.items())),
        "excluded_by_repo": dict(sorted(excluded_by_repo.items())),
        "route_classes": dict(sorted(route_classes.items())),
        "new_package_selected": len(new_selected),
        "new_package_excluded": len(new_excluded),
    }


def _git_tree_entry(checkout: Path, path: str) -> tuple[str, str, str]:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(checkout), "ls-tree", "-z", "HEAD", "--", path],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace")
        raise SourcePolicyError(f"git ls-tree failed for {path}: {detail.strip()}") from exc
    records = [item for item in raw.split(b"\0") if item]
    need(len(records) == 1, f"source is missing or ambiguous in Git tree: {path}")
    meta, encoded_path = records[0].split(b"\t", 1)
    mode, kind, blob = meta.decode("ascii").split()
    need(encoded_path.decode("utf-8", "surrogateescape") == path,
         f"Git tree path differs: {path}")
    return mode, kind, blob


def _expanded_install_sources(expression: str) -> set[str]:
    match = re.fullmatch(r"([^{}]*)\{([^{}]+)\}([^{}]*)", expression)
    if not match:
        return {expression}
    prefix, choices, suffix = match.groups()
    return {prefix + item + suffix for item in choices.split(",")}


def _logical_recipe_commands(lines: list[str]) -> list[str]:
    commands = []
    current = ""
    for line in lines:
        part = line.rstrip()
        continuation = part.endswith("\\")
        if continuation:
            part = part[:-1]
        current = f"{current} {part.strip()}".strip()
        if not continuation:
            commands.append(current)
            current = ""
    if current:
        commands.append(current)
    return commands


def _verify_recipe(checkout: Path, row: dict[str, Any]) -> None:
    recipe_ref = row["install_recipe"]
    match = re.fullmatch(r"(.+):(\d+)-(\d+)", recipe_ref)
    need(match is not None, f"malformed install recipe reference: {recipe_ref}")
    recipe_path, first_s, last_s = match.groups()
    safe_source_path(recipe_path)
    mode, kind, blob = _git_tree_entry(checkout, recipe_path)
    need(kind == "blob" and mode in ("100644", "100755"),
         f"install recipe is not a regular file: {recipe_path}")
    need(blob == row["install_recipe_git_blob"],
         f"install recipe Git blob differs: {recipe_path}")
    recipe = checkout.joinpath(*PurePosixPath(recipe_path).parts)
    need(not recipe.is_symlink() and recipe.is_file(),
         f"install recipe is missing, symlinked or non-file: {recipe_path}")
    recipe_bytes = recipe.read_bytes()
    need(sha256(recipe_bytes) == row["install_recipe_source_sha256"],
         f"install recipe SHA-256 differs: {recipe_path}")
    lines = recipe_bytes.decode("utf-8").splitlines()
    first, last = int(first_s), int(last_s)
    need(1 <= first <= last <= len(lines),
         f"install recipe line range is invalid: {recipe_ref}")
    source_expression = row["install_source_expression"]
    destination_expression = row["install_destination_expression"]
    commands = _logical_recipe_commands(lines[first - 1:last])
    need(any((parts := command.split()) and
             re.fullmatch(r"\$\((?:INSTALL_[A-Z]+|CP)\)", parts[0]) and
             parts[1:] == [source_expression, destination_expression]
             for command in commands),
         f"install recipe stage expression differs: {recipe_ref}")
    recipe_dir = PurePosixPath(recipe_path).parent
    staged_sources = {
        (recipe_dir / PurePosixPath(source.removeprefix("./"))).as_posix()
        for source in _expanded_install_sources(source_expression)
    }
    need(row["source_path"] in staged_sources,
         f"install recipe source does not map to selected path: {row['source_path']}")
    destination = destination_expression.removeprefix("$(1)/").rstrip("/")
    installed = row["proposed_installed_path"]
    need(destination and (installed == destination or
                           installed == f"{destination}/{PurePosixPath(row['source_path']).name}"),
         f"install recipe destination does not map to proposed path: {row['source_path']}")
    owner = row["package_owner"]
    recipe_text = recipe_bytes.decode("utf-8")
    need(f"define Package/{owner}/install" in recipe_text and
         f"BuildPackage,{owner}" in recipe_text,
         f"package owner is not defined and built by recipe: {owner}")


def _verify_expected_route(row: dict[str, Any], content: bytes) -> None:
    path = row["source_path"]
    try:
        actual = route_oracle.source_route(
            path, row["proposed_installed_path"], content)
    except candidates.SelectorError as exc:
        raise SourcePolicyError(f"source has no reviewed route: {path}: {exc}") from exc
    need(actual == row["expected_route"],
         f"source-derived route differs: {path}: {actual}")


def verify_source_checkout(checkout: Path, policy: dict[str, Any],
                           baseline: dict[str, Any], policy_raw: bytes) -> dict[str, Any]:
    summary = validate_policy(policy, baseline)
    package_pin = policy["pins"]["packages"]
    need(git(checkout, "rev-parse", "HEAD") == package_pin,
         "packages checkout SHA differs from v0.7 policy pin")
    need(not git(checkout, "status", "--porcelain=v1", "--untracked-files=all"),
         "packages checkout is dirty")

    selected = [row for row in policy["selected"]
                if row.get("repo") == "packages" and row["source_path"] in NEW_SELECTED_PATHS]
    excluded = [row for row in policy["excluded"]
                if row.get("repo") == "packages" and row["source_path"] in NEW_EXCLUDED_PATHS]
    verified_sources = 0
    for row in selected + excluded:
        path = safe_source_path(row["source_path"])
        mode, kind, blob = _git_tree_entry(checkout, path)
        expected_hash = row.get("source_sha256", row.get("sha256"))
        need(kind == "blob" and mode == row["source_mode"] and blob == row["git_blob"],
             f"source mode/type/blob differs: {path}")
        source = checkout.joinpath(*PurePosixPath(path).parts)
        need(not source.is_symlink() and source.is_file(),
             f"source is missing, symlinked or non-file: {path}")
        content = source.read_bytes()
        need(sha256(content) == expected_hash,
             f"source SHA-256 differs: {path}")
        if row in selected:
            _verify_expected_route(row, content)
            _verify_recipe(checkout, row)
        verified_sources += 1

    mock_recipe = checkout / "net/adblock-fast/Makefile"
    mock_recipe_text = mock_recipe.read_text(encoding="utf-8")
    for path in NEW_EXCLUDED_PATHS:
        need(PurePosixPath(path).name not in mock_recipe_text and
             "tests/lib/mocklib" not in mock_recipe_text,
             f"test mock has an adblock-fast package install reference: {path}")

    expected_candidate_paths = {
        row["source_path"] for row in policy["selected"] + policy["excluded"]
        if row.get("repo") == "packages"
    }
    natural_inventory = candidates.make_inventory(
        checkout, package_pin, {"selected": [], "excluded": []}, "packages")
    natural_paths = {row["source_path"] for row in natural_inventory}
    need(len(natural_paths) == 37 and natural_paths == expected_candidate_paths and
         all(row["status"] == "unreviewed" for row in natural_inventory),
         "unseeded package candidate path set differs from v0.7 oracle")

    inventory = candidates.make_inventory(checkout, package_pin, policy, "packages")
    inventory_counts = Counter(row["status"] for row in inventory)
    need(len(inventory) == 37 and inventory_counts["selected"] == 26 and
         inventory_counts["excluded"] == 11 and inventory_counts["unreviewed"] == 0,
         "pinned packages candidate census differs from v0.7 oracle")
    summary["source_files_identity_checked"] = verified_sources
    summary["package_candidate_census"] = {
        "candidate_count": len(inventory),
        "selected_count": inventory_counts["selected"],
        "excluded_count": inventory_counts["excluded"],
        "unreviewed_count": inventory_counts["unreviewed"],
        "status": "inventory_ready",
        "unseeded_paths_match_policy": True,
        "source_paths": sorted(natural_paths),
    }
    summary["policy_sha256"] = sha256(policy_raw)
    summary["package_source_commit"] = package_pin
    summary["limitations"] = [
        "Recipe source and destination expressions support a conditional source-stage mapping only; package builds, prepared stage bytes, IPKs and images were not inspected.",
        "Route values are predictions from the pinned source-route mirror, not observed extractor decisions; snort3 markup routes are provisional and release equivalence is unverified.",
        "The tracked-tree census is bounded by the selector's Ucode suffix, installed-root and first-line shebang signals; binary shebang candidates may be omitted.",
        "This versioned source verifier does not alter or replace the default v0.6 scan, source-truth or CI policy paths.",
    ]
    return summary


def load_policy() -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    policy_raw = POLICY_PATH.read_bytes()
    need(sha256(policy_raw) == POLICY_SHA256,
         "v0.7 policy digest differs from pinned bytes")
    baseline_raw = BASELINE_PATH.read_bytes()
    need(sha256(baseline_raw) == BASELINE_SHA256 ==
         candidates.EXPECTED_MANIFESTS.get("mvp-bounded-corpus-v0.6"),
         "v0.6 baseline digest differs from pinned bytes")
    policy = json.loads(policy_raw)
    expected_route_basis = {
        "implementation": "tools/event_corpus_manifest.py:source_route",
        "implementation_sha256": ROUTE_ORACLE_SHA256,
        "producer_pr_head": route_oracle.ROUTE_PRODUCER_PR_HEAD,
        "extractor_source_sha256": route_oracle.ROUTE_EXTRACTOR_SOURCE_SHA256,
        "release_equivalence_verified": False,
    }
    need(policy.get("route_expectation_basis") == expected_route_basis and
         sha256((ROOT / "tools/event_corpus_manifest.py").read_bytes()) == ROUTE_ORACLE_SHA256,
         "v0.7 source route oracle basis differs")
    return policy, policy_raw, json.loads(baseline_raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages_checkout", type=Path,
                        help="clean packages-feed checkout at the v0.7 pin")
    args = parser.parse_args(argv)
    try:
        policy, policy_raw, baseline = load_policy()
        result = verify_source_checkout(args.packages_checkout, policy, baseline, policy_raw)
        result["schema"] = "packages-feed-source-verification-v0.7"
        result["status"] = "source_oracle_verified"
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, SourcePolicyError, candidates.SelectorError, KeyError,
            TypeError, UnicodeDecodeError, subprocess.CalledProcessError) as exc:
        print(f"packages-feed v0.7 source verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
