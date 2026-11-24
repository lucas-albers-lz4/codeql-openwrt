#!/usr/bin/env python3
"""Prepare a source-first corpus oracle for one reviewed incoming PR head.

This prepares an input contract; it does not run CodeQL or authenticate a
released producer. The frozen v0.6 policy remains the baseline for paths,
installation projections and package conditions.
"""
from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys

from tools.full_tree_candidates import (EXPECTED_MANIFESTS, SelectorError,
                                        blob_contents, compare, git)

POLICY_SCHEMA = "mvp-bounded-corpus-v0.6"
POLICY_SHA256 = EXPECTED_MANIFESTS[POLICY_SCHEMA]
ROUTE_PRODUCER_PR_HEAD = "d39b1e19eb3c9cb63b493f44f2be2e95d89c17f4"
ROUTE_EXTRACTOR_SOURCE_SHA256 = "bc54d2fc6e4dfba095977053d92275c3474bb01ff7e6da7c5301002bde701a11"
RUST_WHITESPACE = frozenset("\t\n\v\f\r \u0085\u00a0\u1680\u2028\u2029\u202f\u205f\u3000" +
                           "".join(chr(code) for code in range(0x2000, 0x200b)))


def need(condition: bool, message: str) -> None:
    if not condition:
        raise SelectorError(message)


def rust_words(text: str) -> list[str]:
    words, current = [], []
    for char in text:
        if char in RUST_WHITESPACE:
            if current:
                words.append("".join(current))
                current.clear()
        else:
            current.append(char)
    if current:
        words.append("".join(current))
    return words


def rust_trim_start(text: str) -> str:
    index = 0
    while index < len(text) and text[index] in RUST_WHITESPACE:
        index += 1
    return text[index:]


def reviewed_owner_roots(policy: dict, repo: str) -> set[str]:
    roots = set()
    for row in policy["selected"]:
        if row["repo"] != repo:
            continue
        parts = PurePosixPath(row["source_path"]).parts
        if repo == "luci" and len(parts) >= 2:
            roots.add("/".join(parts[:2]))
        elif repo == "openwrt" and len(parts) >= 3 and parts[:2] == ("target", "linux"):
            roots.add("/".join(parts[:3]))
        elif repo == "openwrt":
            for index, part in enumerate(parts):
                if part == "files" or part.startswith(("files-", "files_")):
                    roots.add("/".join(parts[:index]))
                    break
    return roots


def relevant_recipe_changes(policy: dict, repo: str, changed_paths: list[str]) -> list[str]:
    roots = reviewed_owner_roots(policy, repo)
    ancestor_files = set()
    for root in roots:
        parts = PurePosixPath(root).parts
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            ancestor_files.update((prefix + "/Makefile", prefix + "/Config.in"))
    relevant = []
    for path in changed_paths:
        name = PurePosixPath(path).name
        policy_input = name in ("Makefile", "Config.in", "luci.mk") or name.startswith("Kconfig") or name.endswith(".mk")
        if not policy_input:
            continue
        if (path in ancestor_files or path in ("rules.mk", "Makefile", "Config.in") or
                path.startswith("include/") or
                (repo == "luci" and path == "luci.mk") or
                any(path.startswith(root + "/") for root in roots)):
            relevant.append(path)
    return sorted(set(relevant))


def changed_paths(checkout: Path, base: str, head: str) -> list[str]:
    raw = subprocess.check_output(["git", "-C", str(checkout), "diff", "--no-renames", "--name-only", "-z",
                                   base, head], stderr=subprocess.PIPE)
    return [path.decode("utf-8", "surrogateescape") for path in raw.split(b"\0") if path]


def source_route(source_path: str, installed_path: str, data: bytes) -> dict[str, str]:
    """Mirror the reviewed release extractor's route precedence from source.

    Any result differing from the frozen policy needs manual route review.
    """
    installed = installed_path.lstrip("/")
    extension = PurePosixPath(installed).suffix
    if installed.startswith("usr/share/rpcd/ucode/") and installed != "usr/share/rpcd/ucode/":
        return {"classification": "plain", "reason": "rpcd_raw_mode_full_path"}
    if extension == ".ut":
        return {"classification": "markup", "reason": "ut_markup_extension"}
    first = data.split(b"\n", 1)[0].decode("utf-8", "replace")
    if first.startswith("#!"):
        words = rust_words(first[2:])
        if words:
            interpreter = words[0]
            command = words[1:] if interpreter in ("/usr/bin/env", "/bin/env") else []
            if command and command[0] == "-S":
                command = command[1:]
            candidate = interpreter if interpreter.rsplit("/", 1)[-1] == "ucode" else command[0] if command else ""
            if candidate.strip("'\"").removeprefix("-S").strip("'\"").rsplit("/", 1)[-1] == "ucode":
                return {"classification": "plain", "reason": "ucode_shebang"}
    lines = data.decode("utf-8", "replace").split("\n")
    if any(rust_trim_start(line.removesuffix("\r")).startswith(("{%", "{{", "{#"))
           for line in lines):
        return {"classification": "markup", "reason": "markup_tag_content"}
    if extension in (".uc", ".ucode"):
        return {"classification": "plain", "reason": "ucode_extension"}
    if installed.startswith("usr/share/ucode/"):
        return {"classification": "uncertain", "reason": "unclassified_usr_share_ucode_path"}
    raise SelectorError(f"source has no reviewed extractor route: {source_path}")


def build(policy: dict, receipt: dict, inventory: dict, checkout: Path) -> dict:
    repo = receipt.get("repository")
    need(repo in ("openwrt", "luci"), "unsupported event repository")
    head = receipt.get("source", {})
    base = receipt.get("base", {})
    need(receipt.get("status") == "identities_resolved_only" and
         isinstance(head, dict) and isinstance(base, dict), "invalid event identity receipt")
    need(inventory.get("status") == "inventory_ready" and inventory.get("fail_closed") is False,
         "candidate inventory requires review")
    need(inventory.get("repository") == repo and
         inventory.get("head_commit") == head.get("commit") and
         inventory.get("head_tree") == head.get("tree") and
         inventory.get("base_commit") == base.get("commit") and
         inventory.get("policy_sha256") == POLICY_SHA256,
         "candidate inventory and event identities differ")
    need(git(checkout, "rev-parse", "HEAD") == head["commit"] and
         git(checkout, "rev-parse", f"{head['commit']}^{{tree}}") == head["tree"] and
         not git(checkout, "status", "--porcelain=v1"), "event checkout changed")
    recipe_changes = relevant_recipe_changes(policy, repo,
                                             changed_paths(checkout, base["commit"], head["commit"]))
    need(not recipe_changes, "reviewed recipe/config input changed: " + ", ".join(recipe_changes))
    historical_fields = {"prior_claims", "prior_local_extraction", "route_support", "source_oracle"}
    selected = [{key: value for key, value in row.items() if key not in historical_fields}
                for row in policy["selected"]]
    excluded = [{key: value for key, value in row.items() if key not in historical_fields}
                for row in policy["excluded"]]
    selected_by_path = {row["source_path"]: row for row in selected if row["repo"] == repo}
    excluded_by_path = {row["source_path"]: row for row in excluded if row["repo"] == repo}
    need(len(selected_by_path) == sum(row["repo"] == repo for row in selected) and
         len(excluded_by_path) == sum(row["repo"] == repo for row in excluded) and
         not set(selected_by_path).intersection(excluded_by_path), "duplicate reviewed source identity")
    events = inventory.get("events")
    need(isinstance(events, list), "candidate events missing")
    heads = {}
    for event in events:
        path = event.get("source_path")
        info = event.get("head")
        need(isinstance(path, str) and path not in heads and isinstance(info, dict),
             "candidate head missing or duplicated")
        allowed_events = (["selected_content_changed_scan_eligible"]
                          if path in selected_by_path else [])
        need(event.get("status") in ("selected", "excluded") and
             event.get("events") in ([], allowed_events) and info.get("source_path") == path,
             "candidate event needs review")
        heads[path] = info
    need(set(heads) == set(selected_by_path) | set(excluded_by_path),
         "head candidate identities differ from reviewed policy")
    blobs = blob_contents(checkout, sorted({info["git_blob"] for info in heads.values()}))
    for path, info in heads.items():
        data = blobs[info["git_blob"]]
        need(hashlib.sha256(data).hexdigest() == info["sha256"] and
             git(checkout, "rev-parse", f"{head['commit']}:{path}") == info["git_blob"],
             f"event Git blob/content mismatch: {path}")
        if path in selected_by_path:
            row = selected_by_path[path]
            route = source_route(path, row["proposed_installed_path"], data)
            need(route == row["expected_route"], f"selected source route changed: {path}")
            row.update(source_commit=head["commit"], source_sha256=info["sha256"],
                       git_blob=info["git_blob"])
        else:
            row = excluded_by_path[path]
            need(row["sha256"] == info["sha256"], f"excluded source changed: {path}")
            row.update(source_commit=head["commit"], git_blob=info["git_blob"])
    installed = [row["proposed_installed_path"] for row in selected]
    need(len(installed) == len(set(installed)), "selected installed-path collision")
    result = {
        "schema": "mvp-incoming-event-corpus-v1",
        "pins": {**policy["pins"], repo: head["commit"]},
        "selected": selected,
        "excluded": excluded,
        "event": {"repository": repo, "base_commit": base["commit"],
                  "head_commit": head["commit"], "head_tree": head["tree"],
                  "pr_number": receipt.get("pr_number"),
                  "policy_sha256": POLICY_SHA256,
                  "route_oracle_basis": {"producer_pr_head": ROUTE_PRODUCER_PR_HEAD,
                                         "extractor_source_sha256": ROUTE_EXTRACTOR_SOURCE_SHA256,
                                         "release_equivalence_verified": False}},
        "counts": {"selected": len(selected), "excluded": len(excluded),
                   "repo_selected": dict(Counter(row["repo"] for row in selected)),
                   "route_classes": dict(Counter(row["expected_route"]["classification"]
                                                for row in selected))},
        "selection_scope": policy.get("selection_scope"),
        "baseline_source_evidence": policy.get("source_evidence", []),
        "boundaries": ["Reviewed installation projections and package conditions are frozen v0.6 policy assumptions; selected-owner and shared recipe/config changes fail closed, but arbitrary upstream build effects are not proven absent.",
                       "Other repositories remain at their frozen v0.6 source pins.",
                       "Selected source hashes and routes are derived from event-head Git blobs before extraction; no actual installed bytes are verified.",
                       "The route oracle mirrors a producer PR source revision; equivalence to an eventual immutable release is not established.",
                       "No released CodeQL scan or consumer handoff has run."],
        "status": "source-first event oracle; recipe policy and installed bytes unverified",
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("event_receipt", type=Path)
    parser.add_argument("candidate_inventory", type=Path)
    parser.add_argument("head_checkout", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        raw = args.policy.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, "frozen v0.6 policy digest drift")
        policy = json.loads(raw)
        need(policy.get("schema") == POLICY_SCHEMA, "frozen v0.6 policy schema drift")
        receipt = json.loads(args.event_receipt.read_bytes())
        inventory = json.loads(args.candidate_inventory.read_bytes())
        fresh = compare(args.head_checkout, inventory["base_commit"],
                        inventory["head_commit"], policy, raw, receipt["repository"])
        need(fresh == inventory, "candidate report differs from fresh Git inventory")
        result = build(policy, receipt, inventory, args.head_checkout)
        result["event"]["identity_receipt_sha256"] = hashlib.sha256(args.event_receipt.read_bytes()).hexdigest()
        result["event"]["candidate_inventory_sha256"] = hashlib.sha256(args.candidate_inventory.read_bytes()).hexdigest()
        result["event"]["route_oracle_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"schema": result["schema"], "event": result["event"],
                          "selected": len(result["selected"]),
                          "manifest_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()},
                         sort_keys=True))
        return 0
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError,
            subprocess.CalledProcessError) as exc:
        print(f"event corpus manifest rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
