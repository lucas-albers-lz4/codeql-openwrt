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
import sys

from tools.full_tree_candidates import (EXPECTED_MANIFESTS, SelectorError,
                                        blob_contents, compare, git)

POLICY_SCHEMA = "mvp-bounded-corpus-v0.6"
POLICY_SHA256 = EXPECTED_MANIFESTS[POLICY_SCHEMA]


def need(condition: bool, message: str) -> None:
    if not condition:
        raise SelectorError(message)


def source_route(source_path: str, installed_path: str, data: bytes) -> dict[str, str]:
    """Mirror the reviewed release extractor's route precedence from source.

    Any result differing from the frozen policy needs manual route review.
    """
    installed = installed_path.lstrip("/")
    extension = PurePosixPath(source_path).suffix
    if installed.startswith("usr/share/rpcd/ucode/") and installed != "usr/share/rpcd/ucode/":
        return {"classification": "plain", "reason": "rpcd_raw_mode_full_path"}
    if extension == ".ut":
        return {"classification": "markup", "reason": "ut_markup_extension"}
    first = data.split(b"\n", 1)[0].decode("utf-8", "replace")
    if first.startswith("#!"):
        words = first[2:].split()
        if words:
            interpreter = words[0]
            command = words[1:] if interpreter in ("/usr/bin/env", "/bin/env") else []
            if command and command[0] == "-S":
                command = command[1:]
            candidate = interpreter if interpreter.rsplit("/", 1)[-1] == "ucode" else command[0] if command else ""
            if candidate.strip("'\"").removeprefix("-S").strip("'\"").rsplit("/", 1)[-1] == "ucode":
                return {"classification": "plain", "reason": "ucode_shebang"}
    if any(line.lstrip().startswith(("{%", "{{", "{#"))
           for line in data.decode("utf-8", "replace").splitlines()):
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
    selected = [dict(row) for row in policy["selected"]]
    excluded = [dict(row) for row in policy["excluded"]]
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
    result = dict(policy)
    result.update(schema="mvp-incoming-event-corpus-v1",
                  pins={**policy["pins"], repo: head["commit"]},
                  selected=selected, excluded=excluded,
                  event={"repository": repo, "base_commit": base["commit"],
                         "head_commit": head["commit"], "head_tree": head["tree"],
                         "pr_number": receipt.get("pr_number"),
                         "policy_sha256": POLICY_SHA256},
                  counts={**policy["counts"], "selected": len(selected),
                          "route_classes": dict(Counter(row["expected_route"]["classification"]
                                                       for row in selected))},
                  status="source-first event oracle; no released scan or installed-byte proof")
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
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"event corpus manifest rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
