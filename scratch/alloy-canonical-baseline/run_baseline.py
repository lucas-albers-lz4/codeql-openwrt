#!/usr/bin/env python3
"""One-off, read-only canonical matrix for the deferred Alloy candidate.

This script evaluates fixture ACL sessions at existing policy gates. It does
not emit reports, grants, alloy_input.json, or producer: step4 records.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policy import (  # noqa: E402
    ubus_file_exec_kill as kill,
    ubus_file_exec_mounts as mounts,
    ubus_hostapd_wps_start as wps,
    ubus_luci_getmountpoints as points,
    ubus_rc_init as init,
    ubus_system_reboot as reboot,
)
from policy.oracle import (  # noqa: E402
    ACL_FIXTURE_FILES,
    OPENWRT_SHA,
    PROFILE,
    LUCI_SHA,
    RPCD_SHA,
    UHTTPD_SHA,
    Session,
    corpus_revision,
    parse_rpcd_logins,
    session_acls,
)
from policy.ubus_system_board import ACL_INDEX_FILE, load_board_catalog  # noqa: E402
from policy.ubus_file_exec import UBUS_STATUS_PERMISSION_DENIED  # noqa: E402

EXPERIMENT_BASE_SHA = "fa745e1c62f1f558bd8f6659a1d1040bb569cb96"


def acl_value(value: Any) -> Any:
    if value is None:
        return None
    if is_dataclass(value):
        return asdict(value)
    return str(value)


def classify_file_exec(result: Any) -> dict[str, str]:
    http_allowed = result.ubus_matched is not None
    http_denied = (
        result.ubus_matched is None
        and isinstance(result.jsonrpc_error, dict)
        and result.jsonrpc_error.get("name") == "ERROR_ACCESS"
    )
    cmdline_checks = [
        step
        for step in result.steps
        if step.get("step") == "rpc_file_access" and step.get("stage") == "cmdline"
    ]
    command_acl_denied = (
        result.outcome == "command_denied"
        and http_allowed
        and result.ubus_status == UBUS_STATUS_PERMISSION_DENIED
        and bool(cmdline_checks)
        and cmdline_checks[-1].get("result") is False
    )
    command_allowed = (
        result.outcome == "allow"
        and http_allowed
        and result.file_matched is not None
        and result.match_stage in {"executable", "cmdline"}
    )
    return {
        "http_gate": "allow" if http_allowed else "deny" if http_denied else "unknown",
        "command_gate": "allow" if command_allowed else "deny" if command_acl_denied else "unknown",
        "relation_outcome": (
            "allow"
            if command_allowed
            else "deny"
            if http_denied or command_acl_denied
            else "unknown"
        ),
    }


def matrix_cell(
    role: str, sid: str, evaluate, sessions, args: dict[str, Any]
) -> dict[str, Any]:
    result = evaluate(session_class=role, sid=sid, sessions=sessions, **args)
    cell: dict[str, Any] = {
        "role": role,
        "outcome": result.outcome,
        "request": args,
        "runtime_execution": "not_evaluated",
    }
    if hasattr(result, "ubus_matched"):
        classification = classify_file_exec(result)
        cell.update(
            {
                **classification,
                "ubus_acl_match": acl_value(result.ubus_matched),
                "command_acl_match": acl_value(result.file_matched),
                "command_match_stage": result.match_stage,
                "ubus_status": result.ubus_status,
                "jsonrpc_error": result.jsonrpc_error,
                "relevant_steps": result.steps,
            }
        )
    else:
        if result.outcome == "allow" and result.matched is not None:
            relation_outcome = "allow"
        elif (
            result.outcome == "deny"
            and isinstance(result.jsonrpc_error, dict)
            and result.jsonrpc_error.get("name") == "ERROR_ACCESS"
        ):
            relation_outcome = "deny"
        else:
            relation_outcome = "unknown"
        cell["http_gate"] = relation_outcome
        cell["relation_outcome"] = relation_outcome
        cell["acl_match"] = acl_value(result.matched)
        cell["jsonrpc_error"] = result.jsonrpc_error
        cell["relevant_steps"] = result.steps
    return cell


def main() -> int:
    logins = parse_rpcd_logins(
        (ROOT / "policy" / "fixtures" / "rpcd.config").read_text(encoding="utf-8")
    )
    roles = [login.username for login in logins if login.username != "root"]
    login_by_role = {login.username: login for login in logins}
    catalog = load_board_catalog()

    lock = json.loads((ROOT / "corpus" / "lock.json").read_text(encoding="utf-8"))
    expected_pins = {
        "profile": lock["profile"],
        "openwrt": lock["repos"]["openwrt"]["sha"],
        "luci": lock["repos"]["luci"]["sha"],
        "rpcd": lock["packages"]["rpcd"]["PKG_SOURCE_VERSION"],
        "uhttpd": lock["packages"]["uhttpd"]["PKG_SOURCE_VERSION"],
    }
    actual_pins = {
        "profile": PROFILE,
        "openwrt": OPENWRT_SHA,
        "luci": LUCI_SHA,
        "rpcd": RPCD_SHA,
        "uhttpd": UHTTPD_SHA,
    }
    pin_matches = {
        name: expected_pins[name] == actual_pins[name] for name in expected_pins
    }
    if not all(pin_matches.values()):
        print(
            "PIN_VALIDATION_FAILURE "
            + json.dumps(
                {"expected": expected_pins, "actual": actual_pins, "matches": pin_matches},
                sort_keys=True,
            )
        )
        return 2

    case_paths = [
        "policy/fixtures/ubus_luci_getmountpoints_cases.json",
        "policy/fixtures/ubus_file_exec_mounts_cases.json",
        "policy/fixtures/ubus_rc_init_cases.json",
        "policy/fixtures/ubus_system_reboot_cases.json",
        "policy/fixtures/ubus_hostapd_wps_start_cases.json",
        "policy/fixtures/ubus_file_exec_kill_cases.json",
    ]
    checked_case_pins = {}
    for relative in case_paths:
        fixture = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        fixture_pins = fixture.get("pins")
        if not isinstance(fixture_pins, dict):
            print(f"PIN_VALIDATION_FAILURE {relative}: missing pins object")
            return 2
        source_names = {"luci", "rpcd", "uhttpd"}
        checks = {
            name: fixture_pins.get(name) == expected_pins[name]
            for name in source_names
        }
        if "openwrt" in fixture_pins:
            checks["openwrt"] = fixture_pins.get("openwrt") == expected_pins["openwrt"]
        checks["profile"] = fixture_pins.get("profile") == expected_pins["profile"]
        if not all(checks.values()):
            print(
                f"PIN_VALIDATION_FAILURE {relative}: "
                + json.dumps({"pins": fixture_pins, "matches": checks}, sort_keys=True)
            )
            return 2
        checked_case_pins[relative] = checks

    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", EXPERIMENT_BASE_SHA, head],
        cwd=ROOT,
        check=True,
    )

    gate_specs = [
        {
            "gate": "mounts_read",
            "analysis_revision": points.ANALYSIS_REVISION,
            "world_name": "mounts_read",
            "load_world": points.load_luci_getmountpoints_world,
            "evaluate": points.evaluate_luci_getmountpoints,
            "args": {"object": "luci", "function": "getMountPoints"},
        },
        {
            "gate": "unmount_exec",
            "analysis_revision": mounts.ANALYSIS_REVISION,
            "world_name": "mount_exec",
            "load_world": mounts.load_mounts_world,
            "evaluate": mounts.evaluate_mounts_exec,
            "args": {"command": "/bin/umount", "params": ["/mnt/sda1"]},
        },
        {
            "gate": "block_exec",
            "analysis_revision": mounts.ANALYSIS_REVISION,
            "world_name": "mount_exec",
            "load_world": mounts.load_mounts_world,
            "evaluate": mounts.evaluate_mounts_exec,
            "args": {"command": "/sbin/block", "params": ["mount"]},
        },
        {
            "gate": "init_action",
            "analysis_revision": init.ANALYSIS_REVISION,
            "world_name": "init",
            "load_world": init.load_rc_init_world,
            "evaluate": init.evaluate_rc_init,
            "args": {"object": "rc", "function": "init"},
        },
        {
            "gate": "reboot",
            "analysis_revision": reboot.ANALYSIS_REVISION,
            "world_name": "reboot",
            "load_world": reboot.load_reboot_world,
            "evaluate": reboot.evaluate_system_reboot,
            "args": {"object": "system", "function": "reboot"},
        },
        {
            "gate": "wps_start",
            "analysis_revision": wps.ANALYSIS_REVISION,
            "world_name": "wps",
            "load_world": wps.load_hostapd_world,
            "evaluate": wps.evaluate_hostapd_wps_start,
            "args": {"object": "hostapd.wlan0", "function": "wps_start"},
        },
        {
            "gate": "kill_exec",
            "analysis_revision": kill.ANALYSIS_REVISION,
            "world_name": "kill",
            "load_world": kill.load_kill_world,
            "evaluate": kill.evaluate_kill_exec,
            "args": {"command": "/bin/kill", "params": ["-15", "42"]},
        },
    ]
    worlds = {}
    for spec in gate_specs:
        name = spec["world_name"]
        if name not in worlds:
            worlds[name] = spec["load_world"]()

    print("ALLOY_CANONICAL_BASELINE_BEGIN")
    pins = {
        "experiment_base_sha": EXPERIMENT_BASE_SHA,
        "execution_git_head": head,
        "github_event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "github_ref": os.environ.get("GITHUB_REF"),
        "corpus_revision": corpus_revision(ROOT),
        "profile": PROFILE,
        "sources": actual_pins,
        "pin_validation": pin_matches,
        "checked_case_pins": checked_case_pins,
        "fixture_sha256": {},
        "runner_sha256": {
            "script": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "workflow": hashlib.sha256(
                (ROOT / ".github" / "workflows" / "m2-policy.yml").read_bytes()
            ).hexdigest(),
        },
        "analysis_revisions": {
            spec["gate"]: spec["analysis_revision"] for spec in gate_specs
        },
    }
    fixture_paths = [
        "corpus/lock.json",
        "policy/fixtures/rpcd.config",
        *[f"policy/fixtures/{name}" for name in ACL_FIXTURE_FILES],
        f"policy/fixtures/{ACL_INDEX_FILE}",
        *case_paths,
    ]
    for relative in fixture_paths:
        pins["fixture_sha256"][relative] = hashlib.sha256(
            (ROOT / relative).read_bytes()
        ).hexdigest()
    print("PINS " + json.dumps(pins, sort_keys=True))
    print(
        "SCOPE "
        + json.dumps(
            {
                "roles": "non-root fixture login classes only; no role unions",
                "question": "one class allows getMountPoints, umount, block mount and excludes rc.init, reboot, WPS start, kill",
                "runtime_execution": "not evaluated; gate allow is not command execution or a safety claim",
                "matrix_format": "one JSON object per role/gate cell follows",
            },
            sort_keys=True,
        )
    )

    summaries: dict[str, dict[str, str]] = {role: {} for role in roles}
    for index, role in enumerate(roles, start=1):
        sid_number = index
        sid = f"{sid_number:032x}"
        while any(sid in world for world in worlds.values()):
            sid_number += 1
            sid = f"{sid_number:032x}"
        login = login_by_role[role]
        session = Session(role, sid, login, session_acls(login, catalog))
        for world in worlds.values():
            for old_sid, old_session in list(world.items()):
                if old_session.session_class == role:
                    del world[old_sid]
            world[sid] = session

        for spec in gate_specs:
            cell = matrix_cell(
                role,
                sid,
                spec["evaluate"],
                worlds[spec["world_name"]],
                spec["args"],
            )
            cell["gate"] = spec["gate"]
            cell["analysis_revision"] = spec["analysis_revision"]
            summaries[role][spec["gate"]] = cell["relation_outcome"]
            print("CELL " + json.dumps(cell, sort_keys=True))

    positive = ("mounts_read", "unmount_exec", "block_exec")
    negative = ("init_action", "reboot", "wps_start", "kill_exec")
    candidates = []
    inconclusive = []
    for role, cells in summaries.items():
        if not all(gate in cells for gate in positive + negative):
            inconclusive.append(role)
        elif all(cells[gate] == "allow" for gate in positive) and all(
            cells[gate] == "deny" for gate in negative
        ):
            candidates.append(role)
        elif any(
            cells[gate] not in {"allow", "deny"}
            for gate in positive + negative
        ):
            inconclusive.append(role)

    print(
        "RELATION_RESULT "
        + json.dumps(
            {
                "candidate_roles": candidates,
                "inconclusive_roles": inconclusive,
                "candidate_expected_by_handwritten_fixture": "luci-mod-system-mounts",
                "interpretation": "canonical evaluator result only; not an independent source oracle or added-value result",
            },
            sort_keys=True,
        )
    )
    print("ALLOY_CANONICAL_BASELINE_END")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
