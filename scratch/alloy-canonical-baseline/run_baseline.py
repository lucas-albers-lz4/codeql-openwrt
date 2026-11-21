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
    AclEntry,
    Session,
    acl_match,
    corpus_revision,
    login_test_permission,
    parse_rpcd_logins,
    load_acl_file,
    session_acls,
)
from policy.ubus_system_board import ACL_INDEX_FILE  # noqa: E402
from policy.ubus_file_exec import UBUS_STATUS_PERMISSION_DENIED  # noqa: E402

EXPERIMENT_BASE_SHA = "fa745e1c62f1f558bd8f6659a1d1040bb569cb96"
APP_ACL_FILES = ("luci-app-firewall.json", "luci-app-package-manager.json")
ALL_ACL_FILES = tuple(dict.fromkeys((*ACL_FIXTURE_FILES, ACL_INDEX_FILE, *APP_ACL_FILES)))
EXPECTED_GETMOUNTPOINTS_GROUPS = {
    "luci-mod-status-index-storage",
    "luci-mod-system-mounts",
    "luci-app-package-manager",
}


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


def acl_entry_set(entries: list[AclEntry]) -> set[tuple[str, str, str, str, str, str]]:
    return {
        (entry.group, entry.perm, entry.scope, entry.object, entry.function, entry.source)
        for entry in entries
    }


def load_complete_acl_catalog(fixtures: Path) -> tuple[list[AclEntry], set[str]]:
    catalog: list[AclEntry] = []
    groups: set[str] = set()
    for name in ALL_ACL_FILES:
        path = fixtures / name
        document = json.loads(path.read_text(encoding="utf-8"))
        groups.update(document)
        catalog.extend(load_acl_file(path))
    return catalog, groups


def validate_acl_fixture_sources(fixtures: Path, lock: dict[str, Any]) -> dict[str, Any]:
    provenance_path = fixtures / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("profile") != lock["profile"]:
        raise ValueError("ACL provenance profile differs from corpus lock")
    records = provenance.get("files", {})
    expected_names = set(ALL_ACL_FILES) | {"rpcd.config"}
    if set(records) != expected_names:
        raise ValueError(
            "ACL provenance does not enumerate every ACL JSON and rpcd config: "
            f"missing={sorted(expected_names - set(records))} "
            f"extra={sorted(set(records) - expected_names)}"
        )
    fixture_hashes: dict[str, str] = {}
    luci_sha = lock["repos"]["luci"]["sha"]
    rpcd_sha = lock["packages"]["rpcd"]["PKG_SOURCE_VERSION"]
    for name in ALL_ACL_FILES:
        raw = (fixtures / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        record = records[name]
        if record.get("sha256") != digest:
            raise ValueError(f"ACL fixture does not match provenance SHA-256: {name}")
        source_sha = rpcd_sha if name == "unauthenticated.json" else luci_sha
        if record.get("sha") != source_sha:
            raise ValueError(f"ACL fixture source revision differs from lock: {name}")
        fixture_hashes[f"policy/fixtures/{name}"] = digest
    rpcd_record = records["rpcd.config"]
    if rpcd_record.get("sha") != lock["repos"]["openwrt"]["sha"]:
        raise ValueError("rpcd config provenance revision differs from OpenWrt lock")
    if not rpcd_record.get("stock_sha256"):
        raise ValueError("rpcd config provenance lacks stock input hash")
    fixture_hashes["policy/fixtures/provenance.json"] = hashlib.sha256(
        provenance_path.read_bytes()
    ).hexdigest()
    return fixture_hashes


def session_for_gate(
    role: str,
    sid: str,
    login: Any,
    world: dict[str, Session],
    complete_catalog: list[AclEntry],
    source_groups: set[str],
) -> tuple[dict[str, Session] | None, str | None, dict[str, Any]]:
    """Preserve a gate's native session; synthesize only from a complete ACL catalog."""
    matches = [session for session in world.values() if session.session_class == role]
    referenced = {
        group
        for group in login.read + login.write
        if group and group != "*" and not group.startswith("!")
    }
    missing_groups = sorted(referenced - source_groups)
    detail: dict[str, Any] = {
        "native_session_present": bool(matches),
        "native_session_count": len(matches),
        "referenced_acl_groups": sorted(referenced),
        "missing_acl_groups": missing_groups,
        "full_catalog_entry_count": None,
    }
    if missing_groups:
        detail["scope_reason"] = "login_acl_group_missing_from_pinned_sources"
        return None, None, detail
    expected = session_acls(login, complete_catalog)
    detail["full_catalog_entry_count"] = len(expected)
    if len(matches) > 1:
        detail["scope_reason"] = "ambiguous_native_sessions"
        return None, None, detail
    if matches:
        native = matches[0]
        native_set = acl_entry_set(native.acls)
        expected_set = acl_entry_set(expected)
        detail.update(
            {
                "session_source": "native_gate_world",
                "native_acl_matches_full_catalog": native_set == expected_set,
                "native_only_acl_entries": sorted(native_set - expected_set),
                "full_catalog_only_acl_entries": sorted(expected_set - native_set),
            }
        )
        if native_set != expected_set:
            detail["scope_reason"] = "native_session_acl_scope_differs_from_full_pinned_catalog"
        return dict(world), native.sid, detail
    detail["session_source"] = "full_pinned_acl_catalog"
    detail["native_acl_matches_full_catalog"] = None
    if not login.read and not login.write:
        detail["scope_reason"] = "login_has_no_acl_scope"
        return None, None, detail
    sessions = dict(world)
    while sid in sessions:
        sid = f"{int(sid, 16) + 1:032x}"
    sessions[sid] = Session(role, sid, login, expected)
    return sessions, sid, detail


def matrix_cell(
    role: str,
    sid: str | None,
    evaluate,
    sessions: dict[str, Session] | None,
    args: dict[str, Any],
    session_detail: dict[str, Any],
) -> dict[str, Any]:
    cell: dict[str, Any] = {
        "role": role,
        "outcome": "not_evaluated",
        "request": args,
        "runtime_execution": "not_evaluated",
        "scope": session_detail,
    }
    if sessions is None or sid is None:
        cell.update(
            {
                "http_gate": "unknown",
                "command_gate": "unknown",
                "relation_outcome": "unknown",
                "scope_complete": False,
                "scope_reason": session_detail.get("scope_reason", "session_not_constructible"),
                "relevant_steps": [],
            }
        )
        return cell
    result = evaluate(session_class=role, sid=sid, sessions=sessions, **args)
    cell["outcome"] = result.outcome
    scope_complete = session_detail.get("session_source") == "full_pinned_acl_catalog" or session_detail.get(
        "native_acl_matches_full_catalog"
    ) is True
    cell["scope_complete"] = scope_complete
    if hasattr(result, "ubus_matched"):
        classification = classify_file_exec(result)
        cell.update(
            {
                **classification,
                "raw_http_gate": classification["http_gate"],
                "raw_command_gate": classification["command_gate"],
                "ubus_acl_match": acl_value(result.ubus_matched),
                "command_acl_match": acl_value(result.file_matched),
                "command_match_stage": result.match_stage,
                "ubus_status": result.ubus_status,
                "jsonrpc_error": result.jsonrpc_error,
                "relevant_steps": result.steps,
            }
        )
        cell["raw_relation_outcome"] = classification["relation_outcome"]
        if not scope_complete:
            cell["relation_outcome"] = "unknown"
            cell["http_gate"] = "unknown"
            cell["command_gate"] = "unknown"
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
        cell["raw_http_gate"] = relation_outcome
        cell["acl_match"] = acl_value(result.matched)
        cell["jsonrpc_error"] = result.jsonrpc_error
        cell["relevant_steps"] = result.steps
        cell["raw_relation_outcome"] = relation_outcome
    if not scope_complete:
        cell["relation_outcome"] = "unknown"
        cell["scope_reason"] = session_detail.get(
            "scope_reason", "native_session_scope_not_verified"
        )
        if hasattr(result, "ubus_matched"):
            cell["http_gate"] = "unknown"
            cell["command_gate"] = "unknown"
        else:
            cell["http_gate"] = "unknown"
    return cell


def main() -> int:
    logins = parse_rpcd_logins(
        (ROOT / "policy" / "fixtures" / "rpcd.config").read_text(encoding="utf-8")
    )
    roles = [login.username for login in logins if login.username != "root"]
    login_by_role = {login.username: login for login in logins}
    lock = json.loads((ROOT / "corpus" / "lock.json").read_text(encoding="utf-8"))
    acl_fixture_hashes = validate_acl_fixture_sources(ROOT / "policy" / "fixtures", lock)
    fixture_acl_files = sorted(
        path.name
        for path in (ROOT / "policy" / "fixtures").glob("luci-*.json")
    )
    discovered_acl_files = set(fixture_acl_files) | {"unauthenticated.json"}
    if discovered_acl_files != set(ALL_ACL_FILES):
        print(
            "ACL_FIXTURE_COVERAGE_FAILURE "
            + json.dumps(
                {
                    "expected": sorted(ALL_ACL_FILES),
                    "discovered": sorted(discovered_acl_files),
                },
                sort_keys=True,
            )
        )
        return 2
    catalog, catalog_groups = load_complete_acl_catalog(ROOT / "policy" / "fixtures")
    source_group_references = {
        group
        for login in login_by_role.values()
        if login.username != "root"
        for group in login.read + login.write
        if group and group != "*" and not group.startswith("!")
    }
    missing_source_groups = sorted(source_group_references - catalog_groups)
    if missing_source_groups:
        print(
            "ACL_GROUP_SCOPE_INCOMPLETE "
            + json.dumps({"missing_groups": missing_source_groups}, sort_keys=True)
        )

    mount_read_entries = [
        entry
        for entry in catalog
        if entry.perm == "read"
        and entry.scope == "ubus"
        and acl_match(entry.object, entry.function, "luci", "getMountPoints")
    ]
    source_mount_read_groups = {entry.group for entry in mount_read_entries}
    source_mount_read_roles = sorted(
        role
        for role in roles
        if any(
            entry.perm == "read"
            and login_test_permission(login_by_role[role], "read", entry.group)
            for entry in mount_read_entries
        )
    )
    if source_mount_read_groups != EXPECTED_GETMOUNTPOINTS_GROUPS:
        print(
            "SOURCE_OVERLAP_VALIDATION_FAILURE "
            + json.dumps(
                {
                    "expected_groups": sorted(EXPECTED_GETMOUNTPOINTS_GROUPS),
                    "actual_groups": sorted(source_mount_read_groups),
                },
                sort_keys=True,
            )
        )
        return 3

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
        "acl_provenance": {
            "profile": lock["profile"],
            "source_groups": sorted(catalog_groups),
            "login_group_references": sorted(source_group_references),
            "missing_login_groups": missing_source_groups,
            "mounts_read_source_groups": sorted(source_mount_read_groups),
            "mounts_read_source_roles": source_mount_read_roles,
            "catalog_files": list(ALL_ACL_FILES),
        },
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
        "policy/fixtures/provenance.json",
        "policy/fixtures/rpcd.config",
        *[f"policy/fixtures/{name}" for name in ALL_ACL_FILES],
        *case_paths,
    ]
    for relative in fixture_paths:
        pins["fixture_sha256"][relative] = hashlib.sha256(
            (ROOT / relative).read_bytes()
        ).hexdigest()
    if any(
        pins["fixture_sha256"].get(path) != digest
        for path, digest in acl_fixture_hashes.items()
    ):
        print("ACL_FIXTURE_HASH_VALIDATION_FAILURE " + json.dumps(acl_fixture_hashes, sort_keys=True))
        return 2
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
    cells_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for index, role in enumerate(roles, start=1):
        login = login_by_role[role]
        for spec in gate_specs:
            base_world = worlds[spec["world_name"]]
            candidate_sid = f"{index:032x}"
            eval_world, sid, session_detail = session_for_gate(
                role,
                candidate_sid,
                login,
                base_world,
                catalog,
                catalog_groups,
            )
            cell = matrix_cell(
                role,
                sid,
                spec["evaluate"],
                eval_world,
                spec["args"],
                session_detail,
            )
            cell["gate"] = spec["gate"]
            cell["analysis_revision"] = spec["analysis_revision"]
            summaries[role][spec["gate"]] = cell["relation_outcome"]
            cells_by_key[(role, spec["gate"])] = cell
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

    mount_read_scope_complete = all(
        cells_by_key[(role, "mounts_read")].get("scope_complete") is True
        and cells_by_key[(role, "mounts_read")]["relation_outcome"] in {"allow", "deny"}
        for role in roles
    )
    observed_mount_read_roles = sorted(
        role
        for role in roles
        if cells_by_key[(role, "mounts_read")]["relation_outcome"] == "allow"
    )
    mount_read_known_mismatch = any(
        cells_by_key[(role, "mounts_read")].get("scope_complete") is True
        and cells_by_key[(role, "mounts_read")]["relation_outcome"] in {"allow", "deny"}
        and cells_by_key[(role, "mounts_read")]["relation_outcome"]
        != ("allow" if role in source_mount_read_roles else "deny")
        for role in roles
    )
    mount_read_validation = (
        "mismatch"
        if mount_read_known_mismatch
        else "unknown"
        if not mount_read_scope_complete
        else "validated"
    )
    expected_candidate_roles = ["luci-mod-system-mounts"]
    candidate_validation = (
        "inconclusive"
        if inconclusive
        else "validated"
        if candidates == expected_candidate_roles
        else "mismatch"
    )
    validation_failure = mount_read_validation == "mismatch" or candidate_validation == "mismatch"

    print(
        "RELATION_RESULT "
        + json.dumps(
            {
                "candidate_roles": candidates,
                "inconclusive_roles": inconclusive,
                "candidate_expected_by_handwritten_fixture": expected_candidate_roles,
                "candidate_validation": candidate_validation,
                "mounts_read_source_expected_roles": source_mount_read_roles,
                "mounts_read_observed_allow_roles": observed_mount_read_roles,
                "mounts_read_overlap_validation": mount_read_validation,
                "interpretation": "canonical evaluator relation with native-session comparison and complete pinned fixture reconstruction for absent sessions; no runtime execution or added-value claim",
            },
            sort_keys=True,
        )
    )
    print("ALLOY_CANONICAL_BASELINE_END")
    return 3 if validation_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
