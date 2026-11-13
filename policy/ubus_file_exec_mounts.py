#!/usr/bin/env python3
"""ubus file.exec oracle for luci-mod-system-mounts umount/block.

Oracle transcribed from pinned source, not from a live daemon:

* uhttpd ``ubus.c`` ``parse_call_params`` / ``uh_ubus_allowed``
  @ ``93b05e0b65d91c23c5aa8fdde378df1f174ec71d``
* rpcd-mod-file ``file.c`` ``rpc_file_exec`` / ``rpc_file_exec_run`` /
  ``rpc_file_exec_lookup`` / ``rpc_canonicalize_path`` / ``rpc_file_access``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-system ACLs and ``fs.exec`` callers @ luci ``b2e0be4b``

Bounded to ubus ``file.exec`` (rpcd-mod-file) of ``/bin/umount`` and
``/sbin/block`` the pinned mounts view reaches via LuCI ``fs.exec``
(not ``fs.exec_direct`` / cgi-exec):

``uh_ubus_allowed`` → ``session.access`` scope=ubus object=file function=exec
then ``rpc_file_access(sid, executable, exec)`` or, on miss,
``rpc_file_access(sid, cmdline, exec)``. Executable is checked first.

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after ubus-file-exec-kill-v1
and upserts synthetic effects into ``reports/handler_effects.json``.
Does not emit dispatcher, ``authorization_violation``, or ``path_found``.
Does not invent luci-ssl grants. Does not fork ``execv``. Does not
staff cgi-io. Does not treat ``shellquote`` / ``basename`` as sanitizers.
``rpc_file_exec_lookup`` PATH search is not a live stat: only the
inventoried absolute paths below are treated as found.
ubus-file-exec-v1 remains luci-mod-status iptables ``-Z`` / routes ``ip``.
ubus-file-exec-ifup-v1 remains luci-mod-network-config ifup/ifdown/wifi.
ubus-file-exec-kill-v1 remains luci-mod-status-processes ``/bin/kill``.
The existing luci-mod-system-mounts fixture is already list read/write
(getBlockDevices / setBlockDetect); this slice reuses that session.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional

from .cgi_backup import FLASH_SESSION_CLASS
from .cgi_exec_status import FIREWALL_SESSION_CLASS
from .oracle import (
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    UHTTPD_SHA,
    corpus_revision,
    dump_json,
)
from .ubus_file_exec import (
    RPCD_SHA,
    UBUS_INGRESS,
    UBUS_METHOD,
    UBUS_OBJECT,
    FileExecResult,
    evaluate_file_exec as evaluate_shared_file_exec,
    load_file_exec_world,
)
from .ubus_file_exec_ifup import NETWORK_READ_SESSION_CLASS

ANALYSIS_REVISION = "policy:ubus-file-exec-mounts-v1"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

MOUNTS_SESSION_CLASS = "luci-mod-system-mounts"

UMOUNT = "/bin/umount"
BLOCK = "/sbin/block"

COMMANDS: dict[str, dict[str, Any]] = {
    "umount": {
        "fs_path": UMOUNT,
        "params": ["/mnt/sda1"],
        "delegated": MOUNTS_SESSION_CLASS,
        "expectation_id": "luci-mod-system-mounts-umount",
        "asset_id": "command:umount",
        "caller": "mounts.js handleUmount fs.exec('/bin/umount', [path])",
        "entrypoint_id": f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{UMOUNT}",
    },
    "block": {
        "fs_path": BLOCK,
        "params": ["mount"],
        "delegated": MOUNTS_SESSION_CLASS,
        "expectation_id": "luci-mod-system-mounts-block",
        "asset_id": "command:block",
        "caller": "mounts.js handleMountAll fs.exec('/sbin/block', ['mount'])",
        "entrypoint_id": f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{BLOCK}",
    },
}

FOUND_PATHS = {spec["fs_path"] for spec in COMMANDS.values()}
CASES_PATH = FIXTURES / "ubus_file_exec_mounts_cases.json"
SYNTHETIC_FILE_EXEC_CLASSES = frozenset(
    {
        MOUNTS_SESSION_CLASS,
        FLASH_SESSION_CLASS,
        FIREWALL_SESSION_CLASS,
        NETWORK_READ_SESSION_CLASS,
    }
)

UNKNOWN_LIVE = (
    "Live uhttpd, rpcd, and rpcd-mod-file were not executed; decisions are "
    "transcribed from pinned C and ACL JSON."
)
UNKNOWN_LOOKUP = (
    "rpc_file_exec_lookup PATH search and live stat(2) are not modeled. This "
    "oracle treats only the inventoried absolute command paths as found."
)
UNKNOWN_EXECV = (
    "execv of the command, helper-internal argv after the file ACL, and "
    "file.exec of commands other than inventoried /bin/umount and "
    "/sbin/block are not modeled."
)
UNKNOWN_UNSTAFFED = (
    "cgi-io cgi-exec stays on policy:cgi-exec-v1 / cgi-exec-file-v1 / "
    "cgi-exec-status-v1. luci-mod-status iptables -Z / routes ip stay on "
    "policy:ubus-file-exec-v1. luci-mod-network-config ifup/ifdown/wifi stay "
    "on policy:ubus-file-exec-ifup-v1. luci-mod-status-processes /bin/kill "
    "stays on policy:ubus-file-exec-kill-v1. luci-mod-network diagnostics "
    "ping/traceroute use fs.exec_direct without a cgi-io grant on "
    "luci-mod-network-diagnostics, so they are not this slice. crontab.js "
    "fs.exec of cron reload has file.exec of the cmdline but ubus file.write "
    "not file.exec. luci-mod-system flash.js sysupgrade/firstboot stay "
    "unstaffed. Track A is unstaffed. dispatcher is not this slice."
)
UNKNOWN_PLUGIN_SID = (
    "rpc_file_access returns true when ubus_rpc_session is absent (local "
    "ubus callers). HTTP /ubus injects the parsed SID after uh_ubus_allowed; "
    "this oracle does not model the plugin skip as an allow."
)
ASSUMPTION_CONJUNCT = (
    "uhttpd uh_ubus_allowed requires session.access scope=ubus object=file "
    "function=exec (uhttpd omits scope). rpcd-mod-file then requires "
    "session.access scope=file of the canonicalized executable or, on miss, "
    "of the cmdline. A ubus file.exec grant is not authorization to run an "
    "arbitrary command."
)
ASSUMPTION_ORDER = (
    "rpc_file_exec_run checks the executable file ACL first, then the "
    "cmdline. That is the reverse of cgi-io main_exec. Inventoried luci-ssl "
    "ACLs grant the bare /bin/umount and /sbin/block executables, so extra "
    "tokens match at the executable stage as intended_access for the mounts "
    "fixture, not authorization_violation and not a PoC."
)
ASSUMPTION_NOT_SANITIZER = (
    "shellquote and basename are not sanitizers. rpc_canonicalize_path is a "
    "textual path normalizer, not a taint sanitizer."
)
ASSUMPTION_NO_EXECV = (
    "This oracle does not fork execv or run the command body."
)
ASSUMPTION_NOT_LUCI = (
    "These commands are not luci object methods. Do not invent a luci "
    "object grant. Callers at luci b2e0be4b use fs.exec → ubus file.exec. "
    "getBlockDevices / setBlockDetect popen/system of /sbin/block stay on "
    "the luci object grants."
)
ASSUMPTION_ENV = (
    "rpc_file_exec_run returns PERMISSION_DENIED when both SID and env are "
    "present. Inventoried callers do not pass env."
)
ASSUMPTION_EXISTING_FIXTURE = (
    "The luci-mod-system-mounts fixture is already list read/write for "
    "luci.getBlockDevices / luci.setBlockDetect. This slice reuses that "
    "session; it does not invent a second mounts login."
)


def identify_command(canon: Optional[str], params: Optional[list[str]] = None) -> Optional[str]:
    del params
    if canon is None:
        return None
    for command_id, spec in COMMANDS.items():
        if spec["fs_path"] == canon:
            return command_id
    return None


def entrypoint_for(command_id: str) -> str:
    return COMMANDS[command_id]["entrypoint_id"]


def grant_id(session_class: str, command_id: str) -> str:
    return f"policy:grant:{session_class}:{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{command_id}"


def effect_record_id(command_id: str) -> str:
    return f"policy:effect:ubus-file-exec-mounts:{command_id}"


def load_mounts_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    return load_file_exec_world(fixtures)


def evaluate_mounts_exec(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    command: Optional[str] = UMOUNT,
    params: Optional[list[str]] = None,
    env: Optional[dict[str, str]] = None,
    data: Any = None,
    sessions: Optional[dict[str, Session]] = None,
    found_paths: Optional[set[str]] = None,
) -> FileExecResult:
    if sessions is None:
        sessions = load_mounts_world()
    result = evaluate_shared_file_exec(
        session_class=session_class,
        sid=sid,
        command=command,
        params=params,
        env=env,
        data=data,
        sessions=sessions,
        found_paths=found_paths if found_paths is not None else FOUND_PATHS,
    )
    return replace(result, command_id=identify_command(result.canon, result.params))


def _identity(record_type: str, record_id: str, revision: str) -> dict[str, str]:
    return {
        "record_type": record_type,
        "evidence_status": "fact",
        "producer": PRODUCER,
        "record_id": record_id,
        "corpus_revision": revision,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
    }


def _pins() -> dict[str, Any]:
    return {
        "uhttpd": UHTTPD_SHA,
        "rpcd": RPCD_SHA,
        "luci": LUCI_SHA,
        "lockfile": "corpus/lock.json",
        "object": UBUS_OBJECT,
        "method": UBUS_METHOD,
        "commands": list(COMMANDS),
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Session]] = None
) -> FileExecResult:
    return evaluate_mounts_exec(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        command=case.get("command"),
        params=case.get("params"),
        env=case.get("env"),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result: FileExecResult, revision: str) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    command_id = result.command_id
    if command_id not in COMMANDS:
        raise ValueError(f"refusing to emit grant for command {command_id!r}")
    if case.get("ubus_object") != UBUS_OBJECT or case.get("method") != UBUS_METHOD:
        raise ValueError("refusing to emit grant for non-file.exec ubus method")
    spec = COMMANDS[command_id]
    record = _identity("policy_grant", grant_id(case["session_class"], command_id), revision)
    record.update(
        {
            "session_class": case["session_class"],
            "ingress": UBUS_INGRESS,
            "entrypoint_id": spec["entrypoint_id"],
            "ubus_object": UBUS_OBJECT,
            "method": UBUS_METHOD,
            "fs_path": spec["fs_path"],
            "target_id": spec["asset_id"],
            "op": "exec",
            "acl_group": (
                result.file_matched.group
                if result.file_matched
                else case.get("acl_group")
            ),
            "expectation_id": case.get("expectation_id"),
            "assessment": case.get("assessment", "intended_access"),
            "requirements": [
                "uh_ubus_allowed",
                "session.access scope=ubus object=file function=exec (uhttpd omits scope)",
                "session.access scope=file object=canonicalized executable or cmdline function=exec",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if case["session_class"] in SYNTHETIC_FILE_EXEC_CLASSES:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result: FileExecResult, revision: str) -> dict[str, Any]:
    command_id = result.command_id if result.command_id in COMMANDS else None
    spec = COMMANDS.get(command_id) if command_id else None
    record = _identity("policy_decision", f"policy:decision:{case['id']}", revision)
    record.update(
        {
            "session_class": case.get("session_class"),
            "ingress": UBUS_INGRESS,
            "entrypoint_id": case.get(
                "entrypoint_id",
                spec["entrypoint_id"] if spec else f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}",
            ),
            "ubus_object": UBUS_OBJECT,
            "method": UBUS_METHOD,
            "fs_path": spec["fs_path"] if spec else result.canon,
            "outcome": result.outcome,
            "command": result.command,
            "params": result.params,
            "canon": result.canon,
            "cmdline": result.cmdline,
            "match_stage": result.match_stage,
            "sid_present": case.get("sid") is not None and case.get("sid") != "",
            "sid": result.sid,
            "jsonrpc_error": result.jsonrpc_error,
            "ubus_status": result.ubus_status,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": f"policy/fixtures/ubus_file_exec_mounts_cases.json#{case['id']}",
                "c_double": "policy/c_double/ubus_file_exec_mounts.c",
            },
            "assumptions": [
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_ORDER,
                ASSUMPTION_NO_EXECV,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
                ASSUMPTION_ENV,
                ASSUMPTION_EXISTING_FIXTURE,
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_LOOKUP,
                UNKNOWN_EXECV,
                UNKNOWN_UNSTAFFED,
                UNKNOWN_PLUGIN_SID,
            ],
        }
    )
    if case.get("target_id"):
        record["target_id"] = case["target_id"]
    if case.get("op"):
        record["op"] = case["op"]
    if case.get("expectation_id"):
        record["expectation_id"] = case["expectation_id"]
    if case.get("assessment"):
        record["assessment"] = case["assessment"]
    if case.get("not"):
        record["not"] = list(case["not"])
    if case.get("note"):
        record["note"] = case["note"]
    if result.session_class in SYNTHETIC_FILE_EXEC_CLASSES:
        record["synthetic_session"] = True
    if result.outcome != "allow":
        record["grant_emitted"] = False
    if result.ubus_matched:
        record["matched_ubus_acl"] = {
            "group": result.ubus_matched.group,
            "scope": result.ubus_matched.scope,
            "object": result.ubus_matched.object,
            "function": result.ubus_matched.function,
            "source": result.ubus_matched.source,
        }
    if result.file_matched:
        record["matched_file_acl"] = {
            "group": result.file_matched.group,
            "scope": result.file_matched.scope,
            "object": result.file_matched.object,
            "function": result.file_matched.function,
            "source": result.file_matched.source,
        }
    return {key: value for key, value in record.items() if value is not None}


def effect_record(command_id: str, grants: list[dict[str, Any]], revision: str) -> dict[str, Any]:
    spec = COMMANDS[command_id]
    command_grants = [row for row in grants if row.get("entrypoint_id") == spec["entrypoint_id"]]
    grant_ids = [row["record_id"] for row in command_grants]
    assessment = "intended_access" if grant_ids else "unassessed"
    record = _identity("handler_effect", effect_record_id(command_id), revision)
    record.update(
        {
            "ingress": UBUS_INGRESS,
            "entrypoint_id": spec["entrypoint_id"],
            "ubus_object": UBUS_OBJECT,
            "method": UBUS_METHOD,
            "fs_path": spec["fs_path"],
            "effect_id": f"file.exec.{command_id}",
            "target_id": spec["asset_id"],
            "op": "exec",
            "sink_kind": "file_exec",
            "asset_id": spec["asset_id"],
            "assessment": assessment,
            "expectation_id": spec["expectation_id"],
            "conditions": [
                "JSON-RPC /ubus call object=file method=exec",
                "data parameter is a BLOBMSG_TYPE_TABLE",
                f"command canonicalizes to {spec['fs_path']}",
                spec["caller"],
            ],
            "requirements": [
                "uh_ubus_allowed",
                "session.access scope=ubus object=file function=exec (uhttpd omits scope)",
                "session.access scope=file object=canonicalized executable or cmdline function=exec",
            ],
            "assumptions": [
                "Synthetic handler_effect transcribed from rpcd-mod-file rpc_file_exec; C, not ucode",
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_ORDER,
                ASSUMPTION_NO_EXECV,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
                ASSUMPTION_ENV,
                ASSUMPTION_EXISTING_FIXTURE,
            ],
            "evidence_refs": grant_ids
            + [
                f"rpcd@{RPCD_SHA[:8]} file.c rpc_file_exec_run executable then cmdline file ACL",
                f"luci@{LUCI_SHA[:8]} {spec['caller']}",
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_LOOKUP,
                UNKNOWN_EXECV,
                UNKNOWN_UNSTAFFED,
                UNKNOWN_PLUGIN_SID,
            ],
        }
    )
    return record


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    sessions = load_mounts_world(fixtures)
    cases = load_expected_cases(fixtures / "ubus_file_exec_mounts_cases.json")
    revision = corpus_revision(repo_root)
    grants_by_id: dict[str, dict[str, Any]] = {}
    decisions: list[dict[str, Any]] = []
    for case in cases:
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result, revision))
        if case.get("expect_grant") and result.outcome == "allow":
            if case.get("ubus_object") != UBUS_OBJECT or case.get("method") != UBUS_METHOD:
                raise ValueError("refusing to emit grant for non-file.exec ubus method")
            record = grant_record(case, result, revision)
            grants_by_id.setdefault(record["record_id"], record)
    grants = list(grants_by_id.values())
    bundle = {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": revision,
        "pins": _pins(),
        "scope": "ubus file.exec of luci-mod-system-mounts umount/block",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/ubus_file_exec_mounts.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_uhttpd": False,
            "live_rpcd": False,
            "live_execv": False,
            "live_rpc_file_exec_lookup": False,
        },
        "assumptions": [
            ASSUMPTION_CONJUNCT,
            ASSUMPTION_ORDER,
            ASSUMPTION_NO_EXECV,
            ASSUMPTION_NOT_SANITIZER,
            ASSUMPTION_NOT_LUCI,
            ASSUMPTION_ENV,
            ASSUMPTION_EXISTING_FIXTURE,
        ],
        "unknowns": [
            UNKNOWN_LIVE,
            UNKNOWN_LOOKUP,
            UNKNOWN_EXECV,
            UNKNOWN_UNSTAFFED,
            UNKNOWN_PLUGIN_SID,
        ],
        "decisions": decisions,
    }
    effects = [effect_record(command_id, grants, revision) for command_id in COMMANDS]
    return grants, bundle, effects


def write_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle, effects = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    bundle_path = repo_root / "policy" / "ubus_file_exec_mounts_decisions.json"
    effect_path = repo_root / "reports" / "m2-ubus-file-exec-mounts-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effects)
    return bundle_path, effect_path
