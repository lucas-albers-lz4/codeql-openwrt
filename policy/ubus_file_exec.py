#!/usr/bin/env python3
"""ubus file.exec oracle for luci-mod-status iptables -Z and routes ip.

Oracle transcribed from pinned source, not from a live daemon:

* uhttpd ``ubus.c`` ``parse_call_params`` / ``uh_ubus_allowed``
  @ ``93b05e0b65d91c23c5aa8fdde378df1f174ec71d``
* rpcd-mod-file ``file.c`` ``rpc_file_exec`` / ``rpc_file_exec_run`` /
  ``rpc_file_exec_lookup`` / ``rpc_canonicalize_path`` / ``rpc_file_access``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-status ACLs and ``fs.exec`` callers @ luci ``b2e0be4b``

Bounded to ubus ``file.exec`` (rpcd-mod-file) commands the pinned status
views reach via LuCI ``fs.exec`` (not ``fs.exec_direct`` / cgi-exec):

``uh_ubus_allowed`` → ``session.access`` scope=ubus object=file function=exec
then ``rpc_file_access(sid, executable, exec)`` or, on miss,
``rpc_file_access(sid, cmdline, exec)``. Executable is checked first.

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after cgi-exec-status-v1 and
upserts synthetic effects into ``reports/handler_effects.json``.
Does not emit dispatcher, ``authorization_violation``, or ``path_found``.
Does not invent luci-ssl grants. Does not fork ``execv``. Does not
staff cgi-io. Does not treat ``shellquote`` / ``basename`` as sanitizers.
``rpc_file_exec_lookup`` PATH search is not a live stat: only the
inventoried absolute paths below are treated as found.
cgi-exec-status-v1 remains ``fs.exec_direct`` dmesg/nft/iptables listing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .cgi_exec_status import (
    FIREWALL_READ_SESSION_CLASS,
    FIREWALL_SESSION_CLASS,
    load_status_world,
)
from .cgi_upload import canonicalize_path
from .oracle import (
    C_DOUBLE_FLAGS,
    ERROR_ACCESS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    Session,
    UBUS_SCOPE,
    UHTTPD_SHA,
    corpus_revision,
    dump_json,
    load_acl_catalog,
    parse_call_params,
    parse_rpcd_logins,
    session_access,
    session_acls,
    uh_ubus_allowed,
)

ANALYSIS_REVISION = "policy:ubus-file-exec-v1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

UBUS_INGRESS = "ubus_http"
UBUS_OBJECT = "file"
UBUS_METHOD = "exec"
FILE_SCOPE = "file"
FILE_FUNCTION = "exec"

ROUTES_SESSION_CLASS = "luci-mod-status-routes"
ROUTES_JSON_SESSION_CLASS = "luci-mod-status-routes-json"
ROUTES_FIXTURE_SID = "77777777777777777777777777777777"
ROUTES_JSON_FIXTURE_SID = "88888888888888888888888888888888"

IPTABLES = "/usr/sbin/iptables"
IP6TABLES = "/usr/sbin/ip6tables"
IP = "/sbin/ip"

UBUS_STATUS_OK = 0
UBUS_STATUS_INVALID_ARGUMENT = 2
UBUS_STATUS_NOT_FOUND = 4
UBUS_STATUS_PERMISSION_DENIED = 6
RPC_CMDLINE_MAX_SIZE = 1024

COMMANDS: dict[str, dict[str, Any]] = {
    "iptables": {
        "fs_path": IPTABLES,
        "params": ["-Z"],
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-iptables-z",
        "asset_id": "command:iptables-z",
        "caller": "iptables.js handleCounterReset fs.exec('/usr/sbin/iptables', ['-Z'])",
        "entrypoint_id": f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{IPTABLES}",
    },
    "ip6tables": {
        "fs_path": IP6TABLES,
        "params": ["-Z"],
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-ip6tables-z",
        "asset_id": "command:ip6tables-z",
        "caller": "iptables.js handleCounterReset fs.exec('/usr/sbin/ip6tables', ['-Z'])",
        "entrypoint_id": f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{IP6TABLES}",
    },
    "ip": {
        "fs_path": IP,
        "params": ["-4", "neigh", "show"],
        "delegated": ROUTES_SESSION_CLASS,
        "expectation_id": "luci-mod-status-routes-ip",
        "asset_id": "command:ip",
        "caller": "routes.js fs.exec('/sbin/ip', ['-4'|'-6', 'neigh'|'route'|'rule', ...])",
        "entrypoint_id": f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{IP}",
    },
    "ip-json": {
        "fs_path": IP,
        "params": ["-4", "-j", "neigh", "show"],
        "delegated": ROUTES_JSON_SESSION_CLASS,
        "expectation_id": "luci-mod-status-routes-json-ip",
        "asset_id": "command:ip-json",
        "caller": "routesj.js fs.exec('/sbin/ip', ['-4'|'-6', '-j', ...])",
        "entrypoint_id": f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{IP}:-j",
    },
}

FOUND_PATHS = {spec["fs_path"] for spec in COMMANDS.values()}
CASES_PATH = FIXTURES / "ubus_file_exec_cases.json"
SYNTHETIC_FILE_EXEC_CLASSES = frozenset(
    {
        FIREWALL_SESSION_CLASS,
        FIREWALL_READ_SESSION_CLASS,
        ROUTES_SESSION_CLASS,
        ROUTES_JSON_SESSION_CLASS,
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
    "file.exec of commands other than inventoried iptables -Z / ip6tables -Z "
    "/ routes ip are not modeled."
)
UNKNOWN_UNSTAFFED = (
    "cgi-io cgi-exec stays on policy:cgi-exec-v1 / cgi-exec-file-v1 / "
    "cgi-exec-status-v1. luci-mod-network diagnostics ping/traceroute, "
    "ifup/ifdown/wifi, and luci-mod-status-processes /bin/kill are not this "
    "slice. Track A is unstaffed. dispatcher is not this slice."
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
    "ACLs grant the cmdline objects, not the bare executables."
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
    "object grant. Callers at luci b2e0be4b use fs.exec → ubus file.exec."
)
ASSUMPTION_ENV = (
    "rpc_file_exec_run returns PERMISSION_DENIED when both SID and env are "
    "present. Inventoried callers do not pass env."
)


def _cmdline(canon: str, params: Optional[list[str]]) -> str:
    if params is None:
        return canon
    # A present params array contributes a separator even when empty.
    return canon + " " + " ".join(params)


def identify_command(canon: Optional[str], params: Optional[list[str]]) -> Optional[str]:
    if canon == IPTABLES:
        return "iptables"
    if canon == IP6TABLES:
        return "ip6tables"
    if canon == IP:
        if params and "-j" in params:
            return "ip-json"
        return "ip"
    return None


def entrypoint_for(command_id: str) -> str:
    return COMMANDS[command_id]["entrypoint_id"]


def grant_id(session_class: str, command_id: str) -> str:
    return f"policy:grant:{session_class}:{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}:{command_id}"


def effect_record_id(command_id: str) -> str:
    return f"policy:effect:ubus-file-exec:{command_id}"


def load_file_exec_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    sessions = load_status_world(fixtures)
    catalog = load_acl_catalog(fixtures)
    logins = {
        login.username: login
        for login in parse_rpcd_logins((fixtures / "rpcd.config").read_text(encoding="utf-8"))
    }
    routes = logins[ROUTES_SESSION_CLASS]
    sessions[ROUTES_FIXTURE_SID] = Session(
        session_class=ROUTES_SESSION_CLASS,
        sid=ROUTES_FIXTURE_SID,
        login=routes,
        acls=session_acls(routes, catalog),
    )
    routes_json = logins[ROUTES_JSON_SESSION_CLASS]
    sessions[ROUTES_JSON_FIXTURE_SID] = Session(
        session_class=ROUTES_JSON_SESSION_CLASS,
        sid=ROUTES_JSON_FIXTURE_SID,
        login=routes_json,
        acls=session_acls(routes_json, catalog),
    )
    return sessions


@dataclass
class FileExecResult:
    outcome: str
    session_class: Optional[str]
    sid: Optional[str]
    command: Optional[str]
    params: Optional[list[str]]
    canon: Optional[str]
    cmdline: Optional[str]
    command_id: Optional[str]
    ubus_matched: Any
    file_matched: Any
    match_stage: Optional[str]
    jsonrpc_error: Optional[dict[str, Any]]
    ubus_status: Optional[int]
    message: str
    steps: list[dict[str, Any]]


def evaluate_file_exec(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    command: Optional[str] = IPTABLES,
    params: Optional[list[str]] = None,
    env: Optional[dict[str, str]] = None,
    data: Any = None,
    sessions: Optional[dict[str, Session]] = None,
    found_paths: Optional[set[str]] = None,
) -> FileExecResult:
    """Evaluate HTTP /ubus file.exec after a typed JSON-RPC call array.

    lookup is not a live PATH/stat search. execv is not forked.
    """
    if sessions is None:
        sessions = load_file_exec_world()
    allowed = found_paths if found_paths is not None else FOUND_PATHS
    if data is None:
        payload: dict[str, Any] = {}
        if command is not None:
            payload["command"] = command
        if params is not None:
            payload["params"] = params
        if env is not None:
            payload["env"] = env
        data = payload
    steps: list[dict[str, Any]] = []
    empty = FileExecResult(
        outcome="deny",
        session_class=session_class,
        sid=sid,
        command=command,
        params=params,
        canon=None,
        cmdline=None,
        command_id=None,
        ubus_matched=None,
        file_matched=None,
        match_stage=None,
        jsonrpc_error=ERROR_ACCESS,
        ubus_status=None,
        message="",
        steps=steps,
    )
    parsed_sid, parsed_obj, parsed_fun, parsed_data, _rewritten, parse_err = parse_call_params(
        sid, UBUS_OBJECT, UBUS_METHOD, data, 0
    )
    steps.append(
        {
            "step": "parse_call_params",
            "sid_present": sid is not None and sid != "",
            "object": parsed_obj,
            "function": parsed_fun,
            "data_is_table": isinstance(parsed_data, dict),
            "result": "ERROR_PARSE" if parse_err else "ok",
        }
    )
    if parse_err is not None:
        steps.append({"step": "uh_ubus_handle_request_object", "result": "ERROR_PARSE"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "jsonrpc_parse_error",
                "sid": parsed_sid,
                "jsonrpc_error": parse_err,
                "message": "Parse error",
            }
        )

    hit = sessions.get(parsed_sid) if parsed_sid is not None else None
    if hit is not None and session_class is not None and session_class != hit.session_class:
        raise ValueError(
            f"session_class {session_class!r} does not match SID session {hit.session_class!r}"
        )
    resolved_class = hit.session_class if hit else None
    ubus_matched = uh_ubus_allowed(sessions, parsed_sid, UBUS_OBJECT, UBUS_METHOD)
    steps.append(
        {
            "step": "uh_ubus_allowed",
            "scope": UBUS_SCOPE,
            "object": UBUS_OBJECT,
            "function": UBUS_METHOD,
            "result": bool(ubus_matched),
        }
    )
    if not ubus_matched:
        steps.append({"step": "uh_ubus_handle_request_object", "result": "ERROR_ACCESS"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "session_class": resolved_class,
                "sid": parsed_sid,
                "ubus_matched": None,
                "jsonrpc_error": ERROR_ACCESS,
                "message": "Access denied",
            }
        )

    body = parsed_data if isinstance(parsed_data, dict) else {}
    # rpc_exec_policy only populates command for a STRING attribute.
    cmd = body.get("command")
    if not isinstance(cmd, str):
        cmd = None
    argv = body.get("params")
    env_table = body.get("env")
    if isinstance(argv, list):
        # rpc_file_exec_run skips non-STRING attributes in the params array.
        argv = [value for value in argv if isinstance(value, str)]
    else:
        argv = None
    if env_table is not None and not isinstance(env_table, dict):
        env_table = None
    if cmd is None:
        steps.append({"step": "rpc_file_exec", "result": "UBUS_STATUS_INVALID_ARGUMENT"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "invalid_argument",
                "session_class": resolved_class,
                "sid": parsed_sid,
                "ubus_matched": ubus_matched,
                "jsonrpc_error": None,
                "ubus_status": UBUS_STATUS_INVALID_ARGUMENT,
                "message": "Invalid argument",
            }
        )

    # Presence of the typed env table matters even when it has no entries.
    if parsed_sid is not None and env_table is not None:
        steps.append(
            {
                "step": "rpc_file_exec_run",
                "result": "UBUS_STATUS_PERMISSION_DENIED",
                "reason": "sid_and_env",
            }
        )
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "command_denied",
                "session_class": resolved_class,
                "sid": parsed_sid,
                "command": cmd,
                "params": argv,
                "ubus_matched": ubus_matched,
                "jsonrpc_error": None,
                "ubus_status": UBUS_STATUS_PERMISSION_DENIED,
                "message": "Permission denied",
            }
        )

    if cmd not in allowed:
        steps.append({"step": "rpc_file_exec_lookup", "result": "UBUS_STATUS_NOT_FOUND", "cmd": cmd})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "not_found",
                "session_class": resolved_class,
                "sid": parsed_sid,
                "command": cmd,
                "params": argv,
                "ubus_matched": ubus_matched,
                "jsonrpc_error": None,
                "ubus_status": UBUS_STATUS_NOT_FOUND,
                "message": "Executable not found",
            }
        )

    canon = canonicalize_path(cmd)
    steps.append({"step": "rpc_canonicalize_path", "cmd": cmd, "canon": canon})
    if not canon:
        steps.append({"step": "rpc_file_exec_run", "result": "UBUS_STATUS_UNKNOWN_ERROR"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "not_found",
                "session_class": resolved_class,
                "sid": parsed_sid,
                "command": cmd,
                "params": argv,
                "ubus_matched": ubus_matched,
                "jsonrpc_error": None,
                "ubus_status": UBUS_STATUS_NOT_FOUND,
                "message": "canonicalize failed",
            }
        )

    cmdline = _cmdline(canon, argv)
    command_id = identify_command(canon, argv)
    file_exe = session_access(hit, FILE_SCOPE, canon, FILE_FUNCTION) if hit else None
    steps.append(
        {
            "step": "rpc_file_access",
            "scope": FILE_SCOPE,
            "object": canon,
            "function": FILE_FUNCTION,
            "stage": "executable",
            "result": bool(file_exe),
        }
    )
    if file_exe:
        steps.append({"step": "rpc_file_exec_run", "result": "allow", "execv": False, "match_stage": "executable"})
        return FileExecResult(
            outcome="allow",
            session_class=resolved_class,
            sid=parsed_sid,
            command=cmd,
            params=argv,
            canon=canon,
            cmdline=cmdline,
            command_id=command_id,
            ubus_matched=ubus_matched,
            file_matched=file_exe,
            match_stage="executable",
            jsonrpc_error=None,
            ubus_status=UBUS_STATUS_OK,
            message="Exec permission granted",
            steps=steps,
        )

    # The pinned C doubles enforce this buffer limit only after the
    # executable ACL misses. Count UTF-8 bytes, including all separators.
    if argv is None or len(cmdline.encode("utf-8")) >= RPC_CMDLINE_MAX_SIZE:
        steps.append(
            {
                "step": "rpc_file_exec_run",
                "result": "UBUS_STATUS_PERMISSION_DENIED",
                "reason": "executable_miss_and_null_params" if argv is None else "cmdline_too_long",
            }
        )
        return FileExecResult(
            outcome="command_denied",
            session_class=resolved_class,
            sid=parsed_sid,
            command=cmd,
            params=argv,
            canon=canon,
            cmdline=cmdline,
            command_id=command_id,
            ubus_matched=ubus_matched,
            file_matched=None,
            match_stage=None,
            jsonrpc_error=None,
            ubus_status=UBUS_STATUS_PERMISSION_DENIED,
            message="Permission denied",
            steps=steps,
        )

    file_cmd = session_access(hit, FILE_SCOPE, cmdline, FILE_FUNCTION) if hit else None
    steps.append(
        {
            "step": "rpc_file_access",
            "scope": FILE_SCOPE,
            "object": cmdline,
            "function": FILE_FUNCTION,
            "stage": "cmdline",
            "result": bool(file_cmd),
        }
    )
    if not file_cmd:
        steps.append({"step": "rpc_file_exec_run", "result": "UBUS_STATUS_PERMISSION_DENIED"})
        return FileExecResult(
            outcome="command_denied",
            session_class=resolved_class,
            sid=parsed_sid,
            command=cmd,
            params=argv,
            canon=canon,
            cmdline=cmdline,
            command_id=command_id,
            ubus_matched=ubus_matched,
            file_matched=None,
            match_stage=None,
            jsonrpc_error=None,
            ubus_status=UBUS_STATUS_PERMISSION_DENIED,
            message="Permission denied",
            steps=steps,
        )

    steps.append({"step": "rpc_file_exec_run", "result": "allow", "execv": False, "match_stage": "cmdline"})
    return FileExecResult(
        outcome="allow",
        session_class=resolved_class,
        sid=parsed_sid,
        command=cmd,
        params=argv,
        canon=canon,
        cmdline=cmdline,
        command_id=command_id,
        ubus_matched=ubus_matched,
        file_matched=file_cmd,
        match_stage="cmdline",
        jsonrpc_error=None,
        ubus_status=UBUS_STATUS_OK,
        message="Exec permission granted",
        steps=steps,
    )


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
    return evaluate_file_exec(
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
                "independent_expected": f"policy/fixtures/ubus_file_exec_cases.json#{case['id']}",
                "c_double": "policy/c_double/ubus_file_exec.c",
            },
            "assumptions": [
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_ORDER,
                ASSUMPTION_NO_EXECV,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
                ASSUMPTION_ENV,
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
    sessions = load_file_exec_world(fixtures)
    cases = load_expected_cases(fixtures / "ubus_file_exec_cases.json")
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
        "scope": "ubus file.exec of luci-mod-status iptables -Z and routes ip",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/ubus_file_exec.c",
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
    bundle_path = repo_root / "policy" / "ubus_file_exec_decisions.json"
    effect_path = repo_root / "reports" / "m2-ubus-file-exec-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effects)
    return bundle_path, effect_path
