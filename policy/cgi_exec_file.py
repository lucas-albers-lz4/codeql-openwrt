#!/usr/bin/env python3
"""cgi-io cgi-exec file.exec oracle for three luci-ssl libexec helpers.

Oracle transcribed from pinned source, not from a live daemon:

* cgi-io ``main.c`` ``main_exec`` / ``util.c`` ``parse_command`` /
  ``canonicalize_path`` / ``lookup_executable`` @ ``31cb3c89``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-ssl libexec helpers and ACLs @ luci ``b2e0be4b``

Bounded to cgi-io's conjunctive second gate for the three inventoried
``#!/bin/sh`` helpers:

``session.access(sid, "cgi-io", "exec", "read")`` then
``session.access(sid, "file", cmdline, "exec")`` or
``session.access(sid, "file", exe, "exec")``.

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after cgi-exec-v1 and
upserts synthetic effects into ``reports/handler_effects.json``.
Does not emit dispatcher, ``authorization_violation``, or ``path_found``.
Does not invent luci-ssl ubus grants. Does not fork ``execv``. Does not
treat ``shellquote`` / ``basename`` as sanitizers. ``canonicalize_path``
is a textual path normalizer, not a taint sanitizer.
``lookup_executable`` PATH search is not a live stat: only the three
installed absolute helper paths are treated as found.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .cgi_backup import load_cgi_world
from .cgi_upload import canonicalize_path
from .oracle import (
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    ROOT_FIXTURE_SID,
    Session,
    corpus_revision,
    dump_json,
    load_acl_catalog,
    load_acl_file,
    parse_rpcd_logins,
    session_access,
    session_acls,
)

ANALYSIS_REVISION = "policy:cgi-exec-file-v1"
CGI_IO_SHA = "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

CGI_INGRESS = "cgi_io"
CGI_ENDPOINT = "cgi-exec"
CGI_SCOPE = "cgi-io"
CGI_OBJECT = "exec"
CGI_FUNCTION = "read"
FILE_SCOPE = "file"
FILE_FUNCTION = "exec"
CONTENT_TYPE_PREFIX = "application/x-www-form-urlencoded"

LOGS_SESSION_CLASS = "luci-mod-status-logs"
LOGS_FIXTURE_SID = "33333333333333333333333333333333"
PKGMGR_SESSION_CLASS = "luci-app-package-manager"
PKGMGR_FIXTURE_SID = "44444444444444444444444444444444"
NETWORK_SESSION_CLASS = "luci-mod-network-config"
HELPER_ACL_FILE = "luci-app-package-manager.json"

SYSLOG_WRAPPER = "/usr/libexec/syslog-wrapper"
LUCI_PEERADDR = "/usr/libexec/luci-peeraddr"
PACKAGE_MANAGER_CALL = "/usr/libexec/package-manager-call"

HELPERS: dict[str, dict[str, str]] = {
    SYSLOG_WRAPPER: {
        "basename": "syslog-wrapper",
        "delegated": LOGS_SESSION_CLASS,
        "package": "luci-mod-status",
        "expectation_id": "luci-mod-status-logs-syslog-wrapper",
        "asset_id": "command:syslog-wrapper",
    },
    LUCI_PEERADDR: {
        "basename": "luci-peeraddr",
        "delegated": NETWORK_SESSION_CLASS,
        "package": "luci-mod-network",
        "expectation_id": "luci-mod-network-config-luci-peeraddr",
        "asset_id": "command:luci-peeraddr",
    },
    PACKAGE_MANAGER_CALL: {
        "basename": "package-manager-call",
        "delegated": PKGMGR_SESSION_CLASS,
        "package": "luci-app-package-manager",
        "expectation_id": "luci-app-package-manager-call",
        "asset_id": "command:package-manager-call",
    },
}

CASES_PATH = FIXTURES / "cgi_exec_file_cases.json"
SYNTHETIC_HELPER_CLASSES = frozenset({LOGS_SESSION_CLASS, PKGMGR_SESSION_CLASS, NETWORK_SESSION_CLASS})

UNKNOWN_LIVE = (
    "Live cgi-io, uhttpd, and rpcd were not executed; decisions are "
    "transcribed from pinned C and ACL JSON."
)
UNKNOWN_POSTDECODE = (
    "CONTENT_LENGTH/body framing and URL-decoding failures in postdecode are "
    "not modeled; this slice assumes successful form-body decoding."
)
UNKNOWN_LOOKUP = (
    "lookup_executable PATH search and live stat(2) are not modeled. This "
    "oracle treats only the three inventoried absolute helper paths as found."
)
UNKNOWN_EXECV = (
    "execv of the helper, helper-internal argv after the file ACL, and "
    "file.exec of commands other than the three luci-ssl libexec helpers "
    "are not modeled."
)
UNKNOWN_UNSTAFFED = (
    "luci-mod-status dmesg/nft/iptables/firewall-init cgi-io file.exec is "
    "policy:cgi-exec-status-v1. ubus file.exec (rpcd-mod-file) is not this "
    "slice, including iptables.js handleCounterReset. Track A is unstaffed."
)
UNKNOWN_OTHER_CGI = (
    "cgi-exec-v1 remains the cgi-io exec read gate only. cgi-exec-status-v1 "
    "remains luci-mod-status fs.exec_direct commands. cgi-backup, "
    "cgi-upload, and cgi-download stay on their own analysis_revisions. "
    "dispatcher is not this slice."
)
ASSUMPTION_CONJUNCT = (
    "cgi-io main_exec requires session.access scope=cgi-io object=exec "
    "function=read AND session.access scope=file of the canonicalized "
    "cmdline or of the executable path. A cgi-io exec read grant is not "
    "authorization to run an arbitrary command."
)
ASSUMPTION_PARSE = (
    "Successful form-body framing and URL decoding are preconditions. "
    "parse_command and canonicalize_path of argv0 are transcribed from "
    "cgi-io util.c; the leading token is canonicalized before the file ACL."
)
ASSUMPTION_NOT_SANITIZER = (
    "shellquote and basename are not sanitizers. canonicalize_path is a "
    "textual path normalizer, not a taint sanitizer."
)
ASSUMPTION_NO_EXECV = (
    "This oracle does not fork execv or run the helper body. Helper-internal "
    "exec is inventory in reports/m4-luci-ssl-files.json, not a live run."
)
ASSUMPTION_NOT_LUCI = (
    "These helpers are not luci object methods. Do not invent a luci-ssl "
    "ubus grant. Callers at luci b2e0be4b use fs.exec_direct → cgi-exec."
)


def parse_command(cmdline: Optional[str]) -> Optional[list[str]]:
    """cgi-io util.c parse_command @ 31cb3c89."""
    if cmdline is None:
        return None
    index = 0
    length = len(cmdline)
    while index < length and cmdline[index].isspace():
        index += 1
    text = cmdline[index:]
    if not text:
        return None
    args: list[str] = []
    buf: list[str] = []
    esc = False
    position = 0
    size = len(text)
    while True:
        char = text[position] if position < size else "\0"
        if esc:
            esc = False
            if char != "\0":
                buf.append(char)
        elif char == "\\" and position + 1 < size:
            esc = True
        elif char == "\0" or char.isspace():
            if buf:
                args.append("".join(buf))
                buf = []
        else:
            buf.append(char)
        if char == "\0":
            break
        position += 1
    return args or None


def helper_cmdline(args: list[str], canon: str) -> str:
    if len(args) == 1:
        return canon
    return canon + " " + " ".join(args[1:])


def entrypoint_for(fs_path: str) -> str:
    return f"{CGI_INGRESS}:{CGI_ENDPOINT}:{fs_path}"


def grant_id(session_class: str, fs_path: str) -> str:
    return f"policy:grant:{session_class}:{CGI_INGRESS}:{CGI_ENDPOINT}:{HELPERS[fs_path]['basename']}"


def effect_id(fs_path: str) -> str:
    return f"policy:effect:cgi-exec-file:{HELPERS[fs_path]['basename']}"


@dataclass
class FileExecResult:
    outcome: str
    http_status: int
    session_class: Optional[str]
    sid: Optional[str]
    command: Optional[str]
    args: Optional[list[str]]
    canon: Optional[str]
    cmdline: Optional[str]
    helper: Optional[str]
    cgi_matched: Any
    file_matched: Any
    match_stage: Optional[str]
    message: str
    steps: list[dict[str, Any]]


def content_type_ok(content_type: Optional[str]) -> bool:
    return content_type is not None and content_type.startswith(CONTENT_TYPE_PREFIX)


def load_helper_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    sessions = load_cgi_world(fixtures)
    extra = load_acl_file(fixtures / HELPER_ACL_FILE)
    catalog = load_acl_catalog(fixtures) + extra
    logins = {
        login.username: login
        for login in parse_rpcd_logins((fixtures / "rpcd.config").read_text(encoding="utf-8"))
    }
    root = logins["root"]
    sessions[ROOT_FIXTURE_SID] = Session(
        session_class="root",
        sid=ROOT_FIXTURE_SID,
        login=root,
        acls=session_acls(root, catalog),
    )
    logs = logins[LOGS_SESSION_CLASS]
    sessions[LOGS_FIXTURE_SID] = Session(
        session_class=LOGS_SESSION_CLASS,
        sid=LOGS_FIXTURE_SID,
        login=logs,
        acls=session_acls(logs, catalog),
    )
    pkgmgr = logins[PKGMGR_SESSION_CLASS]
    sessions[PKGMGR_FIXTURE_SID] = Session(
        session_class=PKGMGR_SESSION_CLASS,
        sid=PKGMGR_FIXTURE_SID,
        login=pkgmgr,
        acls=session_acls(pkgmgr, catalog),
    )
    return sessions


def evaluate_file_exec(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    content_type: Optional[str] = CONTENT_TYPE_PREFIX,
    command: Optional[str] = SYSLOG_WRAPPER,
    sessions: Optional[dict[str, Session]] = None,
    found_paths: Optional[set[str]] = None,
) -> FileExecResult:
    """Evaluate cgi-exec file.exec for an already-decoded command string.

    Successful form-body framing and URL decoding are preconditions.
    lookup_executable is not a live PATH search.
    """
    if sessions is None:
        sessions = load_helper_world()
    allowed = found_paths if found_paths is not None else set(HELPERS)
    steps: list[dict[str, Any]] = [
        {
            "step": "postdecode",
            "body_validation_assumed": True,
            "content_type_prefix": CONTENT_TYPE_PREFIX,
            "content_type_ok": content_type_ok(content_type),
            "sessionid_present": bool(sid),
            "command_present": command is not None,
        }
    ]
    empty = FileExecResult(
        outcome="deny",
        http_status=403,
        session_class=session_class,
        sid=sid,
        command=command,
        args=None,
        canon=None,
        cmdline=None,
        helper=None,
        cgi_matched=None,
        file_matched=None,
        match_stage=None,
        message="",
        steps=steps,
    )
    if not content_type_ok(content_type):
        steps.append({"step": "main_exec", "result": "HTTP_400", "message": "Invalid form data"})
        return FileExecResult(
            **{**empty.__dict__, "outcome": "bad_request", "http_status": 400, "message": "Invalid form data"}
        )
    if sid is None or sid == "":
        steps.append(
            {"step": "main_exec", "result": "HTTP_403", "message": "Exec permission denied"}
        )
        return FileExecResult(
            **{**empty.__dict__, "message": "Exec permission denied"}
        )

    hit = sessions.get(sid)
    if hit is not None and session_class is not None and session_class != hit.session_class:
        raise ValueError(
            f"session_class {session_class!r} does not match SID session {hit.session_class!r}"
        )
    cgi_matched = session_access(hit, CGI_SCOPE, CGI_OBJECT, CGI_FUNCTION) if hit else None
    steps.append(
        {
            "step": "session_access",
            "scope": CGI_SCOPE,
            "object": CGI_OBJECT,
            "function": CGI_FUNCTION,
            "result": bool(cgi_matched),
        }
    )
    resolved_class = hit.session_class if hit else None
    if not cgi_matched:
        steps.append({"step": "main_exec", "result": "HTTP_403", "message": "Exec permission denied"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "session_class": resolved_class,
                "cgi_matched": None,
                "message": "Exec permission denied",
            }
        )

    args = parse_command(command)
    steps.append({"step": "parse_command", "command": command, "args": args})
    if not args:
        steps.append({"step": "main_exec", "result": "HTTP_400", "message": "Invalid command parameter"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "bad_request",
                "http_status": 400,
                "session_class": resolved_class,
                "cgi_matched": cgi_matched,
                "message": "Invalid command parameter",
            }
        )

    canon = canonicalize_path(args[0])
    steps.append({"step": "canonicalize_path", "argv0": args[0], "canon": canon})
    if not canon:
        steps.append({"step": "main_exec", "result": "HTTP_400", "message": "Invalid command parameter"})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "bad_request",
                "http_status": 400,
                "session_class": resolved_class,
                "args": args,
                "cgi_matched": cgi_matched,
                "message": "Invalid command parameter",
            }
        )

    cmdline = helper_cmdline(args, canon)
    steps.append({"step": "cmdline", "cmdline": cmdline})
    if canon not in allowed:
        steps.append({"step": "lookup_executable", "result": "HTTP_404", "exe": canon})
        return FileExecResult(
            **{
                **empty.__dict__,
                "outcome": "not_found",
                "http_status": 404,
                "session_class": resolved_class,
                "args": args,
                "canon": canon,
                "cmdline": cmdline,
                "cgi_matched": cgi_matched,
                "message": "Executable not found",
            }
        )

    file_cmdline = session_access(hit, FILE_SCOPE, cmdline, FILE_FUNCTION) if hit else None
    steps.append(
        {
            "step": "session_access",
            "scope": FILE_SCOPE,
            "object": cmdline,
            "function": FILE_FUNCTION,
            "stage": "cmdline",
            "result": bool(file_cmdline),
        }
    )
    file_matched = file_cmdline
    match_stage = "cmdline" if file_cmdline else None
    if not file_matched:
        file_exe = session_access(hit, FILE_SCOPE, canon, FILE_FUNCTION) if hit else None
        steps.append(
            {
                "step": "session_access",
                "scope": FILE_SCOPE,
                "object": canon,
                "function": FILE_FUNCTION,
                "stage": "executable",
                "result": bool(file_exe),
            }
        )
        file_matched = file_exe
        match_stage = "executable" if file_exe else None
    if not file_matched:
        steps.append(
            {"step": "main_exec", "result": "HTTP_403", "message": "Access to command denied by ACL"}
        )
        return FileExecResult(
            outcome="command_denied",
            http_status=403,
            session_class=resolved_class,
            sid=sid,
            command=command,
            args=args,
            canon=canon,
            cmdline=cmdline,
            helper=canon,
            cgi_matched=cgi_matched,
            file_matched=None,
            match_stage=None,
            message="Access to command denied by ACL",
            steps=steps,
        )

    steps.append({"step": "main_exec", "result": "allow", "execv": False, "match_stage": match_stage})
    return FileExecResult(
        outcome="allow",
        http_status=200,
        session_class=resolved_class,
        sid=sid,
        command=command,
        args=args,
        canon=canon,
        cmdline=cmdline,
        helper=canon,
        cgi_matched=cgi_matched,
        file_matched=file_matched,
        match_stage=match_stage,
        message="Exec permission granted",
        steps=steps,
    )


def _identity(record_type: str, record_id: str) -> dict[str, str]:
    return {
        "record_type": record_type,
        "evidence_status": "fact",
        "producer": PRODUCER,
        "record_id": record_id,
        "corpus_revision": corpus_revision(),
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
    }


def _pins() -> dict[str, str]:
    return {
        "cgi-io": CGI_IO_SHA,
        "luci": LUCI_SHA,
        "rpcd": RPCD_SHA,
        "lockfile": "corpus/lock.json",
        "endpoint": f"{CGI_INGRESS}:{CGI_ENDPOINT}",
        "helpers": list(HELPERS),
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Session]] = None
) -> FileExecResult:
    content_type = case["content_type"] if "content_type" in case else CONTENT_TYPE_PREFIX
    return evaluate_file_exec(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        content_type=content_type,
        command=case.get("command"),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result: FileExecResult) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    if case.get("cgi_endpoint") != CGI_ENDPOINT:
        raise ValueError(f"refusing to emit grant for {case.get('cgi_endpoint')}")
    helper = result.helper
    if helper not in HELPERS:
        raise ValueError(f"refusing to emit grant for helper {helper!r}")
    record = _identity("policy_grant", grant_id(case["session_class"], helper))
    record.update(
        {
            "session_class": case["session_class"],
            "ingress": CGI_INGRESS,
            "entrypoint_id": entrypoint_for(helper),
            "cgi_endpoint": CGI_ENDPOINT,
            "fs_path": helper,
            "target_id": HELPERS[helper]["asset_id"],
            "op": "exec",
            "acl_group": (
                result.file_matched.group
                if result.file_matched
                else case.get("acl_group")
            ),
            "expectation_id": case.get("expectation_id"),
            "assessment": case.get("assessment", "intended_access"),
            "requirements": [
                "session.access scope=cgi-io object=exec function=read",
                "session.access scope=file object=canonicalized cmdline or executable function=exec",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if case["session_class"] in SYNTHETIC_HELPER_CLASSES:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result: FileExecResult) -> dict[str, Any]:
    helper = result.helper if result.helper in HELPERS else None
    record = _identity("policy_decision", f"policy:decision:{case['id']}")
    record.update(
        {
            "session_class": case.get("session_class"),
            "ingress": CGI_INGRESS,
            "entrypoint_id": case.get(
                "entrypoint_id",
                entrypoint_for(helper) if helper else f"{CGI_INGRESS}:{CGI_ENDPOINT}",
            ),
            "cgi_endpoint": CGI_ENDPOINT,
            "fs_path": helper,
            "outcome": result.outcome,
            "http_status": result.http_status,
            "command": result.command,
            "canon": result.canon,
            "cmdline": result.cmdline,
            "match_stage": result.match_stage,
            "sid_present": case.get("sid") is not None and case.get("sid") != "",
            "sid": result.sid,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": f"policy/fixtures/cgi_exec_file_cases.json#{case['id']}",
                "c_double": "policy/c_double/cgi_exec_file.c",
            },
            "assumptions": [
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_PARSE,
                ASSUMPTION_NO_EXECV,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_POSTDECODE,
                UNKNOWN_LOOKUP,
                UNKNOWN_EXECV,
                UNKNOWN_UNSTAFFED,
                UNKNOWN_OTHER_CGI,
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
    if result.session_class in SYNTHETIC_HELPER_CLASSES:
        record["synthetic_session"] = True
    if result.outcome != "allow":
        record["grant_emitted"] = False
    if result.cgi_matched:
        record["matched_cgi_acl"] = {
            "group": result.cgi_matched.group,
            "scope": result.cgi_matched.scope,
            "object": result.cgi_matched.object,
            "function": result.cgi_matched.function,
            "source": result.cgi_matched.source,
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


def effect_record(fs_path: str, grants: list[dict[str, Any]]) -> dict[str, Any]:
    spec = HELPERS[fs_path]
    helper_grants = [row for row in grants if row.get("fs_path") == fs_path]
    grant_ids = [row["record_id"] for row in helper_grants]
    assessment = "intended_access" if grant_ids else "unassessed"
    record = _identity("handler_effect", effect_id(fs_path))
    record.update(
        {
            "ingress": CGI_INGRESS,
            "entrypoint_id": entrypoint_for(fs_path),
            "cgi_endpoint": CGI_ENDPOINT,
            "fs_path": fs_path,
            "effect_id": f"cgi-exec.{spec['basename']}.file-exec",
            "target_id": spec["asset_id"],
            "op": "exec",
            "sink_kind": "file_exec",
            "asset_id": spec["asset_id"],
            "assessment": assessment,
            "expectation_id": spec["expectation_id"],
            "conditions": [
                "argv0 contains cgi-exec",
                "CONTENT_TYPE application/x-www-form-urlencoded",
                "Successfully decoded form body with POST sessionid present",
                f"parse_command argv0 canonicalizes to {fs_path}",
            ],
            "requirements": [
                "session.access scope=cgi-io object=exec function=read",
                "session.access scope=file object=canonicalized cmdline or executable function=exec",
            ],
            "assumptions": [
                "Synthetic handler_effect transcribed from cgi-io main_exec file ACL; C, not ucode",
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_PARSE,
                ASSUMPTION_NO_EXECV,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
            ],
            "evidence_refs": grant_ids
            + [
                f"cgi-io@{CGI_IO_SHA[:8]} main.c main_exec session_access(sid, file, cmdline|exe, exec)",
                f"luci@{LUCI_SHA[:8]} {fs_path}",
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_POSTDECODE,
                UNKNOWN_LOOKUP,
                UNKNOWN_EXECV,
                UNKNOWN_UNSTAFFED,
                UNKNOWN_OTHER_CGI,
            ],
        }
    )
    return record


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    sessions = load_helper_world(fixtures)
    cases = load_expected_cases(fixtures / "cgi_exec_file_cases.json")
    grants_by_id: dict[str, dict[str, Any]] = {}
    decisions: list[dict[str, Any]] = []
    for case in cases:
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result))
        if case.get("expect_grant") and result.outcome == "allow":
            if case.get("cgi_endpoint") != CGI_ENDPOINT:
                raise ValueError(f"refusing to emit grant for {case.get('cgi_endpoint')}")
            record = grant_record(case, result)
            grants_by_id.setdefault(record["record_id"], record)
    grants = list(grants_by_id.values())
    bundle = {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": corpus_revision(repo_root),
        "pins": _pins(),
        "scope": "cgi-io cgi-exec file.exec of three luci-ssl libexec helpers",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/cgi_exec_file.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_cgi_io": False,
            "live_execv": False,
            "live_lookup_executable": False,
        },
        "assumptions": [
            ASSUMPTION_CONJUNCT,
            ASSUMPTION_PARSE,
            ASSUMPTION_NO_EXECV,
            ASSUMPTION_NOT_SANITIZER,
            ASSUMPTION_NOT_LUCI,
        ],
        "unknowns": [
            UNKNOWN_LIVE,
            UNKNOWN_POSTDECODE,
            UNKNOWN_LOOKUP,
            UNKNOWN_EXECV,
            UNKNOWN_UNSTAFFED,
            UNKNOWN_OTHER_CGI,
        ],
        "decisions": decisions,
    }
    effects = [effect_record(path, grants) for path in HELPERS]
    return grants, bundle, effects


def write_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle, effects = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    bundle_path = repo_root / "policy" / "cgi_exec_file_decisions.json"
    effect_path = repo_root / "reports" / "m2-cgi-exec-file-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effects)
    return bundle_path, effect_path
