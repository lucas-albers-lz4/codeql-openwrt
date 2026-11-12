#!/usr/bin/env python3
"""Canonical /ubus luci policy evaluator (M2).

Oracle transcribed from pinned source, not from a live daemon:

* uhttpd ``ubus.c`` ``parse_call_params`` / ``uh_ubus_allowed``
  @ ``93b05e0b65d91c23c5aa8fdde378df1f174ec71d``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  / ``rpc_login_test_permission`` @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-base unauthenticated ACL and luci-mod-{network,status,system} ACLs
  @ luci ``b2e0be4b46ec0fd43394c081fa7c50657af14011``
* stock root login @ openwrt ``4e9642517b48bae612ff10fb72fb9199e559500e``

Literal object/method names only. Emission is bounded to luci.getFeatures
plus the inventoried request.args exec methods, getBlockDevices /
setBlockDetect, and luci.sys getConntrackList / getProcessList. No
fnmatch-witness generator, dispatcher, cgi-io, Alloy, or
``producer: step4``.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

POLICY_DIR = Path(__file__).resolve().parent
REPO_ROOT = POLICY_DIR.parent
FIXTURES = POLICY_DIR / "fixtures"

PROFILE = "luci-ssl-25.12"
ANALYSIS_REVISION = "policy:ubus-luci-exec-methods-v2"
PRODUCER = "policy_facts"

DEFAULT_SID = "00000000000000000000000000000000"
ROOT_FIXTURE_SID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
NETWORK_FIXTURE_SID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
STATUS_FIXTURE_SID = "cccccccccccccccccccccccccccccccc"
SYSTEM_FIXTURE_SID = "dddddddddddddddddddddddddddddddd"
MOUNTS_FIXTURE_SID = "11111111111111111111111111111111"
PROCESSES_FIXTURE_SID = "22222222222222222222222222222222"

UHTTPD_SHA = "93b05e0b65d91c23c5aa8fdde378df1f174ec71d"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"
OPENWRT_SHA = "4e9642517b48bae612ff10fb72fb9199e559500e"

ERROR_PARSE = {"code": -32700, "name": "ERROR_PARSE", "message": "Parse error"}
ERROR_OBJECT = {"code": -32000, "name": "ERROR_OBJECT", "message": "Object not found"}
ERROR_ACCESS = {"code": -32002, "name": "ERROR_ACCESS", "message": "Access denied"}

# glibc/musl FNM_NOESCAPE. Literal M2 names do not depend on this bit.
FNM_NOESCAPE = 1 << 1

C_DOUBLE_FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O0"]

M2_OBJECT = "luci"
M2_METHOD = "getFeatures"
UBUS_SCOPE = "ubus"

ACL_FIXTURE_FILES = (
    "luci-base.json",
    "unauthenticated.json",
    "luci-mod-network.json",
    "luci-mod-status.json",
    "luci-mod-system.json",
)
REQUEST_ARGS_EXEC_METHODS = (
    "getSwconfigFeatures",
    "getSwconfigPortState",
    "getRealtimeStats",
    "setPassword",
    "setLocaltime",
)
FIXED_EXEC_METHODS = (
    "getBlockDevices",
    "setBlockDetect",
    "getConntrackList",
    "getProcessList",
)
EXEC_METHODS = REQUEST_ARGS_EXEC_METHODS + FIXED_EXEC_METHODS
EMITTED_METHODS = frozenset(("getFeatures",) + EXEC_METHODS)
SESSION_SIDS = {
    "unauthenticated": DEFAULT_SID,
    "root": ROOT_FIXTURE_SID,
    "luci-mod-network-config": NETWORK_FIXTURE_SID,
    "luci-mod-status-realtime": STATUS_FIXTURE_SID,
    "luci-mod-system-config": SYSTEM_FIXTURE_SID,
    "luci-mod-system-mounts": MOUNTS_FIXTURE_SID,
    "luci-mod-status-processes": PROCESSES_FIXTURE_SID,
}
SYNTHETIC_SESSION_CLASSES = frozenset(SESSION_SIDS) - {"unauthenticated", "root"}

UNKNOWN_LIVE = (
    "Live rpcd and uhttpd were not executed; decisions are transcribed "
    "from pinned C and ACL JSON."
)
ASSUMPTION_NOAUTH = (
    "Profile luci-ssl-25.12 has uhttpd.no_ubusauth=0. uhttpd ubus.c rewrites "
    "empty/missing SID to UH_UBUS_DEFAULT_SID only when conf.ubus_noauth is "
    "set; that rewrite is not a case in this profile."
)
ASSUMPTION_OBJECT = (
    "ubus object luci is present (luci-base plugin). Object-not-found is "
    "out of M2 scope."
)
UNKNOWN_ACL_SET = (
    "M2 loads rpcd unauthenticated.json, luci-base.json, luci-mod-network.json, "
    "luci-mod-status.json, and luci-mod-system.json. Emission is bounded to "
    "luci.getFeatures plus the inventoried request.args exec methods, "
    "getBlockDevices/setBlockDetect, and luci.sys getConntrackList/"
    "getProcessList; file.exec, cgi-io, and hostapd.* grants in those files "
    "are not emitted."
)


def corpus_revision(repo_root: Path = REPO_ROOT) -> str:
    digest = hashlib.sha256((repo_root / "corpus" / "lock.json").read_bytes()).hexdigest()
    return f"sha256:{digest}"


def _libc():
    name = ctypes.util.find_library("c") or "libc.so.6"
    lib = ctypes.CDLL(name)
    lib.fnmatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.fnmatch.restype = ctypes.c_int
    return lib


_LIBC = None


def libc_fnmatch(pattern: str, string: str, flags: int) -> bool:
    """libc fnmatch; flags 0 for login groups, FNM_NOESCAPE for ubus ACL."""
    global _LIBC
    if _LIBC is None:
        _LIBC = _libc()
    return _LIBC.fnmatch(pattern.encode("utf-8"), string.encode("utf-8"), flags) == 0


def uh_id_len(pattern: str) -> int:
    for index, char in enumerate(pattern):
        if char in "*?[":
            return index
    return len(pattern)


def acl_match(pat_obj: str, pat_fun: str, obj: str, fun: str) -> bool:
    """rpc_session_acl_allowed for one ACL entry (literal names in M2)."""
    sort_len = uh_id_len(pat_obj)
    if pat_obj[:sort_len] != obj[:sort_len]:
        return False
    if not any(c in pat_obj for c in "*?[") and not any(c in pat_fun for c in "*?["):
        return pat_obj == obj and pat_fun == fun
    return libc_fnmatch(pat_obj, obj, FNM_NOESCAPE) and libc_fnmatch(
        pat_fun, fun, FNM_NOESCAPE
    )


@dataclass(frozen=True)
class AclEntry:
    group: str
    perm: str
    scope: str
    object: str
    function: str
    source: str


@dataclass
class Login:
    username: str
    read: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)


@dataclass
class Session:
    session_class: str
    sid: str
    login: Optional[Login]
    acls: list[AclEntry]


@dataclass
class EvalResult:
    outcome: str
    session_class: Optional[str]
    sid: Optional[str]
    object: Optional[str]
    function: Optional[str]
    data_present: bool
    no_ubusauth: int
    sid_rewritten: bool
    matched: Optional[AclEntry]
    jsonrpc_error: Optional[dict[str, Any]]
    steps: list[dict[str, Any]]


def parse_rpcd_logins(text: str) -> list[Login]:
    logins: list[Login] = []
    current: Optional[dict[str, Any]] = None

    def flush() -> None:
        nonlocal current
        if current and current.get("kind") == "login":
            logins.append(
                Login(
                    username=str(current.get("username", "")),
                    read=list(current.get("read", [])),
                    write=list(current.get("write", [])),
                )
            )
        current = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config "):
            flush()
            parts = line.split()
            current = {"kind": parts[1], "read": [], "write": []}
            continue
        if current is None:
            continue
        if line.startswith("option "):
            rest = line[len("option ") :]
            name, _, value = rest.partition(" ")
            current[name] = value.strip().strip("'\"")
        elif line.startswith("list "):
            rest = line[len("list ") :]
            name, _, value = rest.partition(" ")
            current.setdefault(name, []).append(value.strip().strip("'\""))
    flush()
    return logins


def login_test_permission(login: Optional[Login], perm: str, group: str) -> bool:
    """rpc_login_test_permission. Default session (login is None) gets unauthenticated only."""
    if login is None:
        return group == "unauthenticated"
    values = getattr(login, perm)
    for pattern in values:
        if not pattern or pattern[0] != "!":
            continue
        negated = pattern[1:].lstrip()
        if negated and libc_fnmatch(negated, group, 0):
            return False
    for pattern in values:
        if not pattern or pattern[0] == "!":
            continue
        if libc_fnmatch(pattern, group, 0):
            return True
    if perm == "read":
        return login_test_permission(login, "write", group)
    return False


def _iter_scope_grants(group: str, perm: str, scope_name: str, scope_val: Any, source: str) -> Iterable[AclEntry]:
    if isinstance(scope_val, dict):
        for obj_name, functions in scope_val.items():
            if not isinstance(functions, list):
                continue
            for fun in functions:
                if isinstance(fun, str):
                    yield AclEntry(group, perm, scope_name, obj_name, fun, source)
    elif isinstance(scope_val, list):
        for obj_name in scope_val:
            if isinstance(obj_name, str):
                yield AclEntry(group, perm, scope_name, obj_name, perm, source)


def load_acl_file(path: Path) -> list[AclEntry]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries: list[AclEntry] = []
    source = path.name
    for group, body in data.items():
        if not isinstance(body, dict):
            continue
        for perm in ("read", "write"):
            perm_body = body.get(perm)
            if not isinstance(perm_body, dict):
                continue
            for scope_name, scope_val in perm_body.items():
                entries.extend(_iter_scope_grants(group, perm, scope_name, scope_val, source))
    return entries


def load_acl_catalog(fixtures: Path = FIXTURES) -> list[AclEntry]:
    entries: list[AclEntry] = []
    for name in ACL_FIXTURE_FILES:
        entries.extend(load_acl_file(fixtures / name))
    return entries


def session_acls(login: Optional[Login], catalog: list[AclEntry]) -> list[AclEntry]:
    granted: list[AclEntry] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for entry in catalog:
        if not login_test_permission(login, entry.perm, entry.group):
            continue
        key = (entry.group, entry.perm, entry.scope, entry.object, entry.function)
        if key in seen:
            continue
        seen.add(key)
        granted.append(entry)
        meta = AclEntry(entry.group, entry.perm, "access-group", entry.group, entry.perm, entry.source)
        meta_key = (meta.group, meta.perm, meta.scope, meta.object, meta.function)
        if meta_key not in seen:
            seen.add(meta_key)
            granted.append(meta)
    return granted


def load_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    catalog = load_acl_catalog(fixtures)
    logins = {
        login.username: login
        for login in parse_rpcd_logins((fixtures / "rpcd.config").read_text(encoding="utf-8"))
    }
    sessions: dict[str, Session] = {
        DEFAULT_SID: Session(
            session_class="unauthenticated",
            sid=DEFAULT_SID,
            login=None,
            acls=session_acls(None, catalog),
        )
    }
    for session_class, sid in SESSION_SIDS.items():
        if session_class == "unauthenticated":
            continue
        login = logins[session_class]
        sessions[sid] = Session(
            session_class=session_class,
            sid=sid,
            login=login,
            acls=session_acls(login, catalog),
        )
    return sessions


def is_blobmsg_table(data: Any) -> bool:
    """uhttpd parse_call_params requires BLOBMSG_TYPE_TABLE for the fourth parameter."""
    return isinstance(data, dict)


def parse_call_param_array(
    params: Any, no_ubusauth: int
) -> tuple[Optional[str], Optional[str], Optional[str], Any, bool, Optional[dict[str, Any]]]:
    """Model uhttpd and libubox's typed array scan, including skipped types.

    libubox advances the policy index only after a matching attribute. A null
    SID slot therefore does not reserve that position for the next value.
    """
    if not isinstance(params, list):
        return None, None, None, None, False, ERROR_PARSE
    matched: list[Any] = []
    for value in params:
        wants_string = len(matched) < 3
        if (wants_string and isinstance(value, str)) or (
            not wants_string and is_blobmsg_table(value)
        ):
            matched.append(value)
            if len(matched) == 4:
                break
    matched.extend([None] * (4 - len(matched)))
    resolved_sid, object_name, function, data = matched
    rewritten = False
    if no_ubusauth and (resolved_sid is None or resolved_sid == ""):
        resolved_sid = DEFAULT_SID
        rewritten = True
    if resolved_sid is None or object_name is None or function is None:
        return resolved_sid, object_name, function, data, rewritten, ERROR_PARSE
    # Presence is not enough: array/string/number/boolean do not populate d->data.
    if not is_blobmsg_table(data):
        return resolved_sid, object_name, function, data, rewritten, ERROR_PARSE
    return resolved_sid, object_name, function, data, rewritten, None


def parse_call_params(
    sid: Optional[str], object_name: Optional[str], function: Optional[str],
    data: Any, no_ubusauth: int,
) -> tuple[Optional[str], Optional[str], Optional[str], Any, bool, Optional[dict[str, Any]]]:
    """Parse the four supplied JSON array elements; None encodes JSON null."""
    return parse_call_param_array([sid, object_name, function, data], no_ubusauth)


def session_access(session: Session, scope: str, obj: str, fun: str) -> Optional[AclEntry]:
    for entry in session.acls:
        if entry.scope != scope:
            continue
        if acl_match(entry.object, entry.function, obj, fun):
            return entry
    return None


def uh_ubus_allowed(sessions: dict[str, Session], sid: str, obj: str, fun: str) -> Optional[AclEntry]:
    session = sessions.get(sid)
    if session is None:
        return None
    return session_access(session, UBUS_SCOPE, obj, fun)


def evaluate_call(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    object: Optional[str] = M2_OBJECT,
    function: Optional[str] = M2_METHOD,
    data: Any = None,
    no_ubusauth: int = 0,
    sessions: Optional[dict[str, Session]] = None,
    object_exists: bool = True,
) -> EvalResult:
    """Evaluate the gate assuming object lookup succeeds unless explicitly false.

    An allow means this gate was passed, not that ubus execution succeeded.
    """
    if sessions is None:
        sessions = load_world()
    steps: list[dict[str, Any]] = []
    parsed_sid, parsed_obj, parsed_fun, parsed_data, rewritten, parse_err = parse_call_params(
        sid, object, function, data, no_ubusauth
    )
    steps.append(
        {
            "step": "parse_call_params",
            "no_ubusauth": no_ubusauth,
            "sid_present": sid is not None,
            "sid_rewritten_to_default": rewritten,
            "object_present": object is not None,
            "function_present": function is not None,
            "data_present": data is not None,
            "data_is_table": is_blobmsg_table(data),
            "result": "ERROR_PARSE" if parse_err else "ok",
        }
    )
    if parse_err is not None:
        steps.append(
            {
                "step": "uh_ubus_handle_request_object",
                "result": "ERROR_PARSE",
                "not": ["unauthenticated_allow"]
                + ([] if rewritten else ["sentinel_rewrite"])
                + ["file_uci_absent_sid_skip"],
            }
        )
        return EvalResult(
            outcome="jsonrpc_parse_error",
            session_class=session_class,
            sid=parsed_sid,
            object=parsed_obj,
            function=parsed_fun,
            data_present=data is not None,
            no_ubusauth=no_ubusauth,
            sid_rewritten=rewritten,
            matched=None,
            jsonrpc_error=parse_err,
            steps=steps,
        )

    if not object_exists:
        steps.append({"step": "ubus_lookup_id", "result": "ERROR_OBJECT"})
        return EvalResult(
            outcome="jsonrpc_object_error", session_class=None, sid=parsed_sid,
            object=parsed_obj, function=parsed_fun, data_present=True,
            no_ubusauth=no_ubusauth, sid_rewritten=rewritten, matched=None,
            jsonrpc_error=ERROR_OBJECT, steps=steps,
        )

    hit = sessions.get(parsed_sid)
    resolved_class = hit.session_class if hit else None
    if hit is not None and session_class is not None and session_class != resolved_class:
        raise ValueError(
            f"session_class {session_class!r} does not match SID session {resolved_class!r}"
        )

    # uhttpd ubus.c uh_ubus_handle_request_object:
    # if (!conf.ubus_noauth && !uh_ubus_allowed(...)) ERROR_ACCESS
    if no_ubusauth:
        steps.append(
            {
                "step": "uh_ubus_allowed",
                "invoke": "skipped",
                "reason": "conf.ubus_noauth",
                "result": "allow",
                "not": [
                    "session.access",
                    "luci-ssl-acl-grant",
                    "cgi_io",
                    "dispatcher",
                ],
            }
        )
        return EvalResult(
            outcome="allow",
            session_class=resolved_class,
            sid=parsed_sid,
            object=parsed_obj,
            function=parsed_fun,
            data_present=True,
            no_ubusauth=no_ubusauth,
            sid_rewritten=rewritten,
            matched=None,
            jsonrpc_error=None,
            steps=steps,
        )

    steps.append(
        {
            "step": "uh_ubus_allowed",
            "invoke": "session.access",
            "omits_scope": True,
            "args": {
                "ubus_rpc_session": parsed_sid,
                "object": parsed_obj,
                "function": parsed_fun,
            },
        }
    )
    steps.append(
        {
            "step": "rpc_handle_access",
            "scope_default": UBUS_SCOPE,
            "scope_supplied_by_uhttpd": False,
        }
    )
    matched = uh_ubus_allowed(sessions, parsed_sid, parsed_obj, parsed_fun)
    steps.append(
        {
            "step": "rpc_session_acl_allowed",
            "scope": UBUS_SCOPE,
            "object": parsed_obj,
            "function": parsed_fun,
            "match": "literal",
            "acl_group": matched.group if matched else None,
            "acl_source": matched.source if matched else None,
            "result": bool(matched),
        }
    )
    if matched:
        return EvalResult(
            outcome="allow",
            session_class=resolved_class,
            sid=parsed_sid,
            object=parsed_obj,
            function=parsed_fun,
            data_present=True,
            no_ubusauth=no_ubusauth,
            sid_rewritten=rewritten,
            matched=matched,
            jsonrpc_error=None,
            steps=steps,
        )
    steps.append({"step": "uh_ubus_handle_request_object", "result": "ERROR_ACCESS"})
    return EvalResult(
        outcome="deny",
        session_class=resolved_class,
        sid=parsed_sid,
        object=parsed_obj,
        function=parsed_fun,
        data_present=True,
        no_ubusauth=no_ubusauth,
        sid_rewritten=rewritten,
        matched=None,
        jsonrpc_error=ERROR_ACCESS,
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
        "luci": LUCI_SHA,
        "uhttpd": UHTTPD_SHA,
        "rpcd": RPCD_SHA,
        "openwrt": OPENWRT_SHA,
        "lockfile": "corpus/lock.json",
        "first_endpoint": "ubus_http:luci.getFeatures",
    }


def load_expected_cases(path: Path = FIXTURES / "expected_cases.json") -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Session]] = None
) -> EvalResult:
    data = {} if case.get("data_present") else None
    return evaluate_call(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        object=case.get("object"),
        function=case.get("function"),
        data=data,
        no_ubusauth=int(case.get("no_ubusauth", 0)),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result: EvalResult) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    record = _identity(
        "policy_grant",
        f"policy:grant:{case['session_class']}:ubus_http:{case['object']}.{case['function']}",
    )
    record.update(
        {
            "session_class": case["session_class"],
            "ingress": "ubus_http",
            "entrypoint_id": case["entrypoint_id"],
            "ubus_object": case["object"],
            "method": case["function"],
            "target_id": case["target_id"],
            "op": case["op"],
            "acl_group": result.matched.group if result.matched else case.get("acl_group"),
            "expectation_id": case.get("expectation_id"),
            "assessment": case.get("assessment", "intended_access"),
            "requirements": [
                "uh_ubus_allowed",
                "session.access scope=ubus (uhttpd omits scope)",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if result.session_class in SYNTHETIC_SESSION_CLASSES:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result: EvalResult) -> dict[str, Any]:
    record = _identity("policy_decision", f"policy:decision:{case['id']}")
    record.update(
        {
            "session_class": case.get("session_class"),
            "ingress": case.get("ingress", "ubus_http"),
            "entrypoint_id": case.get("entrypoint_id"),
            "ubus_object": case.get("object"),
            "method": case.get("function"),
            "outcome": result.outcome,
            "no_ubusauth": case.get("no_ubusauth", 0),
            "sid_present": case.get("sid") is not None,
            "sid": case.get("sid") if result.jsonrpc_error == ERROR_PARSE else result.sid,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": f"policy/fixtures/expected_cases.json#{case['id']}",
                "c_double": "policy/c_double/uh_ubus_policy.c",
            },
            "assumptions": [ASSUMPTION_NOAUTH, ASSUMPTION_OBJECT],
            "unknowns": [UNKNOWN_LIVE, UNKNOWN_ACL_SET],
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
    if result.jsonrpc_error:
        record["jsonrpc_error"] = result.jsonrpc_error
    if case.get("not"):
        record["not"] = list(case["not"])
    if case.get("note"):
        record["note"] = case["note"]
    if result.session_class in SYNTHETIC_SESSION_CLASSES:
        record["synthetic_session"] = True
    if result.outcome == "deny":
        record["grant_emitted"] = False
    if result.matched:
        record["matched_acl"] = {
            "group": result.matched.group,
            "scope": result.matched.scope,
            "object": result.matched.object,
            "function": result.matched.function,
            "source": result.matched.source,
        }
    return {key: value for key, value in record.items() if value is not None}


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sessions = load_world(fixtures)
    cases = load_expected_cases(fixtures / "expected_cases.json")
    grants: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for case in cases:
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result))
        if case.get("expect_grant") and result.outcome == "allow":
            if int(case.get("no_ubusauth", 0)):
                raise ValueError("refusing to emit luci-ssl grant for no_ubusauth skip")
            obj = case.get("object")
            fun = case.get("function")
            if obj != M2_OBJECT or fun not in EMITTED_METHODS:
                raise ValueError(f"refusing to emit grant for {obj}.{fun}")
            grants.append(grant_record(case, result))
    bundle = {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": corpus_revision(repo_root),
        "pins": _pins(),
        "scope": (
            "/ubus luci.getFeatures plus inventoried request.args exec "
            "methods, getBlockDevices/setBlockDetect, and luci.sys "
            "getConntrackList/getProcessList; literal object/method names"
        ),
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/uh_ubus_policy.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_uhttpd": False,
            "live_rpcd": False,
        },
        "assumptions": [ASSUMPTION_NOAUTH, ASSUMPTION_OBJECT],
        "unknowns": [UNKNOWN_LIVE, UNKNOWN_ACL_SET],
        "decisions": decisions,
    }
    return grants, bundle


def dump_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def emit_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    grants_path = repo_root / "policy" / "grants.json"
    decisions_path = repo_root / "policy" / "policy_decisions.json"
    dump_json(grants_path, grants)
    dump_json(decisions_path, bundle)
    return grants_path, decisions_path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="M2 /ubus luci policy oracle")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("emit", help="write policy/grants.json and policy/policy_decisions.json")
    decide = sub.add_parser("decide", help="evaluate one /ubus call")
    decide.add_argument("--session-class", choices=sorted(SESSION_SIDS))
    decide.add_argument("--sid")
    decide.add_argument("--missing-sid", action="store_true")
    decide.add_argument("--object", default=M2_OBJECT)
    decide.add_argument("--function", default=M2_METHOD)
    decide.add_argument("--no-ubusauth", type=int, default=0)
    args = parser.parse_args(argv)
    if args.cmd == "emit" or args.cmd is None:
        grants_path, decisions_path = emit_artifacts()
        print(grants_path)
        print(decisions_path)
        return 0
    if args.cmd == "decide":
        sid = None if args.missing_sid else args.sid
        if sid is None and not args.missing_sid and args.session_class:
            sid = SESSION_SIDS[args.session_class]
        result = evaluate_call(
            session_class=args.session_class,
            sid=sid,
            object=args.object,
            function=args.function,
            data={},
            no_ubusauth=args.no_ubusauth,
        )
        print(json.dumps({"outcome": result.outcome, "matched": result.matched.source if result.matched else None, "error": result.jsonrpc_error}, indent=2))
        return 0 if result.outcome == "allow" else 1
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
