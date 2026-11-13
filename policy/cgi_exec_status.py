#!/usr/bin/env python3
"""cgi-io cgi-exec file.exec oracle for luci-mod-status dmesg/firewall.

Oracle transcribed from pinned source, not from a live daemon:

* cgi-io ``main.c`` ``main_exec`` / ``util.c`` ``parse_command`` /
  ``canonicalize_path`` / ``lookup_executable`` @ ``31cb3c89``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-status ACLs and ``fs.exec_direct`` callers @ luci ``b2e0be4b``

Bounded to cgi-io's conjunctive second gate for commands the pinned
status views reach via ``fs.exec_direct`` → cgi-exec:

``session.access(sid, "cgi-io", "exec", "read")`` then
``session.access(sid, "file", cmdline, "exec")`` or
``session.access(sid, "file", exe, "exec")``.

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after cgi-exec-file-v1 and
upserts synthetic effects into ``reports/handler_effects.json``.
Does not emit dispatcher, ``authorization_violation``, or ``path_found``.
Does not invent luci-ssl ubus grants. Does not fork ``execv``. Does not
staff ubus ``file.exec`` (rpcd-mod-file), including ``fs.exec`` of
``iptables -Z``. Does not treat ``shellquote`` / ``basename`` as sanitizers.
``lookup_executable`` PATH search is not a live stat: only the inventoried
absolute paths below are treated as found. cgi-exec-file-v1 remains the
three libexec helpers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .cgi_exec_file import (
    CGI_ENDPOINT,
    CGI_FUNCTION,
    CGI_INGRESS,
    CGI_OBJECT,
    CGI_SCOPE,
    CONTENT_TYPE_PREFIX,
    FILE_FUNCTION,
    FILE_SCOPE,
    LOGS_FIXTURE_SID,
    LOGS_SESSION_CLASS,
    evaluate_file_exec,
    load_helper_world,
)
from .oracle import (
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    Session,
    corpus_revision,
    dump_json,
    load_acl_catalog,
    parse_rpcd_logins,
    session_acls,
)

ANALYSIS_REVISION = "policy:cgi-exec-status-v1"
CGI_IO_SHA = "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

FIREWALL_SESSION_CLASS = "luci-mod-status-firewall"
FIREWALL_READ_SESSION_CLASS = "luci-mod-status-firewall-read"
FIREWALL_FIXTURE_SID = "55555555555555555555555555555555"
FIREWALL_READ_SID = "66666666666666666666666666666666"

DMESG = "/bin/dmesg"
NFT = "/usr/sbin/nft"
IPTABLES = "/usr/sbin/iptables"
IP6TABLES = "/usr/sbin/ip6tables"
IPTABLES_SAVE = "/usr/sbin/iptables-save"
IP6TABLES_SAVE = "/usr/sbin/ip6tables-save"
FIREWALL_INIT = "/etc/init.d/firewall"

COMMANDS: dict[str, dict[str, str]] = {
    DMESG: {
        "basename": "dmesg",
        "delegated": LOGS_SESSION_CLASS,
        "expectation_id": "luci-mod-status-logs-dmesg",
        "asset_id": "command:dmesg",
        "caller": "dmesg.js fs.exec_direct('/bin/dmesg', ['-r'])",
    },
    NFT: {
        "basename": "nft",
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-nft",
        "asset_id": "command:nft",
        "caller": "nftables.js fs.exec_direct('/usr/sbin/nft', ['--terse', '--json', 'list', 'ruleset'])",
    },
    IPTABLES: {
        "basename": "iptables",
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-iptables",
        "asset_id": "command:iptables",
        "caller": "iptables.js fs.exec_direct('/usr/sbin/iptables', ['--line-numbers', '-w', '-nvxL', '-t', table])",
    },
    IP6TABLES: {
        "basename": "ip6tables",
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-ip6tables",
        "asset_id": "command:ip6tables",
        "caller": "iptables.js fs.exec_direct('/usr/sbin/ip6tables', ['--line-numbers', '-w', '-nvxL', '-t', table])",
    },
    IPTABLES_SAVE: {
        "basename": "iptables-save",
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-iptables-save",
        "asset_id": "command:iptables-save",
        "caller": "nftables.js fs.exec_direct('/usr/sbin/iptables-save')",
    },
    IP6TABLES_SAVE: {
        "basename": "ip6tables-save",
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-ip6tables-save",
        "asset_id": "command:ip6tables-save",
        "caller": "nftables.js fs.exec_direct('/usr/sbin/ip6tables-save')",
    },
    FIREWALL_INIT: {
        "basename": "firewall-init",
        "delegated": FIREWALL_SESSION_CLASS,
        "expectation_id": "luci-mod-status-firewall-restart",
        "asset_id": "command:firewall-init",
        "caller": "iptables.js fs.exec_direct('/etc/init.d/firewall', ['restart'])",
    },
}

FOUND_PATHS = set(COMMANDS)
CASES_PATH = FIXTURES / "cgi_exec_status_cases.json"
SYNTHETIC_STATUS_CLASSES = frozenset(
    {LOGS_SESSION_CLASS, FIREWALL_SESSION_CLASS, FIREWALL_READ_SESSION_CLASS}
)

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
    "oracle treats only the inventoried luci-mod-status absolute command "
    "paths as found."
)
UNKNOWN_EXECV = (
    "execv of the command, helper-internal argv after the file ACL, and "
    "file.exec of commands other than the inventoried luci-mod-status "
    "dmesg/nft/iptables/firewall-init paths are not modeled."
)
UNKNOWN_UNSTAFFED = (
    "ubus file.exec (rpcd-mod-file) is not this slice, including iptables.js "
    "handleCounterReset fs.exec('/usr/sbin/iptables', ['-Z']). Track A is "
    "unstaffed. luci-mod-status-routes ip exec is ubus file.exec, not cgi-io. "
    "The three luci-ssl libexec helpers stay on policy:cgi-exec-file-v1."
)
UNKNOWN_OTHER_CGI = (
    "cgi-exec-v1 remains the cgi-io exec read gate only. cgi-exec-file-v1 "
    "remains the three libexec helpers. cgi-backup, cgi-upload, and "
    "cgi-download stay on their own analysis_revisions. dispatcher is not "
    "this slice."
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
    "This oracle does not fork execv or run the command body."
)
ASSUMPTION_NOT_LUCI = (
    "These commands are not luci object methods. Do not invent a luci-ssl "
    "ubus grant. Callers at luci b2e0be4b use fs.exec_direct → cgi-exec."
)


def entrypoint_for(fs_path: str) -> str:
    return f"{CGI_INGRESS}:{CGI_ENDPOINT}:{fs_path}"


def grant_id(session_class: str, fs_path: str) -> str:
    return f"policy:grant:{session_class}:{CGI_INGRESS}:{CGI_ENDPOINT}:{COMMANDS[fs_path]['basename']}"


def effect_id(fs_path: str) -> str:
    return f"policy:effect:cgi-exec-status:{COMMANDS[fs_path]['basename']}"


def load_status_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    sessions = load_helper_world(fixtures)
    catalog = load_acl_catalog(fixtures)
    logins = {
        login.username: login
        for login in parse_rpcd_logins((fixtures / "rpcd.config").read_text(encoding="utf-8"))
    }
    firewall = logins[FIREWALL_SESSION_CLASS]
    sessions[FIREWALL_FIXTURE_SID] = Session(
        session_class=FIREWALL_SESSION_CLASS,
        sid=FIREWALL_FIXTURE_SID,
        login=firewall,
        acls=session_acls(firewall, catalog),
    )
    firewall_read = logins[FIREWALL_READ_SESSION_CLASS]
    sessions[FIREWALL_READ_SID] = Session(
        session_class=FIREWALL_READ_SESSION_CLASS,
        sid=FIREWALL_READ_SID,
        login=firewall_read,
        acls=session_acls(firewall_read, catalog),
    )
    return sessions


def evaluate_status_exec(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    content_type: Optional[str] = CONTENT_TYPE_PREFIX,
    command: Optional[str] = DMESG,
    sessions: Optional[dict[str, Session]] = None,
):
    if sessions is None:
        sessions = load_status_world()
    return evaluate_file_exec(
        session_class=session_class,
        sid=sid,
        content_type=content_type,
        command=command,
        sessions=sessions,
        found_paths=FOUND_PATHS,
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


def _pins() -> dict[str, Any]:
    return {
        "cgi-io": CGI_IO_SHA,
        "luci": LUCI_SHA,
        "rpcd": RPCD_SHA,
        "lockfile": "corpus/lock.json",
        "endpoint": f"{CGI_INGRESS}:{CGI_ENDPOINT}",
        "commands": list(COMMANDS),
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Session]] = None
):
    content_type = case["content_type"] if "content_type" in case else CONTENT_TYPE_PREFIX
    return evaluate_status_exec(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        content_type=content_type,
        command=case.get("command"),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    if case.get("cgi_endpoint") != CGI_ENDPOINT:
        raise ValueError(f"refusing to emit grant for {case.get('cgi_endpoint')}")
    helper = result.helper
    if helper not in COMMANDS:
        raise ValueError(f"refusing to emit grant for command {helper!r}")
    record = _identity("policy_grant", grant_id(case["session_class"], helper))
    record.update(
        {
            "session_class": case["session_class"],
            "ingress": CGI_INGRESS,
            "entrypoint_id": entrypoint_for(helper),
            "cgi_endpoint": CGI_ENDPOINT,
            "fs_path": helper,
            "target_id": COMMANDS[helper]["asset_id"],
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
    if case["session_class"] in SYNTHETIC_STATUS_CLASSES:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result) -> dict[str, Any]:
    helper = result.helper if result.helper in COMMANDS else None
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
                "independent_expected": f"policy/fixtures/cgi_exec_status_cases.json#{case['id']}",
                "c_double": "policy/c_double/cgi_exec_status.c",
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
    if result.session_class in SYNTHETIC_STATUS_CLASSES:
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
    spec = COMMANDS[fs_path]
    command_grants = [row for row in grants if row.get("fs_path") == fs_path]
    grant_ids = [row["record_id"] for row in command_grants]
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
                spec["caller"],
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
                f"luci@{LUCI_SHA[:8]} {spec['caller']}",
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
    sessions = load_status_world(fixtures)
    cases = load_expected_cases(fixtures / "cgi_exec_status_cases.json")
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
        "scope": "cgi-io cgi-exec file.exec of luci-mod-status dmesg/nft/iptables/firewall-init",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/cgi_exec_status.c",
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
    effects = [effect_record(path, grants) for path in COMMANDS]
    return grants, bundle, effects


def write_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle, effects = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    bundle_path = repo_root / "policy" / "cgi_exec_status_decisions.json"
    effect_path = repo_root / "reports" / "m2-cgi-exec-status-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effects)
    return bundle_path, effect_path
