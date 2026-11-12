#!/usr/bin/env python3
"""cgi-io cgi-backup policy oracle (M2 ingress promotion).

Oracle transcribed from pinned source, not from a live daemon:

* cgi-io ``main.c`` ``main_backup`` / ``session_access``
  @ ``31cb3c89f02d918d7f17bf62a80c852fc38a1ca1``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-system-flash ``cgi-io`` ``backup`` read
  @ luci ``b2e0be4b46ec0fd43394c081fa7c50657af14011``

Does not rewrite the luci ``/ubus`` grant emitter. Does not emit cgi-exec,
cgi-upload, cgi-download, dispatcher, or ``authorization_violation``.
Does not fork ``/sbin/sysupgrade --create-backup``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

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
    load_world,
    parse_rpcd_logins,
    session_access,
    session_acls,
)

ANALYSIS_REVISION = "policy:cgi-backup-v1"
CGI_IO_SHA = "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

CGI_INGRESS = "cgi_io"
CGI_ENDPOINT = "cgi-backup"
CGI_SCOPE = "cgi-io"
CGI_OBJECT = "backup"
CGI_FUNCTION = "read"
CONTENT_TYPE_PREFIX = "application/x-www-form-urlencoded"
FLASH_SESSION_CLASS = "luci-mod-system-flash"
FLASH_FIXTURE_SID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
EFFECT_RECORD_ID = "policy:effect:cgi-backup-sensitive-read"
EFFECT_ID = "cgi-backup.sysupgrade.create-backup"
ENTRYPOINT_ID = f"{CGI_INGRESS}:{CGI_ENDPOINT}"
TARGET_ID = f"cgi_endpoint:{CGI_ENDPOINT}"
ASSET_ID = "cgi:backup"

CASES_PATH = FIXTURES / "cgi_backup_cases.json"

UNKNOWN_LIVE = (
    "Live cgi-io, uhttpd, and rpcd were not executed; decisions are "
    "transcribed from pinned C and ACL JSON."
)
ASSUMPTION_BACKUP_ONLY = (
    "cgi-io main_backup checks session.access scope=cgi-io object=backup "
    "function=read only. It does not require a file-scope ACL."
)
ASSUMPTION_NO_SYSUPGRADE = (
    "This oracle does not fork /sbin/sysupgrade --create-backup; the "
    "sensitive_backup_read effect is synthetic from the C gate."
)
ASSUMPTION_NOT_SANITIZER = (
    "shellquote and basename are not sanitizers. cgi-backup has no user "
    "path; the modeled command is the fixed argv /sbin/sysupgrade "
    "--create-backup -."
)
UNKNOWN_OTHER_CGI = (
    "cgi-upload, cgi-download, and cgi-exec are not emitted in this slice."
)


@dataclass
class BackupResult:
    outcome: str
    http_status: int
    session_class: Optional[str]
    sid: Optional[str]
    matched: Any
    message: str
    steps: list[dict[str, Any]]


def load_cgi_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    sessions = load_world(fixtures)
    catalog = load_acl_catalog(fixtures)
    logins = {
        login.username: login
        for login in parse_rpcd_logins((fixtures / "rpcd.config").read_text(encoding="utf-8"))
    }
    login = logins[FLASH_SESSION_CLASS]
    sessions[FLASH_FIXTURE_SID] = Session(
        session_class=FLASH_SESSION_CLASS,
        sid=FLASH_FIXTURE_SID,
        login=login,
        acls=session_acls(login, catalog),
    )
    return sessions


def content_type_ok(content_type: Optional[str]) -> bool:
    return content_type is not None and content_type.startswith(CONTENT_TYPE_PREFIX)


def evaluate_backup(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    content_type: Optional[str] = CONTENT_TYPE_PREFIX,
    sessions: Optional[dict[str, Session]] = None,
) -> BackupResult:
    if sessions is None:
        sessions = load_cgi_world()
    steps: list[dict[str, Any]] = [
        {
            "step": "postdecode",
            "content_type_prefix": CONTENT_TYPE_PREFIX,
            "content_type_ok": content_type_ok(content_type),
            "sessionid_present": bool(sid),
        }
    ]
    if not content_type_ok(content_type):
        steps.append({"step": "main_backup", "result": "HTTP_400", "message": "Invalid form data"})
        return BackupResult(
            outcome="bad_request",
            http_status=400,
            session_class=session_class,
            sid=sid,
            matched=None,
            message="Invalid form data",
            steps=steps,
        )
    if sid is None or sid == "":
        steps.append(
            {"step": "main_backup", "result": "HTTP_403", "message": "Backup permission denied"}
        )
        return BackupResult(
            outcome="deny",
            http_status=403,
            session_class=session_class,
            sid=sid,
            matched=None,
            message="Backup permission denied",
            steps=steps,
        )

    steps.append(
        {
            "step": "session_access",
            "scope_supplied_by_cgi_io": True,
            "args": {
                "ubus_rpc_session": sid,
                "scope": CGI_SCOPE,
                "object": CGI_OBJECT,
                "function": CGI_FUNCTION,
            },
        }
    )
    hit = sessions.get(sid)
    if hit is not None and session_class is not None and session_class != hit.session_class:
        raise ValueError(
            f"session_class {session_class!r} does not match SID session {hit.session_class!r}"
        )
    matched = session_access(hit, CGI_SCOPE, CGI_OBJECT, CGI_FUNCTION) if hit else None
    steps.append(
        {
            "step": "rpc_session_acl_allowed",
            "scope": CGI_SCOPE,
            "object": CGI_OBJECT,
            "function": CGI_FUNCTION,
            "match": "literal",
            "acl_group": matched.group if matched else None,
            "acl_source": matched.source if matched else None,
            "result": bool(matched),
        }
    )
    resolved_class = hit.session_class if hit else None
    if matched:
        steps.append({"step": "main_backup", "result": "allow", "sysupgrade": False})
        return BackupResult(
            outcome="allow",
            http_status=200,
            session_class=resolved_class,
            sid=sid,
            matched=matched,
            message="Backup permission granted",
            steps=steps,
        )
    steps.append({"step": "main_backup", "result": "HTTP_403", "message": "Backup permission denied"})
    return BackupResult(
        outcome="deny",
        http_status=403,
        session_class=resolved_class,
        sid=sid,
        matched=None,
        message="Backup permission denied",
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
        "endpoint": ENTRYPOINT_ID,
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Session]] = None
) -> BackupResult:
    content_type = case["content_type"] if "content_type" in case else CONTENT_TYPE_PREFIX
    return evaluate_backup(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        content_type=content_type,
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result: BackupResult) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    if case.get("cgi_endpoint") != CGI_ENDPOINT:
        raise ValueError(f"refusing to emit grant for {case.get('cgi_endpoint')}")
    record = _identity(
        "policy_grant",
        f"policy:grant:{case['session_class']}:{CGI_INGRESS}:{CGI_ENDPOINT}",
    )
    record.update(
        {
            "session_class": case["session_class"],
            "ingress": CGI_INGRESS,
            "entrypoint_id": case["entrypoint_id"],
            "cgi_endpoint": CGI_ENDPOINT,
            "target_id": case["target_id"],
            "op": "read",
            "acl_group": result.matched.group if result.matched else case.get("acl_group"),
            "expectation_id": case.get("expectation_id"),
            "assessment": case.get("assessment", "intended_access"),
            "requirements": [
                "session.access scope=cgi-io object=backup function=read",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if case["session_class"] == FLASH_SESSION_CLASS:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result: BackupResult) -> dict[str, Any]:
    record = _identity("policy_decision", f"policy:decision:{case['id']}")
    record.update(
        {
            "session_class": case.get("session_class"),
            "ingress": CGI_INGRESS,
            "entrypoint_id": case.get("entrypoint_id", ENTRYPOINT_ID),
            "cgi_endpoint": CGI_ENDPOINT,
            "outcome": result.outcome,
            "http_status": result.http_status,
            "sid_present": case.get("sid") is not None and case.get("sid") != "",
            "sid": result.sid,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": f"policy/fixtures/cgi_backup_cases.json#{case['id']}",
                "c_double": "policy/c_double/cgi_backup.c",
            },
            "assumptions": [
                ASSUMPTION_BACKUP_ONLY,
                ASSUMPTION_NO_SYSUPGRADE,
                ASSUMPTION_NOT_SANITIZER,
            ],
            "unknowns": [UNKNOWN_LIVE, UNKNOWN_OTHER_CGI],
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
    if result.session_class == FLASH_SESSION_CLASS:
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


def effect_record(grants: list[dict[str, Any]]) -> dict[str, Any]:
    grant_ids = [row["record_id"] for row in grants]
    record = _identity("handler_effect", EFFECT_RECORD_ID)
    record.update(
        {
            "ingress": CGI_INGRESS,
            "entrypoint_id": ENTRYPOINT_ID,
            "cgi_endpoint": CGI_ENDPOINT,
            "effect_id": EFFECT_ID,
            "target_id": TARGET_ID,
            "op": "read",
            "sink_kind": "sensitive_backup_read",
            "asset_id": ASSET_ID,
            "assessment": "intended_access",
            "expectation_id": "luci-mod-system-flash-backup",
            "conditions": [
                "argv0 contains cgi-backup",
                "CONTENT_TYPE application/x-www-form-urlencoded",
                "POST sessionid present",
            ],
            "requirements": [
                "session.access scope=cgi-io object=backup function=read",
            ],
            "assumptions": [
                "Synthetic handler_effect transcribed from cgi-io main_backup; C, not ucode",
                ASSUMPTION_NO_SYSUPGRADE,
                ASSUMPTION_NOT_SANITIZER,
                "A backup read is not a violation merely because the role lacks write permission",
            ],
            "evidence_refs": grant_ids
            + [
                f"cgi-io@{CGI_IO_SHA[:8]} main.c main_backup session_access(sid, cgi-io, backup, read)",
            ],
            "unknowns": [UNKNOWN_LIVE, UNKNOWN_OTHER_CGI],
        }
    )
    return record


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    sessions = load_cgi_world(fixtures)
    cases = load_expected_cases(fixtures / "cgi_backup_cases.json")
    grants: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for case in cases:
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result))
        if case.get("expect_grant") and result.outcome == "allow":
            if case.get("cgi_endpoint") != CGI_ENDPOINT:
                raise ValueError(f"refusing to emit grant for {case.get('cgi_endpoint')}")
            grants.append(grant_record(case, result))
    bundle = {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": corpus_revision(repo_root),
        "pins": _pins(),
        "scope": "cgi-io cgi-backup → sensitive_backup_read only",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/cgi_backup.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_cgi_io": False,
            "live_sysupgrade": False,
        },
        "assumptions": [
            ASSUMPTION_BACKUP_ONLY,
            ASSUMPTION_NO_SYSUPGRADE,
            ASSUMPTION_NOT_SANITIZER,
        ],
        "unknowns": [UNKNOWN_LIVE, UNKNOWN_OTHER_CGI],
        "decisions": decisions,
    }
    return grants, bundle, effect_record(grants)


def upsert_handler_effect(effect: dict[str, Any], repo_root: Path = REPO_ROOT) -> Path:
    path = repo_root / "reports" / "handler_effects.json"
    if path.exists():
        rows = json.loads(path.read_text(encoding="utf-8"))
        rows = [row for row in rows if row.get("record_id") != effect["record_id"]]
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = []
    rows.append(effect)
    dump_json(path, rows)
    return path
