#!/usr/bin/env python3
"""cgi-io cgi-download policy oracle (M2 ingress promotion).

Oracle transcribed from pinned source, not from a live daemon:

* cgi-io ``main.c`` ``main_download`` / ``canonicalize_path`` / ``session_access``
  @ ``31cb3c89f02d918d7f17bf62a80c852fc38a1ca1``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-system-flash ``cgi-io`` ``download`` read and
  ``/dev/mtdblock[0-9]*`` file read
  @ luci ``b2e0be4b46ec0fd43394c081fa7c50657af14011``

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after luci and cgi-backup
and upserts the synthetic effect into ``reports/handler_effects.json``.
Does not emit cgi-exec, dispatcher, or ``authorization_violation``.
Does not open/stat/sendfile the target path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .cgi_backup import FLASH_FIXTURE_SID, FLASH_SESSION_CLASS, load_cgi_world
from .oracle import (
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    corpus_revision,
    dump_json,
    session_access,
)

ANALYSIS_REVISION = "policy:cgi-download-v1"
CGI_IO_SHA = "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

CGI_INGRESS = "cgi_io"
CGI_ENDPOINT = "cgi-download"
CGI_SCOPE = "cgi-io"
CGI_OBJECT = "download"
CGI_FUNCTION = "read"
FILE_SCOPE = "file"
FILE_FUNCTION = "read"
CONTENT_TYPE_PREFIX = "application/x-www-form-urlencoded"
EFFECT_RECORD_ID = "policy:effect:cgi-download-file-read"
EFFECT_ID = "cgi-download.canonicalize-path.read"
ENTRYPOINT_ID = f"{CGI_INGRESS}:{CGI_ENDPOINT}"
TARGET_ID = f"cgi_endpoint:{CGI_ENDPOINT}"
ASSET_ID = "file:download-path"
FLASH_PATH = "/dev/mtdblock0"
FLASH_FILE_PAT = "/dev/mtdblock[0-9]*"

CASES_PATH = FIXTURES / "cgi_download_cases.json"

UNKNOWN_LIVE = (
    "Live cgi-io, uhttpd, and rpcd were not executed; decisions are "
    "transcribed from pinned C and ACL JSON."
)
UNKNOWN_POSTDECODE = (
    "CONTENT_LENGTH/body framing and URL-decoding failures in postdecode are "
    "not modeled; this slice assumes successful form-body decoding."
)
UNKNOWN_FS = (
    "This oracle does not stat, open, or sendfile the target; regular-file "
    "and block-device checks after the ACL gate are unknown."
)
ASSUMPTION_CONJUNCT = (
    "cgi-io main_download requires session.access scope=cgi-io object=download "
    "function=read AND session.access scope=file object=canonicalize_path(path) "
    "function=read. A cgi-io grant without the file-read grant cannot authorize."
)
ASSUMPTION_CANON = (
    "Path is canonicalized before the file ACL check so a '../' suffix cannot "
    "match an allowed glob prefix while open() resolves outside that prefix."
)
ASSUMPTION_NOT_SANITIZER = (
    "shellquote and basename are not sanitizers. canonicalize_path is a "
    "textual path normalizer, not a taint sanitizer."
)
UNKNOWN_OTHER_CGI = (
    "cgi-upload and cgi-exec are not emitted in this slice. cgi-backup stays "
    "on policy:cgi-backup-v1."
)


def canonicalize_path(path: Optional[str]) -> Optional[str]:
    """cgi-io util.c canonicalize_path @ 31cb3c89."""
    if path is None or path == "":
        return None
    out: list[str] = []
    i = 0
    n = len(path)
    while i < n:
        ch = path[i]
        if ch != "/":
            out.append(ch)
            i += 1
            continue
        if i + 1 < n and path[i + 1] == "/":
            i += 1
            continue
        if i + 1 < n and path[i + 1] == ".":
            if i + 2 >= n or path[i + 2] == "/":
                i += 2
                continue
            if i + 2 < n and path[i + 2] == "." and (i + 3 >= n or path[i + 3] == "/"):
                while out and out.pop() != "/":
                    pass
                i += 3
                continue
        out.append(ch)
        i += 1
    if len(out) > 1 and out[-1] == "/":
        out.pop()
    elif not out:
        out.append("/")
    return "".join(out)


@dataclass
class DownloadResult:
    outcome: str
    http_status: int
    session_class: Optional[str]
    sid: Optional[str]
    path: Optional[str]
    canon: Optional[str]
    cgi_matched: Any
    file_matched: Any
    message: str
    steps: list[dict[str, Any]]


def content_type_ok(content_type: Optional[str]) -> bool:
    return content_type is not None and content_type.startswith(CONTENT_TYPE_PREFIX)


def evaluate_download(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    content_type: Optional[str] = CONTENT_TYPE_PREFIX,
    path: Optional[str] = FLASH_PATH,
    sessions: Optional[dict[str, Any]] = None,
) -> DownloadResult:
    if sessions is None:
        sessions = load_cgi_world()
    steps: list[dict[str, Any]] = [
        {
            "step": "postdecode",
            "body_validation_assumed": True,
            "content_type_prefix": CONTENT_TYPE_PREFIX,
            "content_type_ok": content_type_ok(content_type),
            "sessionid_present": bool(sid),
            "path_present": bool(path),
        }
    ]
    if not content_type_ok(content_type):
        steps.append({"step": "main_download", "result": "HTTP_400", "message": "Invalid form data"})
        return DownloadResult(
            outcome="bad_request",
            http_status=400,
            session_class=session_class,
            sid=sid,
            path=path,
            canon=None,
            cgi_matched=None,
            file_matched=None,
            message="Invalid form data",
            steps=steps,
        )
    if sid is None or sid == "":
        steps.append(
            {
                "step": "main_download",
                "result": "HTTP_403",
                "message": "Download permission denied",
            }
        )
        return DownloadResult(
            outcome="deny",
            http_status=403,
            session_class=session_class,
            sid=sid,
            path=path,
            canon=None,
            cgi_matched=None,
            file_matched=None,
            message="Download permission denied",
            steps=steps,
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
        steps.append(
            {
                "step": "main_download",
                "result": "HTTP_403",
                "message": "Download permission denied",
            }
        )
        return DownloadResult(
            outcome="deny",
            http_status=403,
            session_class=resolved_class,
            sid=sid,
            path=path,
            canon=None,
            cgi_matched=None,
            file_matched=None,
            message="Download permission denied",
            steps=steps,
        )

    canon = canonicalize_path(path) if path else None
    steps.append({"step": "canonicalize_path", "path": path, "canon": canon})
    file_matched = (
        session_access(hit, FILE_SCOPE, canon, FILE_FUNCTION) if hit and canon else None
    )
    steps.append(
        {
            "step": "session_access",
            "scope": FILE_SCOPE,
            "object": canon,
            "function": FILE_FUNCTION,
            "result": bool(file_matched),
        }
    )
    if not canon or not file_matched:
        steps.append(
            {
                "step": "main_download",
                "result": "HTTP_403",
                "message": "Access to path denied by ACL",
            }
        )
        return DownloadResult(
            outcome="path_denied",
            http_status=403,
            session_class=resolved_class,
            sid=sid,
            path=path,
            canon=canon,
            cgi_matched=cgi_matched,
            file_matched=None,
            message="Access to path denied by ACL",
            steps=steps,
        )

    steps.append({"step": "main_download", "result": "allow", "sendfile": False})
    return DownloadResult(
        outcome="allow",
        http_status=200,
        session_class=resolved_class,
        sid=sid,
        path=path,
        canon=canon,
        cgi_matched=cgi_matched,
        file_matched=file_matched,
        message="Download permission granted",
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
    case: dict[str, Any], sessions: Optional[dict[str, Any]] = None
) -> DownloadResult:
    content_type = case["content_type"] if "content_type" in case else CONTENT_TYPE_PREFIX
    return evaluate_download(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        content_type=content_type,
        path=case.get("path", FLASH_PATH),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result: DownloadResult) -> dict[str, Any]:
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
            "acl_group": result.cgi_matched.group if result.cgi_matched else case.get("acl_group"),
            "expectation_id": case.get("expectation_id"),
            "assessment": case.get("assessment", "intended_access"),
            "requirements": [
                "session.access scope=cgi-io object=download function=read",
                "session.access scope=file object=canonicalize_path(path) function=read",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if case["session_class"] == FLASH_SESSION_CLASS:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result: DownloadResult) -> dict[str, Any]:
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
            "path": result.path,
            "canon": result.canon,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": f"policy/fixtures/cgi_download_cases.json#{case['id']}",
                "c_double": "policy/c_double/cgi_download.c",
            },
            "assumptions": [
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_CANON,
                "Successful form-body framing and URL decoding are preconditions; CONTENT_LENGTH/body/URL-decoding failures are outside this slice.",
                ASSUMPTION_NOT_SANITIZER,
            ],
            "unknowns": [UNKNOWN_LIVE, UNKNOWN_POSTDECODE, UNKNOWN_FS, UNKNOWN_OTHER_CGI],
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
            "sink_kind": "file_read",
            "asset_id": ASSET_ID,
            "assessment": "intended_access",
            "expectation_id": "luci-mod-system-flash-download",
            "conditions": [
                "argv0 contains cgi-download",
                "CONTENT_TYPE application/x-www-form-urlencoded",
                "Successfully decoded form body with POST sessionid and path present",
                "path = canonicalize_path(fields[path])",
            ],
            "requirements": [
                "session.access scope=cgi-io object=download function=read",
                "session.access scope=file object=canonicalize_path(path) function=read",
            ],
            "assumptions": [
                "Synthetic handler_effect transcribed from cgi-io main_download; C, not ucode",
                ASSUMPTION_CONJUNCT,
                ASSUMPTION_CANON,
                "Successful form-body framing and URL decoding are preconditions",
                "This oracle does not open, stat, or sendfile the target",
                ASSUMPTION_NOT_SANITIZER,
            ],
            "evidence_refs": grant_ids
            + [
                f"cgi-io@{CGI_IO_SHA[:8]} main.c main_download session_access(sid, cgi-io, download, read) then file read of canonicalize_path(path)",
            ],
            "unknowns": [UNKNOWN_LIVE, UNKNOWN_POSTDECODE, UNKNOWN_FS, UNKNOWN_OTHER_CGI],
        }
    )
    return record


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    sessions = load_cgi_world(fixtures)
    cases = load_expected_cases(fixtures / "cgi_download_cases.json")
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
        "scope": "cgi-io cgi-download → file_read with conjunctive file ACL",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/cgi_download.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_cgi_io": False,
            "live_filesystem": False,
        },
        "assumptions": [
            ASSUMPTION_CONJUNCT,
            ASSUMPTION_CANON,
            "Successful form-body framing and URL decoding are preconditions; CONTENT_LENGTH/body/URL-decoding failures are outside this slice.",
            ASSUMPTION_NOT_SANITIZER,
        ],
        "unknowns": [UNKNOWN_LIVE, UNKNOWN_POSTDECODE, UNKNOWN_FS, UNKNOWN_OTHER_CGI],
        "decisions": decisions,
    }
    return grants, bundle, effect_record(grants)


def write_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle, effect = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    bundle_path = repo_root / "policy" / "cgi_download_decisions.json"
    effect_path = repo_root / "reports" / "m2-cgi-download-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effect)
    return bundle_path, effect_path
