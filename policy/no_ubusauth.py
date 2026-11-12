#!/usr/bin/env python3
"""M2 profile variant: uhttpd ``option no_ubusauth 1``.

Oracle transcribed from pinned source, not from a live daemon:

* uhttpd ``ubus.c`` ``parse_call_params`` SID rewrite and
  ``uh_ubus_handle_request_object`` skip of ``uh_ubus_allowed``
  @ ``93b05e0b65d91c23c5aa8fdde378df1f174ec71d``
* uhttpd ``main.c`` ``-a`` → ``conf.ubus_noauth``
* openwrt ``uhttpd.init`` ``append_bool no_ubusauth -a`` and commented
  ``option no_ubusauth 0`` @ ``4e9642517b48bae612ff10fb72fb9199e559500e``

Does not rewrite the luci ``/ubus`` grant emitter. Does not emit luci-ssl
ACL grants, cgi-io grants, dispatcher, ``authorization_violation``, or
``path_found``. cgi-io and dispatcher ``admin/ubus`` are unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .oracle import (
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    REPO_ROOT,
    SYNTHETIC_SESSION_CLASSES,
    corpus_revision,
    dump_json,
    evaluate_call,
    load_world,
)

ANALYSIS_REVISION = "policy:no-ubusauth-v1"
PROFILE = "luci-ssl-25.12-no-ubusauth"
BASE_PROFILE = "luci-ssl-25.12"
UHTTPD_SHA = "93b05e0b65d91c23c5aa8fdde378df1f174ec71d"
OPENWRT_SHA = "4e9642517b48bae612ff10fb72fb9199e559500e"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"

CASES_PATH = FIXTURES / "no_ubusauth_cases.json"
UNKNOWN_SID = "ffffffffffffffffffffffffffffffff"

UNKNOWN_LIVE = (
    "Live rpcd and uhttpd were not executed; decisions are transcribed "
    "from pinned C and the stock uhttpd UCI/init overlay."
)
UNKNOWN_PLUGIN = (
    "This slice is the uhttpd /ubus JSON-RPC HTTP gate only. Plugin-side "
    "session checks, if any, are not modeled. Stock luci.getFeatures has none."
)
UNKNOWN_CGI = (
    "cgi-io and dispatcher admin/ubus are not this profile. no_ubusauth "
    "does not skip those ingresses."
)
ASSUMPTION_SKIP = (
    "uhttpd ubus.c uh_ubus_handle_request_object skips uh_ubus_allowed / "
    "session.access when conf.ubus_noauth is set. That skip is not an ACL "
    "grant and is not luci-ssl-25.12 (that profile has no_ubusauth=0)."
)
ASSUMPTION_REWRITE = (
    "Empty/missing SID is rewritten to UH_UBUS_DEFAULT_SID only when "
    "conf.ubus_noauth is set; parse still requires object, function, and a "
    "BLOBMSG_TYPE_TABLE data parameter."
)
ASSUMPTION_VARIANT = (
    "Stock luci-ssl-25.12 ships commented option no_ubusauth 0. This "
    "profile is the operator-enabled variant option no_ubusauth 1 / uhttpd -a."
)
ASSUMPTION_NO_GRANT = (
    "Skip-allows do not emit policy_grant rows. Unauthenticated luci-ssl "
    "ACLs still name only luci.getFeatures; that ACL is not consulted here."
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
        "base_profile": BASE_PROFILE,
        "uhttpd_flag": "-a",
        "uci_option": "option no_ubusauth 1",
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Any]] = None
) -> Any:
    data = {} if case.get("data_present") else None
    return evaluate_call(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        object=case.get("object"),
        function=case.get("function"),
        data=data,
        no_ubusauth=1,
        sessions=sessions,
    )


def decision_record(case: dict[str, Any], result: Any) -> dict[str, Any]:
    if case.get("expect_grant"):
        raise ValueError("no_ubusauth profile does not emit luci-ssl grants")
    record = _identity("policy_decision", f"policy:decision:{case['id']}")
    record.update(
        {
            "session_class": result.session_class,
            "ingress": case.get("ingress", "ubus_http"),
            "entrypoint_id": case.get("entrypoint_id"),
            "ubus_object": case.get("object"),
            "method": case.get("function"),
            "outcome": result.outcome,
            "no_ubusauth": 1,
            "sid_present": case.get("sid") is not None,
            "sid": result.sid,
            "sid_rewritten": result.sid_rewritten,
            "grant_emitted": False,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": f"policy/fixtures/no_ubusauth_cases.json#{case['id']}",
                "c_double": "policy/c_double/uh_ubus_policy.c",
            },
            "assumptions": [
                ASSUMPTION_SKIP,
                ASSUMPTION_REWRITE,
                ASSUMPTION_VARIANT,
                ASSUMPTION_NO_GRANT,
            ],
            "unknowns": [UNKNOWN_LIVE, UNKNOWN_PLUGIN, UNKNOWN_CGI],
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
    if result.matched:
        raise ValueError("no_ubusauth skip must not record an ACL match")
    return {key: value for key, value in record.items() if value is not None}


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    sessions = load_world(fixtures)
    cases = load_expected_cases(fixtures / "no_ubusauth_cases.json")
    decisions: list[dict[str, Any]] = []
    for case in cases:
        if int(case.get("no_ubusauth", 1)) != 1:
            raise ValueError(f"{case['id']} is not a no_ubusauth=1 case")
        if case.get("expect_grant"):
            raise ValueError(f"{case['id']} must not expect a luci-ssl grant")
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result))
    return {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": corpus_revision(repo_root),
        "pins": _pins(),
        "scope": (
            "/ubus JSON-RPC call with uhttpd option no_ubusauth 1: SID rewrite "
            "plus skip of uh_ubus_allowed; no luci-ssl ACL grants"
        ),
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/uh_ubus_policy.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_uhttpd": False,
            "live_rpcd": False,
        },
        "assumptions": [
            ASSUMPTION_SKIP,
            ASSUMPTION_REWRITE,
            ASSUMPTION_VARIANT,
            ASSUMPTION_NO_GRANT,
        ],
        "unknowns": [UNKNOWN_LIVE, UNKNOWN_PLUGIN, UNKNOWN_CGI],
        "grants": [],
        "decisions": decisions,
    }


def write_artifacts(repo_root: Path = REPO_ROOT) -> Path:
    bundle = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    path = repo_root / "policy" / "no_ubusauth_decisions.json"
    dump_json(path, bundle)
    return path
