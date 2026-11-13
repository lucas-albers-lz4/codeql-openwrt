#!/usr/bin/env python3
"""ubus hostapd.<ifname>.wps_start oracle for luci-ssl wifi views.

Oracle transcribed from pinned source, not from a live daemon:

* uhttpd ``ubus.c`` ``parse_call_params`` / ``uh_ubus_allowed``
  @ ``93b05e0b65d91c23c5aa8fdde378df1f174ec71d``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-status-index-wifi ACL and ``60_wifi.js`` ``handleCallWPS``
  @ luci ``b2e0be4b``

Bounded to HTTP ``/ubus`` ``hostapd.<ifname>.wps_start`` the pinned
status wifi view reaches via LuCI
``rpc.declare({ object: 'hostapd.%s'.format(ifname), method: 'wps_start' })``.
That is hostapd's per-BSS object, not a luci object method.

``uh_ubus_allowed`` → ``session.access`` scope=ubus object=hostapd.*
function=wps_start (uhttpd omits scope; FNM_NOESCAPE).

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after
ubus-hostapd-del-client-v1 and upserts a synthetic effect into
``reports/handler_effects.json``.
Does not emit dispatcher, ``authorization_violation``, or ``path_found``.
Does not invent luci-ssl luci object grants. Does not invent a
``setInitAction`` luci-ssl grant. Does not invent a write flash login.
Does not invoke hostapd WPS. Does not staff ``wps_cancel`` /
``wps_status``. ``hostapd.del_client`` stays on
``policy:ubus-hostapd-del-client-v1``. luci-mod-network-config write
grants ``del_client``, not ``wps_start``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .oracle import (
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    UHTTPD_SHA,
    acl_match,
    corpus_revision,
    dump_json,
    evaluate_call,
)
from .ubus_hostapd_del_client import (
    SYNTHETIC_HOSTAPD_CLASSES,
    WIFI_FIXTURE_SID,
    WIFI_SESSION_CLASS,
    load_hostapd_world,
)

ANALYSIS_REVISION = "policy:ubus-hostapd-wps-start-v1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

UBUS_INGRESS = "ubus_http"
UBUS_OBJECT = "hostapd.*"
UBUS_METHOD = "wps_start"
CALL_OBJECT = "hostapd.wlan0"
ENTRYPOINT_ID = f"{UBUS_INGRESS}:hostapd.{UBUS_METHOD}"
TARGET_ID = "ubus:hostapd.wps_start"
ASSET_ID = "ubus:hostapd.wps_start"
EFFECT_ID = "hostapd.wps_start"
EFFECT_RECORD_ID = "policy:effect:ubus-hostapd-wps-start"
EXPECTATION_ID = "luci-mod-status-index-wifi-hostapd-wps-start"

CASES_PATH = FIXTURES / "ubus_hostapd_wps_start_cases.json"

UNKNOWN_LIVE = (
    "Live uhttpd, rpcd, and hostapd were not executed; decisions are "
    "transcribed from pinned C and ACL JSON."
)
UNKNOWN_HOSTAPD = (
    "hostapd ubus wps_start (PBC start handling) is not invoked. This "
    "oracle models the HTTP /ubus authorization gate only."
)
UNKNOWN_UNSTAFFED = (
    "cgi-io stays on policy:cgi-exec-v1 / cgi-exec-file-v1 / "
    "cgi-exec-status-v1. luci-mod-status iptables -Z / routes ip stay on "
    "policy:ubus-file-exec-v1. luci-mod-network-config ifup/ifdown/wifi stay "
    "on policy:ubus-file-exec-ifup-v1. luci-mod-status-processes /bin/kill "
    "stays on policy:ubus-file-exec-kill-v1. luci-mod-system-mounts "
    "umount/block stays on policy:ubus-file-exec-mounts-v1. luci-mod-system "
    "flash.js sysupgrade --list-backup stays on "
    "policy:ubus-file-exec-list-backup-v1. luci-mod-system-reboot "
    "system.reboot stays on policy:ubus-system-reboot-v1. luci-mod-system-init "
    "rc.init stays on policy:ubus-rc-init-v1. luci-mod-system-init rc.list "
    "stays on policy:ubus-rc-list-v1. luci-mod-status-index system.board "
    "stays on policy:ubus-system-board-v1. luci-mod-status-index system.info "
    "stays on policy:ubus-system-info-v1. luci-mod-status-index luci.getVersion "
    "stays on policy:ubus-luci-getversion-v1. luci-mod-status-index luci.getUnixtime "
    "stays on policy:ubus-luci-getunixtime-v1. luci-mod-network-config-write / "
    "luci-mod-status-index-wifi hostapd.del_client stays on "
    "policy:ubus-hostapd-del-client-v1. Write sysupgrade/firstboot stay "
    "unstaffed (no invented write flash login). luci-mod-network diagnostics "
    "ping/traceroute use fs.exec_direct without a cgi-io grant, so they are "
    "not this slice. crontab.js fs.exec of cron reload has file.exec of the "
    "cmdline but ubus file.write not file.exec. luci-mod-status-index-wifi "
    "also grants hostapd.* wps_cancel / wps_status; this slice does not emit "
    "those grants. luci object methods are not this slice. Track A is "
    "unstaffed. dispatcher is not this slice."
)
ASSUMPTION_GATE = (
    "uhttpd uh_ubus_allowed requires session.access scope=ubus "
    "object=hostapd.* function=wps_start (uhttpd omits scope; "
    "FNM_NOESCAPE). An allow means this HTTP gate was passed, not that "
    "hostapd started WPS. Call objects are hostapd.<ifname> "
    "(example hostapd.wlan0); the inventoried ACL pattern is hostapd.*."
)
ASSUMPTION_NOT_SANITIZER = (
    "shellquote and basename are not sanitizers."
)
ASSUMPTION_NO_WPS = (
    "This oracle does not invoke hostapd wps_start or model PBC arguments."
)
ASSUMPTION_NOT_LUCI = (
    "hostapd.wps_start is not a luci object method. Do not invent a luci "
    "object grant. 60_wifi.js at luci b2e0be4b handleCallWPS rpc.declare "
    "object=hostapd.<ifname> method=wps_start."
)
ASSUMPTION_NOT_DEL_CLIENT = (
    "hostapd.del_client stays on policy:ubus-hostapd-del-client-v1. "
    "luci-mod-network-config write grants hostapd.* del_client, not "
    "wps_start. The network-config-write fixture cannot pass this slice."
)
ASSUMPTION_NOT_OTHER_WPS = (
    "luci-mod-status-index-wifi write also grants hostapd.* wps_cancel / "
    "wps_status. This slice does not emit those grants."
)
ASSUMPTION_NOT_BOARD = (
    "luci-mod-status-index read grants system.board. That method stays on "
    "policy:ubus-system-board-v1. The index fixture cannot pass "
    "hostapd.wps_start."
)
ASSUMPTION_NOT_INFO = (
    "luci-mod-status-index also grants system.info. That method stays on "
    "policy:ubus-system-info-v1. The index fixture cannot pass "
    "hostapd.wps_start."
)
ASSUMPTION_NOT_GETVERSION = (
    "luci-mod-status-index read grants luci.getVersion. That method stays on "
    "policy:ubus-luci-getversion-v1. The index fixture cannot pass "
    "hostapd.wps_start."
)
ASSUMPTION_NOT_GETUNIXTIME = (
    "luci-mod-status-index read grants luci.getUnixtime. That method stays on "
    "policy:ubus-luci-getunixtime-v1. The index fixture cannot pass "
    "hostapd.wps_start."
)
ASSUMPTION_FIXTURE = (
    "Fixture login luci-mod-status-index-wifi is not a stock device login. "
    "That ACL group exists at luci b2e0be4b. This slice does not invent a "
    "write flash login."
)


def is_hostapd_wps_start(obj: Optional[str], fun: Optional[str]) -> bool:
    if obj is None or fun is None:
        return False
    return acl_match(UBUS_OBJECT, UBUS_METHOD, obj, fun)


def grant_id(session_class: str) -> str:
    return f"policy:grant:{session_class}:{UBUS_INGRESS}:hostapd.{UBUS_METHOD}"


def evaluate_hostapd_wps_start(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    object: Optional[str] = CALL_OBJECT,
    function: Optional[str] = UBUS_METHOD,
    data: Any = None,
    sessions: Optional[dict] = None,
):
    if sessions is None:
        sessions = load_hostapd_world()
    if data is None:
        data = {}
    return evaluate_call(
        session_class=session_class,
        sid=sid,
        object=object,
        function=function,
        data=data,
        sessions=sessions,
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
        "object_pattern": UBUS_OBJECT,
        "method": UBUS_METHOD,
        "example_object": CALL_OBJECT,
        "not_methods": ["del_client", "wps_cancel", "wps_status"],
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict] = None
):
    return evaluate_hostapd_wps_start(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        object=case.get("ubus_object", CALL_OBJECT),
        function=case.get("method", UBUS_METHOD),
        data=case.get("data", {}),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result, revision: str) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    if case.get("method") != UBUS_METHOD or not is_hostapd_wps_start(
        case.get("ubus_object"), case.get("method")
    ):
        raise ValueError("refusing to emit grant for non-hostapd.wps_start ubus method")
    if result.function != UBUS_METHOD or not is_hostapd_wps_start(
        result.object, result.function
    ):
        raise ValueError("refusing to emit grant unless evaluated call is hostapd.wps_start")
    record = _identity("policy_grant", grant_id(case["session_class"]), revision)
    record.update(
        {
            "session_class": case["session_class"],
            "ingress": UBUS_INGRESS,
            "entrypoint_id": ENTRYPOINT_ID,
            "ubus_object": UBUS_OBJECT,
            "method": UBUS_METHOD,
            "target_id": TARGET_ID,
            "op": "invoke",
            "acl_group": (
                result.matched.group if result.matched else case.get("acl_group")
            ),
            "expectation_id": case.get("expectation_id"),
            "assessment": case.get("assessment", "intended_access"),
            "requirements": [
                "uh_ubus_allowed",
                "session.access scope=ubus object=hostapd.* function=wps_start "
                "(uhttpd omits scope; FNM_NOESCAPE)",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if case["session_class"] in SYNTHETIC_HOSTAPD_CLASSES:
        record["synthetic_session"] = True
    return record


def decision_record(case: dict[str, Any], result, revision: str) -> dict[str, Any]:
    record = _identity("policy_decision", f"policy:decision:{case['id']}", revision)
    record.update(
        {
            "session_class": case.get("session_class"),
            "ingress": UBUS_INGRESS,
            "entrypoint_id": case.get("entrypoint_id", ENTRYPOINT_ID),
            "ubus_object": case.get("ubus_object", result.object),
            "method": case.get("method", result.function),
            "outcome": result.outcome,
            "sid_present": case.get("sid") is not None and case.get("sid") != "",
            "sid": result.sid,
            "jsonrpc_error": result.jsonrpc_error,
            "input_rule_refs": list(case.get("rule_refs", [])),
            "matching_steps": result.steps,
            "upstream_conformance": {
                "status": "source_transcribed",
                "live_daemon": False,
                "independent_expected": (
                    f"policy/fixtures/ubus_hostapd_wps_start_cases.json#{case['id']}"
                ),
                "c_double": "policy/c_double/ubus_hostapd_wps_start.c",
            },
            "assumptions": [
                ASSUMPTION_GATE,
                ASSUMPTION_NO_WPS,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
                ASSUMPTION_NOT_DEL_CLIENT,
                ASSUMPTION_NOT_OTHER_WPS,
                ASSUMPTION_NOT_BOARD,
                ASSUMPTION_NOT_INFO,
                ASSUMPTION_NOT_GETVERSION,
                ASSUMPTION_NOT_GETUNIXTIME,
                ASSUMPTION_FIXTURE,
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_HOSTAPD,
                UNKNOWN_UNSTAFFED,
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
    if result.session_class in SYNTHETIC_HOSTAPD_CLASSES:
        record["synthetic_session"] = True
    if result.outcome != "allow":
        record["grant_emitted"] = False
    if result.matched:
        record["matched_ubus_acl"] = {
            "group": result.matched.group,
            "scope": result.matched.scope,
            "object": result.matched.object,
            "function": result.matched.function,
            "source": result.matched.source,
        }
    return {key: value for key, value in record.items() if value is not None}


def effect_record(grants: list[dict[str, Any]], revision: str) -> dict[str, Any]:
    command_grants = [row for row in grants if row.get("entrypoint_id") == ENTRYPOINT_ID]
    grant_ids = [row["record_id"] for row in command_grants]
    assessment = "intended_access" if grant_ids else "unassessed"
    record = _identity("handler_effect", EFFECT_RECORD_ID, revision)
    record.update(
        {
            "ingress": UBUS_INGRESS,
            "entrypoint_id": ENTRYPOINT_ID,
            "ubus_object": UBUS_OBJECT,
            "method": UBUS_METHOD,
            "effect_id": EFFECT_ID,
            "target_id": TARGET_ID,
            "op": "invoke",
            "sink_kind": "ubus_call",
            "asset_id": ASSET_ID,
            "assessment": assessment,
            "expectation_id": EXPECTATION_ID,
            "conditions": [
                "JSON-RPC /ubus call object=hostapd.<ifname> method=wps_start",
                "data parameter is a BLOBMSG_TYPE_TABLE",
                "60_wifi.js handleCallWPS rpc.declare object=hostapd.<ifname> method=wps_start",
            ],
            "requirements": [
                "uh_ubus_allowed",
                "session.access scope=ubus object=hostapd.* function=wps_start "
                "(uhttpd omits scope; FNM_NOESCAPE)",
            ],
            "assumptions": [
                "Synthetic handler_effect transcribed from uhttpd uh_ubus_allowed; C, not ucode",
                ASSUMPTION_GATE,
                ASSUMPTION_NO_WPS,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_NOT_LUCI,
                ASSUMPTION_NOT_DEL_CLIENT,
                ASSUMPTION_NOT_OTHER_WPS,
                ASSUMPTION_NOT_BOARD,
                ASSUMPTION_NOT_INFO,
                ASSUMPTION_NOT_GETVERSION,
                ASSUMPTION_NOT_GETUNIXTIME,
                ASSUMPTION_FIXTURE,
            ],
            "evidence_refs": grant_ids
            + [
                f"uhttpd@{UHTTPD_SHA[:8]} ubus.c uh_ubus_allowed session.access hostapd.*/wps_start",
                f"luci@{LUCI_SHA[:8]} 60_wifi.js handleCallWPS rpc.declare hostapd.<ifname> wps_start",
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_HOSTAPD,
                UNKNOWN_UNSTAFFED,
            ],
        }
    )
    return record


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    sessions = load_hostapd_world(fixtures)
    cases = load_expected_cases(fixtures / "ubus_hostapd_wps_start_cases.json")
    revision = corpus_revision(repo_root)
    grants_by_id: dict[str, dict[str, Any]] = {}
    decisions: list[dict[str, Any]] = []
    for case in cases:
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result, revision))
        if case.get("expect_grant") and result.outcome == "allow":
            if case.get("method") != UBUS_METHOD or not is_hostapd_wps_start(
                case.get("ubus_object"), case.get("method")
            ):
                raise ValueError("refusing to emit grant for non-hostapd.wps_start ubus method")
            record = grant_record(case, result, revision)
            grants_by_id.setdefault(record["record_id"], record)
    grants = list(grants_by_id.values())
    bundle = {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": revision,
        "pins": _pins(),
        "scope": "ubus hostapd.wps_start of luci-mod-status-index-wifi",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/ubus_hostapd_wps_start.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_uhttpd": False,
            "live_rpcd": False,
            "live_hostapd": False,
        },
        "assumptions": [
            ASSUMPTION_GATE,
            ASSUMPTION_NO_WPS,
            ASSUMPTION_NOT_SANITIZER,
            ASSUMPTION_NOT_LUCI,
            ASSUMPTION_NOT_DEL_CLIENT,
            ASSUMPTION_NOT_OTHER_WPS,
            ASSUMPTION_NOT_BOARD,
            ASSUMPTION_NOT_INFO,
            ASSUMPTION_NOT_GETVERSION,
            ASSUMPTION_NOT_GETUNIXTIME,
            ASSUMPTION_FIXTURE,
        ],
        "unknowns": [
            UNKNOWN_LIVE,
            UNKNOWN_HOSTAPD,
            UNKNOWN_UNSTAFFED,
        ],
        "decisions": decisions,
    }
    effects = [effect_record(grants, revision)]
    return grants, bundle, effects


def write_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle, effects = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    bundle_path = repo_root / "policy" / "ubus_hostapd_wps_start_decisions.json"
    effect_path = repo_root / "reports" / "m2-ubus-hostapd-wps-start-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effects)
    return bundle_path, effect_path
