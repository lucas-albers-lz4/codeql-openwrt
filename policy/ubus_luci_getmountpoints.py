#!/usr/bin/env python3
"""ubus luci.getMountPoints oracle for luci-mod-status-index-storage.

Oracle transcribed from pinned source, not from a live daemon:

* uhttpd ``ubus.c`` ``parse_call_params`` / ``uh_ubus_allowed``
  @ ``93b05e0b65d91c23c5aa8fdde378df1f174ec71d``
* rpcd ``session.c`` ``rpc_handle_access`` / ``rpc_session_acl_allowed``
  @ ``d99f703e4035d03fbcfbada3cb697db346c2b984``
* luci-mod-status-index-storage ACL and ``25_storage.js`` caller @ luci
  ``b2e0be4b``

Bounded to HTTP ``/ubus`` ``luci.getMountPoints`` the pinned status
storage view reaches via LuCI
``rpc.declare({ object: 'luci', method: 'getMountPoints' })``.
``mounts.js`` and ``package-manager.js`` declare the same method.
That is the luci-base rpcd plugin, not procd ``system``.

``uh_ubus_allowed`` → ``session.access`` scope=ubus object=luci
function=getMountPoints (uhttpd omits scope).

Does not rewrite the luci ``/ubus`` grant emitter. Canonical
``python3 -m policy emit`` appends these grants after
ubus-luci-getodhcp6cstats-v1 and upserts a synthetic effect into
``reports/handler_effects.json``.
Does not emit dispatcher, ``authorization_violation``, or ``path_found``.
Does not invent extra ACL. Does not invent a write flash login.
Does not invent luci-mod-status-index-ports / dhcp / dsl logins.
Does not invoke the luci-base getMountPoints handler
(open ``/proc/mounts`` / ``statvfs``).
``system.board`` stays on ``policy:ubus-system-board-v1``.
``system.info`` stays on ``policy:ubus-system-info-v1``.
``system.reboot`` stays on ``policy:ubus-system-reboot-v1``.
``luci.getVersion`` stays on ``policy:ubus-luci-getversion-v1``.
``luci.getUnixtime`` stays on ``policy:ubus-luci-getunixtime-v1``.
``luci.getOdhcp6cStats`` stays on ``policy:ubus-luci-getodhcp6cstats-v1``.
``luci-mod-status-index`` grants getVersion / getUnixtime /
getOdhcp6cStats, not getMountPoints, and is not this slice.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .cgi_exec_file import PKGMGR_SESSION_CLASS
from .oracle import (
    DEFAULT_UBUS_DATA,
    C_DOUBLE_FLAGS,
    FIXTURES,
    PRODUCER,
    PROFILE,
    REPO_ROOT,
    Session,
    UHTTPD_SHA,
    corpus_revision,
    dump_json,
    evaluate_call,
    parse_rpcd_logins,
    session_acls,
)
from .ubus_file_exec_mounts import MOUNTS_SESSION_CLASS
from .ubus_luci_getodhcp6cstats import (
    FLASH_SESSION_CLASS,
    INDEX_FIXTURE_SID,
    INDEX_SESSION_CLASS,
    INIT_READ_SESSION_CLASS,
    LOGS_SESSION_CLASS,
    REALTIME_SESSION_CLASS,
    REBOOT_SESSION_CLASS,
    load_luci_getodhcp6cstats_world,
)
from .ubus_system_board import load_board_catalog

ANALYSIS_REVISION = "policy:ubus-luci-getmountpoints-v1"
RPCD_SHA = "d99f703e4035d03fbcfbada3cb697db346c2b984"
LUCI_SHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

UBUS_INGRESS = "ubus_http"
UBUS_OBJECT = "luci"
UBUS_METHOD = "getMountPoints"
ENTRYPOINT_ID = f"{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}"
TARGET_ID = f"ubus:{UBUS_OBJECT}.{UBUS_METHOD}"
ASSET_ID = "ubus:luci.getMountPoints"
EFFECT_ID = "luci.getMountPoints"
EFFECT_RECORD_ID = "policy:effect:ubus-luci-getmountpoints"
EXPECTATION_ID = "luci-mod-status-index-storage-getmountpoints"

STORAGE_SESSION_CLASS = "luci-mod-status-index-storage"
STORAGE_FIXTURE_SID = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"

CASES_PATH = FIXTURES / "ubus_luci_getmountpoints_cases.json"
SYNTHETIC_GETMOUNTPOINTS_CLASSES = frozenset(
    {
        STORAGE_SESSION_CLASS,
        MOUNTS_SESSION_CLASS,
        PKGMGR_SESSION_CLASS,
        INDEX_SESSION_CLASS,
        REALTIME_SESSION_CLASS,
        REBOOT_SESSION_CLASS,
        FLASH_SESSION_CLASS,
        LOGS_SESSION_CLASS,
        INIT_READ_SESSION_CLASS,
        "luci-mod-system-config",
    }
)

UNKNOWN_LIVE = (
    "Live uhttpd, rpcd, and the luci-base plugin were not executed; "
    "decisions are transcribed from pinned C and ACL JSON."
)
UNKNOWN_HANDLER = (
    "The luci-base getMountPoints handler is not invoked. "
    "This oracle models the HTTP /ubus authorization gate only."
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
    "stays on policy:ubus-system-info-v1. Write sysupgrade/firstboot stay "
    "unstaffed (no invented write flash login). flash.js tar -tzf and "
    "/sbin/reboot stay unstaffed. luci-mod-network diagnostics ping/"
    "traceroute use fs.exec_direct without a cgi-io grant, so they are not "
    "this slice. crontab.js fs.exec of cron reload has file.exec of the "
    "cmdline but ubus file.write not file.exec. luci.getVersion stays on "
    "policy:ubus-luci-getversion-v1. luci.getUnixtime stays on "
    "policy:ubus-luci-getunixtime-v1. luci.getOdhcp6cStats stays on "
    "policy:ubus-luci-getodhcp6cstats-v1. hostapd.del_client / wps_start / "
    "wps_cancel / wps_status stay on their hostapd revisions. "
    "luci-mod-status-index-ports / dhcp / dsl stay unstaffed. "
    "Track A is unstaffed. dispatcher is not this slice. "
    "setInitAction is not this slice."
)
ASSUMPTION_GATE = (
    "uhttpd uh_ubus_allowed requires session.access scope=ubus "
    "object=luci function=getMountPoints (uhttpd omits scope). An allow means "
    "this HTTP gate was passed, not that the luci-base getMountPoints handler ran."
)
ASSUMPTION_NOT_SANITIZER = (
    "shellquote and basename are not sanitizers."
)
ASSUMPTION_NO_HANDLER = (
    "This oracle does not invoke the luci-base getMountPoints handler or "
    "open /proc/mounts / statvfs."
)
ASSUMPTION_IS_LUCI = (
    "luci.getMountPoints is a luci object method. 25_storage.js at luci "
    "b2e0be4b uses rpc.declare object=luci method=getMountPoints. mounts.js "
    "and package-manager.js declare the same method. This slice does not "
    "rewrite the luci exec-methods emitter "
    "(policy:ubus-luci-exec-methods-v2). luci.getVersion stays on "
    "policy:ubus-luci-getversion-v1. luci.getUnixtime stays on "
    "policy:ubus-luci-getunixtime-v1. luci.getOdhcp6cStats stays on "
    "policy:ubus-luci-getodhcp6cstats-v1."
)
ASSUMPTION_NOT_VERSION = (
    "10_system.js declares luci.getVersion. That method stays on "
    "policy:ubus-luci-getversion-v1; this slice does not emit a getVersion "
    "grant. The index fixture cannot pass getMountPoints."
)
ASSUMPTION_NOT_UNIXTIME = (
    "10_system.js declares luci.getUnixtime. That method stays on "
    "policy:ubus-luci-getunixtime-v1; this slice does not emit a "
    "getUnixtime grant."
)
ASSUMPTION_NOT_ODHCP = (
    "30_network.js declares luci.getOdhcp6cStats. That method stays on "
    "policy:ubus-luci-getodhcp6cstats-v1; this slice does not emit a "
    "getOdhcp6cStats grant. The index fixture cannot pass getMountPoints."
)
ASSUMPTION_NOT_BOARD = (
    "luci-mod-status-index also grants ubus system.board. 10_system.js "
    "declares system.board. That method stays on "
    "policy:ubus-system-board-v1; this slice does not emit a system.board "
    "grant."
)
ASSUMPTION_NOT_INFO = (
    "luci-mod-status-index-storage also grants ubus system.info. "
    "25_storage.js declares system.info. That method stays on "
    "policy:ubus-system-info-v1; this slice does not emit a system.info "
    "grant."
)
ASSUMPTION_NOT_REBOOT = (
    "system.reboot stays on policy:ubus-system-reboot-v1. The storage "
    "fixture cannot pass system.reboot."
)
ASSUMPTION_NOT_BLOCK = (
    "luci-mod-system-mounts also grants luci.getBlockDevices / "
    "luci.setBlockDetect. Those methods stay on the luci exec-methods "
    "emitter. This slice does not emit those grants."
)
ASSUMPTION_FIXTURE = (
    "Fixture logins luci-mod-status-index-storage, luci-mod-system-mounts, "
    "and luci-app-package-manager are not stock device logins. Those ACL "
    "groups exist at luci b2e0be4b. This slice does not invent a write "
    "flash login or luci-mod-status-index-ports / dhcp / dsl logins."
)


def grant_id(session_class: str) -> str:
    return f"policy:grant:{session_class}:{UBUS_INGRESS}:{UBUS_OBJECT}.{UBUS_METHOD}"


def load_luci_getmountpoints_world(fixtures: Path = FIXTURES) -> dict[str, Session]:
    sessions = load_luci_getodhcp6cstats_world(fixtures)
    catalog = load_board_catalog(fixtures)
    logins = {
        login.username: login
        for login in parse_rpcd_logins((fixtures / "rpcd.config").read_text(encoding="utf-8"))
    }
    storage = logins[STORAGE_SESSION_CLASS]
    sessions[STORAGE_FIXTURE_SID] = Session(
        session_class=STORAGE_SESSION_CLASS,
        sid=STORAGE_FIXTURE_SID,
        login=storage,
        acls=session_acls(storage, catalog),
    )
    return sessions


def evaluate_luci_getmountpoints(
    *,
    session_class: Optional[str] = None,
    sid: Optional[str] = None,
    object: Optional[str] = UBUS_OBJECT,
    function: Optional[str] = UBUS_METHOD,
    data: Any = DEFAULT_UBUS_DATA,
    sessions: Optional[dict[str, Session]] = None,
):
    if sessions is None:
        sessions = load_luci_getmountpoints_world()
    if data is DEFAULT_UBUS_DATA:
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
        "object": UBUS_OBJECT,
        "method": UBUS_METHOD,
        "not_method": "getVersion",
        "not_unixtime": "getUnixtime",
        "not_odhcp": "getOdhcp6cStats",
        "not_board": "board",
        "not_info": "info",
        "not_reboot": "reboot",
        "not_object": "system",
    }


def load_expected_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def evaluate_expected_case(
    case: dict[str, Any], sessions: Optional[dict[str, Session]] = None
):
    return evaluate_luci_getmountpoints(
        session_class=case.get("session_class"),
        sid=case.get("sid"),
        object=case.get("ubus_object", UBUS_OBJECT),
        function=case.get("method", UBUS_METHOD),
        data=case.get("data", {}),
        sessions=sessions,
    )


def grant_record(case: dict[str, Any], result, revision: str) -> dict[str, Any]:
    if result.session_class is None or case["session_class"] != result.session_class:
        raise ValueError("grant case session_class does not match evaluated SID session")
    if case.get("ubus_object") != UBUS_OBJECT or case.get("method") != UBUS_METHOD:
        raise ValueError("refusing to emit grant for non-luci.getMountPoints ubus method")
    if result.object != UBUS_OBJECT or result.function != UBUS_METHOD:
        raise ValueError("refusing to emit grant unless evaluated call is luci.getMountPoints")
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
                "session.access scope=ubus object=luci function=getMountPoints (uhttpd omits scope)",
            ],
            "evidence_refs": list(case.get("rule_refs", [])),
        }
    )
    if case.get("note"):
        record["note"] = case["note"]
    if case["session_class"] in SYNTHETIC_GETMOUNTPOINTS_CLASSES:
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
                "independent_expected": f"policy/fixtures/ubus_luci_getmountpoints_cases.json#{case['id']}",
                "c_double": "policy/c_double/ubus_luci_getmountpoints.c",
            },
            "assumptions": [
                ASSUMPTION_GATE,
                ASSUMPTION_NO_HANDLER,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_IS_LUCI,
                ASSUMPTION_NOT_VERSION,
                ASSUMPTION_NOT_UNIXTIME,
                ASSUMPTION_NOT_ODHCP,
                ASSUMPTION_NOT_BOARD,
                ASSUMPTION_NOT_INFO,
                ASSUMPTION_NOT_REBOOT,
                ASSUMPTION_NOT_BLOCK,
                ASSUMPTION_FIXTURE,
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_HANDLER,
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
    if result.session_class in SYNTHETIC_GETMOUNTPOINTS_CLASSES:
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
                "JSON-RPC /ubus call object=luci method=getMountPoints",
                "data parameter is a BLOBMSG_TYPE_TABLE",
                "25_storage.js rpc.declare object=luci method=getMountPoints",
            ],
            "requirements": [
                "uh_ubus_allowed",
                "session.access scope=ubus object=luci function=getMountPoints (uhttpd omits scope)",
            ],
            "assumptions": [
                "Synthetic handler_effect transcribed from uhttpd uh_ubus_allowed; C, not ucode",
                ASSUMPTION_GATE,
                ASSUMPTION_NO_HANDLER,
                ASSUMPTION_NOT_SANITIZER,
                ASSUMPTION_IS_LUCI,
                ASSUMPTION_NOT_VERSION,
                ASSUMPTION_NOT_UNIXTIME,
                ASSUMPTION_NOT_ODHCP,
                ASSUMPTION_NOT_BOARD,
                ASSUMPTION_NOT_INFO,
                ASSUMPTION_NOT_REBOOT,
                ASSUMPTION_NOT_BLOCK,
                ASSUMPTION_FIXTURE,
            ],
            "evidence_refs": grant_ids
            + [
                f"uhttpd@{UHTTPD_SHA[:8]} ubus.c uh_ubus_allowed session.access luci/getMountPoints",
                f"luci@{LUCI_SHA[:8]} 25_storage.js rpc.declare object=luci method=getMountPoints",
            ],
            "unknowns": [
                UNKNOWN_LIVE,
                UNKNOWN_HANDLER,
                UNKNOWN_UNSTAFFED,
            ],
        }
    )
    return record


def build_artifacts(
    fixtures: Path = FIXTURES, repo_root: Path = REPO_ROOT
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    sessions = load_luci_getmountpoints_world(fixtures)
    cases = load_expected_cases(fixtures / "ubus_luci_getmountpoints_cases.json")
    revision = corpus_revision(repo_root)
    grants_by_id: dict[str, dict[str, Any]] = {}
    decisions: list[dict[str, Any]] = []
    for case in cases:
        result = evaluate_expected_case(case, sessions)
        decisions.append(decision_record(case, result, revision))
        if case.get("expect_grant") and result.outcome == "allow":
            if case.get("ubus_object") != UBUS_OBJECT or case.get("method") != UBUS_METHOD:
                raise ValueError("refusing to emit grant for non-luci.getMountPoints ubus method")
            record = grant_record(case, result, revision)
            grants_by_id.setdefault(record["record_id"], record)
    grants = list(grants_by_id.values())
    bundle = {
        "producer": PRODUCER,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "corpus_revision": revision,
        "pins": _pins(),
        "scope": "ubus luci.getMountPoints of luci-mod-status-index-storage",
        "harness": {
            "canonical": "python3 -m policy emit",
            "c_double": "policy/c_double/ubus_luci_getmountpoints.c",
            "compiler": "gcc",
            "flags": C_DOUBLE_FLAGS,
            "live_uhttpd": False,
            "live_rpcd": False,
            "live_luci_plugin": False,
        },
        "assumptions": [
            ASSUMPTION_GATE,
            ASSUMPTION_NO_HANDLER,
            ASSUMPTION_NOT_SANITIZER,
            ASSUMPTION_IS_LUCI,
            ASSUMPTION_NOT_VERSION,
            ASSUMPTION_NOT_UNIXTIME,
            ASSUMPTION_NOT_ODHCP,
            ASSUMPTION_NOT_BOARD,
            ASSUMPTION_NOT_INFO,
            ASSUMPTION_NOT_REBOOT,
            ASSUMPTION_NOT_BLOCK,
            ASSUMPTION_FIXTURE,
        ],
        "unknowns": [
            UNKNOWN_LIVE,
            UNKNOWN_HANDLER,
            UNKNOWN_UNSTAFFED,
        ],
        "decisions": decisions,
    }
    effects = [effect_record(grants, revision)]
    return grants, bundle, effects


def write_artifacts(repo_root: Path = REPO_ROOT) -> tuple[Path, Path]:
    grants, bundle, effects = build_artifacts(repo_root / "policy" / "fixtures", repo_root)
    bundle_path = repo_root / "policy" / "ubus_luci_getmountpoints_decisions.json"
    effect_path = repo_root / "reports" / "m2-ubus-luci-getmountpoints-effect.json"
    dump_json(bundle_path, {"grants": grants, **bundle})
    dump_json(effect_path, effects)
    return bundle_path, effect_path
