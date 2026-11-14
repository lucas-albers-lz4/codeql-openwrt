#!/usr/bin/env python3
"""Grant ↔ handler_effect joins against committed reports/handler_effects.json."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.oracle import (  # noqa: E402
    EXEC_METHODS,
    REQUEST_ARGS_EXEC_METHODS,
    corpus_revision,
)

JOIN_KEYS = (
    "corpus_revision",
    "profile",
    "ingress",
    "entrypoint_id",
    "ubus_object",
    "method",
)
CGI_JOIN_KEYS = (
    "corpus_revision",
    "profile",
    "ingress",
    "entrypoint_id",
    "cgi_endpoint",
)
CGI_BACKUP_EFFECT_ID = "policy:effect:cgi-backup-sensitive-read"
CGI_UPLOAD_EFFECT_ID = "policy:effect:cgi-upload-file-write"
CGI_DOWNLOAD_EFFECT_ID = "policy:effect:cgi-download-file-read"
CGI_EXEC_EFFECT_ID = "policy:effect:cgi-exec-session-access"
CGI_EXEC_FILE_SNAPSHOT = "reports/m2-cgi-exec-file-effect.json"
CGI_CATALOG = {
    CGI_BACKUP_EFFECT_ID: {
        "cgi_endpoint": "cgi-backup",
        "sink_kind": "sensitive_backup_read",
        "op": "read",
        "snapshot": None,
        "delegated_class": "luci-mod-system-flash",
    },
    CGI_UPLOAD_EFFECT_ID: {
        "cgi_endpoint": "cgi-upload",
        "sink_kind": "file_write",
        "op": "write",
        "snapshot": "reports/m2-cgi-upload-effect.json",
        "delegated_class": "luci-base",
    },
    CGI_DOWNLOAD_EFFECT_ID: {
        "cgi_endpoint": "cgi-download",
        "sink_kind": "file_read",
        "op": "read",
        "snapshot": "reports/m2-cgi-download-effect.json",
        "delegated_class": "luci-mod-system-flash",
    },
    CGI_EXEC_EFFECT_ID: {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-effect.json",
        "delegated_class": "luci-mod-network-config",
    },
    "policy:effect:cgi-exec-file:syslog-wrapper": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": CGI_EXEC_FILE_SNAPSHOT,
        "delegated_class": "luci-mod-status-logs",
    },
    "policy:effect:cgi-exec-file:luci-peeraddr": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": CGI_EXEC_FILE_SNAPSHOT,
        "delegated_class": "luci-mod-network-config",
    },
    "policy:effect:cgi-exec-file:package-manager-call": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": CGI_EXEC_FILE_SNAPSHOT,
        "delegated_class": "luci-app-package-manager",
    },
    "policy:effect:cgi-exec-status:dmesg": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-logs",
    },
    "policy:effect:cgi-exec-status:nft": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:iptables": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:ip6tables": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:iptables-save": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:ip6tables-save": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
    "policy:effect:cgi-exec-status:firewall-init": {
        "cgi_endpoint": "cgi-exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": "reports/m2-cgi-exec-status-effect.json",
        "delegated_class": "luci-mod-status-firewall",
    },
}
FILE_EXEC_SNAPSHOT = "reports/m2-ubus-file-exec-effect.json"
IFUP_FILE_EXEC_SNAPSHOT = "reports/m2-ubus-file-exec-ifup-effect.json"
KILL_FILE_EXEC_SNAPSHOT = "reports/m2-ubus-file-exec-kill-effect.json"
MOUNTS_FILE_EXEC_SNAPSHOT = "reports/m2-ubus-file-exec-mounts-effect.json"
LIST_BACKUP_FILE_EXEC_SNAPSHOT = "reports/m2-ubus-file-exec-list-backup-effect.json"
SYSTEM_REBOOT_SNAPSHOT = "reports/m2-ubus-system-reboot-effect.json"
SYSTEM_BOARD_SNAPSHOT = "reports/m2-ubus-system-board-effect.json"
SYSTEM_INFO_SNAPSHOT = "reports/m2-ubus-system-info-effect.json"
LUCI_GETVERSION_SNAPSHOT = "reports/m2-ubus-luci-getversion-effect.json"
LUCI_GETUNIXTIME_SNAPSHOT = "reports/m2-ubus-luci-getunixtime-effect.json"
LUCI_GETODHCP6CSTATS_SNAPSHOT = "reports/m2-ubus-luci-getodhcp6cstats-effect.json"
LUCI_GETTIMEZONES_SNAPSHOT = "reports/m2-ubus-luci-gettimezones-effect.json"
LUCI_GETLEDS_SNAPSHOT = "reports/m2-ubus-luci-getleds-effect.json"
LUCI_GETMOUNTPOINTS_SNAPSHOT = "reports/m2-ubus-luci-getmountpoints-effect.json"
LUCI_GETBUILTINETHERNETPORTS_SNAPSHOT = "reports/m2-ubus-luci-getbuiltinethernetports-effect.json"
HOSTAPD_DEL_CLIENT_SNAPSHOT = "reports/m2-ubus-hostapd-del-client-effect.json"
HOSTAPD_WPS_START_SNAPSHOT = "reports/m2-ubus-hostapd-wps-start-effect.json"
HOSTAPD_WPS_CANCEL_SNAPSHOT = "reports/m2-ubus-hostapd-wps-cancel-effect.json"
HOSTAPD_WPS_STATUS_SNAPSHOT = "reports/m2-ubus-hostapd-wps-status-effect.json"
RC_INIT_SNAPSHOT = "reports/m2-ubus-rc-init-effect.json"
RC_LIST_SNAPSHOT = "reports/m2-ubus-rc-list-effect.json"
FILE_EXEC_CATALOG = {
    "policy:effect:ubus-file-exec:iptables": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-status-firewall",
        "entrypoint_id": "ubus_http:file.exec:/usr/sbin/iptables",
    },
    "policy:effect:ubus-file-exec:ip6tables": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-status-firewall",
        "entrypoint_id": "ubus_http:file.exec:/usr/sbin/ip6tables",
    },
    "policy:effect:ubus-file-exec:ip": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-status-routes",
        "entrypoint_id": "ubus_http:file.exec:/sbin/ip",
    },
    "policy:effect:ubus-file-exec:ip-json": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-status-routes-json",
        "entrypoint_id": "ubus_http:file.exec:/sbin/ip:-j",
    },
    "policy:effect:ubus-file-exec-ifup:ifup": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": IFUP_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-network-config-write",
        "entrypoint_id": "ubus_http:file.exec:/sbin/ifup",
    },
    "policy:effect:ubus-file-exec-ifup:ifdown": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": IFUP_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-network-config-write",
        "entrypoint_id": "ubus_http:file.exec:/sbin/ifdown",
    },
    "policy:effect:ubus-file-exec-ifup:wifi": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": IFUP_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-network-config-write",
        "entrypoint_id": "ubus_http:file.exec:/sbin/wifi",
    },
    "policy:effect:ubus-file-exec-kill:kill": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": KILL_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-status-processes-write",
        "entrypoint_id": "ubus_http:file.exec:/bin/kill",
    },
    "policy:effect:ubus-file-exec-mounts:umount": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": MOUNTS_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-system-mounts",
        "entrypoint_id": "ubus_http:file.exec:/bin/umount",
    },
    "policy:effect:ubus-file-exec-mounts:block": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": MOUNTS_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-system-mounts",
        "entrypoint_id": "ubus_http:file.exec:/sbin/block",
    },
    "policy:effect:ubus-file-exec-list-backup:list-backup": {
        "ubus_object": "file",
        "method": "exec",
        "sink_kind": "file_exec",
        "op": "exec",
        "snapshot": LIST_BACKUP_FILE_EXEC_SNAPSHOT,
        "delegated_class": "luci-mod-system-flash",
        "entrypoint_id": "ubus_http:file.exec:/sbin/sysupgrade:--list-backup",
    },
}
SYSTEM_REBOOT_CATALOG = {
    "policy:effect:ubus-system-reboot": {
        "ubus_object": "system",
        "method": "reboot",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": SYSTEM_REBOOT_SNAPSHOT,
        "delegated_class": "luci-mod-system-reboot",
        "entrypoint_id": "ubus_http:system.reboot",
    },
}
SYSTEM_BOARD_CATALOG = {
    "policy:effect:ubus-system-board": {
        "ubus_object": "system",
        "method": "board",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": SYSTEM_BOARD_SNAPSHOT,
        "delegated_class": "luci-mod-status-index",
        "entrypoint_id": "ubus_http:system.board",
    },
}
SYSTEM_INFO_CATALOG = {
    "policy:effect:ubus-system-info": {
        "ubus_object": "system",
        "method": "info",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": SYSTEM_INFO_SNAPSHOT,
        "delegated_class": "luci-mod-status-index",
        "entrypoint_id": "ubus_http:system.info",
    },
}
LUCI_GETVERSION_CATALOG = {
    "policy:effect:ubus-luci-getversion": {
        "ubus_object": "luci",
        "method": "getVersion",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETVERSION_SNAPSHOT,
        "delegated_class": "luci-mod-status-index",
        "entrypoint_id": "ubus_http:luci.getVersion",
    },
}
LUCI_GETUNIXTIME_CATALOG = {
    "policy:effect:ubus-luci-getunixtime": {
        "ubus_object": "luci",
        "method": "getUnixtime",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETUNIXTIME_SNAPSHOT,
        "delegated_class": "luci-mod-status-index",
        "entrypoint_id": "ubus_http:luci.getUnixtime",
    },
}
LUCI_GETODHCP6CSTATS_CATALOG = {
    "policy:effect:ubus-luci-getodhcp6cstats": {
        "ubus_object": "luci",
        "method": "getOdhcp6cStats",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETODHCP6CSTATS_SNAPSHOT,
        "delegated_class": "luci-mod-status-index",
        "entrypoint_id": "ubus_http:luci.getOdhcp6cStats",
    },
}
LUCI_GETTIMEZONES_CATALOG = {
    "policy:effect:ubus-luci-gettimezones": {
        "ubus_object": "luci",
        "method": "getTimezones",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETTIMEZONES_SNAPSHOT,
        "delegated_class": "luci-mod-system-config",
        "entrypoint_id": "ubus_http:luci.getTimezones",
    },
}
LUCI_GETLEDS_CATALOG = {
    "policy:effect:ubus-luci-getleds": {
        "ubus_object": "luci",
        "method": "getLEDs",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETLEDS_SNAPSHOT,
        "delegated_class": "luci-mod-system-config",
        "entrypoint_id": "ubus_http:luci.getLEDs",
    },
}
LUCI_GETMOUNTPOINTS_CATALOG = {
    "policy:effect:ubus-luci-getmountpoints": {
        "ubus_object": "luci",
        "method": "getMountPoints",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETMOUNTPOINTS_SNAPSHOT,
        "delegated_class": "luci-mod-status-index-storage",
        "entrypoint_id": "ubus_http:luci.getMountPoints",
    },
}
LUCI_GETBUILTINETHERNETPORTS_CATALOG = {
    "policy:effect:ubus-luci-getbuiltinethernetports": {
        "ubus_object": "luci",
        "method": "getBuiltinEthernetPorts",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": LUCI_GETBUILTINETHERNETPORTS_SNAPSHOT,
        "delegated_class": "luci-mod-status-index-ports",
        "entrypoint_id": "ubus_http:luci.getBuiltinEthernetPorts",
    },
}
HOSTAPD_DEL_CLIENT_CATALOG = {
    "policy:effect:ubus-hostapd-del-client": {
        "ubus_object": "hostapd.*",
        "method": "del_client",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": HOSTAPD_DEL_CLIENT_SNAPSHOT,
        "delegated_class": "luci-mod-network-config-write",
        "entrypoint_id": "ubus_http:hostapd.del_client",
    },
}
HOSTAPD_WPS_START_CATALOG = {
    "policy:effect:ubus-hostapd-wps-start": {
        "ubus_object": "hostapd.*",
        "method": "wps_start",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": HOSTAPD_WPS_START_SNAPSHOT,
        "delegated_class": "luci-mod-status-index-wifi",
        "entrypoint_id": "ubus_http:hostapd.wps_start",
    },
}
HOSTAPD_WPS_CANCEL_CATALOG = {
    "policy:effect:ubus-hostapd-wps-cancel": {
        "ubus_object": "hostapd.*",
        "method": "wps_cancel",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": HOSTAPD_WPS_CANCEL_SNAPSHOT,
        "delegated_class": "luci-mod-status-index-wifi",
        "entrypoint_id": "ubus_http:hostapd.wps_cancel",
    },
}
HOSTAPD_WPS_STATUS_CATALOG = {
    "policy:effect:ubus-hostapd-wps-status": {
        "ubus_object": "hostapd.*",
        "method": "wps_status",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": HOSTAPD_WPS_STATUS_SNAPSHOT,
        "delegated_class": "luci-mod-status-index-wifi",
        "entrypoint_id": "ubus_http:hostapd.wps_status",
    },
}
SYSTEM_CATALOG = {**SYSTEM_REBOOT_CATALOG, **SYSTEM_BOARD_CATALOG, **SYSTEM_INFO_CATALOG}
RC_INIT_CATALOG = {
    "policy:effect:ubus-rc-init": {
        "ubus_object": "rc",
        "method": "init",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": RC_INIT_SNAPSHOT,
        "delegated_class": "luci-mod-system-init",
        "entrypoint_id": "ubus_http:rc.init",
    },
}
RC_LIST_CATALOG = {
    "policy:effect:ubus-rc-list": {
        "ubus_object": "rc",
        "method": "list",
        "sink_kind": "ubus_call",
        "op": "invoke",
        "snapshot": RC_LIST_SNAPSHOT,
        "delegated_class": "luci-mod-system-init-read",
        "entrypoint_id": "ubus_http:rc.list",
    },
}
RC_CATALOG = {**RC_INIT_CATALOG, **RC_LIST_CATALOG}
COPIED_EFFECT_SNAPSHOTS = (
    "reports/findings.json",
    "reports/m4-getfeatures-direct-exec.json",
    "reports/m4-luci-sys-init-action-findings.json",
    "reports/m4-block-device-exec.json",
    "reports/m4-luci-sys-status-exec.json",
)
PROJECTED_PATH_SNAPSHOT = "reports/m4-findings.json"
LUCI_EFFECT_COUNT = 17
COPIED_EFFECT_COUNT = 12
SOURCE_FIELDS = (
    "corpus_revision",
    "profile",
    "analysis_revision",
    "ingress",
    "entrypoint_id",
    "ubus_object",
    "method",
    "target_id",
    "op",
    "sink_kind",
    "assessment",
)
SCHEMA = json.loads((REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
REQUIRED = SCHEMA["required"]


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestHandlerEffectJoins(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.effects = _load(REPO / "reports" / "handler_effects.json")
        cls.grants = _load(REPO / "policy" / "grants.json")
        cls.taint_paths = _load(REPO / "reports" / "m4-findings.json")

    def test_catalog_is_handler_effects_only(self) -> None:
        self.assertIsInstance(self.effects, list)
        self.assertGreaterEqual(len(self.effects), LUCI_EFFECT_COUNT + 1)
        ids = [row["record_id"] for row in self.effects]
        effect_ids = [row["effect_id"] for row in self.effects]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(effect_ids), len(set(effect_ids)))
        luci_rows = [
            row
            for row in self.effects
            if row.get("ingress") == "ubus_http"
            and row.get("ubus_object") == "luci"
            and row.get("producer") == "step3"
        ]
        getversion_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getVersion"
        ]
        getunixtime_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getUnixtime"
        ]
        getodhcp6cstats_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getOdhcp6cStats"
        ]
        gettimezones_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getTimezones"
        ]
        getleds_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getLEDs"
        ]
        getmountpoints_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getMountPoints"
        ]
        getbuiltinethernetports_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "luci" and row.get("method") == "getBuiltinEthernetPorts"
        ]
        hostapd_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "hostapd.*" and row.get("method") == "del_client"
        ]
        hostapd_wps_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "hostapd.*" and row.get("method") == "wps_start"
        ]
        hostapd_wps_cancel_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "hostapd.*" and row.get("method") == "wps_cancel"
        ]
        hostapd_wps_status_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "hostapd.*" and row.get("method") == "wps_status"
        ]
        file_exec_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "file" and row.get("method") == "exec"
        ]
        reboot_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "system" and row.get("method") == "reboot"
        ]
        board_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "system" and row.get("method") == "board"
        ]
        info_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "system" and row.get("method") == "info"
        ]
        rc_init_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "rc" and row.get("method") == "init"
        ]
        rc_list_rows = [
            row
            for row in self.effects
            if row.get("ubus_object") == "rc" and row.get("method") == "list"
        ]
        cgi_rows = [row for row in self.effects if row.get("ingress") == "cgi_io"]
        self.assertEqual(len(luci_rows), LUCI_EFFECT_COUNT)
        self.assertEqual(len(cgi_rows), len(CGI_CATALOG))
        self.assertEqual(len(file_exec_rows), len(FILE_EXEC_CATALOG))
        self.assertEqual(len(reboot_rows), len(SYSTEM_REBOOT_CATALOG))
        self.assertEqual(len(board_rows), len(SYSTEM_BOARD_CATALOG))
        self.assertEqual(len(info_rows), len(SYSTEM_INFO_CATALOG))
        self.assertEqual(len(getversion_rows), len(LUCI_GETVERSION_CATALOG))
        self.assertEqual(len(getunixtime_rows), len(LUCI_GETUNIXTIME_CATALOG))
        self.assertEqual(len(getodhcp6cstats_rows), len(LUCI_GETODHCP6CSTATS_CATALOG))
        self.assertEqual(len(gettimezones_rows), len(LUCI_GETTIMEZONES_CATALOG))
        self.assertEqual(len(getleds_rows), len(LUCI_GETLEDS_CATALOG))
        self.assertEqual(len(getmountpoints_rows), len(LUCI_GETMOUNTPOINTS_CATALOG))
        self.assertEqual(len(getbuiltinethernetports_rows), len(LUCI_GETBUILTINETHERNETPORTS_CATALOG))
        self.assertEqual(len(hostapd_rows), len(HOSTAPD_DEL_CLIENT_CATALOG))
        self.assertEqual(len(hostapd_wps_rows), len(HOSTAPD_WPS_START_CATALOG))
        self.assertEqual(len(hostapd_wps_cancel_rows), len(HOSTAPD_WPS_CANCEL_CATALOG))
        self.assertEqual(len(hostapd_wps_status_rows), len(HOSTAPD_WPS_STATUS_CATALOG))
        self.assertEqual(len(rc_init_rows), len(RC_INIT_CATALOG))
        self.assertEqual(len(rc_list_rows), len(RC_LIST_CATALOG))
        self.assertEqual({row["record_id"] for row in cgi_rows}, set(CGI_CATALOG))
        self.assertEqual({row["record_id"] for row in file_exec_rows}, set(FILE_EXEC_CATALOG))
        self.assertEqual({row["record_id"] for row in reboot_rows}, set(SYSTEM_REBOOT_CATALOG))
        self.assertEqual({row["record_id"] for row in board_rows}, set(SYSTEM_BOARD_CATALOG))
        self.assertEqual({row["record_id"] for row in info_rows}, set(SYSTEM_INFO_CATALOG))
        self.assertEqual({row["record_id"] for row in getversion_rows}, set(LUCI_GETVERSION_CATALOG))
        self.assertEqual({row["record_id"] for row in getunixtime_rows}, set(LUCI_GETUNIXTIME_CATALOG))
        self.assertEqual({row["record_id"] for row in getodhcp6cstats_rows}, set(LUCI_GETODHCP6CSTATS_CATALOG))
        self.assertEqual({row["record_id"] for row in gettimezones_rows}, set(LUCI_GETTIMEZONES_CATALOG))
        self.assertEqual({row["record_id"] for row in getleds_rows}, set(LUCI_GETLEDS_CATALOG))
        self.assertEqual({row["record_id"] for row in getmountpoints_rows}, set(LUCI_GETMOUNTPOINTS_CATALOG))
        self.assertEqual({row["record_id"] for row in getbuiltinethernetports_rows}, set(LUCI_GETBUILTINETHERNETPORTS_CATALOG))
        self.assertEqual({row["record_id"] for row in hostapd_rows}, set(HOSTAPD_DEL_CLIENT_CATALOG))
        self.assertEqual({row["record_id"] for row in hostapd_wps_rows}, set(HOSTAPD_WPS_START_CATALOG))
        self.assertEqual({row["record_id"] for row in hostapd_wps_cancel_rows}, set(HOSTAPD_WPS_CANCEL_CATALOG))
        self.assertEqual({row["record_id"] for row in hostapd_wps_status_rows}, set(HOSTAPD_WPS_STATUS_CATALOG))
        self.assertEqual({row["record_id"] for row in rc_init_rows}, set(RC_INIT_CATALOG))
        self.assertEqual({row["record_id"] for row in rc_list_rows}, set(RC_LIST_CATALOG))
        self.assertEqual(
            len(self.effects),
            len(luci_rows)
            + len(cgi_rows)
            + len(file_exec_rows)
            + len(reboot_rows)
            + len(board_rows)
            + len(info_rows)
            + len(getversion_rows)
            + len(getunixtime_rows)
            + len(getodhcp6cstats_rows)
            + len(gettimezones_rows)
            + len(getleds_rows)
            + len(getmountpoints_rows)
            + len(getbuiltinethernetports_rows)
            + len(hostapd_rows)
            + len(hostapd_wps_rows)
            + len(hostapd_wps_cancel_rows)
            + len(hostapd_wps_status_rows)
            + len(rc_init_rows)
            + len(rc_list_rows),
        )
        self.assertEqual(
            {row["cgi_endpoint"] for row in cgi_rows},
            {spec["cgi_endpoint"] for spec in CGI_CATALOG.values()},
        )
        lock_hash = corpus_revision()
        for row in luci_rows:
            for key in REQUIRED:
                self.assertIn(key, row, key)
            self.assertEqual(row["record_type"], "handler_effect")
            self.assertEqual(row["evidence_status"], "fact")
            self.assertEqual(row["producer"], "step3")
            self.assertEqual(row["profile"], "luci-ssl-25.12")
            self.assertEqual(row["ubus_object"], "luci")
            self.assertEqual(row["op"], "exec")
            self.assertIn(row["sink_kind"], ("popen", "system"))
            self.assertIn(row["assessment"], ("intended_access", "unassessed"))
            self.assertNotEqual(row["assessment"], "authorization_violation")
            self.assertNotIn("cgi_endpoint", row)
            self.assertNotIn("route_path", row)
            self.assertIn(row["record_type"], SCHEMA["properties"]["record_type"]["enum"])
            self.assertIn(row["sink_kind"], SCHEMA["properties"]["sink_kind"]["enum"])
            self.assertEqual(row["corpus_revision"], lock_hash)
        for cgi in cgi_rows:
            spec = CGI_CATALOG[cgi["record_id"]]
            self.assertEqual(cgi["cgi_endpoint"], spec["cgi_endpoint"])
            self.assertEqual(cgi["producer"], "policy_facts")
            self.assertEqual(cgi["sink_kind"], spec["sink_kind"])
            self.assertEqual(cgi["op"], spec["op"])
            self.assertEqual(cgi["assessment"], "intended_access")
            self.assertNotEqual(cgi["assessment"], "authorization_violation")
            self.assertEqual(cgi["corpus_revision"], lock_hash)
            self.assertEqual(cgi["evidence_status"], "fact")
            self.assertNotEqual(cgi["evidence_status"], "path_found")
        for file_exec in file_exec_rows:
            spec = FILE_EXEC_CATALOG[file_exec["record_id"]]
            self.assertEqual(file_exec["ubus_object"], spec["ubus_object"])
            self.assertEqual(file_exec["method"], spec["method"])
            self.assertEqual(file_exec["producer"], "policy_facts")
            self.assertEqual(file_exec["sink_kind"], spec["sink_kind"])
            self.assertEqual(file_exec["op"], spec["op"])
            self.assertEqual(file_exec["assessment"], "intended_access")
            self.assertNotEqual(file_exec["assessment"], "authorization_violation")
            self.assertEqual(file_exec["corpus_revision"], lock_hash)
            self.assertEqual(file_exec["evidence_status"], "fact")
            self.assertNotEqual(file_exec["evidence_status"], "path_found")
            self.assertEqual(file_exec["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", file_exec)
        for reboot in reboot_rows:
            spec = SYSTEM_REBOOT_CATALOG[reboot["record_id"]]
            self.assertEqual(reboot["ubus_object"], spec["ubus_object"])
            self.assertEqual(reboot["method"], spec["method"])
            self.assertEqual(reboot["producer"], "policy_facts")
            self.assertEqual(reboot["sink_kind"], spec["sink_kind"])
            self.assertEqual(reboot["op"], spec["op"])
            self.assertEqual(reboot["assessment"], "intended_access")
            self.assertNotEqual(reboot["assessment"], "authorization_violation")
            self.assertEqual(reboot["corpus_revision"], lock_hash)
            self.assertEqual(reboot["evidence_status"], "fact")
            self.assertNotEqual(reboot["evidence_status"], "path_found")
            self.assertEqual(reboot["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", reboot)
        for board in board_rows:
            spec = SYSTEM_BOARD_CATALOG[board["record_id"]]
            self.assertEqual(board["ubus_object"], spec["ubus_object"])
            self.assertEqual(board["method"], spec["method"])
            self.assertEqual(board["producer"], "policy_facts")
            self.assertEqual(board["sink_kind"], spec["sink_kind"])
            self.assertEqual(board["op"], spec["op"])
            self.assertEqual(board["assessment"], "intended_access")
            self.assertNotEqual(board["assessment"], "authorization_violation")
            self.assertEqual(board["corpus_revision"], lock_hash)
            self.assertEqual(board["evidence_status"], "fact")
            self.assertNotEqual(board["evidence_status"], "path_found")
            self.assertEqual(board["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", board)
        for info in info_rows:
            spec = SYSTEM_INFO_CATALOG[info["record_id"]]
            self.assertEqual(info["ubus_object"], spec["ubus_object"])
            self.assertEqual(info["method"], spec["method"])
            self.assertEqual(info["producer"], "policy_facts")
            self.assertEqual(info["sink_kind"], spec["sink_kind"])
            self.assertEqual(info["op"], spec["op"])
            self.assertEqual(info["assessment"], "intended_access")
            self.assertNotEqual(info["assessment"], "authorization_violation")
            self.assertEqual(info["corpus_revision"], lock_hash)
            self.assertEqual(info["evidence_status"], "fact")
            self.assertNotEqual(info["evidence_status"], "path_found")
            self.assertEqual(info["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", info)
        for getversion in getversion_rows:
            spec = LUCI_GETVERSION_CATALOG[getversion["record_id"]]
            self.assertEqual(getversion["ubus_object"], spec["ubus_object"])
            self.assertEqual(getversion["method"], spec["method"])
            self.assertEqual(getversion["producer"], "policy_facts")
            self.assertEqual(getversion["sink_kind"], spec["sink_kind"])
            self.assertEqual(getversion["op"], spec["op"])
            self.assertEqual(getversion["assessment"], "intended_access")
            self.assertNotEqual(getversion["assessment"], "authorization_violation")
            self.assertEqual(getversion["corpus_revision"], lock_hash)
            self.assertEqual(getversion["evidence_status"], "fact")
            self.assertNotEqual(getversion["evidence_status"], "path_found")
            self.assertEqual(getversion["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", getversion)
        for getunixtime in getunixtime_rows:
            spec = LUCI_GETUNIXTIME_CATALOG[getunixtime["record_id"]]
            self.assertEqual(getunixtime["ubus_object"], spec["ubus_object"])
            self.assertEqual(getunixtime["method"], spec["method"])
            self.assertEqual(getunixtime["producer"], "policy_facts")
            self.assertEqual(getunixtime["sink_kind"], spec["sink_kind"])
            self.assertEqual(getunixtime["op"], spec["op"])
            self.assertEqual(getunixtime["assessment"], "intended_access")
            self.assertNotEqual(getunixtime["assessment"], "authorization_violation")
            self.assertEqual(getunixtime["corpus_revision"], lock_hash)
            self.assertEqual(getunixtime["evidence_status"], "fact")
            self.assertNotEqual(getunixtime["evidence_status"], "path_found")
            self.assertEqual(getunixtime["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", getunixtime)
        for getodhcp6cstats in getodhcp6cstats_rows:
            spec = LUCI_GETODHCP6CSTATS_CATALOG[getodhcp6cstats["record_id"]]
            self.assertEqual(getodhcp6cstats["ubus_object"], spec["ubus_object"])
            self.assertEqual(getodhcp6cstats["method"], spec["method"])
            self.assertEqual(getodhcp6cstats["producer"], "policy_facts")
            self.assertEqual(getodhcp6cstats["sink_kind"], spec["sink_kind"])
            self.assertEqual(getodhcp6cstats["op"], spec["op"])
            self.assertEqual(getodhcp6cstats["assessment"], "intended_access")
            self.assertNotEqual(getodhcp6cstats["assessment"], "authorization_violation")
            self.assertEqual(getodhcp6cstats["corpus_revision"], lock_hash)
            self.assertEqual(getodhcp6cstats["evidence_status"], "fact")
            self.assertNotEqual(getodhcp6cstats["evidence_status"], "path_found")
            self.assertEqual(getodhcp6cstats["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", getodhcp6cstats)
        for gettimezones in gettimezones_rows:
            spec = LUCI_GETTIMEZONES_CATALOG[gettimezones["record_id"]]
            self.assertEqual(gettimezones["ubus_object"], spec["ubus_object"])
            self.assertEqual(gettimezones["method"], spec["method"])
            self.assertEqual(gettimezones["producer"], "policy_facts")
            self.assertEqual(gettimezones["sink_kind"], spec["sink_kind"])
            self.assertEqual(gettimezones["op"], spec["op"])
            self.assertEqual(gettimezones["assessment"], "intended_access")
            self.assertNotEqual(gettimezones["assessment"], "authorization_violation")
            self.assertEqual(gettimezones["corpus_revision"], lock_hash)
            self.assertEqual(gettimezones["evidence_status"], "fact")
            self.assertNotEqual(gettimezones["evidence_status"], "path_found")
            self.assertEqual(gettimezones["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", gettimezones)
        for getleds in getleds_rows:
            spec = LUCI_GETLEDS_CATALOG[getleds["record_id"]]
            self.assertEqual(getleds["ubus_object"], spec["ubus_object"])
            self.assertEqual(getleds["method"], spec["method"])
            self.assertEqual(getleds["producer"], "policy_facts")
            self.assertEqual(getleds["sink_kind"], spec["sink_kind"])
            self.assertEqual(getleds["op"], spec["op"])
            self.assertEqual(getleds["assessment"], "intended_access")
            self.assertNotEqual(getleds["assessment"], "authorization_violation")
            self.assertEqual(getleds["corpus_revision"], lock_hash)
            self.assertEqual(getleds["evidence_status"], "fact")
            self.assertNotEqual(getleds["evidence_status"], "path_found")
            self.assertEqual(getleds["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", getleds)
        for getmountpoints in getmountpoints_rows:
            spec = LUCI_GETMOUNTPOINTS_CATALOG[getmountpoints["record_id"]]
            self.assertEqual(getmountpoints["ubus_object"], spec["ubus_object"])
            self.assertEqual(getmountpoints["method"], spec["method"])
            self.assertEqual(getmountpoints["producer"], "policy_facts")
            self.assertEqual(getmountpoints["sink_kind"], spec["sink_kind"])
            self.assertEqual(getmountpoints["op"], spec["op"])
            self.assertEqual(getmountpoints["assessment"], "intended_access")
            self.assertNotEqual(getmountpoints["assessment"], "authorization_violation")
            self.assertEqual(getmountpoints["corpus_revision"], lock_hash)
            self.assertEqual(getmountpoints["evidence_status"], "fact")
            self.assertNotEqual(getmountpoints["evidence_status"], "path_found")
            self.assertEqual(getmountpoints["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", getmountpoints)
        for getbuiltinethernetports in getbuiltinethernetports_rows:
            spec = LUCI_GETBUILTINETHERNETPORTS_CATALOG[getbuiltinethernetports["record_id"]]
            self.assertEqual(getbuiltinethernetports["ubus_object"], spec["ubus_object"])
            self.assertEqual(getbuiltinethernetports["method"], spec["method"])
            self.assertEqual(getbuiltinethernetports["producer"], "policy_facts")
            self.assertEqual(getbuiltinethernetports["sink_kind"], spec["sink_kind"])
            self.assertEqual(getbuiltinethernetports["op"], spec["op"])
            self.assertEqual(getbuiltinethernetports["assessment"], "intended_access")
            self.assertNotEqual(getbuiltinethernetports["assessment"], "authorization_violation")
            self.assertEqual(getbuiltinethernetports["corpus_revision"], lock_hash)
            self.assertEqual(getbuiltinethernetports["evidence_status"], "fact")
            self.assertNotEqual(getbuiltinethernetports["evidence_status"], "path_found")
            self.assertEqual(getbuiltinethernetports["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", getbuiltinethernetports)
        for hostapd in hostapd_rows:
            spec = HOSTAPD_DEL_CLIENT_CATALOG[hostapd["record_id"]]
            self.assertEqual(hostapd["ubus_object"], spec["ubus_object"])
            self.assertEqual(hostapd["method"], spec["method"])
            self.assertEqual(hostapd["producer"], "policy_facts")
            self.assertEqual(hostapd["sink_kind"], spec["sink_kind"])
            self.assertEqual(hostapd["op"], spec["op"])
            self.assertEqual(hostapd["assessment"], "intended_access")
            self.assertNotEqual(hostapd["assessment"], "authorization_violation")
            self.assertEqual(hostapd["corpus_revision"], lock_hash)
            self.assertEqual(hostapd["evidence_status"], "fact")
            self.assertNotEqual(hostapd["evidence_status"], "path_found")
            self.assertEqual(hostapd["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", hostapd)
        for hostapd_wps in hostapd_wps_rows:
            spec = HOSTAPD_WPS_START_CATALOG[hostapd_wps["record_id"]]
            self.assertEqual(hostapd_wps["ubus_object"], spec["ubus_object"])
            self.assertEqual(hostapd_wps["method"], spec["method"])
            self.assertEqual(hostapd_wps["producer"], "policy_facts")
            self.assertEqual(hostapd_wps["sink_kind"], spec["sink_kind"])
            self.assertEqual(hostapd_wps["op"], spec["op"])
            self.assertEqual(hostapd_wps["assessment"], "intended_access")
            self.assertNotEqual(hostapd_wps["assessment"], "authorization_violation")
            self.assertEqual(hostapd_wps["corpus_revision"], lock_hash)
            self.assertEqual(hostapd_wps["evidence_status"], "fact")
            self.assertNotEqual(hostapd_wps["evidence_status"], "path_found")
            self.assertEqual(hostapd_wps["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", hostapd_wps)
        for hostapd_wps_cancel in hostapd_wps_cancel_rows:
            spec = HOSTAPD_WPS_CANCEL_CATALOG[hostapd_wps_cancel["record_id"]]
            self.assertEqual(hostapd_wps_cancel["ubus_object"], spec["ubus_object"])
            self.assertEqual(hostapd_wps_cancel["method"], spec["method"])
            self.assertEqual(hostapd_wps_cancel["producer"], "policy_facts")
            self.assertEqual(hostapd_wps_cancel["sink_kind"], spec["sink_kind"])
            self.assertEqual(hostapd_wps_cancel["op"], spec["op"])
            self.assertEqual(hostapd_wps_cancel["assessment"], "intended_access")
            self.assertNotEqual(hostapd_wps_cancel["assessment"], "authorization_violation")
            self.assertEqual(hostapd_wps_cancel["corpus_revision"], lock_hash)
            self.assertEqual(hostapd_wps_cancel["evidence_status"], "fact")
            self.assertNotEqual(hostapd_wps_cancel["evidence_status"], "path_found")
            self.assertEqual(hostapd_wps_cancel["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", hostapd_wps_cancel)
        for hostapd_wps_status in hostapd_wps_status_rows:
            spec = HOSTAPD_WPS_STATUS_CATALOG[hostapd_wps_status["record_id"]]
            self.assertEqual(hostapd_wps_status["ubus_object"], spec["ubus_object"])
            self.assertEqual(hostapd_wps_status["method"], spec["method"])
            self.assertEqual(hostapd_wps_status["producer"], "policy_facts")
            self.assertEqual(hostapd_wps_status["sink_kind"], spec["sink_kind"])
            self.assertEqual(hostapd_wps_status["op"], spec["op"])
            self.assertEqual(hostapd_wps_status["assessment"], "intended_access")
            self.assertNotEqual(hostapd_wps_status["assessment"], "authorization_violation")
            self.assertEqual(hostapd_wps_status["corpus_revision"], lock_hash)
            self.assertEqual(hostapd_wps_status["evidence_status"], "fact")
            self.assertNotEqual(hostapd_wps_status["evidence_status"], "path_found")
            self.assertEqual(hostapd_wps_status["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", hostapd_wps_status)
        for rc_init in rc_init_rows:
            spec = RC_INIT_CATALOG[rc_init["record_id"]]
            self.assertEqual(rc_init["ubus_object"], spec["ubus_object"])
            self.assertEqual(rc_init["method"], spec["method"])
            self.assertEqual(rc_init["producer"], "policy_facts")
            self.assertEqual(rc_init["sink_kind"], spec["sink_kind"])
            self.assertEqual(rc_init["op"], spec["op"])
            self.assertEqual(rc_init["assessment"], "intended_access")
            self.assertNotEqual(rc_init["assessment"], "authorization_violation")
            self.assertEqual(rc_init["corpus_revision"], lock_hash)
            self.assertEqual(rc_init["evidence_status"], "fact")
            self.assertNotEqual(rc_init["evidence_status"], "path_found")
            self.assertEqual(rc_init["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", rc_init)
        for rc_list in rc_list_rows:
            spec = RC_LIST_CATALOG[rc_list["record_id"]]
            self.assertEqual(rc_list["ubus_object"], spec["ubus_object"])
            self.assertEqual(rc_list["method"], spec["method"])
            self.assertEqual(rc_list["producer"], "policy_facts")
            self.assertEqual(rc_list["sink_kind"], spec["sink_kind"])
            self.assertEqual(rc_list["op"], spec["op"])
            self.assertEqual(rc_list["assessment"], "intended_access")
            self.assertNotEqual(rc_list["assessment"], "authorization_violation")
            self.assertEqual(rc_list["corpus_revision"], lock_hash)
            self.assertEqual(rc_list["evidence_status"], "fact")
            self.assertNotEqual(rc_list["evidence_status"], "path_found")
            self.assertEqual(rc_list["entrypoint_id"], spec["entrypoint_id"])
            self.assertNotIn("cgi_endpoint", rc_list)

    def test_every_grant_joins_an_effect(self) -> None:
        for grant in self.grants:
            keys = CGI_JOIN_KEYS if grant.get("ingress") == "cgi_io" else JOIN_KEYS
            matches = [
                effect
                for effect in self.effects
                if all(effect.get(key) == grant[key] for key in keys)
                and grant["record_id"] in effect.get("evidence_refs", [])
            ]
            self.assertTrue(
                matches,
                f"grant {grant['record_id']} has no joining handler_effect",
            )

    def test_exec_method_effects_join_delegated_and_root_grants(self) -> None:
        by_method = {}
        for row in self.effects:
            if row.get("method") in EXEC_METHODS:
                by_method.setdefault(row["method"], []).append(row)
        self.assertEqual(set(by_method), set(EXEC_METHODS))
        for method, effects in by_method.items():
            delegated = next(
                grant
                for grant in self.grants
                if grant.get("method") == method and grant["session_class"] != "root"
            )
            root = next(
                grant
                for grant in self.grants
                if grant.get("method") == method and grant["session_class"] == "root"
            )
            for effect in effects:
                refs = effect["evidence_refs"]
                self.assertIn(delegated["record_id"], refs)
                self.assertIn(root["record_id"], refs)
                self.assertEqual(effect["assessment"], "intended_access")
            unauth_grants = [
                grant
                for grant in self.grants
                if grant.get("method") == method and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth_grants, [])

    def test_getfeatures_effects_join_unauthenticated_and_root(self) -> None:
        effects = [row for row in self.effects if row.get("method") == "getFeatures"]
        self.assertEqual(len(effects), 6)
        for effect in effects:
            self.assertIn(
                "policy:grant:unauthenticated:ubus_http:luci.getFeatures",
                effect["evidence_refs"],
            )
            self.assertIn(
                "policy:grant:root:ubus_http:luci.getFeatures",
                effect["evidence_refs"],
            )
            self.assertEqual(effect["assessment"], "intended_access")

    def test_setinitaction_has_effect_without_grant(self) -> None:
        effects = [row for row in self.effects if row.get("method") == "setInitAction"]
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["assessment"], "unassessed")
        self.assertFalse(any("policy:grant:" in ref for ref in effects[0]["evidence_refs"]))
        self.assertEqual([row for row in self.grants if row.get("method") == "setInitAction"], [])

    def test_projected_effects_cite_existing_taint_paths(self) -> None:
        taint_ids = {row["record_id"] for row in self.taint_paths}
        for method in REQUEST_ARGS_EXEC_METHODS:
            effect = next(
                row
                for row in self.effects
                if row.get("method") == method
                and any(ref in taint_ids for ref in row.get("evidence_refs", []))
            )
            cited = [ref for ref in effect["evidence_refs"] if ref in taint_ids]
            self.assertEqual(len(cited), 1, method)
            source = next(row for row in self.taint_paths if row["record_id"] == cited[0])
            self.assertEqual(source["record_type"], "taint_path")
            self.assertEqual(source["entrypoint_id"], effect["entrypoint_id"])
            self.assertEqual(source["sink_kind"], effect["sink_kind"])
            self.assertEqual(source["target_id"], effect["target_id"])

    def test_every_catalog_effect_resolves_to_its_producer_snapshot(self) -> None:
        """Catalog rows must be copied effects or projections of retained paths."""
        copied_sources = []
        for relative_path in COPIED_EFFECT_SNAPSHOTS:
            for row in _load(REPO / relative_path):
                if (
                    row.get("record_type") == "handler_effect"
                    and row.get("evidence_status") == "fact"
                ):
                    copied_sources.append((relative_path, row))

        path_sources = [
            (PROJECTED_PATH_SNAPSHOT, row)
            for row in _load(REPO / PROJECTED_PATH_SNAPSHOT)
            if row.get("record_type") == "taint_path"
            and row.get("evidence_status") == "path_found"
        ]
        self.assertEqual(len(copied_sources), COPIED_EFFECT_COUNT)
        self.assertEqual(len(path_sources), len(REQUEST_ARGS_EXEC_METHODS))

        luci_effects = [
            row
            for row in self.effects
            if row.get("ingress") == "ubus_http"
            and row.get("ubus_object") == "luci"
            and row.get("producer") == "step3"
        ]
        resolved_source_keys = []
        for effect in luci_effects:
            copied = [
                (path, source)
                for path, source in copied_sources
                if source["record_id"] == effect["record_id"]
            ]
            projected = [
                (path, source)
                for path, source in path_sources
                if source["record_id"] in effect.get("evidence_refs", [])
            ]
            matches = copied + projected
            self.assertEqual(
                len(matches),
                1,
                f"{effect['record_id']} must resolve uniquely to a retained source row",
            )
            source_path, source = matches[0]
            resolved_source_keys.append((source_path, source["record_id"]))

            if source_path == PROJECTED_PATH_SNAPSHOT:
                self.assertEqual(source["record_type"], "taint_path")
                self.assertEqual(source["evidence_status"], "path_found")
                self.assertIn(effect["method"], REQUEST_ARGS_EXEC_METHODS)
            else:
                self.assertEqual(source["record_type"], "handler_effect")
                self.assertEqual(source["record_id"], effect["record_id"])

            for field in SOURCE_FIELDS:
                self.assertEqual(
                    effect.get(field),
                    source.get(field),
                    f"{effect['record_id']} drifted from {source_path} in {field}",
                )

        self.assertEqual(len(resolved_source_keys), LUCI_EFFECT_COUNT)
        self.assertEqual(
            len(resolved_source_keys),
            len(set(resolved_source_keys)),
            "catalog effects must resolve one-to-one to retained producer rows",
        )

    def test_shellquote_and_basename_are_not_sanitizers(self) -> None:
        quoted = [
            "m4:effect:luci-getSwconfigFeatures-popen",
            "m4:effect:luci-getSwconfigPortState-popen",
            "m4:effect:luci-getRealtimeStats-popen",
            "m4:effect:luci-setPassword-system",
        ]
        by_id = {row["record_id"]: row for row in self.effects}
        for record_id in quoted:
            text = " ".join(by_id[record_id]["assumptions"]).lower()
            self.assertIn("shellquote", text)
            self.assertIn("not", text)
            self.assertIn("sanitizer", text)
        init_text = " ".join(by_id["m4:luci-sys-init-action-system"]["assumptions"]).lower()
        self.assertIn("basename is not a modeled sanitizer", init_text)
        localtime = " ".join(by_id["m4:effect:luci-setLocaltime-system"]["assumptions"]).lower()
        self.assertIn("not treat localtime or sprintf %d as sanitizers", localtime)
        for record_id in (
            "m4:effect:luci-getBlockDevices-popen",
            "m4:effect:luci-setBlockDetect-system",
            "m4:effect:luci-setLocaltime-sysfixtime-system",
            "m4:effect:luci-getConntrackList-popen",
            "m4:effect:luci-getProcessList-popen",
        ):
            text = " ".join(by_id[record_id]["assumptions"]).lower()
            self.assertIn("not a taint path", text)
            self.assertNotIn("path_found", text)
        process_text = " ".join(by_id["m4:effect:luci-getProcessList-popen"]["assumptions"]).lower()
        self.assertIn("file.exec", process_text)
        self.assertIn("not", process_text)
        for record_id in (
            CGI_BACKUP_EFFECT_ID,
            CGI_UPLOAD_EFFECT_ID,
            CGI_DOWNLOAD_EFFECT_ID,
            CGI_EXEC_EFFECT_ID,
            "policy:effect:cgi-exec-file:syslog-wrapper",
            "policy:effect:cgi-exec-file:luci-peeraddr",
            "policy:effect:cgi-exec-file:package-manager-call",
            "policy:effect:cgi-exec-status:dmesg",
            "policy:effect:cgi-exec-status:nft",
            "policy:effect:cgi-exec-status:iptables",
            "policy:effect:cgi-exec-status:firewall-init",
            "policy:effect:ubus-file-exec:iptables",
            "policy:effect:ubus-file-exec:ip",
            "policy:effect:ubus-file-exec-ifup:ifup",
            "policy:effect:ubus-file-exec-kill:kill",
            "policy:effect:ubus-file-exec-mounts:umount",
            "policy:effect:ubus-file-exec-mounts:block",
            "policy:effect:ubus-file-exec-list-backup:list-backup",
            "policy:effect:ubus-system-reboot",
            "policy:effect:ubus-rc-init",
        ):
            cgi_text = " ".join(by_id[record_id]["assumptions"]).lower()
            self.assertIn("shellquote", cgi_text)
            self.assertIn("basename", cgi_text)
            self.assertIn("not sanitizers", cgi_text)

    def test_cgi_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in CGI_CATALOG.values():
            if spec["snapshot"]:
                loaded = _load(REPO / spec["snapshot"])
                snapshots[spec["snapshot"]] = loaded if isinstance(loaded, list) else [loaded]
        for record_id, spec in CGI_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            if spec["snapshot"]:
                snapshot_rows = snapshots[spec["snapshot"]]
                snapshot = next(row for row in snapshot_rows if row["record_id"] == record_id)
                self.assertEqual(effect, snapshot)

    def test_ubus_file_exec_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in FILE_EXEC_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in FILE_EXEC_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "file")
            self.assertEqual(effect["method"], "exec")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_system_reboot_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in SYSTEM_REBOOT_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in SYSTEM_REBOOT_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "system")
            self.assertEqual(effect["method"], "reboot")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_system_board_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in SYSTEM_BOARD_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in SYSTEM_BOARD_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "system")
            self.assertEqual(effect["method"], "board")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_system_info_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in SYSTEM_INFO_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in SYSTEM_INFO_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "system")
            self.assertEqual(effect["method"], "info")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_getversion_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETVERSION_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETVERSION_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getVersion")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_getunixtime_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETUNIXTIME_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETUNIXTIME_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getUnixtime")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_getodhcp6cstats_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETODHCP6CSTATS_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETODHCP6CSTATS_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getOdhcp6cStats")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_gettimezones_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETTIMEZONES_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETTIMEZONES_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getTimezones")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_getleds_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETLEDS_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETLEDS_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getLEDs")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_getmountpoints_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETMOUNTPOINTS_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETMOUNTPOINTS_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getMountPoints")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_luci_getbuiltinethernetports_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in LUCI_GETBUILTINETHERNETPORTS_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in LUCI_GETBUILTINETHERNETPORTS_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "luci")
            self.assertEqual(effect["method"], "getBuiltinEthernetPorts")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_hostapd_wps_start_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in HOSTAPD_WPS_START_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in HOSTAPD_WPS_START_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "hostapd.*")
            self.assertEqual(effect["method"], "wps_start")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            network_write = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "luci-mod-network-config-write"
            ]
            self.assertEqual(network_write, [])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_hostapd_wps_cancel_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in HOSTAPD_WPS_CANCEL_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in HOSTAPD_WPS_CANCEL_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "hostapd.*")
            self.assertEqual(effect["method"], "wps_cancel")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            network_write = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "luci-mod-network-config-write"
            ]
            self.assertEqual(network_write, [])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_hostapd_wps_status_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in HOSTAPD_WPS_STATUS_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in HOSTAPD_WPS_STATUS_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "hostapd.*")
            self.assertEqual(effect["method"], "wps_status")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            network_write = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "luci-mod-network-config-write"
            ]
            self.assertEqual(network_write, [])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_hostapd_del_client_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in HOSTAPD_DEL_CLIENT_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in HOSTAPD_DEL_CLIENT_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            wifi = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "luci-mod-status-index-wifi"
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(wifi["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "hostapd.*")
            self.assertEqual(effect["method"], "del_client")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_rc_init_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in RC_INIT_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in RC_INIT_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            config = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "luci-mod-system-config"
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(config["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "rc")
            self.assertEqual(effect["method"], "init")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_rc_list_effects_join_delegated_and_root_grants(self) -> None:
        lock_hash = corpus_revision()
        snapshots = {}
        for spec in RC_LIST_CATALOG.values():
            snapshots[spec["snapshot"]] = _load(REPO / spec["snapshot"])
        for record_id, spec in RC_LIST_CATALOG.items():
            effect = next(row for row in self.effects if row["record_id"] == record_id)
            delegated = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == spec["delegated_class"]
            )
            init_write = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "luci-mod-system-init"
            )
            config = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "luci-mod-system-config"
            )
            root = next(
                grant
                for grant in self.grants
                if grant["record_id"] in effect["evidence_refs"]
                and grant["session_class"] == "root"
            )
            refs = effect["evidence_refs"]
            self.assertIn(delegated["record_id"], refs)
            self.assertIn(init_write["record_id"], refs)
            self.assertIn(config["record_id"], refs)
            self.assertIn(root["record_id"], refs)
            self.assertEqual(effect["assessment"], "intended_access")
            self.assertEqual(effect["corpus_revision"], lock_hash)
            self.assertEqual(delegated["corpus_revision"], lock_hash)
            self.assertEqual(root["corpus_revision"], lock_hash)
            self.assertEqual(effect["ubus_object"], "rc")
            self.assertEqual(effect["method"], "list")
            self.assertEqual(effect["sink_kind"], "ubus_call")
            self.assertEqual(effect["entrypoint_id"], spec["entrypoint_id"])
            unauth = [
                grant
                for grant in self.grants
                if grant.get("entrypoint_id") == effect["entrypoint_id"]
                and grant["session_class"] == "unauthenticated"
            ]
            self.assertEqual(unauth, [])
            snapshot = next(
                row for row in snapshots[spec["snapshot"]] if row["record_id"] == record_id
            )
            self.assertEqual(effect, snapshot)

    def test_catalog_does_not_invent_forbidden_claims(self) -> None:
        for row in self.effects:
            self.assertNotEqual(row.get("assessment"), "authorization_violation")
            self.assertNotEqual(row.get("ingress"), "dispatcher")
            if row.get("ingress") == "cgi_io":
                spec = CGI_CATALOG[row["record_id"]]
                self.assertEqual(row.get("sink_kind"), spec["sink_kind"])
            elif row.get("ubus_object") == "file":
                spec = FILE_EXEC_CATALOG[row["record_id"]]
                self.assertEqual(row.get("sink_kind"), spec["sink_kind"])
                self.assertEqual(row.get("method"), "exec")
                self.assertNotIn("cgi_endpoint", row)
            elif row.get("ubus_object") == "system":
                spec = SYSTEM_CATALOG[row["record_id"]]
                self.assertEqual(row.get("sink_kind"), spec["sink_kind"])
                self.assertEqual(row.get("method"), spec["method"])
                self.assertNotIn("cgi_endpoint", row)
            elif row.get("ubus_object") == "rc":
                spec = RC_CATALOG[row["record_id"]]
                self.assertEqual(row.get("sink_kind"), spec["sink_kind"])
                self.assertEqual(row.get("method"), spec["method"])
                self.assertNotIn("cgi_endpoint", row)
            elif row.get("ubus_object") == "hostapd.*":
                spec = {
                    **HOSTAPD_DEL_CLIENT_CATALOG,
                    **HOSTAPD_WPS_START_CATALOG,
                    **HOSTAPD_WPS_CANCEL_CATALOG,
                    **HOSTAPD_WPS_STATUS_CATALOG,
                }[
                    row["record_id"]
                ]
                self.assertEqual(row.get("sink_kind"), spec["sink_kind"])
                self.assertEqual(row.get("method"), spec["method"])
                self.assertNotIn("cgi_endpoint", row)
            else:
                self.assertNotIn("cgi_endpoint", row)
        exec_effect = next(row for row in self.effects if row["record_id"] == CGI_EXEC_EFFECT_ID)
        exec_text = " ".join(exec_effect.get("assumptions", [])).lower()
        self.assertIn("execv", exec_text)
        self.assertIn("file.exec", " ".join(exec_effect.get("unknowns", [])).lower())
        self.assertNotIn("path_found", json.dumps(exec_effect))


if __name__ == "__main__":
    unittest.main()
