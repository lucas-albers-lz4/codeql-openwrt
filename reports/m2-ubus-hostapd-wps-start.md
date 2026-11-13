# M2: ubus hostapd.wps_start of luci-ssl wifi views

C, not ucode. Policy-facts (`policy:ubus-hostapd-wps-start-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `hostapd.<ifname>.wps_start`
the pinned status wifi view reaches via
`60_wifi.js` `handleCallWPS` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. Do not invent a `setInitAction` luci-ssl grant.
`hostapd.del_client` stays on `policy:ubus-hostapd-del-client-v1`.
luci-mod-status-index `system.board` stays on
`policy:ubus-system-board-v1`. luci-mod-status-index `system.info`
stays on `policy:ubus-system-info-v1`. luci-mod-status-index
`luci.getVersion` stays on `policy:ubus-luci-getversion-v1`.
luci-mod-status-index `luci.getUnixtime` stays on
`policy:ubus-luci-getunixtime-v1`.
luci-mod-system-init `rc.init` stays on `policy:ubus-rc-init-v1`.
luci-mod-system-init `rc.list` stays on `policy:ubus-rc-list-v1`.
luci-mod-system-reboot `system.reboot` stays on
`policy:ubus-system-reboot-v1`. luci-mod-network-config ifup/ifdown/wifi
`file.exec` stays on `policy:ubus-file-exec-ifup-v1`.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=`hostapd.*`
   function=wps_start (uhttpd omits scope; `FNM_NOESCAPE`)

An allow means this HTTP gate was passed, not that hostapd started WPS.
Call objects are `hostapd.<ifname>` (example `hostapd.wlan0`);
the inventoried ACL pattern is `hostapd.*`. Bare object `hostapd` does
not match. This oracle does not invoke hostapd.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `hostapd.<ifname>.wps_start` | `luci-mod-status-index-wifi` | ubus `hostapd.*` / `wps_start` (`60_wifi.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. The
write `luci-mod-network-config` fixture grants `hostapd.*` /
`del_client`, not `wps_start`. The read `luci-mod-network-config`
fixture has ubus `file.exec`, not `hostapd.wps_start`. The list-read
flash fixture, reboot fixture, and `luci-mod-status-index`
`system.board` / `system.info` / `luci.getVersion` / `luci.getUnixtime`
fixture likewise lack the method.
Stock root `*` is `intended_access` (`root-administration`).

`luci-mod-status-index-wifi` also grants `wps_cancel` / `wps_status`.
Write implies those methods can pass the HTTP gate; this slice does
not emit those grants. `hostapd.del_client` stays on
`policy:ubus-hostapd-del-client-v1`.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-hostapd-wps-start-effect.json`; decisions:
`policy/ubus_hostapd_wps_start_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
