# M2: ubus hostapd.del_client of luci-ssl wifi views

C, not ucode. Policy-facts (`policy:ubus-hostapd-del-client-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `hostapd.<ifname>.del_client`
the pinned wireless and status wifi views reach via
`network.js` `disconnectClient` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. Do not invent a `setInitAction` luci-ssl grant.
luci-mod-system-init `rc.init` stays on `policy:ubus-rc-init-v1`.
luci-mod-system-init `rc.list` stays on `policy:ubus-rc-list-v1`.
luci-mod-system-reboot `system.reboot` stays on
`policy:ubus-system-reboot-v1`. luci-mod-network-config ifup/ifdown/wifi
`file.exec` stays on `policy:ubus-file-exec-ifup-v1`.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=`hostapd.*`
   function=del_client (uhttpd omits scope; `FNM_NOESCAPE`)

An allow means this HTTP gate was passed, not that hostapd deauthenticated
a client. Call objects are `hostapd.<ifname>` (example `hostapd.wlan0`);
the inventoried ACL pattern is `hostapd.*`. Bare object `hostapd` does
not match. This oracle does not invoke hostapd.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `hostapd.<ifname>.del_client` | `luci-mod-network-config-write` | ubus `hostapd.*` / `del_client` (`wireless.js`) |
| `hostapd.<ifname>.del_client` | `luci-mod-status-index-wifi` | ubus `hostapd.*` / `del_client` (`60_wifi.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. The
read `luci-mod-network-config` fixture has ubus `file.exec`, not
`hostapd.del_client`. The list-read flash fixture and reboot fixture
likewise lack the method. Stock root `*` is `intended_access`
(`root-administration`).

`luci-mod-status-index-wifi` also grants `wps_start` / `wps_cancel` /
`wps_status`. Write implies those methods can pass the HTTP gate; this
slice does not emit those grants.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-hostapd-del-client-effect.json`; decisions:
`policy/ubus_hostapd_del_client_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
