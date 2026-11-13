# M2: ubus luci.getMountPoints of luci-mod-status-index-storage

C, not ucode. Policy-facts (`policy:ubus-luci-getmountpoints-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `luci.getMountPoints` the pinned
status storage view reaches via `rpc.declare` at luci pin `b2e0be4b`.
`mounts.js` and `package-manager.js` declare the same method.

This is a luci object method. It does not rewrite the luci exec-methods
emitter (`policy:ubus-luci-exec-methods-v2`). Do not invent extra ACL.
Do not invent a `setInitAction` luci-ssl grant.
Do not invent luci-mod-status-index-ports / dhcp / dsl logins.
`system.board` stays on `policy:ubus-system-board-v1`.
`system.info` stays on `policy:ubus-system-info-v1`.
`system.reboot` stays on `policy:ubus-system-reboot-v1`.
`luci.getVersion` stays on `policy:ubus-luci-getversion-v1`.
`luci.getUnixtime` stays on `policy:ubus-luci-getunixtime-v1`.
`luci.getOdhcp6cStats` stays on `policy:ubus-luci-getodhcp6cstats-v1`.
`luci.getTimezones` stays on `policy:ubus-luci-gettimezones-v1`.
`luci.getLEDs` stays on `policy:ubus-luci-getleds-v1`.
`luci-mod-status-index` grants getVersion / getUnixtime / getOdhcp6cStats,
not getMountPoints. `hostapd.del_client` / `wps_start` / `wps_cancel` /
`wps_status` stay on their hostapd revisions.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=luci
   function=getMountPoints (uhttpd omits scope)

An allow means this HTTP gate was passed, not that the luci-base
`getMountPoints` handler ran. That handler opens `/proc/mounts` and
`statvfs` and is not invoked here.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `luci.getMountPoints` | `luci-mod-status-index-storage` (read) | ubus `luci` / `getMountPoints` (`25_storage.js`) |
| `luci.getMountPoints` | `luci-mod-system-mounts` (existing read/write) | ubus `luci` / `getMountPoints` (`mounts.js`) |
| `luci.getMountPoints` | `luci-app-package-manager` (existing read/write) | ubus `luci` / `getMountPoints` (`package-manager.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`
(unauthenticated ACLs grant only `luci.getFeatures`). The
list-read `luci-mod-system-flash` fixture has ubus `file.exec`, not
`luci.getMountPoints`. `luci-mod-status-index` has getVersion /
getUnixtime / getOdhcp6cStats, not `luci.getMountPoints`.
`luci-mod-status-realtime` has luci realtime methods, not
`luci.getMountPoints`. `luci-mod-system-reboot` has `system.reboot`,
not `luci.getMountPoints`. Stock root `*` is `intended_access`
(`root-administration`).

`system.info` is also on the storage ACL; the storage fixture can pass
that HTTP gate without this slice emitting a `system.info` grant.
`luci.getBlockDevices` / `luci.setBlockDetect` stay on the luci
exec-methods emitter.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-luci-getmountpoints-effect.json`; decisions:
`policy/ubus_luci_getmountpoints_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
