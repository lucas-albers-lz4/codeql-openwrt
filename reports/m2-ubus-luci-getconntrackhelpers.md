# M2: ubus luci.getConntrackHelpers of luci-app-firewall

C, not ucode. Policy-facts (`policy:ubus-luci-getconntrackhelpers-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `luci.getConntrackHelpers` the pinned
luci-app-firewall views reach via `rpc.declare` at luci pin `b2e0be4b`.
`zones.js`, `rules.js`, and `forwards.js` declare this method in luci-ssl at this pin.

This is a luci object method. It does not rewrite the luci exec-methods
emitter (`policy:ubus-luci-exec-methods-v2`). Do not invent extra ACL.
Do not invent a `setInitAction` luci-ssl grant.
Do not invent luci-mod-status-index-dhcp / dsl logins.
`system.board` stays on `policy:ubus-system-board-v1`.
`system.info` stays on `policy:ubus-system-info-v1`.
`system.reboot` stays on `policy:ubus-system-reboot-v1`.
`luci.getVersion` stays on `policy:ubus-luci-getversion-v1`.
`luci.getUnixtime` stays on `policy:ubus-luci-getunixtime-v1`.
`luci.getOdhcp6cStats` stays on `policy:ubus-luci-getodhcp6cstats-v1`.
`luci.getTimezones` stays on `policy:ubus-luci-gettimezones-v1`.
`luci.getLEDs` stays on `policy:ubus-luci-getleds-v1`.
`luci.getMountPoints` stays on `policy:ubus-luci-getmountpoints-v1`.
`luci.getBuiltinEthernetPorts` stays on `policy:ubus-luci-getbuiltinethernetports-v1`.
`getUSBDevices` stays unstaffed (no luci-ssl `rpc.declare` at this pin).
`luci-mod-status-index` grants getVersion / getUnixtime / getOdhcp6cStats,
not getConntrackHelpers. `hostapd.del_client` / `wps_start` / `wps_cancel` /
`wps_status` stay on their hostapd revisions.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=luci
   function=getConntrackHelpers (uhttpd omits scope)

An allow means this HTTP gate was passed, not that the luci-base
`getConntrackHelpers` handler ran. That handler is not invoked here.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `luci.getConntrackHelpers` | `luci-app-firewall` (read) | ubus `luci` / `getConntrackHelpers` (`zones.js` / `rules.js` / `forwards.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`
(unauthenticated ACLs grant only `luci.getFeatures`). The
`luci-mod-status-index-ports` fixture grants `luci.getBuiltinEthernetPorts`, not
`luci.getConntrackHelpers`. Stock root `*` is `intended_access`
(`root-administration`).

The firewall ACL grants only `luci.getConntrackHelpers`; the firewall fixture
cannot pass `system.info`. `luci-mod-network-diagnostics` ping/traceroute uses
`fs.exec_direct` and has no cgi-io exec grant; that mismatch is not this slice.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-luci-getconntrackhelpers-effect.json`; decisions:
`policy/ubus_luci_getconntrackhelpers_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
