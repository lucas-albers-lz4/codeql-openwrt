# M2: ubus system.board of luci-mod-status-index

C, not ucode. Policy-facts (`policy:ubus-system-board-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `system.board` the pinned
status index view reaches via `rpc.declare` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. Do not invent a `setInitAction` luci-ssl grant.
`system.reboot` stays on `policy:ubus-system-reboot-v1`.
`system.info` is a different method on the same ACL and is not this slice.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=system
   function=board (uhttpd omits scope)

An allow means this HTTP gate was passed, not that procd `board_info`
ran. The ubus object is procd `system`, not luci `getVersion`.
This oracle does not invoke `board_info`.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `system.board` | `luci-mod-status-index` (read) | ubus `system` / `board` (`10_system.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. The
list-read `luci-mod-system-flash` fixture has ubus `file.exec`, not
`system.board`. `luci-mod-status-realtime` has luci realtime methods,
not `system.board`. `luci-mod-system-reboot` has `system.reboot`, not
`system.board`. Stock root `*` is `intended_access`
(`root-administration`).

`system.info` is a different method; the index fixture can pass that
HTTP gate without this slice emitting a grant. `luci.getVersion` /
`getUnixtime` on the same view stay luci object methods.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-system-board-effect.json`; decisions:
`policy/ubus_system_board_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
