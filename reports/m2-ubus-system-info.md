# M2: ubus system.info of luci-mod-status-index

C, not ucode. Policy-facts (`policy:ubus-system-info-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `system.info` the pinned
status index view reaches via `rpc.declare` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. Do not invent a `setInitAction` luci-ssl grant.
`system.board` stays on `policy:ubus-system-board-v1`.
`system.reboot` stays on `policy:ubus-system-reboot-v1`.
`luci.getVersion` / `getUnixtime` on the same view stay luci object
methods.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=system
   function=info (uhttpd omits scope)

An allow means this HTTP gate was passed, not that the procd
`system.info` handler ran. The ubus object is procd `system`, not luci
`getVersion`. This oracle does not invoke the procd handler.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `system.info` | `luci-mod-status-index` (read) | ubus `system` / `info` (`10_system.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. The
list-read `luci-mod-system-flash` fixture has ubus `file.exec`, not
`system.info`. `luci-mod-status-realtime` has luci realtime methods,
not `system.info`. `luci-mod-system-reboot` has `system.reboot`, not
`system.info`. Stock root `*` is `intended_access`
(`root-administration`).

`system.board` is a different method on the same ACL; the index fixture
can pass that HTTP gate without this slice emitting a grant.
`luci-mod-status-index-storage` also grants `system.info` and is not
this slice (no invented storage login).

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-system-info-effect.json`; decisions:
`policy/ubus_system_info_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
