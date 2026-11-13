# M2: ubus luci.getUnixtime of luci-mod-status-index

C, not ucode. Policy-facts (`policy:ubus-luci-getunixtime-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `luci.getUnixtime` the pinned
status index view reaches via `rpc.declare` at luci pin `b2e0be4b`.

This is a luci object method. It does not rewrite the luci exec-methods
emitter (`policy:ubus-luci-exec-methods-v2`). Do not invent extra ACL.
Do not invent a `setInitAction` luci-ssl grant.
`system.board` stays on `policy:ubus-system-board-v1`.
`system.info` stays on `policy:ubus-system-info-v1`.
`system.reboot` stays on `policy:ubus-system-reboot-v1`.
`luci.getVersion` stays on `policy:ubus-luci-getversion-v1`.
`getOdhcp6cStats` on the same ACL stays another luci object method.
`luci-mod-system-config` / `system.js` also grant `getUnixtime` and are
not this slice.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=luci
   function=getUnixtime (uhttpd omits scope)

An allow means this HTTP gate was passed, not that the luci-base
`getUnixtime` handler ran. That handler returns `{ result: time() }`
from builtin `time()` and is not invoked here.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `luci.getUnixtime` | `luci-mod-status-index` (read) | ubus `luci` / `getUnixtime` (`10_system.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`
(unauthenticated ACLs grant only `luci.getFeatures`). The
list-read `luci-mod-system-flash` fixture has ubus `file.exec`, not
`luci.getUnixtime`. `luci-mod-status-realtime` has luci realtime methods,
not `luci.getUnixtime`. `luci-mod-system-reboot` has `system.reboot`, not
`luci.getUnixtime`. Stock root `*` is `intended_access`
(`root-administration`).

`system.board` / `system.info` are different methods on the same ACL;
the index fixture can pass those HTTP gates without this slice emitting
those grants. `luci.getVersion` is declared on the same view and stays on
`policy:ubus-luci-getversion-v1`. `getOdhcp6cStats` is on the same ACL
without a `10_system.js` caller and is not this slice.
`luci-mod-system-config` / `system.js` also grant `getUnixtime` and are
not this slice (no extra config grant).
`luci-mod-status-index-storage` is not this slice (no invented storage
login).

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-luci-getunixtime-effect.json`; decisions:
`policy/ubus_luci_getunixtime_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
