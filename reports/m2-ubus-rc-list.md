# M2: ubus rc.list of luci-mod-system-init

C, not ucode. Policy-facts (`policy:ubus-rc-list-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `rc.list` the pinned
startup and system views reach via `rpc.declare` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. Do not invent a `setInitAction` luci-ssl grant.
luci-mod-system-init `rc.init` stays on `policy:ubus-rc-init-v1`.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=rc
   function=list (uhttpd omits scope)

An allow means this HTTP gate was passed, not that rpcd `rc.c` scanned
`/etc/init.d`. The ubus object is rpcd `rc`, not luci `setInitAction`.
This oracle does not invoke `rc_list`.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `rc.list` | `luci-mod-system-init-read` (read) | ubus `rc` / `list` (`startup.js`) |
| `rc.list` | `luci-mod-system-init` (existing write) | write implies read (`startup.js`) |
| `rc.list` | `luci-mod-system-config` (existing write) | write implies read (`system.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. The
list-read `luci-mod-system-flash` fixture has ubus `file.exec`, not
`rc.list`. `luci-mod-system-reboot` and `luci-mod-system-mounts`
likewise lack the method. Stock root `*` is `intended_access`
(`root-administration`).

`rc.init` is a different method and stays on `policy:ubus-rc-init-v1`.
The read `luci-mod-system-init-read` fixture cannot pass `rc.init`.
luci `setInitAction` has no luci-ssl delegated grant at this pin.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.
Write sysupgrade/firstboot stay unstaffed.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-rc-list-effect.json`; decisions:
`policy/ubus_rc_list_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
