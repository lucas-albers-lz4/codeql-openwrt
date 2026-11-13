# M2: ubus system.reboot of luci-mod-system-reboot

C, not ucode. Policy-facts (`policy:ubus-system-reboot-v1`) evaluates the
HTTP `/ubus` gate from pinned uhttpd `uh_ubus_allowed` @ `93b05e0` plus
rpcd `session.access` @ `d99f703`, bounded to `system.reboot` the pinned
reboot view reaches via `rpc.declare` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. luci-mod-status iptables `-Z` / routes `ip` stay on
`policy:ubus-file-exec-v1`. luci-mod-network-config ifup/ifdown/wifi stay
on `policy:ubus-file-exec-ifup-v1`. luci-mod-status-processes `/bin/kill`
stays on `policy:ubus-file-exec-kill-v1`. luci-mod-system-mounts
umount/block stays on `policy:ubus-file-exec-mounts-v1`. luci-mod-system-flash
`sysupgrade --list-backup` stays on `policy:ubus-file-exec-list-backup-v1`.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=system
   function=reboot (uhttpd omits scope)

An allow means this HTTP gate was passed, not that procd `reboot()` ran.
The ubus object is procd `system`, not rpcd `rpc-sys`. This oracle does
not invoke `reboot()`.

| Method | Delegated fixture | ACL |
| --- | --- | --- |
| `system.reboot` | `luci-mod-system-reboot` (write) | ubus `system` / `reboot` (`reboot.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. The list-read
`luci-mod-system-flash` fixture has ubus `file.exec`, not `system.reboot`.
`luci-mod-system-config` and `luci-mod-system-mounts` likewise lack the
method. Stock root `*` is `intended_access` (`root-administration`).

`file.exec` of `/sbin/reboot` on the same ACL is unused by `reboot.js`.
flash.js `fs.exec('/sbin/reboot')` is write flash and stays unstaffed.
Do not invent a write flash login. `rpc-sys.reboot` is a different
object and is not this slice.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
crontab.js `fs.exec` of `/etc/init.d/cron reload` has file.exec of the
cmdline but ubus `file.write`, not `file.exec`.

`shellquote` and `basename` are not sanitizers.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-system-reboot-effect.json`; decisions:
`policy/ubus_system_reboot_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
