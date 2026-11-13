# M2: ubus file.exec of luci-mod-status-processes /bin/kill

C, not ucode. Policy-facts (`policy:ubus-file-exec-kill-v1`) evaluates the
conjunctive HTTP `/ubus` `file.exec` gate from pinned uhttpd
`uh_ubus_allowed` @ `93b05e0` plus rpcd-mod-file `rpc_file_exec_run` @
`d99f703`, bounded to luci-mod-status-processes write `/bin/kill` the pinned
view reaches via `fs.exec` at luci pin `b2e0be4b`.

This is not a luci object method. Do not invent luci-ssl luci object
grants. luci-mod-status iptables `-Z` / routes `ip` stay on
`policy:ubus-file-exec-v1`. luci-mod-network-config ifup/ifdown/wifi stay on
`policy:ubus-file-exec-ifup-v1`.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=file function=exec
   (uhttpd omits scope)
3. `rpc_file_exec_lookup` of argv0 (inventoried absolute path only)
4. `rpc_canonicalize_path` of argv0
5. `session.access(sid, "file", executable, "exec")`, or else
   `session.access(sid, "file", cmdline, "exec")`

A ubus `file.exec` grant is not authorization to run an arbitrary command.
`rpc_file_exec_lookup` is not a live PATH/stat search: only `/bin/kill` is
treated as found. This oracle does not fork `execv`. rpcd-mod-file checks
the executable ACL first, then the cmdline (reverse of cgi-io `main_exec`).
Inventoried luci-ssl ACLs grant the bare executable, so extra tokens match
at the executable stage as `intended_access` for the write fixture, not
`authorization_violation` and not a PoC.

| Command | Delegated fixture | File ACL |
| --- | --- | --- |
| `/bin/kill -<sig> <pid>` | `luci-mod-status-processes-write` | bare executable (`processes.js` handleSignal) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. A session with
ubus `file.exec` but without the command file ACL is
`UBUS_STATUS_PERMISSION_DENIED`. The existing `luci-mod-status-processes`
read fixture has `luci.getProcessList` only (no ubus `file.exec`). Stock
root `*` is `intended_access` (`root-administration`). SID plus `env` is
`UBUS_STATUS_PERMISSION_DENIED`, including a present empty table; inventoried
callers do not pass env.

`luci-mod-network-diagnostics` ping/traceroute uses `fs.exec_direct` and has
no cgi-io exec grant; that mismatch is not this slice.
`luci-mod-system-mounts` umount/`block mount` is not this slice
(`policy:ubus-file-exec-mounts-v1`). flash.js sysupgrade/firstboot stay
unstaffed.

`shellquote` and `basename` are not sanitizers. `rpc_canonicalize_path` is a
textual path normalizer, not a taint sanitizer.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-file-exec-kill-effect.json`; decisions:
`policy/ubus_file_exec_kill_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
