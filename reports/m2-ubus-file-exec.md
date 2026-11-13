# M2: ubus file.exec of luci-mod-status iptables -Z and routes ip

C, not ucode. Policy-facts (`policy:ubus-file-exec-v1`) evaluates the
conjunctive HTTP `/ubus` `file.exec` gate from pinned uhttpd
`uh_ubus_allowed` @ `93b05e0` plus rpcd-mod-file `rpc_file_exec_run` @
`d99f703`, bounded to luci-mod-status commands the pinned views reach via
`fs.exec` at luci pin `b2e0be4b`.

These are not luci object methods. Do not invent luci-ssl luci object
grants. cgi-io listing of iptables stays on `policy:cgi-exec-status-v1`.

Bounded gate, after a typed JSON-RPC `/ubus` call array:

1. `parse_call_params` (missing SID with `no_ubusauth=0` is `ERROR_PARSE`)
2. `uh_ubus_allowed` → `session.access` scope=ubus object=file function=exec
   (uhttpd omits scope)
3. `rpc_file_exec_lookup` of argv0 (inventoried absolute paths only)
4. `rpc_canonicalize_path` of argv0
5. `session.access(sid, "file", executable, "exec")`, or else
   `session.access(sid, "file", cmdline, "exec")`

A ubus `file.exec` grant is not authorization to run an arbitrary command.
`rpc_file_exec_lookup` is not a live PATH/stat search: only the inventoried
absolute paths below are treated as found. This oracle does not fork `execv`.
rpcd-mod-file checks the executable ACL first, then the cmdline (reverse of
cgi-io `main_exec`). Inventoried luci-ssl ACLs grant the cmdline objects, not
the bare executables.

| Command | Delegated fixture | File ACL |
| --- | --- | --- |
| `/usr/sbin/iptables -Z` | `luci-mod-status-firewall` write | exact cmdline (`iptables.js` handleCounterReset) |
| `/usr/sbin/ip6tables -Z` | `luci-mod-status-firewall` write | exact cmdline (`iptables.js` handleCounterReset) |
| `/sbin/ip -[46] neigh/route/rule …` | `luci-mod-status-routes` | globs (`routes.js`) |
| `/sbin/ip -[46] -j neigh/route/rule …` | `luci-mod-status-routes-json` | globs (`routesj.js`) |

Unauthenticated is deny (`ERROR_ACCESS`) at `uh_ubus_allowed`. A session with
ubus `file.exec` but without the command file ACL is
`UBUS_STATUS_PERMISSION_DENIED`. A read-only firewall fixture has no ubus
`file.exec` (read grants `file` `stat` only). Extra tokens on the exact
iptables `-Z` cmdline miss. Stock root `*` is `intended_access`
(`root-administration`). Bare executable fallback is not granted for these
commands. `/usr/sbin/iptables-legacy` is `UBUS_STATUS_NOT_FOUND` here (not
inventoried, not a live PATH search). SID plus `env` is
`UBUS_STATUS_PERMISSION_DENIED`; inventoried callers do not pass `env`.

`luci-mod-network-config` has ubus `file.exec` but not the iptables `-Z` file
ACL. `luci-mod-status-routes` and `luci-mod-status-routes-json` do not cover
each other's `-j` vs plain `ip` globs. luci-mod-network diagnostics ping,
ifup/ifdown/wifi, and luci-mod-status-processes `/bin/kill` are not this
slice.

`shellquote` and `basename` are not sanitizers. `rpc_canonicalize_path` is a
textual path normalizer, not a taint sanitizer.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-ubus-file-exec-effect.json`; decisions:
`policy/ubus_file_exec_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
