# M4 evidence: luci.sys `conntrack_list` / `process_list` fixed popen

These are **call-body inventory** records (`handler_effect` / `fact`), not taint paths and not a new query. At luci pin `b2e0be4b` the sinks live in `modules/luci-base/ucode/sys.uc` (`/usr/share/ucode/luci/sys.uc`). The rpcd methods are thin wrappers with `call: function()` (no `request.args`). `shellquote` and `basename` are not sanitizers (and are not present on these sinks). This slice does not claim `path_found`. QL for these helpers waits on open `codeql-ucode#12`.

## Methods

| Method | Helper | Sink | Argv | Reach | ACL / M2 grant |
| --- | --- | --- | --- | --- | --- |
| `getConntrackList` | `conntrack_list()` | named `popen` | `/usr/sbin/conntrack -L -o extended` | fallback after `open('/proc/net/nf_conntrack')` fails | existing `luci-mod-status-realtime` read → `policy:grant:luci-mod-status-realtime:ubus_http:luci.getConntrackList` |
| `getProcessList` | `process_list()` | named `popen` | `/bin/busybox top -bn1` | unconditional in the helper | `luci-mod-status-processes` read → `policy:grant:luci-mod-status-processes:ubus_http:luci.getProcessList` |

Unauthenticated `/ubus` still only grants `luci.getFeatures` (M2). These methods are **not** unauthenticated (no-grant deny). Both fixture roles are synthetic, not stock logins. Stock root `*` remains `intended_access` (`root-administration`), not a violation. Canonical catalog: [handler_effects.md](handler_effects.md).

`getConntrackList` reuses the `#12` `luci-mod-status-realtime` session (the ACL array already listed it next to `getRealtimeStats`); that is not a new session class. The `luci-mod-status-processes` fixture for `getProcessList` is **read-only**. Write `file.exec` `/bin/kill` is the separate M2 slice `policy:ubus-file-exec-kill-v1`, not this luci.sys popen.

See `reports/m4-luci-sys-status-exec-coverage.json`.

## Still unmodeled in this slice

- `getConntrackList` primary `open('/proc/net/nf_conntrack')` (file_read, not exec)
- `luci-mod-status-processes` write `file.exec` `/bin/kill` (C `file.exec`; M2 is `policy:ubus-file-exec-kill-v1`, not this luci.sys popen)
- `getRealtimeStats` later `flags` reassignment (CFG/SSA; QL waits on `codeql-ucode#12`)
- same-function `flags` / `u`/`p` quoting ([m4-realtime-password-quoted-locals.md](m4-realtime-password-quoted-locals.md))
- `setInitAction` → `luci.sys` `init_action` interprocedural dataflow (no luci-ssl delegated grant)
