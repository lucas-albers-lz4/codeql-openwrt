# M4 evidence: luci fixed `/sbin/block` exec and `setLocaltime` sysfixtime

These are **call-body inventory** records (`handler_effect` / `fact`), not taint paths. At luci pin `b2e0be4b` they live in the rpcd plugin `modules/luci-base/root/usr/share/rpcd/ucode/luci`, not in `luci.sys`. `shellquote` and `basename` are not sanitizers (and are not present on these sinks). This slice does not claim `path_found`.

## Methods

| Method | Sink | Argv | `request.args` | ACL / M2 grant |
| --- | --- | --- | --- | --- |
| `getBlockDevices` | named `popen` | `/sbin/block info 2>/dev/null` | none (`call: function()`) | `luci-mod-system-mounts` read → `policy:grant:luci-mod-system-mounts:ubus_http:luci.getBlockDevices` |
| `setBlockDetect` | builtin `system` | `/sbin/block detect > /etc/config/fstab` | none (`call: function()`) | `luci-mod-system-mounts` write → `policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect` |
| `setLocaltime` (extra) | builtin `system` | `/etc/init.d/sysfixtime restart >/dev/null` | not in this argv | existing `luci-mod-system-config` write grant; not a new method grant |

Unauthenticated `/ubus` still only grants `luci.getFeatures` (M2). These methods are **not** unauthenticated (no-grant deny). The `luci-mod-system-mounts` fixture is a synthetic role, not a stock login. Stock root `*` remains `intended_access` (`root-administration`), not a violation. Canonical catalog: [handler_effects.md](handler_effects.md).

`setLocaltime`'s `date` sink stays on the request.args inventory ([m4-request-args.md](m4-request-args.md)); this report only adds the second, fixed sysfixtime exec.

See `reports/m4-block-device-exec-coverage.json`.

## Still unmodeled in this slice

- `getRealtimeStats` later `flags` reassignment (CFG/SSA)
- same-function `flags` / `u`/`p` quoting ([m4-realtime-password-unquoted.md](m4-realtime-password-unquoted.md))
- `setInitAction` → `luci.sys` `init_action` interprocedural dataflow (no luci-ssl delegated grant)
- `getBlockDevices` `readfile` of `/sys/class/block/${dev}/size` (not exec)
