# M4 evidence: luci `request.args` → `popen` / `system`

Findings are evidence, not proof. Models walk generated TreeSitter nodes plus same-function name bindings. Wrapper AST/CFG/SSA libraries are not imported. `shellquote` is observed in the query message; it is **not** a modeled sanitizer.

## Methods

| Method | Sink | Param | Quoting | ACL / M2 grant |
| --- | --- | --- | --- | --- |
| `getSwconfigFeatures` | named `popen` `swconfig` | `switch` | `shellquote` in the sink argument | `luci-mod-network-config` read → `policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigFeatures` |
| `getSwconfigPortState` | named `popen` `swconfig` | `switch` | `shellquote` in the sink argument | `luci-mod-network-config` read → `policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigPortState` |
| `getRealtimeStats` | named `popen` `luci-bwc` | `device` | `shellquote` into local `flags` | `luci-mod-status-realtime` read → `policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats` |
| `setPassword` | builtin `system` `passwd` | `username`, `password` | `shellquote` into locals `u`/`p` | `luci-mod-system-config` write → `policy:grant:luci-mod-system-config:ubus_http:luci.setPassword` |
| `setLocaltime` | builtin `system` `date` | `localtime` | none; `localtime()` then `sprintf %d` | `luci-mod-system-config` write → `policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime` |

Unauthenticated `/ubus` still only grants `luci.getFeatures` (M2). These five methods are **not** unauthenticated (no-grant deny). Delegated module sessions are **intended_access** via the grants above. This slice does not emit `authorization_violation`. Root `*` remains `intended_access` (`root-administration`), not a violation.

`getFeatures` is absent from `RequestArgsExec.ql` (negative control). Synthetic `taint_pos` / `taint_neg` are excluded by the luci-basename filter.

See `reports/m4-coverage.json`.

## Still unmodeled in this slice

- `setInitAction` → `init_action(request.args.*)` interprocedural dataflow (helper body in [m4-luci-sys-init-action.md](m4-luci-sys-init-action.md); no luci-ssl delegated grant at pin `b2e0be4b`)
- full CFG/SSA and global flow

Moved to sibling M4 reports: getFeatures direct helpers ([m4-getfeatures-direct-exec.md](m4-getfeatures-direct-exec.md)); complete-argument `shellquote` ([m4-shellquote.md](m4-shellquote.md)).
