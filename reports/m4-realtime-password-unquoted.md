# M4: same-function locals are outside the complete-argument `shellquote` barrier

Inventory/report only. Not a new query. `basename` is not a sanitizer. `shellquote` is not a sanitizer unless the pack's complete-argument barrier already applies: the quoted value is a template substitution **inside** the `popen`/`system` argument. That barrier is inventoried for `getSwconfigFeatures` / `getSwconfigPortState` in [m4-shellquote.md](m4-shellquote.md). It does **not** apply through same-function locals.

These methods already have M2 grants (`policy:ubus-luci-exec-methods-v2`). This slice does not invent grants, does not rewrite the luci emitter, and does not claim `path_found`.

## Methods

| Method | Local | Sink interpolation | Complete-argument barrier | ACL / M2 grant |
| --- | --- | --- | --- | --- |
| `getRealtimeStats` | `flags` | named `popen` ``luci-bwc ${flags}`` | **no** (`shellquote` is in the `flags` assignment, not in the sink argument) | `luci-mod-status-realtime` read → `policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats` |
| `setPassword` | `u`, `p` | builtin `system` interpolates `${p}` and `${u}` | **no** (`shellquote` is assigned to `u`/`p`, then those locals are interpolated) | `luci-mod-system-config` write → `policy:grant:luci-mod-system-config:ubus_http:luci.setPassword` |

At luci pin `b2e0be4b` (`modules/luci-base/root/usr/share/rpcd/ucode/luci`):

- `getRealtimeStats.call`: `let flags;` then interface/wireless assign a template containing `shellquote(request.args.device)` into `flags`; conntrack/load assign literal flags; then `popen` interpolates `${flags}`.
- `setPassword.call`: `const u` / `const p` from `shellquote(request.args.username/password)`, then builtin `system` interpolates `${u}` / `${p}`.

Unauthenticated `/ubus` still only grants `luci.getFeatures` (M2). These two methods are **not** unauthenticated (no-grant deny). The delegated module sessions are synthetic fixture roles, not stock logins. For a session with the corresponding ACL, access is **intended_access** via the existing grants. Stock root `*` remains `intended_access` (`root-administration`), not a violation. This slice does not emit `authorization_violation`.

Does not retract request.args taint-reaches-sink evidence ([m4-request-args.md](m4-request-args.md)). Join keys: `corpus_revision` + `profile` + `ingress` / `entrypoint_id` / `ubus_object` / `method`. Canonical handler sinks stay in [handler_effects.md](handler_effects.md); these rows are quoting inventory, not extra sinks.

See `reports/m4-realtime-password-unquoted-coverage.json`.

## Still unmodeled in this slice

- `getRealtimeStats` later `flags` reassignment (CFG/SSA: interface vs wireless vs literal branches)
- QL/DataFlow for same-function locals (lives in `codeql-ucode`, not this tree)
- `setInitAction` → `init_action` interprocedural dataflow (no luci-ssl delegated grant)
