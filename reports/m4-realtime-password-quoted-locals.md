# M4: shellquoted locals and the analyzer's direct-template barrier

Inventory/report only, transcribed from pinned source. The luci `shellquote` helper returns single-quoted, escaped text. Its quote characters survive storage in `flags`, `u`, and `p` and remain in the command strings after template interpolation. This inventory records an analyzer coverage gap; it does not establish unquoted runtime input or prove overall command safety.

The analyzer's current complete-argument barrier recognizes a direct `shellquote(...)` template substitution inside the `popen`/`system` argument. It does not follow quoted values through same-function locals. That direct-template model is inventoried for `getSwconfigFeatures` / `getSwconfigPortState` in [m4-shellquote.md](m4-shellquote.md). The analyzer does not treat `shellquote` as a global sanitizer. `basename` is not a sanitizer.

These methods already have M2 grants (`policy:ubus-luci-exec-methods-v2`). This slice does not invent grants, does not rewrite the luci emitter, and does not claim `path_found`.

## Methods

| Method | Local | Runtime quoting | Analyzer complete-argument barrier | ACL / M2 grant |
| --- | --- | --- | --- | --- |
| `getRealtimeStats` | `flags` | The device value keeps its `shellquote` wrapping and escaping inside `flags`, then ``luci-bwc ${flags}`` | Unmodeled through the local | `luci-mod-status-realtime` read → `policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats` |
| `setPassword` | `u`, `p` | The `shellquote` wrapping and escaping in `u`/`p` survive `${u}` / `${p}` interpolation into builtin `system` | Unmodeled through the locals | `luci-mod-system-config` write → `policy:grant:luci-mod-system-config:ubus_http:luci.setPassword` |

At luci pin `b2e0be4b` (`modules/luci-base/root/usr/share/rpcd/ucode/luci`):

- `shellquote(s)` returns single-quote wrapping with embedded apostrophes escaped.
- `getRealtimeStats.call`: `let flags;` then interface/wireless assign a template containing `shellquote(request.args.device)` into `flags`; conntrack/load assign literal flags; then `popen` interpolates `${flags}`.
- `setPassword.call`: `const u` / `const p` from `shellquote(request.args.username/password)`, then builtin `system` interpolates `${u}` / `${p}`.

Unauthenticated `/ubus` still only grants `luci.getFeatures` (M2). These two methods are **not** unauthenticated (no-grant deny). The delegated module sessions are synthetic fixture roles, not stock logins. For a session with the corresponding ACL, access is **intended_access** via the existing grants. Stock root `*` remains `intended_access` (`root-administration`), not a violation. This slice does not emit `authorization_violation`.

Does not retract request.args taint-reaches-sink evidence ([m4-request-args.md](m4-request-args.md)). Join keys: `corpus_revision` + `profile` + `ingress` / `entrypoint_id` / `ubus_object` / `method`. Canonical handler sinks stay in [handler_effects.md](handler_effects.md); these rows are quoting inventory, not extra sinks.

See `reports/m4-realtime-password-quoted-locals-coverage.json`.

## Still unmodeled in this slice

- `getRealtimeStats` later `flags` reassignment (CFG/SSA: interface vs wireless vs literal branches)
- QL/DataFlow for same-function locals (lives in `codeql-ucode`, not this tree)
- `setInitAction` → `init_action` interprocedural dataflow (no luci-ssl delegated grant)
