# M4: luci.sys `init_action` reaches builtin `system`

`setInitAction.call` forwards `request.args.name` and `request.args.action` into imported `init_action` from `'luci.sys'`. This slice extracts that module (`sys.uc`) and records the helper body.

`init_action` interpolates `basename(name)` and `action` into builtin `system` via a template string. **`basename` is not a modeled sanitizer.** There is no `shellquote` on this sink. Interprocedural taint from the rpcd method is not claimed (still local TreeSitter only).

The stock `setInitAction` caller switches on a fixed action token list before calling the helper; that allowlist is **not** proven by `InitActionSystem.ql`.

Evidence: `handler_effect` / `fact`. Assessment stays **unassessed** (no M2 grant row for this method in the first-release evaluator).

See `reports/m4-luci-sys-init-action-findings.json`.
