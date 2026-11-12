# M4: `request.args` into imported callees

`setInitAction.call` forwards `request.args.name` and `request.args.action` to `init_action` imported from `'luci.sys'`. That module is **not** extracted in M1/M3 (basename glob is `luci` / fixtures). Same-file call resolution does not apply.

Evidence: `taint_path` / `inconclusive` (`unresolved_call`). This is not `no_path` and not a demonstrated sink. Promoting `luci.sys` extraction is a later routing/glob change.

See `reports/m4-imported-callee-findings.json`.
