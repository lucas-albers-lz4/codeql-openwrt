# M4: `request.args` into imported callees

`setInitAction.call` forwards `request.args.name` and `request.args.action` to `init_action` imported from `'luci.sys'`. Under the M1/M3 basename glob (`luci` / fixtures), that module is **not** in the extract set. Same-file call resolution does not apply.

Evidence: `taint_path` / `inconclusive` (`unresolved_call`). This is not `no_path` and not a demonstrated sink.

The separate M4 `sys.uc` slice in codeql-ucode records the helper `system` sink and a syntactic caller/sink pair; see [m4-luci-sys-init-action.md](m4-luci-sys-init-action.md). Interprocedural taint is still unclaimed.

See `reports/m4-imported-callee-findings.json`.
