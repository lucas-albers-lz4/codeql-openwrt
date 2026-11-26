# Bounded privileged LuCI app review

This packet selects **one app package**, `luci-app-adblock-fast`, using the LuCI `cb87fe60e1e2e052af36a93647f2264577829e0a` source inventory and its separately audited actual IPK. It joins the package inventory, the `setInitAction` source operation and the independently retained [testing-query evidence](../issue175-adblock-ipk-20261126/README.md). It does not establish installation, effective access, request reachability, runtime effects, taint flow, vulnerability or security coverage. The exact structured [scope](scope.json) retains source-candidate paths/dispositions and all nine regular app IPK members, modes and SHA-256 identities.

## Package selection and lead dispositions

The [pinned source inventory](../issue172-luci-source-inventory-20261125/README.md) reviewed the following explicit source-package leads. Absence of a selected candidate is only a result of that inventory's policy, not proof that the application has no behavior or no relevant installed files. No app in the last five rows was package-staged or queried in this review.

| Source package | Inventory disposition at cb87 | Review disposition |
| --- | --- | --- |
| `luci-app-adblock-fast` | One selected rpcd Ucode candidate; two extensionless shell-shaped paths classified unknown by #172. | Selected; actual IPK and lexical testing query below. |
| `luci-app-firewall` | No candidate in the retained inventory policy. | Source lead not selected; package bytes and operation coverage unobserved. |
| `luci-app-acl` | No candidate in the retained inventory policy. | Source lead not selected; ACL administration and runtime policy unobserved. |
| `luci-app-openvpn` | `root/etc/config/openvpn_recipes`, extensionless config, unsupported/unknown. | Not selected as Ucode; package bytes and runtime unobserved. |
| `luci-app-opkg` | No candidate in the retained inventory policy. | Translation-only source directory at this pin, with no app recipe; installed bytes and operations unobserved. |
| `luci-app-package-manager` | `root/usr/libexec/package-manager-call`, extensionless `#!/bin/sh` script, unsupported/unknown. | Not selected as Ucode; its subprocess behavior and package bytes are unobserved. |

All six named directories exist at the pinned source tree; the inventory contains 5 candidate paths across this set, only the adblock rpcd provider selected. The OpenVPN and package-manager first lines were checked against pinned Git source; #172's unknown classifications are preserved. These dispositions are not negative query results. Companion `adblock-fast` service is a separate package: the app imports `/lib/adblock-fast/adblock-fast.uc`, but the service's identity, contents and effects are not inferred from app membership. Its independent #173 batch is outside this query stage.

## Complete actual app regular-member scope

The actual `luci-app-adblock-fast` IPK from [run 45748188587, artifact 15087445880](https://github.com/lucas-albers-lz4/codeql-openwrt/actions/runs/45748188587/artifacts/15087445880) has control `1.2.4-r4`, `all`, SHA-256 `b3d18c736a970f0ba17919e1249c837dae393b04f5ec541950a6cce737110e0f`. The [independently audited receipt](../issue175-adblock-ipk-20261126/provenance/app-comparison.json) enumerates archive/control records; the following are **all nine regular data members**, all mode `0644`:

| Installed path | Review treatment |
| --- | --- |
| `etc/uci-defaults/40_luci-adblock-fast` | Shell-shaped source-equal auxiliary; excluded from this Ucode query. |
| `etc/uci-defaults/95_adblock-fast-api` | Second shell-shaped source-equal auxiliary; excluded from this Ucode query. |
| `usr/share/luci/menu.d/luci-app-adblock-fast.json` | Source-equal menu context; not selected. |
| `usr/share/rpcd/acl.d/adblock-fast-api.json` | Source-equal ACL context; not selected. |
| `usr/share/rpcd/acl.d/luci-app-adblock-fast.json` | Source-equal ACL context; not selected. |
| `usr/share/rpcd/ucode/luci.adblock-fast` | Source-equal selected rpcd Ucode input, SHA-256 `3cb9d07b33a0aec36743326a5cb1e18885d245a132ef92174eb4c8b70aaebdd8`. |
| `www/luci-static/resources/adblock-fast/status.js` | Auxiliary frontend; not selected; minification provenance unverified. |
| `www/luci-static/resources/view/adblock-fast/overview.js` | Auxiliary frontend; not selected; minification provenance unverified. |
| `www/luci-static/resources/view/status/include/70_adblock-fast.js` | Auxiliary frontend; not selected; minification provenance unverified. |

The two shell paths were source-first route controls; they were **not** included in the three-file CodeQL run, so this packet does not claim observed route exclusion for them. The receipt reports source/prepared/stage/IPK comparisons; build-time prepared and staged trees were not uploaded, while the selected provider and one ACL were independently reread from raw IPK and retained. Three JS outputs differ from their source under enabled minification; the transform's semantics have not been independently verified. Directory and control records are in the receipt, not counted in the nine regular data members.

## Request, grants and source effects

Pinned [provider source](https://github.com/openwrt/luci/blob/cb87fe60e1e2e052af36a93647f2264577829e0a/applications/luci-app-adblock-fast/root/usr/share/rpcd/ucode/luci.adblock-fast) exports `luci.adblock-fast` (line 673) with `setInitAction` (401–403). The [source frontend](https://github.com/openwrt/luci/blob/cb87fe60e1e2e052af36a93647f2264577829e0a/applications/luci-app-adblock-fast/htdocs/luci-static/resources/adblock-fast/status.js) declares the RPC name and arguments at 252–255 and invokes it at 304–305; this is source wiring, not an observed browser request. The handler reads `req.args.name` and `.action` (404–405), compares the name with `adblock-fast`, checks the action against a literal set (406–411), and checks init-script executable access (421–422).

The retained app ACL declares a write ubus grant for `luci.adblock-fast.setInitAction` and a UCI write grant for `adblock-fast`; it also declares read grants for other ubus methods and UCI packages. The separate [API ACL](adblock-fast-api.json), source-equal to the independently audited IPK member SHA-256 `6e1a9ccb00b528da74265311b23c4c7190f2650cf4480c52a5fa94648fd105ed`, declares read access to `getInitStatus` and write access to `setInitAction`, without a UCI write grant. Its exact bytes are copied from the [pinned LuCI source](https://github.com/openwrt/luci/blob/cb87fe60e1e2e052af36a93647f2264577829e0a/applications/luci-app-adblock-fast/root/usr/share/rpcd/acl.d/adblock-fast-api.json); the linked testing packet retains the upstream license and notice. These declarations do not establish which principal, if any, has the grant. Under the handler's source branches, `system` calls at 429, 444 and 446 invoke `/etc/init.d/adblock-fast` with the selected action; enable/disable success is followed by UCI `set` and `commit` at 430–433. Some actions are backgrounded in source and return an optimistic result. For enable/start/disable/stop, the method also calls `cron_write(action, null)` at 452–456 without using its return value. The helper can read `/etc/crontabs/root`, write a temporary crontab, rename it, chmod the result and invoke a cron reload (132–138, 223–234); its branches and outcomes remain unobserved. Source inspection does not establish that subprocesses, UCI commits, file changes, scheduling or service actions occurred. The imported service, rpcd/uhttpd/session dispatch and their privileges are separate unverified boundaries; cgi-io is not asserted as part of this path.

## Query and controls

The retained local testing run used producer `a7bf614e2fb59200e303f04b6255af7e6d4007e2` `BuiltinSystem.ql`, a syntactic inventory excluded from the released default suite. It selected the app provider plus two synthetic files, checked three successful-file diagnostics and zero extraction errors, and reported the 13 predeclared app `system` call expressions plus one synthetic positive. The otherwise matching formal-shadow negative produced no baseline row; a separately reviewed one-predicate mutant produced that row and a coordinate witness checked all 15 source spans and shared AST identities. Exact ranges, messages, counts, routes, warnings, costs, failed verifier attempt and stopped/decode-only mutation are in the [retained evidence](../issue175-adblock-ipk-20261126/README.md). The 13 lexical rows include three calls in `setInitAction`; they are not proven request-to-sink flow. No new scan was performed for this packet.

`RequestArgsExec.ql` is not applied to this provider: its basename `luci.adblock-fast` matches neither the `luci` basename rule nor the seven explicit installed-path exceptions. Lexical shadow modeling has limited supported forms, and imported/runtime binding, reassignment, cross-component request flow and shell interpretation remain unsupported or unobserved. No new producer miss is established here; concrete extractor or model gaps belong in a linked producer issue if demonstrated. Issue #175 disposition is an owner decision, not a security conclusion.

Run `python3 -B evidence/issue175-app-review-20261126/verify.py` and the verifier/tests in the linked testing packet. The cross-check binds the five source leads, all nine member records and ACL grants to retained inputs; it does not authenticate the external artifact or repeat the build, extraction or query.
