# M4 evidence: luci fixed `/sbin/block` exec and `setLocaltime` sysfixtime

These records are **call-body inventory** records (`handler_effect` / `fact`). They are not taint paths. At luci pin `b2e0be4b46ec0fd43394c081fa7c50657af14011`, they are in the rpcd plugin `usr/share/rpcd/ucode/luci`, not in `luci.sys`. `shellquote` and `basename` are not sanitizers. Neither appears on these sinks. This slice does not claim `path_found`.

## Methods and lineage

| Method | Sink | Argv | `request.args` | ACL / M2 grant |
| --- | --- | --- | --- | --- |
| `getBlockDevices` | named `popen` | `/sbin/block info 2>/dev/null` | none (`call: function()`) | `luci-mod-system-mounts` read → `policy:grant:luci-mod-system-mounts:ubus_http:luci.getBlockDevices` |
| `setBlockDetect` | builtin `system` | `/sbin/block detect > /etc/config/fstab` | none (`call: function()`) | `luci-mod-system-mounts` write → `policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect` |
| `setLocaltime` (extra) | builtin `system` | `/etc/init.d/sysfixtime restart >/dev/null` | not in this argv | existing `luci-mod-system-config` write grant; not a new method grant |

Unauthenticated `/ubus` still only grants `luci.getFeatures` (M2). These methods are not unauthenticated (no-grant deny). The `luci-mod-system-mounts` fixture is a synthetic role, not a stock login. Stock root `*` is `intended_access` (`root-administration`), not a violation. Canonical join catalog: [handler_effects.md](handler_effects.md).

Issue [#81](https://github.com/lucas-albers-lz4/codeql-openwrt/issues/81) selected **only** the existing `setBlockDetect` exact-literal `system` source-observation family. The [pre-implementation scope decision](https://github.com/lucas-albers-lz4/codeql-openwrt/issues/81#issuecomment-6888709031) records this choice. This report recognizes work that shipped earlier. It does not claim that #81 produced the implementation.

The producer baseline is [`fbcad5ff8840d83042a4ea2992fbd31c5f94a681`](https://github.com/lucas-albers-lz4/codeql-ucode/tree/fbcad5ff8840d83042a4ea2992fbd31c5f94a681). The query is [`SetBlockDetectEffectTable.ql`](https://github.com/lucas-albers-lz4/codeql-ucode/blob/fbcad5ff8840d83042a4ea2992fbd31c5f94a681/ql/src/m4/SetBlockDetectEffectTable.ql). The consumer baseline is [`e4f57889b5eb375e57f28ad1e8ce411c4b7e209e`](https://github.com/lucas-albers-lz4/codeql-openwrt/tree/e4f57889b5eb375e57f28ad1e8ce411c4b7e209e).

The actual #83 paired run used consumer commit [`d233b0e6615d618d9ddab3b6fa252573cafeaf2f`](https://github.com/lucas-albers-lz4/codeql-openwrt/tree/d233b0e6615d618d9ddab3b6fa252573cafeaf2f). It did not use the later merge identity. [#83](https://github.com/lucas-albers-lz4/codeql-openwrt/issues/83) and the [merged PR #87 handoff and reproduction record](https://github.com/lucas-albers-lz4/codeql-openwrt/pull/87) preserve the executed pins and reproducible commands. The executed and later merged consumer commits have the same complete tree (`eae3830e37e310ba7065fa1b9ef21f248525c28d`). This tree identity does not mean the run used the merge SHA. The producer's earlier [#80 import](https://github.com/lucas-albers-lz4/codeql-openwrt/pull/80) predates this #81 report-only change. The consumer [bounded adapter](../policy/setblock_table.py) also predates this change.

The bounded producer table supplies the `setBlockDetect` location. The import verifies the pinned source, existing mounts expectation, delegated/root grants, and retained unauthenticated deny. A separate table supplies the `getBlockDevices` row. `setLocaltime` remains a pinned-source transcription.

The imported `setBlockDetect` CSV row has nine columns. The columns are `callback_body_call`, `setBlockDetect`, `system`, `/sbin/block detect > /etc/config/fstab`, `usr/share/rpcd/ucode/luci`, `532`, `21`, `532`, and `68`. The consumer verifies the byte-pinned installed-relative source, lock/profile, header, row, cardinality, target identities, and policy context. It updates only the bounded target in the two retained reports. The CSV is not a typed interchange record. The adapter maps it to the existing `handler_effect` / `fact` contract.

## Selected scope, assumptions, and limits

The producer selects a file named `luci`. It selects syntactic containment in a recognized `setBlockDetect: { call: function(...) { ... } }`. It also requires a `BuiltinSystemCall`, exactly one argument, and the exact literal `/sbin/block detect > /etc/config/fstab`. The selected consumer case uses one byte-pinned installed source and one exact observation. This source-syntax observation has `partial` coverage. It does not prove that the callback is registered, invoked, reachable from a request, or executed.

Builtin `system` classification uses a shared syntactic lexical-binding approximation. It excludes imports, formals, and visible declarations named `system`. It does not establish global rebinding, alias semantics, or runtime target identity. Syntactic ancestry can include nested function bodies. It does not prove that a nested function is called or that a callback is registered.

The source call does not establish `intended_access`. The primary mounts grant joins to the independent synthetic mounts expectation (`expectation_id` `luci-mod-system-mounts`). The supplementary root grant joins separately to `root-administration`. These aggregate joins do not transfer the mounts assessment to root callers. Unauthenticated has no grant. The existing `policy:decision:unauthenticated-setBlockDetect-deny` remains intact.

This family excludes other methods, commands, files, and profiles. It excludes arbitrary nonliteral commands and member/receiver/wrapped/aliased callees. It excludes interprocedural flow, CFG/SSA, taint or sanitizer proofs, callback registration, and live uhttpd/rpcd or firmware execution. Exploitability and authorization violations are also outside this family. Do not close broader #64 or producer #54/#55 from this selection. The sibling `setLocaltime` inventory row remains relevant historical coverage. It is not part of this selected family.

## Existing controls and their interpretation

The producer's existing [fixture family](https://github.com/lucas-albers-lz4/codeql-ucode/tree/fbcad5ff8840d83042a4ea2992fbd31c5f94a681/ql/test/effect-controls/setblockdetect) is query input only. No fixture runs as ucode or on a router. The focused smoke extracts fourteen inputs and asserts exactly five locations. Retained local stdout reports those five rows. Pinned producer-main CI reports the same five rows. This evidence defines the query's selection boundary. It does not show general behavior for all `system` calls.

| Class | Existing controls | What the result means |
| --- | --- | --- |
| Real positive | [`ql/test/extractor-smoke/usr/share/rpcd/ucode/luci`](https://github.com/lucas-albers-lz4/codeql-ucode/tree/fbcad5ff8840d83042a4ea2992fbd31c5f94a681/ql/test/extractor-smoke) | One exact installed-relative row at `532:21–532:68`. The multi-file smoke's `modules/real/root/...` path is not directly importable as the installed-relative source. |
| Synthetic positives | `positive`, `positive-renamed-import` | Match rows at `3:5–3:52` and `4:5–4:52`. `import system as other` does not shadow identifier `system`. |
| Syntactic negatives | `negative-method`, `negative-command` | No row for this exact family. A different method or command is not evidence of “no privileged effect” or `no_path`. |
| Lexical exclusions | `negative-import-named`, `negative-import-alias`, `negative-import-default`, `negative-formal-parameter`; `sibling-shadow` lines 5 and 12 | No builtin-classified row. The excluded binding's actual/runtime effect is unresolved, not safe. |
| Unsupported/unknown shapes | `negative-nonliteral`, `negative-member`, `negative-receiver`, `negative-extra-argument` | No table row because these shapes are outside the modeled family. Their meaning remains inconclusive; do not turn absence into `no_path`, harmlessness, or a fabricated observation. |
| Reachability counter-control | `sibling-shadow` | Rows at `8:7–8:54` inside uncalled `sibling()` and `14:5–14:52` demonstrate that an emitted observation does not prove execution. |
| Policy controls | Existing mounts/root grants and unauthenticated deny | Primary/supplementary partition is preserved; there is no unauthenticated grant and the deny remains. Do not transfer the mounts expectation to root callers. |
| Handoff/corruption controls | Existing `policy/tests/test_setblock_bundle.py` and related tests | Missing/failed diagnostics or receipts are errors/inconclusive, not negative observations. Tests reject coherent omission, duplicate/substituted rows, dropped unknowns, forged negative claims and mutation of non-target state. |

Names prefixed `negative-` are fixture labels, not semantic verdicts. A no-match proves only non-selection for the tested exact query conditions. Unresolved calls and unsupported shapes remain unknown; no `no_path`, safe, or negative-effect record is inferred.

## Actual #83 handoff and control results

The retained unique-path run used producer `fbcad5ff8840d83042a4ea2992fbd31c5f94a681` and consumer `d233b0e6615d618d9ddab3b6fa252573cafeaf2f`. It used CodeQL CLI 2.27.4 and LuCI `b2e0be4b46ec0fd43394c081fa7c50657af14011`. The source SHA-256 was `6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e`. The lock-derived corpus was `sha256:b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a`. The profile was `luci-ssl-25.12`.

The fresh database indexed one installed-relative source with no extraction errors. The query emitted the exact row above. The decoded CSV SHA-256 was `9d9a1a7178e7f5fbd3cb772122fe172354004fac09ce00e91647d6b35ba9d0a0`. The effects CSV matched the committed consumer oracle's single observation. Successful-extraction diagnostics named the staged source. The extraction-errors diagnostics had no rows.

The real adapter ran twice. Both retained reports stayed synchronized and byte-identical at three points: before import, after import, and after reimport. The adapter checked the target and policy context. The mounts and root joins were present. Unrelated rows and grants/decisions were preserved. The unauthenticated grant remained absent, and its deny remained. Uncertainty was retained.

The offline checker returned `consistent_offline`, `coverage=partial`, `observation_count=1`, `execution_verified=false`, and `freshness_verified=false`. The checker result is separate from the command ledger. The ledger records actual subprocess execution.

The PR #87 provenance record lists reproducible commands, output artifacts, hashes, and receipts. It reports 51 focused and 832 full consumer tests. It reports 35 producer Python tests and six Rust tests. It also reports the focused CodeQL smoke and the M3 plus 33 M4 aggregate smokes as passed. These are prior recorded executions, not runs from this documentation-only change.

The expected context came from the runner. No independent approval occurred before execution. OS/Python startup, bytecode, and query-cache closure remain incomplete. This is reproducible local execution evidence, not a complete runtime attestation. A separate authorized run is required for independent pre-run approval or execution at the later merge SHA. This report claims neither.

The retained [coverage record](m4-block-device-exec-coverage.json) remains `partial`. It describes the mixed historical slice: getBlockDevices, setBlockDetect, setLocaltime, plus policy facts. This report does not relabel that broader slice as freshly executed or complete. This documentation reconciliation changes no query, model, adapter, schema, grants, decisions, JSON, or producer.

## Still unmodeled in this slice

- `getRealtimeStats` later `flags` reassignment (CFG/SSA)
- Same-function `flags` / `u`/`p` quoting ([m4-realtime-password-quoted-locals.md](m4-realtime-password-quoted-locals.md))
- `setInitAction` → `luci.sys` `init_action` interprocedural dataflow (no M2 grant)
- `getBlockDevices` `readfile` of `/sys/class/block/${dev}/size` (not exec)
