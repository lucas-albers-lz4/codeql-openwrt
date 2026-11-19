# Issue #69 inventory bridge

## Scope

This report joins the shipped manifest, extraction record, and three source-site inventories for #69. It does not report a new extraction.

The retained artifacts come from separate runs. The RPC evidence records an OpenWrt base at `4de68a67efa6a9939cc7da0bffd65b94dedbd327`. The filesystem evidence records an OpenWrt base at `23ae5aec9846ab5a4846579df70d2a65ce8b11b8`.

Both runs use LuCI commit `b2e0be4b46ec0fd43394c081fa7c50657af14011`, as pinned in [`corpus/lock.json`](../corpus/lock.json). The inventory artifacts and their run records are retained under [`ql-js/evidence/`](../ql-js/evidence/).

## Pinned selection and digests

The [manifest](../ql-js/manifest.json) contains 88 JavaScript paths from ten packages. Its SHA-256 is `3161274241e086d121fd5122e0dfe0c5fb5d97872710d79c87f86244be2b2627`.

The [source lock](../corpus/lock.json) SHA-256 is `b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a`. It pins the LuCI source commit stated above.

The [CodeQL pack lock](../ql-js/codeql-pack.lock.yml) SHA-256 is `eb487627c92c867a5760b9c24405db13d028eff5582378a9c4ff252debe13925`. This digest also appears in both accepted input records.

Each manifest row records the package, original source path, installed path, Git blob ID, file mode, and source-byte SHA-256. The source paths are relative to the LuCI repository. The installed paths start at `/www/luci-static/resources/`.

For example, `modules/luci-base/htdocs/luci-static/resources/rpc.js` maps to `/www/luci-static/resources/rpc.js`. The [manifest](../ql-js/manifest.json) contains all 88 individual mappings. It has 88 distinct installed paths.

The package closure and package-to-Makefile mapping are transcribed inputs. This report does not use an OpenWrt image build to verify these inputs. The mapping uses the existing `luci.mk` htdocs rule. This report does not prove build or install behavior.

## Retained extraction evidence

The retained extraction gate accepted all 88 selected paths and recorded zero `JSParseError` rows. The [accepted record](../ql-js/evidence/accepted/ACCEPTED.json) and [extraction notes](../ql-js/evidence/README.md) retain this result.

The gate scope is exact path membership and `JSParseError` rows only. This report does not claim that the extractor has no other diagnostics or failure modes.

The RPC and filesystem site runs use separate databases and separate source roots. Their evidence READMEs and command logs identify each run. A second inventory query on the same database is not a new extraction.

The CGI slice uses a private copy of the previously accepted database. It does not use a fresh corpus extraction. Its receipt records the same LuCI pin and 88 selected files. It records `TopLevel` membership and `JSParseError` scope. The CGI runner checked source bytes before and after the query. See the [CGI receipt](../ql-js/evidence/cgi-surface/ACCEPTED.json) and [run notes](../ql-js/evidence/cgi-surface/README.md).

The accepted records give matching input digests for the manifest and lock. See [RPC acceptance](../ql-js/evidence/rpc-surface/ACCEPTED.json) and [filesystem acceptance](../ql-js/evidence/fs-surface/ACCEPTED.json).

## Separate candidate inventories

| Family | Retained result | Evidence SHA-256 | Meaning |
|---|---|---|---|
| `rpc.declare` | 98 syntactic property-access candidates in 40 selected files | `30d42dca49978cc400e49345516324a30a0c7bfeb42eacf1c62fcdd1d9afda61` | All rows are dot accesses. Rows are candidates, not proven calls or resolved bindings. |
| `fs` | 102 syntactic property-access candidates in 27 selected files | `d7acf028aa478ed22ff6b1a3e6e938fc1afb927830b629012aae3affbd5517ff` | All rows are dot accesses. Rows are candidates, not proven calls or resolved bindings. |
| CGI construction | 6 syntactic construction candidates in 3 selected files | `8af4c02d36cd81f17a771c1082706ac19d151a6ce9e357913ed25a6d94519727` | Two bounded shapes only. Rows do not prove requests, routes, bindings, server operations, grants, or effects. |

The RPC [inventory](../ql-js/evidence/rpc-surface/inventory.json) and [run notes](../ql-js/evidence/rpc-surface/README.md) retain spans and limitations. The filesystem [inventory](../ql-js/evidence/fs-surface/inventory.json) and [run notes](../ql-js/evidence/fs-surface/README.md) do the same.

The CGI [inventory](../ql-js/evidence/cgi-surface/inventory.json) and [run notes](../ql-js/evidence/cgi-surface/README.md) retain the six candidate rows and query limits. The rows cover four `base-plus-string` expressions and two `template-base-and-suffix` expressions. They occur in `fs.js`, `ui.js`, and `view/system/flash.js` under the pinned LuCI source tree. The source-first oracle is a pin-specific cross-check, not a parser or completeness proof.

The RPC query only detects syntactic accesses through the identifier `rpc`. The filesystem query only detects syntactic accesses through the identifier `fs`. Shadowed names, property reads, unresolved computed keys, aliases, indirect references, and generated references do not establish runtime behavior. Aliases and indirect references remain unresolved.

The filesystem inventory JSON currently labels each row with `type: rpc_surface`. The file, query, and evidence README identify the inventory as filesystem access candidates. This field label does not establish an RPC result.

## Open boundaries

- Pull request [#126](https://github.com/lucas-albers-lz4/codeql-openwrt/pull/126) merged this bounded CGI syntax slice as `84e2006ecde13c091d24882ad2fe926c89fbd2fd`. It records six candidates in three files. It does not cover all CGI constructions or establish request behavior, bindings, server operations, grants, or effects.
- UCI inventory remains held. Its prior approval was withdrawn. This report does not change that decision.
- The candidate counts do not prove complete source coverage, semantic bindings, runtime calls, effects, taint, grants, or exploitability.
- The extraction result covers the selected paths and recorded `JSParseError` rows. It does not establish semantic correctness or all possible extraction failures.
- The manifest and package closure do not establish an OpenWrt image build or actual installed files.
- The roadmap work tracked by pull request [#122](https://github.com/lucas-albers-lz4/codeql-openwrt/pull/122) is separate from this report.

This report bridges retained evidence. It does not implement UCI inventory, promote Track A, or change issue status.
