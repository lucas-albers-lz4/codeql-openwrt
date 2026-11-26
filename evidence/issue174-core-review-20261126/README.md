# Bounded core LuCI operation review

This packet connects the previously reviewed [source-first operation map](operation-map.json) to independently retained package and query evidence. Its historical `status`, pending-package statements and expectations describe the time the map was frozen; the observations below supersede those statements without changing the original source-first oracle. LuCI source is `cb87fe60e1e2e052af36a93647f2264577829e0a`. The dependency collection `luci-mod-admin-full` is context, not a fourth module IPK or the provider.

| Package | Bounded observation |
| --- | --- |
| `luci-base` | The IPK contains `usr/share/rpcd/ucode/luci`, SHA-256 `04c9cc966f9cbdd9bea942f55ab139ba11bff78e751ed3ee2e99f52be9c73dbf`; the [retained testing run](../issue174-localtime-ipk-20261126/README.md) extracted that exact member once with zero extraction errors and reported seven tuples below. |
| `luci-mod-network` | The [actual IPK](../issue173-core-packages-20261126/README.md) contains the source-equal ACL declaring read access to `getSwconfigFeatures` and `getSwconfigPortState`; those methods execute `popen` expressions in the shared provider. |
| `luci-mod-system` | Its actual IPK contains the source-equal ACL declaring write access to `setLocaltime` and `setPassword`; the provider contains `system` expressions for date and password operations. |
| `luci-mod-status` | Its actual IPK contains the source-equal ACL declaring read access to `getRealtimeStats`; the provider contains a `popen` for `luci-bwc`. The IPK's `usr/share/ucode/luci/template/admin_status/index.ut` SHA-256 is `652842b1e54f8a2904458ae1f5693ddfc68b97f106d8b8ff48a4d8747d673019`. |

The package receipt includes all four ACLs and exact IPK, source and runner comparisons. Prepared and staged trees were not uploaded; its direct source/IPK comparisons and runner-reported stage comparisons have distinct limits. Package membership does not establish installation or effective ACLs. The independent released [source-corpus run 45765672693](https://github.com/lucas-albers-lz4/codeql-openwrt/actions/runs/45765672693) artifact 15091663969 (ZIP SHA-256 `f08291ae6f855980bb50551c0777dfdd970dd38af4071d6f480135daa4fe9ed6`) extracted source-identical status `index.ut` once as markup with zero errors; this is a separate source-corpus stage, not extraction of the actual IPK member. Markup semantics remain inconclusive. The three package build observations themselves did not run CodeQL.

## Testing query and controls

Producer `a7bf614e2fb59200e303f04b6255af7e6d4007e2` `RequestArgsExec.ql` is a testing query, excluded from the released default suite. The exact results from the separately retained [raw query output](../issue174-localtime-ipk-20261126/raw/retry-output/query.json), with inclusive coordinates, are:

| Method | `request.args` source | Call sink | Message |
| --- | --- | --- | --- |
| `setLocaltime` | 108:22–108:43 | `system` 111:5–111:118 | setLocaltime request.args reaches system |
| `getSwconfigFeatures` | 343:49–343:67 | `popen` 343:16–343:88 | getSwconfigFeatures request.args reaches popen via shellquote |
| `getSwconfigPortState` | 400:49–400:67 | `popen` 400:16–400:88 | getSwconfigPortState request.args reaches popen via shellquote |
| `setPassword` | 470:25–470:45 | `system` 474:13–474:96 | setPassword request.args reaches system via shellquote |
| `setPassword` | 471:25–471:45 | `system` 474:13–474:96 | setPassword request.args reaches system via shellquote |
| `getRealtimeStats` | 575:30–575:48 | `popen` 585:15–585:45 | getRealtimeStats request.args reaches popen via shellquote |
| `getRealtimeStats` | 577:30–577:48 | `popen` 585:15–585:45 | getRealtimeStats request.args reaches popen via shellquote |

The same-handler literal `system('/etc/init.d/sysfixtime restart >/dev/null')` at 112:5–112:55 is the near miss: no request-argument tuple names it. The [source-first expected tuples](setlocaltime-and-request-args-expected.json) predate the observed run. The actual diagnostic, route, entity IDs, exact multiplicity, command provenance, per-phase costs, warnings and stopped attempts are preserved in the linked testing packet. No new extraction or query was run for this review.

## Boundaries and follow-up

The exported `luci` provider and its `request.args` reads are source observations; neither HTTP/rpcd dispatch nor session identity and effective authorization are established. The ACL declarations specify names and read/write groups, not runtime access decisions. The selected methods show no UCI commit; observed expressions are not executed here and do not establish device or service effects. `shellquote` in a query message is a syntactic observation, not a shell-safety conclusion. The bounded model does not establish CFG/SSA flow, runtime callee identity, cross-component behavior, vulnerabilities, or security coverage. The owner of remaining core-operation review is #174; any concrete extractor/model/query miss should be routed to a linked producer issue when demonstrated. No such new miss is asserted here. #174 remains open for its wider acceptance.

Run `python3 -B evidence/issue174-core-review-20261126/verify.py` from the repository root, and the verification commands in the linked package and query packets for their full retained evidence. This small cross-check binds the original source map, frozen oracle, query bytes and complete seven observed tuples; it is not a replay or external artifact authentication.
