# M4 menu-route declaration provenance — local discovery milestone

## Named evidence need

`M4:menu-route-declaration-provenance`: supply the pinned `menu.d` source
universe omitted by `reports/m4-luci-ssl-files.md:59`, retaining each declaration's
source identity before any dispatcher tree, policy or handler interpretation.
This answers which JSON declarations are present in the existing reviewed
LuCI-only `luci-ssl-25.12` package closure and where each comes from. It is an
independent source-discovery deliverable for OpenWrt #70, not a claim that an
M4 taint query is blocked or that dispatcher implementation has been promoted.

This local work follows the caller's express source-only discovery scope. The
live #70 and the dispatcher implementation in ucode #58 remain deferred; they
were not edited by this discovery task. A concurrent owner-side update to #58
names ucode #129, a separate plain-`dispatcher.uc` source-shape inventory. That
inventory is complementary, not a prerequisite for collecting menu JSON, and
this work does not satisfy its report-decision or source-site acceptance tests.
No grants, policy expectations, effect catalogs, finding schemas or extraction
settings change. This document is not a replacement policy contract or an issue
closure.

## Pins and source evidence

- Consumer base: `lucas-albers-lz4/codeql-openwrt`
  `6c24543eddc81f97ad1ece655e96cd96b0160675`, copied from its GitHub archive.
  Collector, corpus, tests and this report are uncommitted additions, not code
  executed from that base commit. The report fingerprints the collector and
  existing package-scope module actually consumed.
- LuCI lock pin: `b2e0be4b46ec0fd43394c081fa7c50657af14011`.
- LuCI tree: `34b39b1f15d8a68898d84cab7f48e87f1ba80ac6`.
- Profile: `luci-ssl-25.12`; context uses the SHA-256 of actual `corpus/lock.json`.
- `corpus/luci_ssl_files.py` supplies the existing static LuCI-only package
  closure and Makefile paths. This is not a general Make dependency resolver.
- [luci.mk at the pin](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/luci.mk)
  copies package `root/*` to `/`; this source mapping is not an observed install.
- [dispatcher.uc at the pin](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-base/ucode/dispatcher.uc#L346-L432)
  names `/usr/share/luci/menu.d/*.json`. It also loads Lua controllers and builds
  a runtime tree; this collector does neither.
- [luci-base.json](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-base/root/usr/share/luci/menu.d/luci-base.json)
  supplies the `admin` auth declaration and the distinct `admin/ubus/*` empty
  auth object. Both are retained literally, not resolved into effective auth.
- [controller/admin/index.uc](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-base/ucode/controller/admin/index.uc)
  is provenance for later handler assessment only. This work does not analyze
  its HTTP values, sentinel SID handling or session checks.

`reports/m4-menu-route-provenance.json` records Git blob IDs, SHA-256, source
sizes, installed-path mappings, source tree, package scope including packages
without menu files, and the hashes of relevant pinned source evidence. Every
row retains its literal route key, JSON pointer, full spec and source blob.
`corpus/menu-route-sources/` mirrors the six exact upstream JSON blobs under
source-relative paths. Upstream contents and notices are unchanged.

## Observed corpus

| Package | JSON files | Declarations |
| --- | ---: | ---: |
| luci-app-firewall | 1 | 7 |
| luci-app-package-manager | 1 | 1 |
| luci-base | 1 | 15 |
| luci-mod-network | 1 | 8 |
| luci-mod-status | 1 | 16 |
| luci-mod-system | 1 | 13 |
| **Total** | **6** | **60** |

The selected pin has 60 distinct literal route keys and no cross-file repeated
literal keys. This does not exclude equivalent runtime paths or interactions
with Lua, installed overrides, package patches or caches. The two-file/same-route
control is synthetic, not an observed pinned collision.

## Reproduction and tests

From this local source tree, with a Git object store containing the LuCI pin:

```sh
python3 -B -m corpus.menu_routes --luci-git /path/to/luci > inventory.json
MENU_LUCI_GIT=/path/to/luci python3 -B -m unittest policy.tests.test_menu_routes -v
python3 -B -m unittest discover -s policy/tests -t . -v
```

The collector reads committed objects, not worktree contents or current HEAD;
it emits UTF-8 JSON on stdout and does not write policy or reports itself. The
caller chooses the output file. Sorting by source and literal route is only a
deterministic presentation order, never runtime load/merge order.

The normal policy gate uses `menu-route-expected-v1.json` for file/route
multiplicity and `menu-route-pinned-v1.json` for pinned file identities, context,
package scope, source evidence and limitations. The latter was transcribed from
this retained report after an independent reviewer checked the report and all six
blobs and 17 evidence identities against the pinned Git tree; it is not a second
independent enumeration or an attestation. These fixtures are trusted inputs;
the new fixture and subsequent changes require independent review. The offline
check reconciles each copied blob and full declaration spec against those
identities, validates context, derived counts and duplicates, and requires all
named limitations. The optional
Git/API/CLI check compares actual collector stdout byte-for-byte with the retained
report and each copied JSON with its pinned blob; without `MENU_LUCI_GIT` those
Git-specific tests are explicitly skipped, not credited as live Git verification.
The original file/route list was prepared by the discovery agent.

Minimal controls:

1. Two JSON documents contribute the same literal route: retain two rows and
   two sources, without selecting a winner or merging specs.
2. Parent auth, child `"auth": {}`, and absent child auth remain distinct raw
   specs; no inherited/effective auth field is synthesized.
3. Preserve literal wildcard keys and JSON-pointer escaping; retain additional
   spec fields without interpreting them.
4. Reject duplicate JSON names at every depth, non-JSON constants, malformed
   UTF-8/JSON, non-object documents and non-object declarations. This defines the
   inventory's supported input, not LuCI's runtime error behavior.
5. Reject a changed profile or LuCI pin before reading source objects.
6. Reconcile the actual pinned Git collector and CLI with the retained corpus.

## Local verification outcome

The initial source-only candidate was independently reviewed. Its retained
report and source bytes matched the pin, but the reviewer showed a coordinated
source/spec/hash mutation and false metadata passed the existing gate. The
remediation adds the pinned fixture and retained-report integration checks above;
it requires a new independent review before publication.

The remediated isolated candidate passed 932 policy tests normally and under
`-O` with the pinned Git store available. The eight focused tests passed both
ways; with no Git store, two Git-specific focused tests were explicitly skipped.
Negative controls modify disposable copies, not upstream files. They cover a
coherent source/spec/blob/digest mutation, a coherent omission with the old
route list edited, pin/profile/tree/lock, package and source evidence, counts,
duplicates and missing limitations. Removing the offline pin guard makes the
coherent mutation and omission controls fail; removing the Git byte-comparison
guard makes its byte-only control fail. These tests establish source annotation
fidelity, not effective authentication. Hashes and fixtures are not runtime or
build attestation.

There were no commits, pushes or GitHub writes from this task.

## Unassessed semantics and real dependencies

This source-only milestone needs **no** CodeQL database, markup extraction,
ucode guard model, live router, policy grant or heavy-run approval. It does need
the pinned Git objects and the existing reviewed package-scope definition.

It is not dispatcher coverage. Remaining separately scoped work includes:

- Runtime file enumeration/order, tree merge precedence, wildcard/base action
  behavior, parent/child auth semantics, dependency checks and index caches.
- Installed package availability/configuration and the active HTTP entrypoint.
  `uhttpd.uc` remains markup; this work adds no markup AST/CFG extraction.
- Lua controller semantics (`lua_not_analyzed`) and resolution/invocation of
  declared action modules. A declaration does not establish a reachable handler.
- For ucode #58: approved HTTP source models and value/result-sensitive guard
  modeling, with denied/missing/error result controls. These are not satisfied by
  retaining JSON auth fields or observing a `session.access` call in source.
- Sentinel SID rewriting and the handler's session gate; empty dispatcher auth
  is not evidence of a handler bypass. `no_ubusauth` is a separate HTTP `/ubus`
  profile behavior and supplies no conclusion about `admin/ubus/*` here.
- Any future assessed policy/effect join needs a separately approved contract,
  caller context, independent expectations and appropriate execution evidence.

No taint, authorization, bypass, safety or security finding is emitted. No
`path_found`, policy grant or handler effect is manufactured. Hashes establish
source consistency, not source-to-runtime or build attestation. Completing this
corpus does not complete #70 or #58.
