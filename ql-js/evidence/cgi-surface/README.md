# CGI construction candidates, issue #69

This slice inventories two bounded syntactic shapes only:

- `L.env.cgi_base + '/cgi-…'`, where the suffix is one string literal matching
  `/cgi-[A-Za-z0-9_-]+`; parentheses and literal property indexes are allowed.
- A template containing a syntactic `L.env.cgi_base` interpolation and a
  template element matching the same suffix pattern. The two elements need only
  co-occur: order, other interpolations and other literal elements are not
  constrained. A row identifies the whole expression and one matching suffix
  token. A template with multiple matching suffix tokens can produce multiple
  rows.

Each row is `rpc_surface` / `candidate` with inclusive UTF-16 source span,
source path, transcribed installed path, syntactic shape and suffix token. A
shadowed `L` remains a candidate. This does **not** assert that the result is a
complete URL, actual request, route, binding, server operation, grant or effect.
Dynamic or split suffixes, aliases, lone CGI strings, standalone `cgi_base`
properties, and other constructions are outside this grammar; they are
unknown, not safe or absent. It is not an inventory of all CGI calls or sites.
There is no taint, policy join, runtime or exploit analysis. CGI rows in the
upstream `fs.js` file are source locations only and do not model the fs API.

## Reproduction

Run the existing extraction gate first, then the runner (all output locations
must be private and trusted; source bytes and database must not be concurrently
changed):

```sh
python3 ql-js/cgi_inventory.py \
  --luci-git /path/to/luci.git --codeql /path/to/codeql \
  --packs /path/to/packs --gate-output /path/to/accepted-output \
  --common-caches /path/to/private-common-cache \
  --output /path/to/new-cgi-output
```

The runner reconstructs the manifest from the pinned tree, validates the
extraction receipt input hashes, checks source hashes before and after query
execution, rechecks absolute file membership and `JSParseError` results, and
retains the raw BQRS, JSON and sorted `inventory.json`. CodeQL query evaluation
can write to a database and caches: use a **private database copy** and private
common cache, rather than a database or cache used by another lane. If copying
an accepted database, its extracted absolute source paths must still identify
the checked source root. Pack lock and version checks are not authentication
of the toolchain or database. TopLevel and JSParseError checks do not cover all
extractor failure modes. Closure and installed paths are transcriptions, not an
OpenWrt build.

Run fixture controls with `JS69_CODEQL`, `JS69_PACKS`, and `JS69_COMMON_CACHE`
set, then `python3 -m unittest discover -s ql-js -p 'test_cgi_surface.py' -v`.
The fixture creates its own database and checks exact spans including shadowed
and bracket bases, form values, reversed/extra-interpolation templates, and
negative comment, string, unrelated, alias, dynamic, split and setup cases.
Without those variables the real-CodeQL fixture test is skipped. Offline CI
uses unittest discovery and does not execute CodeQL fixtures.

## Evidence retained here

`commands.log` records actual runner queries over a **private copy of the
previously created and accepted database**, not a fresh corpus extraction.
The extraction receipt was copied from `evidence/rpc-surface/`; the underlying
corpus extraction command and logs are retained there. The LuCI source pin is
`b2e0be4b46ec0fd43394c081fa7c50657af14011`. The runner independently rebuilt
and matched the 88-file manifest, checked staged bytes around its queries, found
exactly 88 selected file rows and zero `JSParseError` rows, and produced six
construction candidates in three files. The database archive's selected 88
paths and bytes were separately matched against the pinned Git blobs and the
staged source. The retained BQRS files were independently decoded with CodeQL
2.27.4 and matched their retained JSON structurally. The evaluation used
`codeql/javascript-all` 3.0.0; compilation emitted low-heap warnings.

`source-oracle.json` is the six-expression source-first, pin-specific literal
cross-check from the earlier survey, not a parser or general completeness
proof. `test_cgi_surface.py` compares it with the normalized rows. The fixture
is separate from that corpus oracle. `cgi-concat-only.log` and
`cgi-overbroad.log` record two intentional fixture test failures: removing the
template arm missed three fixture sites, while permitting an empty suffix
added the split-suffix case. Both failed the exact-row assertion, not setup.
Those runs predate the additional retained-evidence offline test and each ran
two tests. The independent CGI fixture is extracted afresh; it is not a fresh
extraction of the 88-file corpus. All evidence assumes trusted local inputs.
