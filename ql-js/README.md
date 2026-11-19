# Pinned LuCI JavaScript extraction and source-site inventories

The first bounded slice of #69 was the extraction gate. The site inventories
cover syntactic `rpc.declare` and `fs` accesses described below, not all JavaScript
surfaces. The manifest records original Git blob IDs and SHA-256 hashes for
`htdocs/**/*.js` in the existing `luci-ssl-25.12` LuCI package closure at
`corpus/lock.json`'s LuCI pin. Installed paths follow the existing `luci.mk`
htdocs mapping. The closure and package-to-Makefile mapping come from
`corpus/luci_ssl_files.py`; this check does not independently derive OpenWrt
Make dependency or build/install semantics.

## Run

Prerequisites: Python 3, Git, CodeQL CLI **2.27.4**, and an additional-packs
root resolving `codeql/javascript-all` **3.0.0** and its locked dependencies.
The LuCI Git object database must contain the pinned commit and its blobs; a
clean checkout is not needed. Use trusted CodeQL binaries and packs. The
version checks and pack lock are not a cryptographic verification of the CLI
or pack contents.

```sh
python3 ql-js/extraction_gate.py \
  --luci-git /path/to/luci.git \
  --codeql /path/to/codeql \
  --packs /path/to/additional-packs \
  --output /path/to/new-evidence-directory
```

The output directory must not already exist. The gate reconstructs the manifest
from the pinned tree and compares every field and row in order, stages original
blob bytes, checks the exact staged set and hashes before and after extraction,
and creates a new JavaScript database with
`CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES=true`. It decodes the two
queries and checks the exact `TopLevel` path multiset and zero `JSParseError`
rows. Any command failure, missing or malformed result, changed identity,
missing or extra path, duplicate path, or reported parse error rejects. Only a
successful run writes `ACCEPTED.json`. Output includes the staged bytes,
database, CLI and resolved pack details, command/extraction log, BQRS and JSON.
Do not treat an existing output directory or extractor completion messages as a
new acceptance. Use a trusted, non-concurrently-modified workspace and packs.

For the real negative controls, supply the successful run's directory and a new
output directory:

```sh
python3 ql-js/real_controls.py \
  --codeql /path/to/codeql --packs /path/to/additional-packs \
  --gate-output /path/to/new-evidence-directory \
  --output /path/to/new-control-directory
```

The controls require default extraction to omit the known minified `uqr.js`,
require a real `JSParseError` from a malformed file paired with a valid file,
and reject changed staged bytes. They use the production result checks; the
control output retains the raw query results and extraction logs.

Fast offline checks: `python3 -m unittest discover -s ql-js -p 'test_*.py' -v`.
CI runs these offline checks, not the real CodeQL gate or controls.

## rpc.declare access candidates

Run the extraction gate first, then use its newly accepted output:

```sh
python3 ql-js/rpc_inventory.py \
  --luci-git /path/to/luci.git --codeql /path/to/codeql \
  --packs /path/to/additional-packs --gate-output /path/to/new-evidence-directory \
  --output /path/to/new-site-evidence-directory
```

The runner reconstructs the pinned manifest, checks the acceptance input hashes,
checks staged bytes before and after the queries, and reruns the file and parse
error queries against that database. It writes raw BQRS and decoded JSON and a
sorted `inventory.json`; its output directory must not exist. Use a trusted,
non-concurrently-modified database and toolchain. A receipt alone does not
cryptographically authenticate the database or CLI.

The query selects property accesses with the syntactic receiver identifier
`rpc`: `rpc.declare`, `rpc['declare']`, and `rpc[expression]` when the property
name cannot be determined. It records the inclusive source span of the property
access, not the enclosing call. Every row is `rpc_surface` / `candidate`: a
shadowed `rpc`, a property read rather than a call, or an unresolved computed
key is not proof of an RPC declaration or runtime target. Aliased receivers,
other API families (`fs`, `uci`, CGI), and indirect or generated references are
not inventoried. No absence of those sites is implied.

The real-CodeQL fixture test checks exact positive and negative source spans,
including a shadowed receiver, computed key, literal bracket access, property
read, comments, strings, and unrelated names. To run it, set `JS69_CODEQL` and
`JS69_PACKS` to the paths above and run the offline discovery command. Without
these variables this one test is skipped; CI does not run real CodeQL.
Retained results and the exact run limits are in `evidence/rpc-surface/`.

## fs access candidates

After running the extraction gate, run:

```sh
python3 ql-js/fs_inventory.py \
  --luci-git /path/to/luci.git --codeql /path/to/codeql \
  --packs /path/to/additional-packs --gate-output /path/to/new-evidence-directory \
  --output /path/to/new-fs-site-evidence-directory
```

This independently reconstructs the manifest, rechecks the acceptance inputs,
selected bytes, exact file membership and `JSParseError` rows, and retains raw
and decoded results. The new output path must not exist. It selects property
accesses whose syntactic receiver is the identifier `fs`: dot accesses, literal
indices, and unresolved computed indices. The property is reported as returned
by CodeQL, or `<unknown>` for an unresolved index. The `kind` distinguishes an
actual literal `<unknown>` from that placeholder. Every row is `rpc_surface` /
`candidate`, including property reads and shadowed receivers; no binding or
runtime call is proven. Aliases, indirect accesses and other families are outside
this query. The fixture covers positive, negative, shadowed and computed sites,
including a numeric index. See `evidence/fs-surface/` for real execution and
mutation controls. CI runs offline checks only, not real CodeQL fixture tests.

## Limits

The check establishes membership according to `TopLevel.getFile()` and absence
of rows from `JSParseError` for this staged selection, not that every possible
extractor diagnostic, semantic construct, or extraction failure is covered.
CodeQL has its own extern files; matching uses absolute `.js` paths under the
staged root and rejects unexpected query paths rather than claiming coverage of
externs. The manifest
is a source-file selection, not evidence of an actual image or package build.
It does not inventory all rpc or fs references, or uci/cgi sites, and says
nothing about taint, grants, runtime behavior or exploitability.
Track A and other deferred tracks remain held.
