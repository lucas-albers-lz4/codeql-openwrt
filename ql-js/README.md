# Pinned LuCI JavaScript extraction and source-site inventories

The first bounded slice of #69 was the extraction gate. The site inventories
cover syntactic `rpc.declare` and `fs` accesses described below. A separate,
bounded CGI slice records six syntactic construction candidates in three files.
These inventories do not cover all JavaScript surfaces.

The manifest covers `htdocs/**/*.js` in the existing `luci-ssl-25.12` LuCI
package closure. It records original Git blob IDs and SHA-256 hashes. The closure
uses the LuCI pin in `corpus/lock.json`. Installed paths follow the existing
`luci.mk` htdocs mapping. The closure and package-to-Makefile mapping come from
`corpus/luci_ssl_files.py`. The extraction gate does not independently derive OpenWrt
Make dependency or build/install semantics.

## Run

The prerequisites are Python 3, Git, CodeQL CLI **2.27.4**, and an
additional-packs root. The root must resolve `codeql/javascript-all` **3.0.0**
and its locked dependencies. The LuCI Git object database must contain the
pinned commit and its blobs. The gate does not require a clean checkout.

Use trusted CodeQL binaries and packs.

The version checks and pack lock do not cryptographically authenticate the CLI
or pack contents.

```sh
python3 ql-js/extraction_gate.py \
  --luci-git /path/to/luci.git \
  --codeql /path/to/codeql \
  --packs /path/to/additional-packs \
  --output /path/to/new-evidence-directory
```

The output directory must not already exist. The gate reconstructs the manifest
from the pinned tree. It compares every field and row in order. It
stages the original blob bytes. It compares the exact staged set and hashes
before and after extraction.

The gate creates a new JavaScript database with
`CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES=true`. It decodes the two
queries. It compares the exact `TopLevel` path multiset. The gate requires zero
rows from the `JSParseError` query. The gate rejects a run if a command fails,
a result is missing or malformed, or an identity changes. It also rejects a run if a path
is missing or extra, a path is duplicated, or a parse error appears.

Only a successful run writes `ACCEPTED.json`. Output includes the staged bytes,
database, CLI and resolved pack details, command/extraction log, BQRS and JSON.

If the output directory already exists, do not use it for a new acceptance. Do
not treat extractor completion messages as a new acceptance. Use a trusted
workspace and packs. Do not let another process modify them while the gate runs.

For the real negative controls, supply the directory from the successful run
and a new output directory:

```sh
python3 ql-js/real_controls.py \
  --codeql /path/to/codeql --packs /path/to/additional-packs \
  --gate-output /path/to/new-evidence-directory \
  --output /path/to/new-control-directory
```

The controls require default extraction to omit the known minified `uqr.js`.
They require a real `JSParseError` from a malformed file paired with a valid
file. They reject changed staged bytes. They use the production result checks.
The control output retains the raw query results and extraction logs.

Run the offline tests with `python3 -m unittest discover -s ql-js -p 'test_*.py' -v`.

CI runs these offline tests, not the real CodeQL gate or controls.

## rpc.declare access candidates

After the extraction gate succeeds, use its accepted output for this query:

```sh
python3 ql-js/rpc_inventory.py \
  --luci-git /path/to/luci.git --codeql /path/to/codeql \
  --packs /path/to/additional-packs --gate-output /path/to/new-evidence-directory \
  --output /path/to/new-site-evidence-directory
```

The runner reconstructs the pinned manifest and compares the acceptance input
hashes. It compares staged bytes before and after the queries. It reruns the
file and parse-error queries against that database. It writes raw BQRS and
decoded JSON and a sorted `inventory.json`. The output directory must not exist.

Use a trusted database and toolchain. Do not let another process modify them
while the runner runs.

A receipt alone does not cryptographically authenticate the database or CLI.

The query selects property accesses with the syntactic receiver identifier
`rpc`: `rpc.declare`, `rpc['declare']`, and `rpc[expression]` when the property
name cannot be determined. It records the inclusive source span of the property
access, not the enclosing call. Every row is `rpc_surface` / `candidate`.

A shadowed `rpc` does not prove an RPC declaration or runtime target. A property
read does not prove an RPC declaration or runtime target. An unresolved computed
key does not prove an RPC declaration or runtime target. This query does not
inventory aliased receivers, other API families (`fs`, `uci`, CGI), or indirect
or generated references. It does not imply that those sites are absent.

The real-CodeQL fixture test compares exact positive and negative source spans.
The spans include a shadowed receiver, computed key, literal bracket access,
property read, comments, strings, and unrelated names. Retained results and the
exact run limits are in `evidence/rpc-surface/`.

If you want to run this fixture test, set `JS69_CODEQL` and `JS69_PACKS` to the
paths above. Then run the offline discovery command.

The offline test run skips this test if these variables are not set. CI does not run real
CodeQL.

## fs access candidates

After the extraction gate succeeds, run:

```sh
python3 ql-js/fs_inventory.py \
  --luci-git /path/to/luci.git --codeql /path/to/codeql \
  --packs /path/to/additional-packs --gate-output /path/to/new-evidence-directory \
  --output /path/to/new-fs-site-evidence-directory
```

The runner independently reconstructs the manifest. It compares the acceptance
inputs, selected bytes, exact file membership, and `JSParseError` rows. It
retains raw and decoded results. The new output path must not exist.

The query selects property accesses whose syntactic receiver is the identifier
`fs`. These include dot accesses, literal indices, and unresolved computed
indices. CodeQL returns the property name, or `<unknown>` for an unresolved
index. The `kind` field distinguishes a literal `<unknown>` from this
placeholder. Every row is `rpc_surface` / `candidate`, including property reads
and shadowed receivers.

These rows do not prove bindings or runtime calls. Aliases, indirect accesses,
and other families are outside this query.

The fixture covers positive, negative, shadowed, and computed sites, including
a numeric index. Real execution and mutation controls are in
`evidence/fs-surface/`. CI runs offline checks only. It does not run real
CodeQL fixture tests.

## Limits

For this staged selection, the gate establishes membership according to
`TopLevel.getFile()`. The gate requires zero rows from the `JSParseError` query.
The gate does not cover every extractor diagnostic, semantic construct, or
extraction failure.

CodeQL has its own extern files. Matching uses absolute `.js` paths under the
staged root. The gate rejects unexpected query paths. This README does not claim
coverage of externs. The manifest is a source-file selection, not evidence of an
actual image or package build.

These inventories do not cover all RPC or filesystem references, or all UCI or
CGI sites. The bounded CGI slice records six syntactic construction candidates
in three files. The retained rows and limits are in [the CGI evidence](evidence/cgi-surface/README.md)
and [the issue #69 inventory bridge](../docs/issue-69-inventory-bridge.md).
These candidates do not establish requests,
routes, bindings, server operations, grants, or effects. This README says
nothing about taint, runtime behavior, or exploitability.

UCI inventory remains held. Track A and other deferred tracks remain held.
