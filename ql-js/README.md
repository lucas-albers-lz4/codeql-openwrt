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
queries. It compares the exact selected set of `TopLevel` paths; the query uses distinct paths and does not establish entity multiplicity. The gate requires zero
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

## UCI access candidates

`uci_surface.ql` selects nonoptional property accesses whose immediate receiver,
after stripping parentheses, is the bare identifier `uci` or exactly the
nonoptional dot member `L.uci` with bare `L`. It retains property reads and
shadowed identifiers as syntactic candidates. The optional member itself is
excluded; a nonoptional member followed by an optional call remains. Other
receivers, aliases, deeper receivers and private dot properties are excluded.
Results contain the database-local access identity, source path and inclusive
span, receiver form, `dot` or `computed-index` kind, property-known flag,
property string and `candidate` assessment. Distinct entities at one span
remain distinct; comparison uses full tuple multiplicities.

Computed accesses are retained even when their key is unknown. The currently
known subset is raw single- or double-quoted strings of at most 128 characters
from `[A-Za-z0-9_$#<>. -]`, unescaped no-substitution templates of at most 128 characters in the same
alphabet, decimal integers from `0` through nine digits without leading zeros,
the same decimal literal with one direct unary plus or minus (negative zero
becomes `0`), decimal bigints of up to 128 digits without leading zeros, and
`true`, `false` or `null`. Whole-expression parentheses are allowed. Other
forms, including escapes, substitutions, radix and separator numbers,
fractions, concatenations and variables, remain unknown. A known literal
`'<unknown>'` and an unresolved key share text but have different known flags.

The two source-first fixture files and their full expected rows are in
`tests/uci-fixture/`. The offline test verifies their pinned bytes and row
schema. To explicitly run the real fixture test with an already installed
CodeQL 2.27.4 and `codeql/javascript-all` 3.0.0 plus all 12 locked transitive
packs, use physical absolute paths from the repository root:

```sh
UCI_CODEQL=/absolute/path/to/codeql UCI_PACKS=/absolute/path/to/packs \
  PYTHONPATH=ql-js python3 -m unittest test_uci_fixture -v
```

This example creates a fresh temporary database and private caches, permits
minified files, checks the selected path set and zero `JSParseError` rows, and
compares the complete candidate multiset. It is a new test invocation, not the
retained fixture evidence; it does not download prerequisites. Without both
environment variables the real fixture test is skipped explicitly. Query and
fixture mutation controls require their separately reviewed execution setup.

[The owner decision](https://github.com/lucas-albers-lz4/codeql-openwrt/issues/69#issuecomment-7118342035) resumed the bounded UCI work; Track A remains deferred.

`uci_run.py` is an experimental corpus runner, not a self-authorizing workflow.
It requires a separately reviewed compatible isolation wrapper, an initialized
private attempt with an empty 0600 `wrapper.log`, a fresh `output` path, the
pinned LuCI Git objects, the pinned source multiset, and an independently
reviewed pin file and SHA-256. That file binds the exact wrapper and input
bytes, pack-file inventory and per-query resolver stdout for the specific
attempt path. Run `python3 ql-js/uci_run.py --help` to see the required `--wrapper`,
`--wrapper-log`, `--packs`, `--luci-git`, `--oracle`, `--output`, `--pins` and
`--pins-sha256` arguments. The output must be `<attempt>/output`, with the
initialized mode-0600 log at `<attempt>/wrapper.log`. The runner uses one
thread and 2048 MB. It stages the 88-file manifest and checks source bytes
around extraction and querying. It creates one database, runs the file and
parse-error checks twice on that database before the surface query, and
compares the full result against the source multiset. It retains command and
wrapper logs, decoded and raw query outputs, candidate rows and a successful
receipt with declared evidence hashes. Failures do not produce an acceptance
receipt. Wrapper support
for the exact command and output layout must be verified before use; no
reviewed pins are supplied by this description. The retained
[bounded corpus observation](evidence/uci-corpus/README.md) records 576 exact
source-site tuples across the selected 88-path extraction, with its evidence
and limits; it does not establish runtime or security coverage.

This is a bounded source-site inventory. It does not resolve UCI bindings,
prove calls or runtime behavior, establish authorization or security coverage,
or show that the selected files were built or installed. A hash binds bytes to
an independently selected input; it does not authenticate their origin.

## Limits

For this staged selection, the gate establishes membership according to
`TopLevel.getFile()`. The gate requires zero rows from the `JSParseError` query.
The gate does not cover every extractor diagnostic, semantic construct, or
extraction failure.

CodeQL has its own extern files. Matching uses absolute `.js` paths under the
staged root. The gate rejects unexpected query paths. This README does not claim
coverage of externs. The manifest is a source-file selection, not evidence of an
actual image or package build.

These inventories do not cover all RPC, filesystem, UCI or CGI sites. The bounded CGI slice records six syntactic construction candidates
in three files. The retained rows and limits are in [the CGI evidence](evidence/cgi-surface/README.md)
and [the issue #69 inventory bridge](../docs/issue-69-inventory-bridge.md).
These candidates do not establish requests,
routes, bindings, server operations, grants, or effects. This README says
nothing about taint, runtime behavior, or exploitability.

Track A and other deferred tracks remain held.
