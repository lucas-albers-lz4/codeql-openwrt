# Pinned LuCI JavaScript extraction check

This is the first bounded slice of #69, **not** the JavaScript surface
inventory. The manifest records original Git blob IDs and SHA-256 hashes for
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

## Limits

The check establishes membership according to `TopLevel.getFile()` and absence
of rows from `JSParseError` for this staged selection, not that every possible
extractor diagnostic, semantic construct, or extraction failure is covered.
CodeQL has its own extern files; matching uses absolute `.js` paths under the
staged root and rejects unexpected query paths rather than claiming coverage of
externs. The manifest
is a source-file selection, not evidence of an actual image or package build.
It does not inventory rpc/fs/uci/cgi sites, computed references or unresolved
calls, and says nothing about taint, grants, runtime behavior or exploitability.
Track A and other deferred tracks remain held.
