# Extraction evidence, 2026-11-19

The candidate used OpenWrt base `a657c8abe86d8e6337db623335c28e82246c3e09`
and LuCI commit `b2e0be4b46ec0fd43394c081fa7c50657af14011`.
`accepted/ACCEPTED.json` binds the gate, queries, manifest, pack declarations,
and corpus inputs by SHA-256. `accepted/toolchain.txt` records CLI 2.27.4 and
resolved `codeql/javascript-all` 3.0.0. These are version observations, not
cryptographic authentication of the toolchain or dependencies.

The evidence was generated before the commit using the commands in the
parent README with `/root/workspace/luci-fork` as the Git object database,
`/root/.local/share/gh/extensions/gh-codeql/dist/release/v2.27.4/codeql`
as the CLI, and
`/root/.hermes/profiles/work/cache/scratch/js69-probe/packs` as the pack root.
Each `commands.log` contains the actual CodeQL commands and the minified-file
setting. Paths in logs and decoded output refer to the producing machine.
The database and staged blobs are reproducible from the pinned Git objects but
are not checked in. Raw BQRS and decoded JSON are retained here.

- `accepted`: 88 exact staged absolute paths; 0 JSParseError rows.
- `default-minified`: 87 paths; `uqr.js` missing, so the production comparison
  rejected it. The control uses the same selected original bytes.
- `malformed`: `good.js` contains `const good = 1;` and `broken.js` contains
  `const broken = ;`, both followed by a newline. Real extraction yielded two
  paths and one JSParseError for `broken.js`; acceptance rejected it.
- `identity-controls.txt`: the public gate rejected both a deleted manifest row
  and a changed digest before creating an output directory. The original
  manifest was restored. The real control also changed staged file bytes and
  the source identity check rejected the change.

Offline test-strength controls are reproducible without modifying the production
file: run `python3 ql-js/evidence/offline_mutation_controls.py` and repeat with
`python3 -O`. Each uses an in-memory replacement of the path multiset comparison.
The count-only mutant produces three expected assertion failures (same-count
duplicate, foreign path, and foreign same-basename path), and the set-only
mutant produces one expected duplicate-row subtest failure. There are no setup
errors. Afterward, ordinary offline discovery passes all eight tests in each
interpreter mode. These synthetic unit controls are not new CodeQL extraction
runs; the real extraction evidence above is historical and unchanged.

The queries and their limitations are described in the parent README. This is
not a site inventory, an all-diagnostics extraction guarantee, or a runtime or
security result.
