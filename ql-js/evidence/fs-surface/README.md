# fs property-access candidate inventory evidence

- OpenWrt base: `23ae5aec9846ab5a4846579df70d2a65ce8b11b8`.
- LuCI pin: `b2e0be4b46ec0fd43394c081fa7c50657af14011`.
- CodeQL CLI: 2.27.4; `codeql/javascript-all`: 3.0.0; see `toolchain.txt`.
- A fresh extraction accepted 88 exact selected paths with zero `JSParseError`
  rows. The site runner reran the file and error queries on that database and
  verified staged source hashes before and after. This does not establish the
  absence of other extractor failures; see the parent README.
- `inventory.json` contains 102 candidate property accesses in 27 selected
  files, all dot accesses. This is not a count of proven calls or resolved
  targets. The fixture exercises literal and unresolved indices separately.
- The producing source root was `/root/workspace/js69-fs-extraction-20261119/source`.
  Paths in decoded output and logs refer to that machine. The source and database
  are not committed. The extraction and inventory commands are retained; the
  inventory BQRS and decoded output for all three queries are included. A repeat
  inventory run against the same database returned byte-identical `inventory.json`;
  it was not a second extraction.
- The selected paths and staged bytes were independently reconstructed from the
  pinned Git tree before extraction. A separate lexical spot check found 105
  lines containing `fs.` or `fs[` across the staged files. All query spans
  matched the UTF-16 source columns and spelled the reported `fs.<property>`;
  five lexical-only lines were JSDoc in `fs.js`. This is a scoped cross-check,
  not a general parser, binding, or completeness proof.
- Query SHA-256: `063b3fab6746346ed69a69b0d33e4aa91c0c4a9f875d3e0d05c27da14acaf0b3`.
  Runner SHA-256: `ded03fbc1b4ecd08ce07f1ed8d69901d204eb529047f49ca51e606c1615a910e`.
  Fixture SHA-256: `dfc5765a4ff49f2f834874a68237bfd9adf4f043fe6414378993de2d7c6254a4`.
  Inventory SHA-256: `d7acf028aa478ed22ff6b1a3e6e938fc1afb927830b629012aae3affbd5517ff`.
  BQRS SHA-256: `0eb5c9d5ba6e65e34b667dfb9b43e9826f3395c50a248d9d6ac96b689636cc74`.

## Fixture controls

`fixture-tests.log` records the real CodeQL fixture and offline checks as of
that run. It requires exact absolute paths, spans, property names and kinds for
six accesses: dot, string-index, numeric-index, unresolved index, property read,
and shadowed receiver. It excludes comments, strings, another receiver and a
nested receiver. `dot-only-control.log` and `overbroad-control.log` show the same
fixture failing its exact-row assertion for executable omission and overbroad
query mutants, respectively, without setup errors. Reproduce by setting
`JS69_CODEQL`, `JS69_PACKS` and `JS69_FS_QUERY` to the query under test and
running `python3 -m unittest discover -s ql-js -p test_fs_surface.py -v`.
Unset `JS69_FS_QUERY` for the production query. CI skips the real fixture when
the toolchain variables are absent.

No taint, grants, runtime behavior, image construction, or exploitability is
asserted. Aliases, indirect or generated references, uci and CGI remain outside
this slice. The package closure/install mapping is a transcription, not a build.
