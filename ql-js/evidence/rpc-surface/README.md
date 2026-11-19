# rpc.declare candidate inventory evidence

- OpenWrt base: `4de68a67efa6a9939cc7da0bffd65b94dedbd327`.
- LuCI pin: `b2e0be4b46ec0fd43394c081fa7c50657af14011`.
- CLI: 2.27.4; resolved `codeql/javascript-all`: 3.0.0; see `toolchain.txt`.
- Fresh extraction accepted 88 exact selected paths and zero `JSParseError`
  rows. The inventory runner independently repeated those queries on that same
  database and checked staged source hashes before and after. The existing
  extraction limitations in the parent README still apply.
- `inventory.json`: 98 candidate property accesses in 40 of the selected files;
  all 98 are dot accesses. This is not a count of proven runtime calls. The
  synthetic fixture separately exercises literal and unresolved computed index
  accesses; zero such rows in this pinned result is not a general absence claim.
- The producing source root was `/root/workspace/js69-sites-extraction-20261119/source`.
  Absolute paths in decoded output and logs refer to that machine. Original
  staged bytes and database are not checked in; use the parent README to rebuild.
- `extraction-commands.log` and `inventory-commands.log` record the actual CLI
  calls. `ACCEPTED.json` records the extraction inputs. The inventory run retained
  its BQRS and decoded JSON for all three queries. A second inventory run over
  the same fresh database produced byte-identical `inventory.json`; this is not
  a second extraction.
- `rpc_surface.ql` SHA-256:
  `60c70ba543b93d3c3876d071e7472c3a25c40e1ddd184ac3fd4009ad4a097c55`.
  Runner SHA-256:
  `196aa3ea07cccdf6f10c487eda86325f6a23caa59c5ade3e2088f557cfe4811b`.
  Fixture SHA-256:
  `ac3ed26d3e791e214fbbb17911846fab74e7d2cd8a1f9fd6083fd8639141dede`.
  Inventory SHA-256:
  `30d42dca49978cc400e49345516324a30a0c7bfeb42eacf1c62fcdd1d9afda61`.
  Query BQRS SHA-256:
  `c65ad46be49a1b980e9e38bad1482a477efa07ad553c05410d4942fb6d2d031b`.

## Fixture controls

`fixture-tests.log` is the real CodeQL fixture plus offline discovery. The
fixture requires exactly five spans: direct, string-indexed, unresolved-index,
property-read, and shadowed-receiver candidates. It excludes a comment, a
string, `rpc.other`, `rpc['other']`, and `other.declare`. The test compares
absolute source identity and every expected span, kind, and assessment.

`dot-only-control.log` and `any-dot-control.log` are deliberately failing runs
using `tests/dot-only.ql` and `tests/any-dot.ql` respectively. The former omits
both index candidates; the latter adds the unrelated `rpc.other` site. Both
failed the exact-row assertion, not setup, as shown in the logs. To reproduce,
set `JS69_CODEQL`, `JS69_PACKS`, and `JS69_QUERY` to each control query and run
`python3 -m unittest discover -s ql-js -p test_rpc_surface.py -v`; then unset
`JS69_QUERY` and run the real query. The committed workflow runs offline tests
and skips the real fixture when the two toolchain variables are absent.

A separate source-span spot check read all 98 staged lines at the reported
columns; each spelled `rpc.declare`. It does not prove completeness or source
binding. This inventory does not model aliases, runtime targets, taint, grants,
CGI, fs or uci. Closure/install mapping remains a transcription, not a build.
