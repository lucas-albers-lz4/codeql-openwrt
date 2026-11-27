# v0.7 packages-feed IPK byte experiment

This manual `codeql-openwrt` workflow measures seven selected Ucode-looking
members across the `adblock-fast` and `uvol` feed package IPKs. Its evidence
chain is pinned feed source → package install stage → IPK data member. It does
not establish rootfs/image contents, dependency-complete installation,
CodeQL extraction or query coverage, runtime behavior, or security results.

## Decision and pins

The bounded question is whether the selected package install recipes put the
predeclared source bytes, modes, and one known version substitution into the
real package staging directories and resulting IPKs. The source-first oracle
is stored in `oracle.json` and materialized as `source-oracle.json` before
either package build starts.

| Input | Commit | Git tree |
| --- | --- | --- |
| OpenWrt | `4e9642517b48bae612ff10fb72fb9199e559500e` | `328d4df01c038d365176b72753b778e10c3ff413` |
| packages feed | `07e0d16305d2b5903b37ad7913e33e18795f81a4` | `a6b0fc0935cbfeedb810e6e991b6940f71548ea7` |

The oracle pins Git blob IDs, SHA-256 digests, source modes, destination
members, package metadata, and recipe install operands. It expects two
`adblock-fast` members and five `uvol` members. The `adblock-fast.uc` result
includes only the recipe's one `dev-test` → `1.2.4-r4` version rewrite; the
other six expected members match source bytes. The three test mock files are
negative controls: the comparator rejects their suffixes, source hashes, or
embedded source content anywhere in the IPK data members. The Ucode census
also includes `.uc`, `.ucode`, and `.ut` names, extensionless members under
the v0.7 Ucode roots, and files with a Ucode shebang.

## Staging and archive checks

The comparator takes the stage and IPK paths from exactly one OpenWrt
`Packaged contents of … into …` record per package, then checks the pinned
`build_dir/target-*/<package>-<version>/ipkg-all/<package>` layout. It binds
each selected member to a verbose install command with the exact recipe
source operand and file or directory destination. It compares exact bytes
and modes from that stage to the IPK and records the complete IPK data-member
inventory and control metadata. `PKG_BUILD_DIR/.pkgdir` is a separate root
staging tree; it is not treated as the IPK stage.

Outer IPK, control, and data archives are parsed without extraction. The
bounded reader checks gzip boundaries, raw tar headers and trailer, regular
file/directory types, normalized unique paths, parent/file conflicts, member
and aggregate size limits, and archive entry limits. It rejects links,
sparse files, PAX/GNU extension records, and trailing or concatenated gzip
streams. The run retains both original IPKs and a deterministic gzip USTAR
archive containing only the seven validated stage members. The stage
manifest records each retained path, size, SHA-256, and mode; the byte receipt
records the stage archive digest.

## Workflow gate and resources

The pull-request job runs only the offline contract tests, JSON validation,
and shell syntax check. The expensive job runs only after an explicit
`workflow_dispatch` on the merged default branch. It has one serialized
runner group, no write permissions, and checkout credentials are not
persisted. The run script creates a unique runner-temp root for source
checkouts, `HOME`, `TMPDIR`, tool caches, logs, receipts, and package outputs.

Before bootstrap it requires Linux x86_64, the listed host tools, at least
**85 × 1024³ free bytes** and **8 × 1024³ available memory bytes**. It records
the exact byte readings and `time -v` peak RSS per phase. A failed gate is
`not run / preflight blocked`, not a package-byte pass. The prior successful
same-pin `adblock-fast` run displayed `85G` free in rounded `df -h` output;
that observation does not prove the exact 85 GiB threshold, so the new run
measures bytes directly.

Host tools and the toolchain install sequentially with `-j2`, under one
60-minute deadline. The two selected package targets run sequentially with
`-j1 NO_DEPS=1`, under a combined 10-minute deadline; byte comparison has a
5-minute deadline. The planned budget is **75 minutes plus source checkout**.
The 60-minute bootstrap cap is based on a same-pin historical bootstrap of
53:30 at `-j2`; it is not a guaranteed completion time.

`NO_DEPS=1` is an intentional experiment boundary. The pinned `uvol` runtime
dependency path reaches `kmod-fs-autofs4` and can request a Linux kernel
module build that is not supplied by the tools/toolchain bootstrap. The
selected package recipes and package writer still run, while dependency
compilation and closure are excluded. The workflow captures `.config` and
OpenWrt package dependency metadata so the selection and boundary remain
reviewable. A later image/runtime claim would need its own dependency-complete
build and verification.

## Expected artifacts and CI mapping

The 14-day Actions artifact contains source identities and digests, final
configuration and feed selection, package/dependency metadata, full phase
logs and timings, exact resource readings, source oracle, retained IPKs,
selected stage archive and manifest, and final byte-comparison receipt. Full
verbose logs remain in the artifact; only their last 80 lines are printed to
the Actions log. Timeout or detected build-download failures are incomplete;
verified oracle/byte mismatches are failures. Resource and initial source
checkout failures are recorded as preflight blocks.

| Contract | Local / CI gate |
| --- | --- |
| Source pins, blobs, source-first rewrite, recipe preparation hooks | `source_first_oracle` and oracle unit tests; run before builds |
| Archive safety, metadata, paths, types, gzip/tar boundaries, size bounds | Offline archive contract tests; same parser reads actual IPKs |
| Install provenance, actual stage layout, file/directory recipe operands | Pinned-recipe fixtures and exact `Packaged contents` record at comparison |
| Bytes, modes, Ucode census, mock exclusions, complete data inventory | Source-shaped tests, then exact stage-to-IPK comparison |
| Resource and run freshness | Linux runner preflight plus unique run-owned paths and receipts |
| Workflow wiring | Local `actionlint`; PR contract job checks shell syntax and offline contracts |

The prior same-pin adblock-fast evidence is recorded in
`evidence/issue173-adblock-batches-20261126/README.md` (hosted run
`45748188587`). It already retained and independently checked an adblock-fast
IPK, but not its raw package stage. This paired experiment adds fresh `uvol`
and retained selected stage bytes; it is not described as first adblock-fast
byte evidence.

## Review corrections and runbook amendment

Independent review found that the initial stage-path assumption was wrong:
the pinned `include/package.mk` and `include/package-pack.mk` place IPK stages
under `PKG_BUILD_DIR/ipkg-all/<package>`, not a nested `package/feeds/...`
tree. The comparator now derives both roots from the actual packaging log and
validates the pinned layout. Review also caught `.pkgdir` being distinct from
the IPK stage, uvol's directory destinations, an incorrect prepared-copy
assumption, an `ipkg-*` component test, omitted extensionless Ucode roots,
and mock copies that could be renamed. Those assumptions were removed or
replaced with recipe-shape, exact source/destination, root-census, and
hash/content controls, covered by fixtures. Review tightened hosted output
to bounded log tails, recursive timeout handling, exact byte resource gates,
and raw archive/total-size validation. An absent separate prepared file is
allowed by the experiment; uvol has an explicit empty `Build/Prepare`, while
adblock-fast uses default no-source preparation.

The v0.7 runbook should therefore record these execution choices: sequential
`-j2` tools and toolchain installs with a 60-minute combined cap, followed
by sequential `-j1 NO_DEPS=1` package targets with a 10-minute combined cap,
then a 5-minute comparison; 75 minutes plus checkout overall; and exact
85-GiB/8-GiB preflight thresholds. `NO_DEPS=1` limits the claim to the two
selected package recipes, install stages, and IPK members, not dependency
closure or an image. No hosted package-byte result exists until the manual
workflow runs on an eligible runner and its retained receipt is reviewed.
