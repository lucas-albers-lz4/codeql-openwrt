# Consumer R2.5 package-to-stage lane

Status: consumer implementation prepared; no released R2.5 consumer run is
claimed. The live package step is part of the R3 Linux job and remains skipped
while `docs/r3-release-lock.json` is null.

## Decision and contract

The consumer owns the adapter from the pinned OpenWrt `.ipk` artifacts to a
fresh installation-shaped stage. It checks the whole archive digest, package
control identity, exact regular `data.tar.gz` member inventory and each
member's source-first digest before writing any staged file. It stages only
regular files named by the pinned oracle and records relative identities in a
consumer receipt. After the release lock is populated, the R3 job invokes the
actual bundled `runner/run-installed-stage.py` on those same stage roots with
the release-locked CodeQL executable and archive. The consumer compares the
runner's route and successful-file multisets, extraction errors, resolved
suite, coverage receipt and fresh SARIF bytes.

The exact per-package default-suite expectation is **zero SARIF results** for
these pinned package bytes. This is a regression expectation for these inputs;
it is not a security-negative, a vulnerability statement, or the OpenVPN
parent/fix acceptance gate. Any new result stops the package lane for review.

The adapter never uses `tarfile.extractall`. It reads only a regular,
single-link IPK under the run-owned input root after validating the checked-in
oracle. The artifact downloader streams the REST ZIP response into an
exclusive run-owned file with a live byte cap and timeout, then accepts only
bounded archives containing regular, unencrypted members with safe unique
paths, sizes and supported compression. It writes only the exact pinned IPK
member, using an exclusive output file, and leaves build logs and other
artifact files unexpanded. It bounds compressed and decompressed package
inputs, rejects traversal, aliases, duplicate paths, symlinks and special
files, checks all package member digests before staging, and creates output
files exclusively below a new run-owned directory.
The GitHub token is used only by the artifact-list and artifact-ZIP download
subprocesses; it is removed from the environment passed to the released
producer runner.

## Frozen inputs

- Consumer package lock: [`r25-package-lock.json`](r25-package-lock.json).
- Source-first producer fixtures, copied byte-for-byte from PR #170:
  [`r25-package-oracles/`](r25-package-oracles/README.md).
- OpenWrt, LuCI, packages-feed and extractor route-source pins are recorded in
  the package lock and oracle README. The release-specific producer and CodeQL
  fields remain exclusively in the R3 lock and are not changed here.
- `luci-base` artifact: run `45513606386`, artifact ID `14979253876`, name
  `luci-ipk-byte-45513606386-1`, ZIP SHA-256
  `cefdf043c269e61a6e13d2dbe9213898c8898f30b7d9413761d3a51c5d9c95da`, whole IPK SHA-256
  `1a2188f5206ce61c993fdcc451781a06994ae2175b489eef56595858ef22b363`.
- Ucode-enabled `wifi-scripts` artifact: run `45548269425`, artifact ID
  `14997815607`, name `wifi-ipk-byte-45548269425-1`, ZIP SHA-256
  `c52528d8bf453585cc5c384d1a573263db7a0102c2a9df443bee7a029869970a`, whole IPK SHA-256
  `20f2e18297a10e2c2fc0f3457dee52e5ee2db01a8d17d52ba44dffaf79ba833a`.
- Producer R2.5 source fixture interface at PR #170 pre-merge head
  `d508217bfb5d31e205eb51dd797075e0277966ec` pins
  `stage-installed-ipk.py` SHA-256
  `991c92bb72f5c7a048d25b12021ff03b28c2d3c462a977b6a596d070aa7122a9` and
  `run-installed-stage.py` SHA-256
  `0480553ff6598438bbcaf7d973f8dfef20097728480a94cdcdea0f011b0611fa`.
  Hosted run `45748014676` passed R2 and R2.5 at that pre-merge head. The
  combined PR #170 head `1fcf11ddaca88b77ed1e0c94e261c3dae4b0065a` passed
  R2/R2.5 in run `45750828683`. The stage-helper pin is provenance-only
  because this consumer uses its own IPK adapter. The released runner pin is
  enforced against both the bundle manifest and this consumer lock; the R3
  job executes the runner file in the immutable release.
  The artifact ZIP hashes bind the downloaded transport archives; GitHub's
  metadata digest is checked against them. The independently reviewed IPK
  SHA-256 pins remain the source-byte acceptance check.

The oracle positive and near miss discriminate route selection inside the
Wi-Fi package: Ucode-shebang `lib/netifd/wireless/mac80211.sh` is plain, while
the shell-shebang `etc/hotplug.d/ieee80211/10-wifi-detect` remains excluded.
The already-recorded Ucode-disabled package has a second same-path shell
control, but this two-package R2.5 runner gate does not scan that separate
configuration.

## Gate map and output

- Pull requests run `tools.test_r25_package_stage` through the package
  contract test job. These tests cover the source-oracle pins, a valid package
  archive, extensionless/shebang routing identities, archive and path
  rejection, package metadata, exact member multisets, digest mismatch, and
  output alias protection. They do not run CodeQL.
- In the existing R3 workflow, `lock-state` must report the full immutable
  release pin as ready. A null release lock skips the complete live job,
  including this package step. Once ready, the package runner reuses the
  verified `bundle/`, CodeQL CLI and archive created earlier in that same R3
  job. It independently compares the CLI archive and executable hashes to
  the lock, checks the bundled runner against both its manifest and the
  consumer package lock, downloads only the pinned package artifact IDs as
  REST ZIPs, validates each bounded archive and extracts only the exact pinned
  IPK before staging, then runs both actual package stages through the released
  runner.
- Each package is a separate run-owned stage/database/cache/output. The
  package parser is bounded to 4 MiB per compressed IPK/data archive, 2 MiB
  per regular member, 16 MiB total regular member bytes and 512 archive
  entries. No package build or large source scan is added to R3; the live
  step performs two package scans using the existing released bundle. The
  existing R3 Linux job retains its 90-minute cap and GNU-time receipts.
- The combined R3 artifact retains the downloaded artifact ZIPs and IPKs, stage receipts and
  exact staged member files, producer `receipt.json`, `commands.json`, raw
  routing/SARIF/coverage outputs, and phase logs. Database and writable
  caches remain in the runner workspace rather than the artifact.

## Evidence boundary and limits

The local adapter check used both retained pinned IPKs in fresh run-owned
directories. It staged and hash-checked 76 luci-base members and 31
Ucode-enabled Wi-Fi members, with route counts matching the source-first
oracles and the Wi-Fi Ucode positive selected while the shell near miss was
excluded. Both adapter processes exited 0 (0.04s and 0.03s). The normalized
record is in
[`r25-package-oracles/consumer-stage-validation.json`](r25-package-oracles/consumer-stage-validation.json);
the actual REST downloads and bounded ZIP validation are summarized in
[`r25-package-oracles/artifact-api-validation.json`](r25-package-oracles/artifact-api-validation.json).
Raw outputs remain under ignored ledger `work/`. Earlier timing-wrapper,
archive-shape and harness failures are recorded and are not counted as passes.
These local consumer checks did not run the producer or CodeQL.

The producer R2.5 package gate passed both before the tag and on the tagged
commit. The immutable producer prerelease now exists and the R3 lock is
populated. A released runner invocation and downstream package handoff remain
unclaimed until the hosted live consumer job passes and its output is reviewed. The selected IPK
artifacts are retention-limited. If they expire before R3, rebuild them from
the same recorded source/configuration pins and prepare/review new oracle and
artifact digests before changing the package lock. A package member is not
proof that a device root filesystem installed it. The zero-result assertion
does not establish absence of vulnerabilities or whole-OpenWrt coverage.
