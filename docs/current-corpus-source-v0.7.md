# Packages-feed source policy v0.7 candidate

Status: opt-in source policy candidate, 2026-11-26. This policy does not
replace the default v0.6 manifest, enable a scan, or claim a built package.
The exact policy is [current-corpus-source-v0.7.json](current-corpus-source-v0.7.json),
SHA-256 `2ef4dc10e78b6c3aef873e3f0652b5102698cedb317c9cf96587806941c61d2e`.

## Decision and revisions

Add a separately versioned source-stage scope for 14 files whose package
recipes place them in named packages, plus three explicit adblock-fast test
mock exclusions. Keep the eight optional Prometheus collector exclusions and
every selected/excluded row from v0.6 byte-for-byte unchanged. A package row
means “include this source when its named package is selected by a build
configuration”; it does not assert that a configuration, image or runtime
contains that package.

The implementation started from a clean disposable `codeql-openwrt` checkout at PR
#261 merge `483431db4fa3bcdad516f85ccf7d6a41f8490d5e` (tree
`24ebe39d5761c4bba0e833160cf50f69c53f621a`). Its three repository pins are
carried forward from v0.6; the packages feed is commit
`07e0d16305d2b5903b37ad7913e33e18795f81a4`, tree
`a6b0fc0935cbfeedb810e6e991b6940f71548ea7`.

The ledger's pre-output oracle is retained at
`work/packages-feed-v07-policy-20261126/pre-output-oracle.json` with SHA-256
`566b87366b22ed0728324b44954398a5531543c2088d9a87f112296595abbdad`. It
records all 17 source paths, Git modes, blob IDs, source hashes, package
owners, recipe evidence and proposed route expectations before the policy
tests or candidate inventory. That work path is local to the preparation
machine; the JSON policy contains the portable row identities.

## Source-stage oracle

The 14 selected additions have the following owner and expected route groups.
Each row in the JSON also freezes source mode, Git blob, SHA-256, recipe line
range and stage destination expression. Every route support value is
`source_expected_not_extracted`.

| Package owner | Paths | Expected route | Source qualification |
|---|---:|---|---|
| `adblock-fast` | 2 | Plain `ucode_extension` | The recipe applies a version `$(SED)` substitution to `adblock-fast.uc`. |
| `mwan3` | 1 | Plain `rpcd_raw_mode_full_path` | Extensionless source is staged under `/usr/share/rpcd/ucode/`. |
| `snort3` | 3 | Markup `markup_tag_content` | Provisional route expectation; all three rows remain unextracted. |
| `uneighbord` | 1 | Plain `ucode_shebang` | Source begins with a Ucode shebang. |
| `librespeed-common` | 2 | Plain `ucode_shebang`; plain `rpcd_raw_mode_full_path` | The aggregate recipe applies version substitution; the Ucode plugin has a Ucode shebang but is staged in the rpcd Ucode root. |
| `uvol` | 5 | Four plain `ucode_extension`; one plain `ucode_shebang` | Recipe stages four modules under `/usr/lib/uvol` and `/usr/lib/uvol/backends`, and the script under `/usr/sbin`. |

The three excluded paths are
`net/adblock-fast/tests/lib/mocklib.uc`,
`net/adblock-fast/tests/lib/mocklib/ubus.uc`, and
`net/adblock-fast/tests/lib/mocklib/uci.uc`. The source verifier confirms
their exact pinned identities and that the adblock-fast package recipe does
not reference them. They are eligible near misses for the `.uc` suffix
candidate signal.

The policy pins route expectations to
`tools/event_corpus_manifest.py:source_route` (SHA-256
`eba5741635bde7b5719d3e60f3bb8847f6603d91d6939c6c5602c02bcca6be9e`). The
source verifier recomputes each proposed route with that helper and requires
exact equality with the policy. The helper mirrors the reviewed extractor
source hash `bc54d2fc…`, but release equivalence remains unverified. In
particular, `net/snort3/files/nftables.uc` begins with a generated-file
comment; a later qualifying template line yields the provisional markup
expectation. The near-miss test places a template token inside a comment and
requires the route helper to classify it as plain Ucode.

The expected package-feed candidate set at the pin is 37 paths: 26 selected
(12 carried from the base Prometheus package and 14 new conditional paths),
11 excluded (eight optional collector files and three test mocks), and zero
unreviewed under the bounded suffix, installed-root and first-line shebang
signals. The full manifest therefore has 142 selected paths and 16 excluded
paths. Expected route classes are 104 plain and 38 markup. These are source
policy counts, not extraction counts.

Before assigning policy dispositions, the source verifier runs the tracked
signal inventory with empty selected/excluded policy lists and requires its
natural 37-path set to equal these 37 policy identities. This detects an
unexpected candidate and prevents policy-seeded paths from hiding a missing
suffix, installed-root or shebang signal.

## Checks and gate map

The source verifier is explicitly versioned and must be invoked with a clean
packages checkout at the pinned commit:

```sh
python3 -m tools.packages_feed_source_v07 \
  ../source-truth-luci-packages-45875169837-20261126/packages
```

It verifies the v0.6 row carry-forward, all 17 new package-file modes/blobs/
SHA-256 values, 14 recipe source/destination mappings, three non-install
mock controls and the 37-path packages candidate census. It does not build a
package or modify a source checkout.

Focused tests:

```sh
python3 -m unittest -v \
  tools.test_packages_feed_source_v07 \
  tools.test_full_tree_candidates
```

The synthetic inventory test first checks natural signal paths with an empty
policy, then checks that the policy classifies those fixture paths as 26
selected and 11 excluded. The existing
`.github/workflows/incoming-event-preflight.yml` `contract` job already runs
`tools/test_full_tree_candidates.py`; its existing path filter includes that
test file, so the synthetic fixture runs there without a workflow edit. The
new package-specific unit test and pinned source verifier are local checks and
are not wired into CI. The current selector CLI intentionally exposes only
LuCI and OpenWrt; package-feed census remains a separate, versioned verifier.
No v0.7 digest was added to the selector's manifest allowlist, and no default
scan or CI policy path was switched. There is no CodeQL database, extraction,
query, package build, IPK creation, image build or resource-budget consumption
in this candidate preparation.

## Boundaries

- Recipe mapping is conditional source staging evidence. Prepared package
  bytes, IPK members and installed image contents were not inspected.
- The adblock-fast and librespeed aggregate recipes transform staged source;
  source hashes are not package-byte hashes.
- Route names are recomputed from pinned source and destination paths with the
  source-route mirror; no observed extractor route or CodeQL run is claimed.
  All three `snort3` markup routes remain provisional pending fresh extraction
  and release-equivalence validation.
- The v0.6 scan and source verifier still require their exact 128-selected,
  13-excluded manifest. This v0.7 policy is not consumed by the current
  default-branch runner or its default-tip/event builders.
- The packages-feed candidate census is bounded. Its shebang search omits
  binary blobs and its suffix/root/shebang signals do not establish full feed
  completeness, installability, image membership, reachability or safety.
