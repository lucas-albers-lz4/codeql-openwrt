# #173 `luci-base` source-first package-byte oracle and preflight

Created 2026-11-26 UTC in scratch outside repository checkouts. This is a pre-output source/recipe projection. No package build, stage, or fresh package output was inspected.

## Inputs

- Reviewed #172 source inventory: `codeql-openwrt@460c6ed45c445fbe9de199e324f08fc7542dc2bc:evidence/issue172-luci-source-inventory-20261125/inventory.json` (SHA-256 `91fcf7f84e2934a1df21c7438f898fb5cd097eb9f6cfde3bc80239369c0d7cbc`). LuCI commit `cb87fe60e1e2e052af36a93647f2264577829e0a`, tree `1d7bf89bc8708fca69d005b0690ca823c9071692`; checkout was clean when read.
- Prior source census: Claim 085 inventory SHA-256 `ec86e2f2a7cd1e9ac97f3d54db48d90d62674e2e05abd4fa937ccdae829392e9`, baseline LuCI `b2e0be4b46ec0fd43394c081fa7c50657af14011`. The LuCI branch is eight commits ahead; the one changed prior candidate is the `luci-base` rpcd provider.
- Machine-readable source-first oracle: [`source-first-oracle.json`](source-first-oracle.json), SHA-256 `5fe8593458900f5eca20e20de5e68e1d7cba079fd985e93ec53bff5551b5f999`.

## Scope and expectations

The packet contains **17 selected `luci-base` source identities** (15 `.uc`/`.ut` files plus the extensionless rpcd Ucode provider and executable CGI Ucode entry point) and **3 extensionless unknowns**. Expected package paths are recipe projections, not observed members. `luci.mk` copies `root/` to `/`, `ucode/` to `/usr/share/ucode/luci`, and `htdocs/` to `/www`. The producer source-path mapper limitation for htdocs remains explicit.

`luci.mk` applies `.ut` version substitution. The pinned `header.ut` contains the only matching `PKG_VERSION` token among this package's `.ut` files. The pinned source recipe projects `PKG_SRC_VERSION` as `26.317.52279~1c75ea4` from latest non-`po/` commit `1c75ea4`; the build must still report actual variables and IPK metadata. `version.uc` is separately generated from `LUCI_VERSION` and `LUCI_GITBRANCH`.

The critical negative is the stale rpcd source digest: old `6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e` versus current `04c9cc966f9cbdd9bea942f55ab139ba11bff78e751ed3ee2e99f52be9c73dbf`. The shell `ucitrack` file is a separate extensionless non-Ucode control; the future package receipt must observe it as one regular member with its source digest/mode or explain the recipe delta. Neither is a fresh IPK observation.

## Build preflight

Historical successful run 45513606386 used OpenWrt `4e9642517b48bae612ff10fb72fb9199e559500e`, packages feed `07e0d16305d2b5903b37ad7913e33e18795f81a4`, old LuCI `b2e0be4b46ec0fd43394c081fa7c50657af14011`, x86_64/IPK, and `CONFIG_PACKAGE_luci-base=m`. The prior IPK SHA-256 was `1a2188f5206ce61c993fdcc451781a06994ae2175b489eef56595858ef22b363`; it is historical and cannot establish membership/bytes at the new LuCI pin. Its complete suffix inventory did not cover extensionless Ucode.

The existing helper is hardcoded to the old LuCI pin and only `http.uc`/`header.ut`; it must be reviewed and parameterized before a new run. The command plan is captured in the JSON. The new run config input must contain exactly `CONFIG_TARGET_x86=y`, `CONFIG_TARGET_x86_64=y`, `CONFIG_PACKAGE_luci-base=m`, `CONFIG_USE_APK=n`, then run `make defconfig` and retain/hash the final config. The actual runner should use a fresh Linux run root, record clean repository heads/trees, feed links, final config hash, exact output IPK digest and archive diagnostics. It should use one serial package target after host tools/toolchain; no `make -n` probe.

## Unresolved until a later build

- Whether the 17 selected source identities and three unknown paths are members of the new `luci-base` IPK, and their actual package modes/digests.
- Actual generated `version.uc`, version variables, transformed header bytes, IPK digest, package config hash, and complete package member list.
- Htdocs extractor mapping, any source-to-stage/package mismatch, and all extraction/semantic results.

The archive parser should reject missing/duplicate data archives, duplicate normalized member names, unsafe paths, and any symlink/special file before staging. For the detailed source identities, recipe hashes, inputs, and exact command skeleton, see the JSON.
