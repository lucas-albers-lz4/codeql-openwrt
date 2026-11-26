# Source-first R2.5 package member oracles

The two JSON manifests in this directory are byte-for-byte copies of the
producer fixtures at PR #170 fixture source commit
`d508217bfb5d31e205eb51dd797075e0277966ec`. Its exact-head hosted R2.5 run
`45748014676` passed before PR #170 incorporated main. The combined PR #170
head `1fcf11ddaca88b77ed1e0c94e261c3dae4b0065a` then passed R2/R2.5 in run
`45750828683`. These manifests and the stage/runner source files have the
same hashes as at the earlier passing R2.5 head
`0fc65454b5e4b0b5f51bd1c0e0fa291286f948a2`; the consumer lock pins the SHA-256
of each copied oracle and each exact OpenWrt package artifact.

| Package | Oracle SHA-256 | Regular members | Plain | Markup/inconclusive | Excluded |
|---|---|---:|---:|---:|---:|
| `luci-base` | `efd49d1bec85b1c1ae2a12a6c64957f9c09e283d2ce326f80d881339b1f93fe8` | 76 | 10 | 8 | 58 |
| `wifi-scripts`, Ucode enabled | `5ac6c87cbbc12361581ee630083484b67c84d74d3b840ac8275fa3f0ff237aff` | 31 | 17 | 0 | 14 |

The source pins are OpenWrt
`4e9642517b48bae612ff10fb72fb9199e559500e`, LuCI
`b2e0be4b46ec0fd43394c081fa7c50657af14011`, and packages feed
`07e0d16305d2b5903b37ad7913e33e18795f81a4`. The routing expectations trace
to producer `extractor/src/extractor.rs`, blob
`6a94c6ab472fb8aa4610fa8d6e9ee5eaf2656349`, SHA-256
`bc54d2fc6e4dfba095977053d92275c3474bb01ff7e6da7c5301002bde701a11`.

The expected positive unusual path is Wi-Fi
`lib/netifd/wireless/mac80211.sh`, SHA-256
`f7d6ae091777a8eb77ba55c2c1f09bf8caff1a4364dc6de4f19a1ecb322801aa`, routed
as Ucode by its shebang. An eligible shell near miss in the same IPK is
`etc/hotplug.d/ieee80211/10-wifi-detect`, whose pinned bytes use the shell
route and are excluded. The separate Ucode-disabled `wifi-scripts` build
also has a same-path `mac80211.sh` shell member with SHA-256
`5f87f07cca56b20b0cf08cf02711c1c4fc4ddbbb17de7c8780282625c8d3be07`; that
conditional package-byte control is documented in
[`evidence/mvp-wifi-ipk-linux-20261125`](../../evidence/mvp-wifi-ipk-linux-20261125/README.md)
and is not part of the two-package producer invocation in this lane.

For `luci-base`, extensionless `usr/share/rpcd/ucode/luci` and
`www/cgi-bin/luci` are included. All eight `.ut` routes are successful
extraction identities but remain `markup_not_modeled`. `template/header.ut`
contains the package-version substitution, so its expected digest is the
actual IPK member digest. For Ucode-enabled `wifi-scripts`, the oracle includes
extensionless `usr/bin/iwinfo` and the Ucode-shebang `mac80211.sh` collision.

The consumer adapter's local package-byte-to-stage check is summarized in
[`consumer-stage-validation.json`](consumer-stage-validation.json). It records
the input artifact identities, source-first oracle hashes, per-route and
member counts, command statuses and timing, staged receipt digests, and two
failed harness attempts. It is limited to the consumer adapter: no producer,
CodeQL, or released workflow invocation was made.

The live, read-only GitHub artifact REST downloads, ZIP metadata checks, raw
archive hashes, API command receipts, and successive fail-closed attempts are
summarized in
[`artifact-api-validation.json`](artifact-api-validation.json). Only the
expected pinned IPKs were expanded; build logs and the Wi-Fi `n` variant
remain unexpanded.

These manifests describe exact regular IPK `data.tar.gz` members at
installation-shaped paths. They do not prove root-filesystem/device
installation. Package artifacts are retained only for a limited period; the
workflow will fail closed when the pinned artifact is expired or its ID,
name, package metadata, bytes, member inventory, or member digest changes.
