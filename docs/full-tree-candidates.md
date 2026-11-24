# Full-tree Ucode candidate inventory

`tools/full_tree_candidates.py` enumerates tracked blobs at both immutable source
revisions and unions four signals: `.uc`, `.ucode`, and `.ut` suffixes; a
Ucode interpreter in the first-line shebang; extensionless files below the
three installed Ucode roots; and paths explicitly reviewed in the checked-in
v0.4 source manifest. It preserves one row per path/blob identity, even when
multiple paths have identical bytes. Each head candidate is labeled `selected`,
`excluded`, or `unreviewed`. An unresolved candidate, candidate addition or
removal, or source-signal change sets `fail_closed`; content edits to reviewed
selected identities are recorded and remain scan-eligible. Excluded-file edits
require review. A v0.4 identity missing from both source revisions fails closed.

The tool is a source candidate inventory. It does not infer package recipes,
configuration conditions, source-to-installed rewrites, or actual installed
bytes. The v0.4 manifest contributes only its existing reviewed dispositions;
newly discovered paths deliberately remain unreviewed. Run one repository per
invocation (`openwrt` or `luci`).

## Bounded run against existing OpenWrt PR control

The consumer implementation was based on PR #156 head
`3a2197cd087bb5b76e4ffaaa3fe2df3e829a3f55`, with base
`15a440d04453b1ce480444d57ff924db6b6f6e77`. The source comparison used the
captured OpenWrt PR #26933 source base `727d8d2f8e5b19a2121e2cf05824e9e5cac35310`
and head `bce40f6a15c273778061e8fceced7b9e0f58d99b`. It also enumerated the
pinned LuCI source revision `b2e0be4b46ec0fd43394c081fa7c50657af14011` as
both base and head because no LuCI event pair was part of that fixture.

The manifest SHA-256 was
`1e25cf9c2adc40c854502fed8d1ccc0977a3c4825d6ee4a1c0a543ffe0a76699`.
Commands from the consumer checkout:

```sh
python3 -B tools/full_tree_candidates.py docs/current-corpus-source-v0.4.json openwrt ../incoming-live-pr26933-20261124/source 727d8d2f8e5b19a2121e2cf05824e9e5cac35310 bce40f6a15c273778061e8fceced7b9e0f58d99b ../incoming-live-pr26933-20261124/full-tree-openwrt.json
python3 -B tools/full_tree_candidates.py docs/current-corpus-source-v0.4.json luci ../stage6-luci/collections/luci b2e0be4b46ec0fd43394c081fa7c50657af14011 b2e0be4b46ec0fd43394c081fa7c50657af14011 ../incoming-live-pr26933-20261124/full-tree-luci.json
python3 -B tools/test_full_tree_candidates.py -v
```

The first implementation found 50 OpenWrt identities and 15 unreviewed paths.
After correcting nested installed-root matching and the shebang parser, the
same exact source pair found 52 identities on each side: 34 selected, one
excluded, and 17 unreviewed on the head. The two additional identities were
first-line shebang candidates missed by the old parser. The run failed closed;
there were no candidate additions/removals or signal transitions between the
source base and head. LuCI remained at 69 identities: 65 selected and four
excluded, with no unreviewed identities. The seven local controls passed:
ordinary selected edit, excluded-content review, selected/excluded policy identities
missing from both revisions, duplicate-byte path multiplicity, a new suffix plus two
first-line shebang candidates and a line-2 shebang negative, nested OpenWrt and
LuCI installed roots with a `fakeusr/` negative, and rename/deletion plus
signal-change fail-closed behavior.

The OpenWrt head's 17 unreviewed identities are listed with Git blob and
content SHA-256 identities. Each remains unresolved by the v0.4 disposition:

| Source path | Git blob | Content SHA-256 |
|---|---|---|
| `package/base-files/files/usr/libexec/duid-generate` | `2318239feb7b41dd44d92a0b1b363f5075376d8c` | `b1bd9cd34dc960f22eb65cfb666b3746dae21143f3b83668e26354c4f48a7af0` |
| `package/boot/uboot-tools/uboot-envtools/files/fw_loadenv` | `9fe302ce892315c2bcc36f0855e93a72ff296745` | `6a03dcf045db393a2bfbd94ca6dd56d635c425730f2118ff409d8c69f556d26a` |
| `package/network/config/netifd/files/lib/netifd/main.uc` | `56911347a75d1b85211eecf3cc33d34d93924041` | `0643779b5403e23d91e55550942e695d6901e3ddff605898b9f40f368cf830cf` |
| `package/network/config/netifd/files/lib/netifd/proto-ucode.uc` | `7db61cdb2c16a608c2e13a5d6408d2a17f38ec1d` | `798f452425e7f0dd48774588fec9753c20bfc6ae74622f370ca1eb24cab6e399` |
| `package/network/config/netifd/files/lib/netifd/proto.uc` | `b1a4e2ee1269c439dd4d64eadb74d85a3ccd8657` | `de46a4cf72156d5364ed91d150fd710203d64a8772df03e6ff2cd783490afee6` |
| `package/network/config/netifd/files/lib/netifd/utils.uc` | `8cfd326876da81b05e69aa965733d37c0840212f` | `c648bf128fa2ead12ef58edc0beadb1efe718b995a857bca95c739dfb7849540` |
| `package/network/config/netifd/files/usr/libexec/network/packet-steering.uc` | `853845ecaa2b793e38f956bb71366544bf948e14` | `543e97d8c6f43fcab3e5d75eb182455db063f462b286b8604acbcaa9b2840b5c` |
| `package/network/config/wifi-scripts/files/lib/netifd/wireless-macaddr.uc` | `8ff487629760ca239c78fa947b79f01084b5fb7a` | `7f1c7e78220b0062f876bf48f5251bbe02850b634340e2cfc23543da33b9644c` |
| `package/network/services/hostapd/files/hostapd.uc` | `c76fac22ebf8ec38f0def5f78b48b2a8067eb0be` | `160af9e095108a5d8d476dd5a87771491b733fde4b422406352baafca02dd242` |
| `package/network/services/hostapd/files/wpa_supplicant.uc` | `26a29af6bfe165d700a16ffc907df79816c5b580` | `1549afdf956241bf64c35176104556dbe014a8c0dbce93fc8d6ff073f7b3a0f7` |
| `package/network/services/umdns/files/mdns.uc` | `5b767847aae059f3d6c8840b7cb9deb9fc783533` | `f2b409874d5e6370bf187806da0bd1e3bd120fe41de0e9f67b9ac92f74996a31` |
| `package/network/services/unetd/files/unet.uc` | `45f023e2036d42829adb15543745b4d5d49ad093` | `b952432a1e79e7336447a03c4045723427b07dcf335b686e1e46dd68e72aae32` |
| `package/network/utils/wireguard-tools/files/wireguard.uc` | `fe876ebdbbc8e1b66328c5fcad60acf3680ac810` | `5b895085d72c3feb297d18f378676daae596ab40145113d354ff345d8d8b5d39` |
| `package/utils/provision/files/usr/sbin/provision` | `b0afbafc2563c17c5d6cbbb3a1d26eae942083b9` | `5d21c8a68ffe1813f35a4cf52c283bce543cb414d0f709e8044532c427314498` |
| `package/utils/provision/files/usr/share/ucode/provision.uc` | `50fccfaad9a9a20f89503fdd9ff76901277aefba` | `6b13625355cf4dfc48f8d76510f12b4efaf9a1aaea4e421e5b8f129f1317a7c3` |
| `package/utils/ucode-mod-pkgen/files/pkgen` | `e37e5f5329d100b374bb4dcbd48a6f4aef6ccfdf` | `5927d4050793b5f5b68ebcd87ff0f26dae695b31e2a16933945645752bd350dd` |
| `target/linux/ipq806x/base-files/usr/bin/base64decode.uc` | `7dcf30986c045dd92b6ea010319d6f6dee026ed6` | `1ca194eb61dd9ed6a8e1954a7dc057c4b40e153d2da306b8e69d6db0ab909562` |

This local selector result is not Gate 8. It does not cover package feeds,
recipe-only selection changes, installation mapping, extraction, CodeQL, SARIF,
or a producer-to-consumer event run. The checked-in v0.4 policy is not a
