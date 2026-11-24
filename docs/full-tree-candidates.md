# Full-tree Ucode candidate inventory

`tools/full_tree_candidates.py` enumerates tracked blobs at both immutable source
revisions and unions four signals: `.uc`, `.ucode`, and `.ut` suffixes; a
Ucode interpreter in the first-line shebang; extensionless files below the
three installed Ucode roots; and paths explicitly reviewed in the checked-in
v0.4 source manifest. It preserves one row per path/blob identity, even when
multiple paths have identical bytes. Each head candidate is labeled `selected`,
`excluded`, or `unreviewed`. An unresolved candidate, candidate addition or
removal, or source-signal change sets `fail_closed`; content edits to reviewed
selected identities are recorded and remain eligible for review/selection.

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

The OpenWrt inventory found 50 candidate identities on each side: 34 selected,
one excluded, and 15 unreviewed on the head. It failed closed on those 15
unreviewed source paths. There were no candidate additions/removals or signal
transitions on this event pair. The LuCI pin yielded 69 identities: 65 selected
and four excluded, with no unreviewed identities. The four local controls passed:
ordinary selected edit, duplicate-byte path multiplicity, newly added candidate
outside the diff with extensionless and shebang signals, and rename/deletion
plus signal-change fail-closed behavior.

This local selector result is not Gate 8. It does not cover package feeds,
recipe-only selection changes, installation mapping, extraction, CodeQL, SARIF,
or a producer-to-consumer event run. The checked-in v0.4 policy is not a
complete install recipe catalog.
