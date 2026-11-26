# Historical direct-commit source-first manifest

`tools/direct_commit_corpus_manifest.py` binds four pinned inputs for the
LuCI OpenVPN introduction: the direct-commit identity receipt, the separate
source-admission check, the historical policy v0.1 and its full-tree
candidate inventory. It independently reruns the admission source/recipe
check and candidate inventory on clean source/control Git checkouts, then
rebuilds the source-first corpus manifest. The output schema is
`mvp-direct-commit-corpus-v1`, with `kind=direct_commit`, no PR number and
byte digests for each input receipt. Its 112 selected paths comprise 49
historical LuCI, 51 frozen OpenWrt and 12 frozen packages-feed paths.
It also records the clean consumer commit and the byte digests of the direct
builder, admission checker, candidate selector and shared route oracle.

The manifest is an **input oracle**, not a released scan. Its source checkout
is the introducing commit, and its base is the actual first parent. The
historical identity probe used a synthetic interval derived from a captured
canonical compare; this builder does not replay or authenticate the linked
gap/checkpoint bytes. A live incoming claim needs that separate custody step.
Source paths are staged by reviewed installation projections; actual IPK
bytes and a clean/no-alert control are not established here.
The historical LuCI policy pin equals the introducing head, so the shared
builder's generic recipe-drift diff has no interval to inspect. The separate
admission verifier checks the exact OpenVPN package Makefile and `luci.mk`
blobs; it does not prove that unrelated recipe/configuration inputs were
unchanged between the parent and introduction.

The existing PR event manifest contract remains `mvp-incoming-event-corpus-v1`.
The historical policy and admitted addition are passed explicitly to its
shared source-oracle builder; no new candidate is accepted by the current
v0.6 incoming selector.

Run the focused controls with:

```sh
python3 -B -m unittest tools.test_direct_commit_corpus_manifest tools.test_event_corpus_manifest -v
```
