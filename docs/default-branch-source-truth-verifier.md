# Default-branch source-byte and route verifier

Status: local implementation and bounded run, 2026-11-26. The disposable
consumer checkout is at merge commit
`0c0aa609fce939970dfe579e1180a265d7bf2eba` (codeql-openwrt PR #255). The
implementation and this note are untracked in that checkout; nothing was
committed, pushed, or merged.

`tools/default_branch_source_truth.py` reads a frozen manifest, coverage and
routing documents plus three caller-supplied source checkouts. It binds the
manifest selected/excluded lists to the digest-checked v0.6 policy. For the
event repository, it permits only builder-defined commit/blob/SHA identity
deltas, then checks those values against the pinned tree. Non-event policy rows
and source pins must match the frozen policy. It reads source blobs from local
Git, recomputes Git blob IDs and SHA-256 hashes, recomputes selected routes
from source bytes, and compares coverage/routing identities and decisions by
exact multiplicity.

The checkout roots and receipt documents are untrusted supplied inputs. The
tool checks exact HEADs and reads pinned Git tree objects; it does not inspect
worktree cleanliness or attest canonical Git provenance. It does not
authenticate a hosted run, signature, queue action or live completion. It does
not verify installed package bytes, extraction, CodeQL results, or runtime
behavior.

## Exact command and recorded run

Run from the disposable consumer checkout root. All inputs below are in
ledger `work/`; `HOME`, `TMPDIR`, and the captured receipt belong to this run.

```sh
/usr/bin/time -p -o ../run/time.txt \
  env HOME=../home TMPDIR=../tmp \
  python3 -m tools.default_branch_source_truth \
    --manifest ../../source-truth-preflight-45875169837-pr254-20261126/artifact-inputs/default-branch-inputs-45875169837-1/manifest.json \
    --coverage ../../source-truth-preflight-45875169837-pr254-20261126/artifact-inputs/r3-ucode-45875169837-1/default-branch-corpus/out/coverage-default-branch.json \
    --routing ../../source-truth-preflight-45875169837-pr254-20261126/artifact-inputs/r3-ucode-45875169837-1/default-branch-corpus/out/routing.json \
    --luci-checkout ../../source-truth-luci-packages-45875169837-20261126/luci \
    --openwrt-checkout ../../source-truth-preflight-45875169837-pr254-20261126/openwrt-canonical-fetch-attempt \
    --packages-checkout ../../source-truth-luci-packages-45875169837-20261126/packages \
    > ../run/receipt.json
```

The command exited **3**, the documented partial exit: the selected/excluded
rows, their source bytes and routes, and their coverage/routing tuples matched;
candidate source signals remain outside the frozen denominator. The full JSON
receipt is at
`work/source-oracle-verifier-0c0aa60-20261126/run/receipt.json` (SHA-256
`c4494796de1e608da3dcd9f37c8e9018251ccc97aa2cb55e9472bba07568f165`, 73,722
bytes). `time.txt` records 1.81 seconds wall, 1.76 seconds user, 0.94 seconds
system. Peak memory was not captured. Each root receipt has
`worktree_clean_checked: false`; cleanliness is not observed by this tool.

Input document names and SHA-256 values:

| Input | SHA-256 |
|---|---|
| `manifest.json` | `0624f93376829ed47355ee29da61c12d1ee2a9422bbde444e3669760cc9fb097` |
| `coverage-default-branch.json` | `b4f207adcab637f1c7f6147622aee53d1abc9801b96101baa5de899728fa43b5` |
| `routing.json` | `c8cfaf1300d82ff5f7a654424e0910817740853775b8a7b2961e9a2caf163bfa` |

The operator's separate preflight recorded distinct checkouts at these frozen
pins. Worktree cleanliness is not checked by this verifier and is outside its
receipt claim:

| Repository | Commit | Tree | Selected | Excluded |
|---|---|---|---:|---:|
| LuCI | `b2e0be4b46ec0fd43394c081fa7c50657af14011` | `34b39b1f15d8a68898d84cab7f48e87f1ba80ac6` | 65 | 4 |
| OpenWrt | `fef3901d8c9849c0ebab16f5feebdd59be09ef6c` | `e5b13a045395d66a71edd9d1256cb0c7070c8491` | 51 | 1 |
| Packages | `07e0d16305d2b5903b37ad7913e33e18795f81a4` | `a6b0fc0935cbfeedb810e6e991b6940f71548ea7` | 12 | 8 |
| **Total** | | | **128** | **13** |

The event identity binds OpenWrt head `fef3901d8c9849c0ebab16f5feebdd59be09ef6c`
to tree `e5b13a045395d66a71edd9d1256cb0c7070c8491`. The v0.6 policy-row
binding and event-tree binding both passed. Route decisions were rederived
from the pinned source bytes and matched coverage and routing by exact
multiplicity: 93 plain and 35 markup-inconclusive. Excluded coverage rows are
compared as complete canonical rows, including optional commit and blob
fields. Excluded sources without a frozen blob field have their blob IDs
derived from the pinned tree and recomputed from their bytes.

The route oracle file SHA-256 is
`eba5741635bde7b5719d3e60f3bb8847f6603d91d6939c6c5602c02bcca6be9e`, matching
the manifest. The frozen manifest's extractor source digest is
`bc54d2fc6e4dfba095977053d92275c3474bb01ff7e6da7c5301002bde701a11`; it also
records `release_equivalence_verified: false`. This verifier does not fetch or
reverify producer source bytes, so it reports
`release_route_source_bytes_reverified_by_this_tool: false`. The selected
routes are checked against the exact frozen Python route oracle.

### Candidate signals outside the denominator

The frozen source selector contract is reimplemented with bounded local Git
reads for LuCI and OpenWrt. The packages feed uses a separately coded tracked
tree signal census because the frozen selector CLI does not cover that
repository. It counts 4,918 tracked paths and 37 candidate paths: 12 selected,
8 excluded, and **17 source-signal paths outside the frozen denominator**.
The census uses tracked filenames, installed-root path shapes, and
`git grep -I` first-line shebang signals. `-I` omits binary blobs from the
shebang scan, so this is a bounded tracked-candidate signal census, not proof
that every source signal or installable package was found. These signals do
not establish installability or eligibility. Each outside path is recorded
with its pinned-tree mode, blob ID, SHA-256, and signal in the local receipt.
For example,
`net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc` is mode `100644`,
blob `55cfd30bfb0849701ebae44705df23a29ed17f91`, SHA-256
`19727b189472f380b9791b1fc37c4acdec60eea06650f7d845fea8fafbd49315`. No route
decision is claimed for any outside candidate because no installed path is
frozen for it. `tracked_candidate_signals_accounted_for` is `false`.

## Safety and limits

The verifier has bounded JSON, Git-output, blob, and tracked-tree byte limits;
local Git commands have a 30-second timeout. JSON opens use `O_NOFOLLOW` and
`O_NONBLOCK` before checking that the input is a regular file. Git lazy fetch,
replacement objects, system/global config, network protocols, fsmonitor, and
untracked cache are disabled. It does not run `git status` or inspect effective
checkout configuration. It only invokes fixed local Git read commands; it does
not write into source roots, run builds, access credentials, or mutate a queue.

The implementation does not treat matching rows as authenticated execution.
It reports whether caller-supplied source bytes and frozen consumer receipts
agree within the bounded corpus. It makes no claim about the 17 outside
signals, release equivalence, a hosted scan, signature, queue completion, or
installed package bytes.

## Tests and controls

```sh
python3 -m unittest -v tools.test_default_branch_source_truth
```

Result: **15 tests passed**, exit 0. The controls include source-derived route
precedence, a synchronized route lie, source-hash mutation, synchronized
alternate `.uc` selection, `.ut` to rpcd installed-path/route swap, exclusion
promotion, coverage multiplicity and optional excluded identity fields,
duplicate paths, an untracked-worktree object-only observation, FIFO rejection,
and CLI status mapping. A newly committed package `.uc` signal is identified by
its source blob and SHA and remains outside the denominator without an
installability or route claim. The recorded real artifact invocation exited
3, the defined partial status.

CLI exit 0 means no outside candidate signals were found; exit 2 means malformed
or mismatched inputs; exit 3 means the bounded selected/excluded comparison
matched but source signals remain outside the frozen denominator. The expected
raw coverage schema is `ucode-default-branch-corpus-coverage-v1`.

Environment: Git 2.56.1 and Python 3.15.2. The verifier source SHA-256 is
`345a6acae3e6b9c01c45622a43bd8edba13f3f345f56f9e2af18efe90ef8c74b`; the test
source SHA-256 is
`ef8f6434165384a2caff974e717fee61f00bc21172697771f69c03f6cff35de5`. The
receipt and all source checkouts remain under ignored local `work/`; these
paths are not portable evidence.
