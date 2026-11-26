# Default branch consumer replay

`tools.default_branch_consumer_replay` replays the actual event triage consumer
against supplied early and final artifacts. Run it from the disposable
`codeql-openwrt` checkout that contains this verifier; provide a separate
checkout at the consumer commit recorded in the final manifest, plus the three
source checkouts at the recorded pins.

The verifier reads ZIP members through the bounded reader in
`default_branch_final_proof.py`; it never calls `ZipFile.extract`. It requires
the early artifact's exact ten-member layout and validates the receipt, then
compares all nine frozen input files byte-for-byte with the final artifact. It
checks the final R3 inventory and command receipts, consumer/SARIF/route digests,
and the exact consumer commit. It reads `sarif_accept.py` and the v0.6 policy
from that commit's Git objects, requires both files to equal the implementation
base, and writes the consumer script into private run scratch before execution.

Selected stage files come only from the source Git objects named by the frozen
manifest. The existing source-truth verifier checks the pinned policy, selected
and excluded identities, source hashes, and selected routes. Its partial
outside-denominator result stays partial; local Git objects do not prove
canonical Git provenance. The consumer runs with `-I -S -B`, an isolated
`HOME`/`TMPDIR`, a 60-second timeout, and bounded output. Scratch and the
create-only receipt path must be outside every input checkout.

The verifier requires exact byte equality between the replayed consumer stdout
and archived `out/triage.json`, then checks the full packet, status, and a
seven-field tuple multiset with multiplicity. A duplicate SARIF tuple remains
two results; the verifier does not collapse it into a set. Whitespace-only
output changes fail byte equality.

## Run

Use a fresh work directory for each attempt. The output parent must already
exist, and the receipt path must not exist:

```sh
python3 -B -m tools.default_branch_consumer_replay \
  --final-zip <retained-final.zip> \
  --early-zip <retained-early.zip> \
  --consumer-checkout <consumer-at-manifest-event.consumer_commit> \
  --luci-checkout <luci-at-manifest-pin> \
  --openwrt-checkout <openwrt-at-manifest-pin> \
  --packages-checkout <packages-at-manifest-pin> \
  --work-root <fresh-run-owned-work-directory> \
  --output <new-receipt.json> \
  --expected-consumer-base <full-implementation-base-sha>
```

The receipt includes ZIP and frozen-input digests, checkout commit/tree
identities, consumer and policy hashes, exact child argv/exit/stdout/stderr
digests, phase timings, tuple multiplicity, and limitations. Worktree status is
not run by the replay: source verification reads pinned Git objects through the
existing object-only helper. Record checkout cleanliness separately during
operator preflight. Keep raw ZIPs, scratch, consumer stdout/stderr, and the full
receipt under ignored `work/`.

## Offline controls and hosted gate

`tools.test_default_branch_consumer_replay` invokes the real consumer for a
two-row duplicate tuple and a zero-row near miss. It also rejects stale SARIF
digests, changed input, whitespace-only and multiplicity-mismatched output,
duplicate ZIP members, excessive JSON nesting, unsafe stage paths, output
aliases, wrong source pins, and source hash changes. The default branch scan's
hosted `contract` job runs this module alongside the final-proof contract.

This replay establishes reproducibility for supplied bytes. It does not
authenticate the GitHub capture or artifact uploader, attest hosted command
execution or freshness, sign a start/completion, mutate a queue, rerun CodeQL,
establish package-installed bytes, or assign alert disposition.
