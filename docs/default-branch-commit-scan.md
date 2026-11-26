# Linked default-branch commit scan

The manual `default-branch-commit-scan.yml` workflow runs only from consumer
`main`. Its linked predecessor and successor may be successful
`workflow_dispatch` or scheduled discovery runs. It accepts exact run IDs, attempts,
checkpoint digests, a gap digest, one first-parent commit SHA and a distinct
canonical control SHA. It checks the run metadata, downloads both named
artifacts, verifies their digests, replays the gap and resolves the selected
commit against canonical Git objects. A commit outside the bounded linked
interval fails before source selection or CodeQL. Pull requests run only the
contract tests; their checkout cannot produce a released scan receipt. The
scan itself remains a manual dispatch; scheduled discovery does not trigger it.

The manual inputs also accept an optional all-or-none `queue_id`,
`reservation_sequence`, and `reservation_sha256` triplet. After linked-gap replay,
canonical commit resolution, and source-first manifest construction, the job
retains `reservation-claim.json` in its always-upload scan artifact. On claim
validation failure, the tool attempts to write `reservation-claim-failure.json`
to that artifact with `status: claim_failed` and no asserted reservation
values; if that write fails, the workflow still fails and reports the error in
its logs. A generated claim record is either `absent` or
`claimed_unverified` and binds any caller-asserted triplet to the exact
repository/ref/commit/tree/first-parent/ordinal, predecessor and successor
checkpoint and gap digests, discovery run IDs and attempts, workflow run and
attempt, consumer head, identity receipt, and manifest bytes. Malformed or
partial triplets fail the job before the scan.

After a successful claim, the job uploads a separate
`default-branch-start-<run>-<attempt>` artifact **only** when the claim status
is `claimed_unverified`. It is prepared and uploaded before the R3 handoff and
corpus scan. The artifact contains the exact `reservation-claim.json`,
`identity.json`, `manifest.json`, `inventory.json`, `previous/decisions.json`,
`current/decisions.json`, `current/gap/gap.json`, and the fetched
`previous-run-api.json` and `current-run-api.json`, plus `receipt.json` with
the byte count and SHA-256 for every payload file. The writer reads bounded
regular files without following their final symlink, requires private run
inputs and exclusive private outputs, checks the claim-bound identity,
manifest, checkpoint and gap digests, checks the inventory bytes against the
manifest digest, verifies the linked discovery run API identities, and reads
the frozen copies back to compare them with the captured source bytes. The
decision and gap paths match the final artifact's relative layout. The final
`default-branch-scan-<run>-<attempt>` artifact remains an independent
always-uploaded artifact.

This early artifact is an observation and has no signer or queue mutation. Its
name does not attest that the job was live when an operator fetched it, that
R3 started, that the scan completed, or that the asserted triplet matches the
private backlog. It does not authorize a start or establish queue state. A
`claimed_unverified` status remains an unverified caller assertion.

The hosted job does not read the private backlog, match a queue row or action,
or compare this triplet with the private intake receipt or artifact origin. A
well-formed forged triplet therefore remains
`claimed_unverified`; it does not authorize a scan, record a start or completion,
or establish queue state. The claim is retained before the scan. The scan receipt
links the same manifest to its SARIF digest, but this increment adds no separate
postscan link receipt and does not authenticate execution or artifact custody.
The replayed linked discovery run/checkpoint/gap values are the supplied scan
inputs; they are not a verified private queue origin.

An operator can compare a retained run-bound scan artifact with the local
reservation and retained intake archives using the read-only
[reservation claim reconciliation](default-branch-reservation-reconciliation.md).
That step validates the claim and input identities only. GitHub artifact
metadata is run-bound rather than job-bound, and the local action, policy and
operator fields remain unkeyed claims; reconciliation does not write a start,
completion, scan outcome or coverage state.

`tools/default_branch_corpus_manifest.py` applies frozen v0.6 candidate
policy to the exact first-parent-to-commit interval. It stages the full
selected corpus at the commit and retains the other repositories at their
policy pins. It compares the source-first manifest with fresh Git objects,
routes and selected/excluded identities, including relevant recipe drift
from the policy pin. The distinct `mvp-default-branch-commit-corpus-v1`
schema includes linked checkpoint/gap digests and contains no PR number.
A new candidate, changed excluded source or unreviewed recipe drift fails
closed for policy review.

After a same-job immutable R3 handoff, `tools/default_branch_corpus_linux.py`
rebuilds that input oracle, snapshots its bytes in a run-owned directory and
runs the released extractor and default suite. It requires exact successful
file identities, zero extraction errors and matching routes before passing
the actual SARIF to the triage consumer. Its directory, coverage and receipt
schemas are separate from PR and historical OpenVPN runs. A clean result is
only a bounded result for the selected source-staged files; the control SHA
is an identity reference and is not asserted as a clean or fixed scan.

This manual path exercises a real linked upstream direct commit. The daily
read-only discovery schedule does not dispatch it or create a durable commit
backlog. Each gap is tied to one predecessor/successor pair; if a later
discovery advances the checkpoint, unscanned commits from the older gap are
not carried into the next gap. Scan only from the exact retained gap, and do
not describe scheduled discovery as per-commit scan coverage. A durable
one-item-per-cycle scan needs a bounded backlog with completion and retry
receipts before it can advance across gaps. GitHub discovery artifacts expire
after 30 days. Source paths are projected to reviewed installed paths; actual
installed package bytes remain unverified. This pilot does not satisfy Gate 8
without a predeclared incoming known alert and control.
