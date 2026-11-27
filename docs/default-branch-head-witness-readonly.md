# Read-only head-witness fixture contract

Status: independently reviewed local candidate; hosted exact-head checks
pending. This API neither reads a witness service nor authorizes a live
sequence-two action.

## Decision and source boundary

The candidate starts from clean merged `codeql-openwrt` #269 commit
`2f1d2f460c017e3a0b305655c7ff1506ef914ec2`, tree
`a66c249a654cad1797b1b4edb5e6ede7a9cd0b9e`. The decision is whether a
complete, independently authenticated witness record stream and an HMAC-verified
fixture queue head describe one of the narrow recovery states in the ledger's
terminal issuer recovery design. This adds a parser/classifier and hosted
fixture check, plus a read-only authenticated SQLite snapshot helper. It does
not change the existing issuer, queue writer, capture, key handling, or
released scan job.

The source oracle, before interpreting the classifier result, is the merged
`verify_issued_chain` contract: a signed start has sequence 1 and its exact
document SHA-256; one fresh failed execution appends sequence 2 with a different
exact digest. The existing fixture supplies both the signed positive and the
eligible active-job near miss. The expected state matrix is:

| Witness stream | Authenticated queue | Decision |
|---|---|---|
| Final start head 1, no intent | Same head 1 | `ready` |
| Pending digest D after head 1 | Exact head 2 D | `finalize_pending` |
| Final head 2 D after pending D | Exact head 2 D | `existing_terminal` |
| Pending D | Original valid head 1 | `quarantine` |
| Final head 2 D | Older valid head 1 | `freeze` |
| Missing, mismatched or divergent witness | Any head | `freeze` or validation error |

The method returns candidate state names for an offline caller to inspect. It
performs no finalization, rebootstrap, reservation, retry, signing, or queue
mutation.
`ready` is a fixture state, not permission to sign. A production caller must
freshly authenticate the latest **complete** returned witness history, not
individual authentic records or a saved prefix. A prior valid prefix plus a
restored older queue could otherwise appear `ready`. Even a
`finalize_pending` classification requires exact retained invocation manifest,
receipt, signed action and reservation checks before any finalization.

## Record bytes and custody

Each record is an exact newline-terminated canonical JSON object (sorted keys,
compact separators, UTF-8, at most 4096 bytes) with version
`default-branch-head-witness-record-v1`. It has exactly `witness_id`,
`queue_id`, `queue_generation`, `reservation_sha256`, `kind`, `sequence`,
`issued_sha256`, `base_issued_sha256`, `previous_record_sha256`, and
`invocation_id` plus `schema`. IDs are 128-bit lowercase hex strings; digests
are lowercase SHA-256 hex strings. The first record is head 1 with zero base
and predecessor; the second is an intent for sequence 2 and one exact digest;
the third, if present, finalizes that same digest and invocation. Each
predecessor hashes the exact previous raw record. No caller-supplied head digest
can replace a missing record.

The classifier accepts **bytes**, not witness paths. Its first witness I/O is
therefore owned by a future caller: authenticate the witness service identity
and one fresh latest complete returned stream. The queue adapter
`read_authenticated_head_snapshot(root, key)` checks the root and database
owner, mode, regular-file/link/inode identity and sidecars before the first
SQLite parse, deserializes a bounded no-follow read-only image, and binds the
HMAC-verified issued head, signed start digest and reservation digest from that
single image. Its plain dictionary is process-local trusted verifier output;
never pass an externally supplied JSON object in its place. The separate store
must be outside the queue restore unit and inaccessible to the queue writer. This
candidate does not implement witness first-I/O or its credential boundary. The
existing offline issuer still has no witness gate and must not be used as a
live launcher.

## Controls and gate

`python3 -B -m unittest tools.test_default_branch_head_witness
tools.test_default_branch_private_terminal_issuer -v` runs the focused local
positive, active-job near miss, missing/mismatch, older valid queue head,
pending-intent, malformed/canonical byte, chain, generation and unauthenticated
head controls. The `contract` job in
`.github/workflows/default-branch-commit-scan.yml` executes the new test
module on a hosted exact head. Its expected artifact is test output only; no
database, key or witness artifact is published. The local check should take
under 10 seconds and 10 MiB of temporary fixture disk; no CodeQL extraction,
package build, network call or live workflow is needed. The existing issuer
fixture remains a separate gate. Independent review and exact-head hosted
contract, unit and typed-handoff gates are required before any promotion.

The fixture derives its start and queue digest from a disposable signed v3
queue. Its witness bytes are synthetic and are not an external monotonic store.
The test cannot prove durable append semantics, API authenticity, rollback
resistance, first-I/O safety, or a live terminal observation.

## Local candidate receipt

The source checkout was clean at the base SHA and tree above before editing.
`docs/r3-release-lock.json` SHA-256 was
`53ef87cdaa69ae58be3da9386f4e710050309368649f8ae886c0a7f9ee5c2526`.
Python was 3.15.2. With run-owned `HOME` and `TMPDIR` under ignored `work/`,
the command below exited 0: 25 tests passed in 0.852 seconds; wall time was
0.97 seconds. `git diff --check` also exited 0.

```sh
HOME="$PWD/work/witness-readonly-test-20261126/home" \
TMPDIR="$PWD/work/witness-readonly-test-20261126/tmp" \
/usr/bin/time -p python3 -B -m unittest \
  tools.test_default_branch_head_witness \
  tools.test_default_branch_private_terminal_issuer \
  tools.test_default_branch_authenticated_start -v
```

`/usr/bin/time -l` ran an earlier 24-test version but exited 1 because sandboxed
`sysctl kern.clockrate` was denied. Peak memory was therefore unavailable; the
subsequent `-p` command is the successful timing receipt. No hosted run has
occurred for this candidate.

Independent review found that the first draft accepted an issued-head mapping
plus separately supplied start and reservation digests. A valid sequence-two
head could have been paired with unrelated witness anchors. The added control
uses a genuine signed sequence-two snapshot and two self-consistent witness
streams with a substituted start or reservation; both now reject. The adapter
binds all three identities from one checked, read-only database image. Review
also found that hash linking alone cannot establish witness freshness; the
caller contract now requires one fresh, authenticated latest complete stream.
The independent reviewer reported no remaining blocker on the revised
contracts and passed 83 adjacent tests, Ruff, actionlint and whitespace
checks on the reviewed code. Those local checks do not substitute for a
hosted exact-head gate.
