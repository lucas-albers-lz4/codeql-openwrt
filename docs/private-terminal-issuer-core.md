# Private terminal issuer core (incremental candidate)

Base: clean `6de8563d72ecd5cd3fab437057ea7c47f44d1ecb` (merged #266).
This branch adds a **failure-only** sequence-two issuer core. It has no CLI,
live key access, live root, GitHub call, or queue dispatch in its tests. The
fixture key and root are disposable. A signed `failed_execution` in these
fixtures is an offline authority-flow check, not a live terminal action.

## Decision, oracle, and gate

The decision is whether a fresh exact-run failure can become a signed
sequence-two action without a caller supplying the outcome or digests. The
positive fixture signs a sequence-one start, then supplies two complete,
identical terminal `failure/failure` run/job API observations through the
canonical capture's in-process test seam. The eligible near miss is the same
signed start with an active run. Wrong attempt, post-capture self-consistent
replacement, writer-handoff database replacement, and expired transaction
deadline are separate rejection controls. The test compares the exact v1/v2
backlog rows before and after issuance and checks the HMAC-verified sequence-two
head plus all four signed API digests against retained bytes.

Affected contracts: v3 terminal evidence accepts a new
`operator-default-branch-terminal-observation-v2` shape while retaining the
existing v1 reader; `issue_terminal` accepts optional transaction freshness
and expected storage-identity guards. The `contract` job of
`default-branch-commit-scan.yml` runs
`tools.test_default_branch_private_terminal_issuer`. The expected artifact is
the hosted test log. No hosted gate has run for this local candidate.

## Trusted path and current limits

`issue_failed_execution(root, key, run_id, attempt)` authenticates the exact
sequence-one HMAC, reservation, origin-linked start observation, and retained
early ZIP through the merged preflight. It invokes the merged canonical
two-observation failure capture itself. It reopens the invocation-specific
capture path derived from the returned ID, checks the exact manifest,
directory inventory, readback hashes and the capture-returned receipt
digest, and rederives the exact run/job outcome from all four raw API files.
It reauthenticates the start and compares root/database inode and metadata
fingerprints before CAS. The writer checks the expected storage fingerprint
before SQLite open and again inside `BEGIN IMMEDIATE`; the transaction checks
the exact start/head/queue/reservation and a monotonic deadline. The new signed
evidence binds the capture receipt digest, both run/jobs digest pairs, and the
reservation policy SHA. It never accepts a caller proof path, API bytes,
outcome, digest, or terminal attestation.

The deadline is checked before commit; it does not bound a blocked SQLite
commit. A stable second GitHub observation narrows but does not eliminate the
API-to-CAS race. A hostile writer with the issuer's own UID could still race
path opens; the live issuer requires a private OS account and stronger
first-I/O isolation review. An interrupted pre-CAS capture leaves an auditable
orphan and a new invocation can capture the same run/attempt. The signed
receipt digest transitively binds the invocation ID and manifest; the issuer
also returns that ID. Recovery that trusts only a committed, authenticated
action remains required. This core
does not maintain an independent durable head checkpoint, so a restored older
valid queue could pass HMAC checks. No live launcher or key-loading path is
provided. Do not call it with a live key until these gates are resolved.

## Completion path still required

The same issuer design needs a `complete` branch in the trusted invocation.
It must capture both canonical terminal observations and exact early/final
ZIPs; pass exact sequence-one bytes and captured bytes through
`default_branch_final_proof.verify_final_proof`; acquire canonical Git objects
and independently derive the frozen source and route oracle, using
`canonical_source_preflight` and `default_branch_source_truth`; run the pinned
consumer privately over retained SARIF and compare exact semantic output and
SARIF tuples using `default_branch_consumer_replay` and
`default_branch_sarif_tuple_proof`. Only then can it derive `complete` fields
and call the same sequence-two CAS. The current read-only final proof is not
a signing warrant. Success with failed proof needs a reviewed explicit
`indeterminate` policy; transient API failure or an active execution writes
no terminal action.

Before a live pilot, add the approved completion policy and explicit binding
to the reservation's policy and the approved start-policy bytes; OS-isolate
ZIP/source/consumer workers from the key and queue; pin the interpreter and
import path before private I/O; keep an external durable head checkpoint with
crash reconciliation outside the queue restore unit; add post-CAS recovery;
review the first I/O and credential
boundary; run exact-head hosted contract, unittests and typed-handoff gates.
The canonical source verifier remains partial on the 17 outside-v0.6
packages-feed signals described in the ledger, and this change does not
claim installed package bytes, independent CodeQL execution, or alert
disposition.
