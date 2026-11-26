# Offline default-branch issued start and terminal actions

`tools/default_branch_backlog_issued.py` adds a deliberate v2→v3 migration,
a sequence-1 start action, and one sequence-2 terminal action. It is an
internal offline module with no CLI, key-file reader, launcher integration or
GitHub client. The migration preserves the prior receipt, backlog and
reservation bytes. The start action still requires one timely reservation;
the terminal action must follow that verified start and may be observed after
the reservation expires.

## Sequence 1: start

The start primitive requires exactly one pending, unexpired reservation and
an empty issued head. It checks the supplied structured attestation against
the reservation's queue ID, action digest, source identity, intake origin,
policy digest, consumer commit and release-lock digest, and compares an
explicit approved consumer/release-lock pair. Its transaction uses
expected-head CAS to append sequence 1 only once. The action envelope is
sorted compact UTF-8 JSON with a trailing newline; its HMAC-SHA256 domain is
`codeql-openwrt/default-branch-issued-action-v1` followed by a newline. The
stored document includes the MAC and has its own SHA-256 action digest.

These checks bind bytes supplied to the primitive. They do not authenticate
the caller's observation time, GitHub run/job/artifact digests, early ZIP or
policy approval. A format-valid forged attestation could be signed by a caller
that has the key. A future private launcher must control both the key and
construction of these fields, recheck the job while it is in progress, and
reject completed or stale attempts before invoking this module.

## Sequence 2: one terminal action

`issue_terminal(...)` accepts only a typed terminal record whose `kind` is
exactly one of `complete`, `failed_execution` or `indeterminate`. It verifies
the sequence-1 MAC with the supplied byte key inside the write transaction,
before append, then binds the same queue ID, reservation sequence and digest,
complete source identity, run ID, attempt, workflow, job ID and job name. It
requires `start_sha256` to equal the sequence-1 action digest. The terminal
envelope is sequence 2
and its predecessor digest is the start digest. `BEGIN IMMEDIATE`, an exact
expected-head comparison and a conditional head update allow only one
terminal action. Both action rows have update/delete triggers and are checked
as one continuous chain.

The start record must already have passed its original `created_at <
observed_at < expires_at` check. Terminal issuance does not re-check
reservation expiry, so an already timely start remains reconcilable after
expiry. Terminal time must be canonical UTC and cannot precede the start.
Sequence 2 does not clear or rewrite `commit_backlog` status, create a retry,
authorize another reservation, or allow a second start. A stale or duplicate
CAS fails closed.

Each terminal kind has an exact evidence object:

| Kind | Typed fields required by this offline schema |
|---|---|
| `complete` | A future `operator-default-branch-authenticated-final-proof-v1` record; `proof_status: independently_authenticated`; proof and canonical-Git source-oracle SHA-256 values; `source_truth: verified_from_canonical_git_objects`; final and early artifact identities; exactly 9 equal frozen inputs; verified discovery-origin replay; `clean_scan` with zero SARIF rows and `no_results`, or `triage_required` with nonzero rows and `triage_required_open`; installed-package bytes remain explicitly false. |
| `failed_execution` | Run and job both report `completed`; both conclusions are one of `failure`, `cancelled` or `timed_out`; the record carries run and jobs API SHA-256 values. |
| `indeterminate` | A fixed reason (`missing_artifact`, `inconsistent_api_state`, `failed_proof` or `operator_quarantine`) and an evidence SHA-256 value. |

The current final-proof verifier returns
`verified_against_supplied_start_only`, leaves source truth open and reports
`alert_disposition: not_evaluated`. That record is rejected for `complete`.
The `complete` shape describes a future independently authenticated proof;
the field names and values alone do not establish that such proof exists.
This module only type-checks and MAC-binds the supplied terminal fields. A
later private completion issuer must independently authenticate every final
artifact, API, source-oracle, archive-replay, extraction and SARIF/consumer
field before it constructs this record. Do not use `complete` from an
operational CLI or launcher until that issuer exists and has been reviewed.
The complete record's early artifact ID, digest and size must equal those in
the signed start, and its final artifact ID must be distinct.

`failed_execution` and `indeterminate` likewise bind only caller-supplied
typed claims. They do not authenticate GitHub responses. `indeterminate` is a
quarantine terminal, not an implicit retry instruction.

## Trust boundary

The existing v2 queue and policy remain local operator inputs. Path, owner,
mode, regular-file, link-count and SQLite sidecar checks are inherited from
the reservation module and run before the database is opened. The caller
passes key bytes directly to the primitive; there is no key-file path or key
reader here. The module performs no network requests, receives no workflow
token and never launches code from a scan artifact.

The expected-head CAS and SQLite triggers provide atomic append behavior and
protect against accidental row edits. HMAC verifies that the holder of the
provided key signed these exact bytes. It does not prove that caller-supplied
API, ZIP, source-oracle, final-proof or failure claims are true. A same-user
process with write access to the SQLite file can bypass SQLite triggers and
recompute unkeyed hashes; a key holder can sign inaccurate evidence. The
private key owner must therefore authenticate all inputs before signing.

## Review packet

| Item | Bounded contract |
|---|---|
| Decision | Add one offline sequence-2 terminal CAS after a verified sequence-1 start. No operational CLI, retry, dispatch or backlog-status update is included. |
| Producer revision | `codeql-openwrt` clean disposable checkout at base `674735d016567945225b6303e440bc68dab40488`; candidate branch is `codex/default-branch-terminal-cas-v3` in ignored `work/default-branch-terminal-cas`. The local capture checkout's `origin` was not used for network access or push. |
| Affected contracts | Issued envelope sequence/predecessor, HMAC and action hash verification, one-reservation identity, start-expiry rule, terminal-after-expiry rule, append-only SQLite rows, pending backlog status, outcome evidence typing, and the default-branch contract workflow. |
| Oracle and positive | Disposable two-intake fixture from `tools.test_default_branch_backlog_intake.Fixture`; reserve one exact fixture row, migrate to v3, issue one valid start, then issue one typed terminal for the same queue/source/run/attempt/job/start digest. Each terminal kind gets a valid control. Fixture archives are synthetic; no upstream source corpus is used. The test policy pins `docs/r3-release-lock.json` bytes at SHA-256 `53ef87cdaa69ae58be3da9386f4e710050309368649f8ae886c0a7f9ee5c2526`. |
| Eligible near misses | Current supplied-start-only final proof; wrong source identity and float/bool identity values; altered early artifact ID, digest or size; sequence-2 start-shaped document passed to the start parser; stale sequence/hash; late start after expiry; duplicate and concurrent terminal; forged MAC after hash/head rewrite; raw terminal-document tamper; mismatched clean/triage count. Each must leave the terminal head unchanged. |
| Test-to-CI map | `python3 -B -m unittest tools.test_default_branch_backlog_issued -v` is a separate contract step in `.github/workflows/default-branch-commit-scan.yml`; the incoming-discovery contract also runs the complete issued module. No live scan job is part of this local check. |
| Expected artifacts | Disposable SQLite roots and fixture files under ignored `work/`; no corpus run or generated artifact is committed. No key is read from disk; tests use a fixed disposable byte key. |
| Resource budget and observed run | Python 3.15.2 with SQLite 3.54.1. Local Python tests only; no network, CodeQL build, database extraction or full-corpus scan. The 27-test issued module passed in 0.727 seconds; the 122-test adjacent contract set passed in 4.454 seconds normally and 4.090 seconds under `-O`. Peak memory was not measured. |

Before any later live terminal issuer, review its first API/artifact I/O,
credential boundary, proof-to-field mapping, source-object replay and exact
head. The offline tests do not establish freshness, API authenticity, final
artifact custody, source truth, scan execution, consumer correctness or
operator-key custody.

Run the focused issue tests with:

```sh
python3 -B -m unittest tools.test_default_branch_backlog_issued -v
```
