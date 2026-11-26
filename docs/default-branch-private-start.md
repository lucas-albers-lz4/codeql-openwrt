# Private default-branch live start launcher

Status: implementation packet for the first trusted live-start operator
entry point. No live invocation is authorized by this document. The target is
one newly dispatched default-branch job that is still `in_progress` when its
start is issued.

## Decision and exact revisions

- Consumer base: clean detached `456359574bbf3a5346d8d51cc5ddd9588ba930d0`
  (tree `d57fe162b2e26d852b2b49b03d6a548e6b2e17b0`), the actual GitHub main
  merge of PR #252; parent `1a811399f024a63f8e4e5c63938d8dac8e1832a2`.
- Candidate: uncommitted implementation diff in this disposable checkout; no
  candidate commit/tree was created. The owner will assign the exact head/tree
  when committing after review. Changed files are the launcher, v3 signer
  deadline, focused tests, contract workflow and this packet.
- Pre-commit source/workflow content identity: `71467b66e5fd3bff7740a5dfce2112ecb2777e589e878e742f9488a8cdfb83de`, SHA-256 over the four sorted source/workflow paths and their exact bytes (path, NUL, 8-byte big-endian length, bytes for each file); it excludes this packet.
- Producer: immutable prerelease `v0.1.0-rc.1`,
  `131605a726b7a79eb926886d07bf44eb721fe450`; no producer code changes.
- Affected contracts: v3 empty issued-head/CAS, the PR #252
  `verified_bytes_only` verifier, the exact early-artifact and GitHub API
  shapes, the private 0600 key, policy-file schema, and the local checkout
  trust boundary.
- Tool preflight at implementation start: `git 2.56.1`, `gh 2.104.0`,
  `Python 3.15.2`, macOS 15.6 arm64. Free disk reported 78 GiB; no heavy scan
  or database build is planned.

## Source-first oracle and eligible controls

The launcher accepts no caller-supplied attestation or observation JSON. Its
only live input is a positive run ID and attempt, plus a pre-created private
root. The fetched run must be the exact approved repository, workflow,
`workflow_dispatch` on `main`, approved consumer SHA, attempt, and live run.
The one-page jobs and artifacts listings must be complete; exactly one
`released-default-branch-scan` job and one attempt-named early artifact must
match. The ZIP digest/size and exact ten regular members are checked by the
merged verifier. That verifier must return `verified_bytes_only`; it must not
return a caller-created sign-ready attestation.

The independent private policy binds queue ID, consumer repository and full
commit, release-lock SHA-256, workflow, job, and an approval record. It is
read from a fixed path under the private root with duplicate-key, owner, mode,
link-count, no-follow and byte-bound checks. It is compared with both the
clean local checkout and verified queue components; the reservation's
unkeyed policy is not the approval source.

Positive: the existing synthetic live-observation fixture, adapted to a fake
`gh api` process and a disposable v3 root, with a live run/job and exact early
ZIP. Eligible near misses include a completed run or job, wrong attempt/head,
wrong queue or private approval policy, altered ZIP/API bytes, a stale issued
head, and key/policy/receipt path aliases. The retained completed run
`45875169837` is an explicit rejection-only control; the generic live-state
contract must reject it before key read or `issue_start`.

Local verification used the retained raw run/job/artifact API bytes for
`45875169837`; the launcher rejected the completed run after three read-only
fake-`gh` responses, before key access, receipt creation or signing. Hosted CI
does not depend on ignored ledger `work/` data and always runs the synthetic
completed-run/job control.

## First I/O and credential boundary

1. Parse only bounded integer run/attempt arguments and fixed root path.
   Require an existing operator-owned 0700 root with safe ancestors outside
   the checkout and its ignored `work/`, `/tmp`, `/private/tmp`, configured
   temporary directories, and macOS per-user `var/folders/.../T` storage.
2. Require a clean checkout whose full `HEAD` equals the private policy's
   approved consumer SHA. Hash the tracked release lock from that checkout.
   Read only the fixed policy path with `O_NOFOLLOW`; do not inspect or read
   the signing key yet.
3. Fetch only fixed canonical `gh api --hostname github.com` run, jobs,
   artifacts and artifact-ZIP endpoints in a local trusted process. Do not
   pass run-controlled data to a shell. Bound each raw API response to 16 MiB
   and the ZIP to 64 MiB; retain command, exit status, duration, byte count and
   raw SHA-256. API and ZIP bytes stay untrusted until verifier success.
4. Re-fetch run and jobs immediately before the in-process verifier and record
   the internal UTC observation time at the second fetch. Re-read and compare
   the exact policy bytes and clean checkout/release-lock identity after
   verification. Reject if signing would occur more than 30 seconds after the
   second fetch; the v3 transaction checks the monotonic deadline after lock
   acquisition and again before commit.
5. Invoke the merged `verify_live_observation_bytes` directly. Compare its
   returned queue, commit, release lock, workflow and job identities with the
   independently approved policy. Do not accept a serialized result from CLI
   or disk.
6. Exclusively create a private per-run/attempt directory and retain all six
   fetched raw bodies: initial run/jobs/artifacts, early ZIP, and the second
   run/jobs pair. Each file is a 0600 no-follow singly-linked regular file,
   created with `O_EXCL`, fsynced, and read back for byte/hash equality.
   Exclusively create and fsync the receipt after those files. It binds their
   paths, digests and sizes, policy digest/approval provenance, internal
   observation time, fetch commands/results, and verified identities. Any
   partial capture blocks key access and CAS; the same run/attempt cannot
   overwrite it.
7. Only after all checks and receipt retention, open fixed `issuer.key` with
   no-follow/nonblocking flags. Require operator ownership, mode 0600, one
   link, a regular file and at least 32 raw bytes. Then call `issue_start`
   with the verifier components plus the retained receipt SHA-256 and exact
   expected issued head `(0, ZERO_HASH)`. The v3 signer revalidates the
   reservation under its immediate transaction and performs the CAS.

The policy's approval fields are a protected local operator record, not a
cryptographic identity assertion. The operator must provision that file only
after independent review of the exact queue/consumer/release-lock/workflow/job
tuple. The private signing key is never passed to `gh`, a hosted runner, or a
caller-controlled process. The root checks reject known system and per-user
temporary locations; an alternate temporary mount not named by the host may
still require operator-specific review. The job can complete after the
second fetch and before the local SQLite CAS. The 30-second deadline is
checked inside the v3 transaction and before commit, which narrows but does
not eliminate that non-atomic race; the start attestation records both
fetches.

## Gate map and resources

- Local focused gate: `python3 -B -m unittest
  tools.test_default_branch_private_start -v`; tests use disposable roots and
  a fake `gh` executable, and assert that rejected cases do not read the key
  or call the signer. Result: 16/16 passed, including the actual retained
  completed-run negative.
- Hosted contract gate: `.github/workflows/default-branch-commit-scan.yml`
  now runs `tools.test_default_branch_private_start` and
  `tools.test_default_branch_backlog_issued` in the existing `contract` job.
  The wired contract command passed 125/125 tests in 6.088 seconds. No hosted
  signer, key or network fetch is added.
- Local static gates: `actionlint
  .github/workflows/default-branch-commit-scan.yml` and `git diff --check`
  both exited 0. A read-only security review found no blocking code gap.
- No full-corpus or CodeQL run was needed. Each of the five API bodies is
  bounded at 16 MiB and the ZIP at 64 MiB, so six simultaneously retained raw
  inputs have a 144 MiB maximum before Python object/copy overhead. The
  verifier separately bounds expanded ZIP members at 128 MiB. Budget 1 GiB
  for transient process memory; peak RSS was not measured.
- Expected artifacts: code, focused tests, workflow gate wiring, this packet,
  and the test command/results above. The actual observation receipt is
  created only by a later authorized live invocation in the operator's
  durable private root.

## Review questions and stop conditions

Review the first filesystem write, receipt no-replacement behavior, policy
provenance semantics, the interval from second fetch to issue CAS, all paths
that may reach the key, and the exact caller surface. A completed job, policy
mismatch, invalid root/key path, stale checkout or issued head, incomplete API
page, API/ZIP mismatch, or verifier error must fail closed before key read and
must never issue a start. Do not write to a hosted environment, create a live
receipt, or claim fresh issuance while running these local tests. The job can
still complete after the second fetch and before the local SQLite CAS; the
30-second freshness bound narrows but does not eliminate that race.
