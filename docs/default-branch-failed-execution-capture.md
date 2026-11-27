# Read-only failed execution capture

`tools.default_branch_failed_execution_capture.capture_failed_execution(private_root,
key, run_id, attempt)` accepts key bytes in process. It has no CLI, key reader,
terminal writer, CAS, artifact download, or automatic retry path. Its typed status is
`verified_failed_execution_bytes`; this is evidence for later review, not a
signed terminal action.

The path validator runs before the existing authenticated-start preflight. The
first database and retained-start I/O boundary is that preflight: a
checked private root, singly linked 0600 database snapshot without sidecars,
HMAC-verified sequence-one head, reservation chain and exact retained start
receipt/API/early ZIP bytes. Only then does the caller generate a 128-bit
CSPRNG invocation ID and open an exclusive 0700 capture directory named with
the run, attempt and ID. A canonical manifest is exclusively written and read
back before network I/O; it binds the ID to the queue, reservation, start, observation,
run, attempt and job. The canonical HTTPS transport fetches the fixed consumer
repository run and attempt-specific complete jobs listing twice, with bounded
direct-200 responses and no credential-forwarding redirect. The signed run,
workflow, authenticated main head, attempt and unique scan job ID must match.
Both run and scan job must be `completed` and carry the same reviewed failure
conclusion: `failure`, `cancelled`, or `timed_out`. Mixed conclusions remain
unresolved. Completion and update times must follow the signed start.
Artifact presence is irrelevant to this branch.

Each of the four raw API bodies is exclusively created, fsynced and read back
under the private root. The two parsed observations must agree. After the
second observation, the same private start is authenticated again, including
its exact signed bytes and singleton sequence-one head. The attempt directory
must have its exact file inventory before staging. The canonical receipt is
exclusively written and fsynced as pending bytes. Publication follows all
directory, parent and root post-use checks; the published receipt is reopened
by its original inode. A readback failure removes the published receipt. A
failure can leave a partial capture directory without `receipt.json`; a later
manual invocation uses a new ID and leaves the orphan for audit. The receipt and return include
the invocation ID and manifest digest under the v2 capture schema. No result from this function authorizes
issuance.

The `contract` job runs synthetic fixture tests with a real fixture HMAC and
queue. They cover terminal failure without any artifact, active/success/mixed
outcomes, run/attempt/job/head/complete-listing mismatch, second observation
drift, changed durable head, legitimate sequence-two advancement, late
directory check failure, extra entries, transport redirect and incomplete
custody, two invocations for one run/attempt, pre-receipt interruption followed
by retry, deterministic ID collision and manifest binding. They do not prove
a live GitHub run or prevent rollback to an older valid store.
Production terminal issuance still needs an independent durable checkpoint,
proof review, a recheck-to-CAS deadline and the issuer's own transaction.

## Review packet

### Invocation naming slice

Base is clean merged #267 `8f7c1ff3ec5960941ad3b4ec1362b33d71c86e30`
(tree `33f5c64e08bfc2766bc79fc220d4b64be21ab899`). The affected contracts
are the capture path, manifest and receipt, and the private issuer reader of
that returned path. The signed terminal document schema and offline issuer
call signature are unchanged. The source-first positive is the signed fixture
start for run 9, attempt 1, job 33 followed by two identical completed
`failure/failure` observations; the active scan job is the eligible near miss.
Before the first network request, the checked root and authenticated database
and retained start are read, then the exclusive invocation directory and
manifest are created. No fixture test opens a live credential or queue. The
focused capture and issuer tests already run in the hosted `contract` job of
`default-branch-commit-scan.yml`. Expected output is the test log; local
budget is under 30 seconds, 2 MiB disk and 100 MiB memory. This change does
not add a witness or authorize a live issuer.

- **Decision and base:** this bounded change starts at merged main
  `8ae2fb4bae82eb770287ed388235b96dd04e0454`. It adds failure byte
  capture without changing `issued_actions`, the signed schema, success proof
  verifier or queue policy. The affected contract is the private read-only
  terminal observation and its `contract` test step.
- **Untrusted bytes and authority:** the operator root and retained files are
  read from a checked private directory; GitHub JSON arrives over the fixed
  canonical HTTPS endpoint. The caller supplies key bytes in process. Only the
  preflight uses those bytes for HMAC verification; the fetch transport sees
  only `GH_TOKEN` from its environment. Neither credential is passed to a
  parser, subprocess argv, raw receipt, or queue writer. This module executes
  no archive member or remote source.
- **Oracle and near miss:** a signed in-progress sequence-one start for run 9,
  attempt 1, job 33 precedes a completed `failure/failure` pair with later
  completion times. A completed `success/success` pair and active job are
  eligible near misses. Mutations of either identity or observation fail.
- **Gate and budget:** `python3 -B -m unittest
  tools.test_default_branch_failed_execution_capture -v` runs in the hosted
  `contract` job. Four bounded API JSON bodies and one small canonical receipt
  are retained; the fixture gate takes under a second locally. No scan or
  artifact download occurs in this slice.
- **Limits:** a synthetic API adapter does not attest the server-side result;
  the production transport's direct-200 rule and token isolation need live
  observation. Reauthentication detects a changed local head before return,
  while an independent checkpoint and a later issuer CAS remain separate
  controls. Exact conclusion matching is intentionally conservative; a mixed
  GitHub run/job outcome is unresolved.
