# Default-branch final proof verifier

Status: bounded implementation slice, based on consumer commit
`2aa4b63161e0cf59968ea603446d0402debdd56d` (the private live-start launcher
merge). The verifier is in `tools/default_branch_final_proof.py`; the
contract tests run in the default-branch workflow's contract job.

## Decision and boundary

This slice prepares a read-only final-artifact proof for one default-branch
scan attempt. It consumes supplied completed run, jobs and artifacts API
bodies; the final and early ZIP bytes; a supplied issued-start document; and
the existing captured v2 reservation/archive store. It does not fetch live
API data, execute CodeQL, read a key, verify an HMAC, write a queue transition,
or assign alert disposition. The function returns
`verified_against_supplied_start_only`; this is a binding to the supplied
document, not an authenticated start or queue completion. A later private
terminal issuer must check the durable v3 issued chain and MAC.

The optional `require_issued_start_head=True` path now replays the same
claim against a v3 read-only queue snapshot. It requires the supplied canonical
sequence-one document bytes to match the exact unkeyed issued head, and binds
the claimed run, attempt, job and reservation to that document. This is a
snapshot structural check; it neither verifies the HMAC nor proves that the
head remains current after the snapshot. The default v2 path and its receipt
shape remain unchanged for historical retained-run analysis. A future private
issuer must authenticate the start with its key, capture and validate final
bytes in the same invocation, and recheck the head inside sequence-two CAS.

This v3 integration increment is based on clean merged consumer
`98e02b5165d26c9b8a7633f923f7c602f83a9b3f`. It changes only the
reservation replay and final-proof call contract. The fixture oracle
is one pending reservation and its exact signed start at sequence one.
An unissued start, changed MAC byte, changed scan job ID, stale head and
sequence-two head are eligible near misses. The contract job already runs
`tools.test_default_branch_reservation_reconcile`,
`tools.test_default_branch_final_proof` and
`tools.test_default_branch_backlog_issued`. These offline controls use no
CodeQL database, source fetch, network call, key file or live queue.

The implementation reuses
`tools.default_branch_reservation_reconcile.reconcile_bytes` to replay the
captured v2 reservation, intake receipt and archived discovery origin. It does
not migrate or modify the queue. The only writes are temporary files used by
that existing archive replay under the caller's run-owned work directory.

## Checks performed

- Canonical completed run, unique scan job and final artifact metadata are
  supplied together. The artifact must be non-expired, run-linked, successful,
  and match the final ZIP's exact size and SHA-256. The early artifact is
  checked against the completed artifacts listing and its ZIP digest/size.
  GitHub binds artifact metadata to a run, not directly to the uploading job;
  the job relation remains a same-run inference.
- Raw ZIP central and local filenames are checked before `zipfile` parsing,
  including rejection of NUL bytes, mismatched local/central names, duplicate
  entries, unsafe paths, directories, links, special files, encryption and
  unsupported compression. The final ZIP must have exactly 9 frozen inputs,
  16 fixed R3/corpus files, and three command-output files for each recipe
  label derived from the selected and eligible excluded manifest rows.
- The early receipt must list exactly nine source/claim/API members. Those
  nine members are compared byte for byte to the final artifact. The
  `validated-default-branch-manifest.json` in the final artifact must also
  equal the frozen manifest bytes.
- The archived claim and discovery origin are replayed against the exact v2
  reservation and retained archive receipts. The supplied start envelope is
  shape-checked and bound to the same run, attempt, unique job, reservation,
  source identity, origin, consumer policy, release lock and early artifact.
  A MAC-shaped string is not treated as a verified MAC.
- R3 must report `accepted` for its exact receipt schema, an immutable release,
  a clean consumer checkout, the approved release-lock digest, and matching
  release asset/manifest/producer, CodeQL binary, query suite and resolved-rule
  identities. Its root command transcript must match the receipt digest and
  contain the 48 labels in the reviewed R3 recipe exactly once, with every
  command exit status zero. A failed or altered R3 receipt or command is
  rejected.
- The source manifest, routing receipt, coverage receipt, producer receipt,
  decoded successful/error query JSON, SARIF and consumer triage JSON are
  checked for exact digests and identity multisets. Each selected installed
  path must route once and occur once in decoded successful rows; error rows
  must be empty. SARIF result tuples are compared with the consumer's retained
  tuples with multiplicity. `clean_scan` requires zero tuples;
  `triage_required` requires one or more exact tuples and means human
  disposition remains open.

The check covers decoded JSON row consistency. The final ZIP contains
`successful.bqrs` and `errors.bqrs`, but this slice does not decode those BQRS
files or independently bind them to the retained decoded JSON; it also does
not rerun CodeQL. The result is therefore not an execution attestation.

## Source-truth limit

The final artifact contains a manifest, source hashes and route claims, but no
staged source bytes. The verifier can replay the archived claim and check
internal identities, but it does not independently establish the source
selection or route oracle. Full source truth needs fresh canonical Git object
retrieval for the pinned source commits plus a rederived selector and route
oracle. The retained run reports 128 selected and 128 successfully extracted
files, with 93 plain routes, 35 markup-inconclusive routes, 13 excluded inputs
and zero extraction errors. It records
`actual_package_installed_bytes_verified: false`.

## Review packet

| Item | Bounded contract |
|---|---|
| Decision | Verify the final default-branch artifact against supplied start bindings before a separate private completion transition. No completion transition is included here. |
| Base | Clean disposable consumer checkout at `2aa4b63161e0cf59968ea603446d0402debdd56d`; this implementation checkout is under ignored `work/default-branch-final-proof-impl`. |
| Affected contracts | Completed run/job/artifact metadata, raw ZIP member inventory and custody bytes, early/final freeze equality, v2 claim/origin replay, R3 release and command receipts, corpus route/extraction receipts, SARIF tuple and consumer triage multiplicity. |
| Oracle and positive | Retained run `45875169837`, attempt 1, scan job `140100374363`, early artifact `15144223386`, final artifact `15144917516`. The final ZIP has 520 regular members: nine frozen inputs, 16 fixed R3/corpus files, and 165 command triples. |
| Eligible near misses | Changed one frozen input byte; extra or duplicate member; unsafe/NUL name; wrong attempt/job; failed R3 receipt; altered route or extraction multiplicity; `clean_scan` paired with a result; collapsed duplicate SARIF tuple. |
| Test-to-CI map | `python3 -B -m unittest tools.test_default_branch_final_proof -v` runs in the `contract` job of `.github/workflows/default-branch-commit-scan.yml`. That workflow already selects `tools/**` on pull requests. The live scan job is not a test gate for this verifier change. |
| Expected artifacts | No generated artifact is committed. Raw APIs, ZIPs and the v2 queue/archive remain under ignored `work/default-branch-early-live-retry-20261126/`. |
| Resource budget | The verifier performs no network request, build or CodeQL scan. It reads at most the existing 64 MiB ZIP limit and 128 MiB expanded-member limit; peak memory was not measured. |

The local real-run control completed in about 2 seconds. It used a synthetic,
zero-filled MAC field solely to test that the returned value keeps
`mac_verified: false`; no key or signer was used. The measured output was
`clean_scan`, zero exact SARIF tuples, 128 successful extraction identities,
zero extraction errors, and 9/9 early/final byte-equal frozen inputs. Final
ZIP SHA-256: `44ef942823a2a460c9b20dd57730965ca8ae124c5da8407ced4fdebfd195bc1e`.
Early ZIP SHA-256: `179b74ab48757cc1c0966e3b5e313546f072085b3f52677046115007d08f5ea4`.
It also validated all 48 R3 command transcript rows with zero failed exits.
The observed consumer disposition remains `not_evaluated`.

This control is not an authenticated start or completion, a source-truth
replay, a BQRS check, an installed-package byte result, or a finding
disposition. It does not close the later private terminal issuer gate.

## Full v3 retained-artifact fixture

On the merged PR #265 base `d3bd691f120050404cc3bb1c6ee4585c747c4a53`
(tree `2415a5550dd5ef462096e0ecd4050d8dd58be03b`), the opt-in
`RetainedRunV3FullProofTests` test exercises the public
`verify_final_proof(..., require_issued_start_head=True)` call over the
retained early and final ZIP bytes, the actual in-progress and completed API
bodies, and a copy of the captured v2 reservation/archive store. The source
oracle is loaded and pinned before inspecting ZIP members:
`rederived-manifest-at-674.json`, SHA-256
`b920839d1bd1e19f14b99491fbdc22f0b240e3a4841b46a01edb22f2a6adf506`.

The early artifact is ID `15144223386`, 14,611,319 bytes, SHA-256
`179b74ab48757cc1c0966e3b5e313546f072085b3f52677046115007d08f5ea4`.
The final artifact is ID `15144917516`, 14,906,724 bytes, SHA-256
`44ef942823a2a460c9b20dd57730965ca8ae124c5da8407ced4fdebfd195bc1e`.
The six supplied API bodies matched their retained receipt hashes. The exact
result was `verified_against_supplied_start_only`, with nine frozen members
equal, all 128 selected identities and 13 excluded identities matching the
pre-output oracle, routing 93 plain and 35 markup-inconclusive files, 0
extraction errors, `clean_scan`, and empty SARIF and consumer result tuples.
The verifier checked 48 R3 command rows and 165 corpus command rows. Both
`start_binding.mac_verified` and
`claim_origin_replay.database.start_mac_verified` were false.

The test copied the captured v2 queue and nine archive files into a new local
work directory, migrated only that copy to v3, then created a sequence-one
start with a test-only key. Its synthetic `observed_at` of
`2026-11-26T18:22:00Z` falls after early artifact upload and before scan-job
completion. The recheck digests reuse the same supplied early observation;
they are synthetic and do not model an independent API recheck. The original
queue, archives, API bodies and ZIP files were rehashed after the run and
remained byte-identical. The raw public return and expected control failure
reasons are retained as `public-proof.json` and `controls.json` under ignored
`work/default-branch-v3-final-proof-*/` in the disposable checkout. The ledger
retains a small normalized receipt with artifact, API, start, database,
control and public-return digests; it does not copy the large raw artifacts
into versioned evidence.

The fixture rejected five controls with specific causes: changed start bytes,
stale issued head, changed final `identity.json`, wrong scan job ID, and wrong
attempt. Run it only when the retained inputs are available and explicitly
set:

```sh
CODEQL_OPENWRT_RETAINED_RUN_ROOT=/path/to/ledger/work/default-branch-early-live-retry-20261126 \
CODEQL_OPENWRT_SOURCE_ORACLE=/path/to/ledger/work/source-truth-preflight-45875169837-pr254-20261126/rederived-manifest-at-674.json \
python3 -B -m unittest \
  tools.test_default_branch_final_proof.RetainedRunV3FullProofTests.test_full_public_v3_proof_and_discriminating_controls -v
```

The fixture is skipped when the retained-run variable is absent and fails if
the configured input bundle is incomplete. Its successful clean result is a
bounded retained-run replay, not a source-derived negative security result.
The run had no real signed start; source provenance, BQRS-to-decoded-row
provenance, installed package bytes, authenticated completion and alert
disposition remain open.
