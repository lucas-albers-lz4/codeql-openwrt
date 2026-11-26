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
  identities. A `failed` or altered R3 receipt is rejected.
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
| Affected contracts | Completed run/job/artifact metadata, ZIP member inventory and custody bytes, early/final freeze equality, v2 claim/origin replay, R3 release receipt, corpus route/extraction receipts, SARIF tuple and consumer triage multiplicity. |
| Oracle and positive | Retained run `45875169837`, attempt 1, scan job `140100374363`, early artifact `15144223386`, final artifact `15144917516`. The final ZIP has 520 regular members: nine frozen inputs, 16 fixed R3/corpus files, and 165 command triples. |
| Eligible near misses | Changed one frozen input byte; extra or duplicate member; unsafe/NUL name; wrong attempt/job; failed R3 receipt; altered route or extraction multiplicity; `clean_scan` paired with a result; collapsed duplicate SARIF tuple. |
| Test-to-CI map | `python3 -B -m unittest tools.test_default_branch_final_proof -v` runs in the `contract` job of `.github/workflows/default-branch-commit-scan.yml`. That workflow already selects `tools/**` on pull requests. The live scan job is not a test gate for this verifier change. |
| Expected artifacts | No generated artifact is committed. Raw APIs, ZIPs and the v2 queue/archive remain under ignored `work/default-branch-early-live-retry-20261126/`. |
| Resource budget | The verifier performs no network request, build or CodeQL scan. It reads at most the existing 64 MiB ZIP limit and 128 MiB expanded-member limit; peak memory was not measured. |

The local real-run control completed in 3.9 seconds. It used a synthetic,
zero-filled MAC field solely to test that the returned value keeps
`mac_verified: false`; no key or signer was used. The measured output was
`clean_scan`, zero exact SARIF tuples, 128 successful extraction identities,
zero extraction errors, and 9/9 early/final byte-equal frozen inputs. Final
ZIP SHA-256: `44ef942823a2a460c9b20dd57730965ca8ae124c5da8407ced4fdebfd195bc1e`.
Early ZIP SHA-256: `179b74ab48757cc1c0966e3b5e313546f072085b3f52677046115007d08f5ea4`.
The observed consumer disposition remains `not_evaluated`.

This control is not an authenticated start or completion, a source-truth
replay, a BQRS check, an installed-package byte result, or a finding
disposition. It does not close the later private terminal issuer gate.
