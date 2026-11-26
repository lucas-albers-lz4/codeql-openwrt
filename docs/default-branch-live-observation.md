# Read-only default-branch live observation verifier

## Decision and boundary

This slice adds an object-only verifier for one claimed default-branch scan
before its run finishes. It reuses the v3 queue's read-only reservation,
receipt and action checks, replays the retained discovery archives and source
claim, and checks the exact early artifact against canonical API bytes. It
does not fetch data, read a key, call `issue_start`, sign, or write to the
private queue.

The verifier accepts saved bytes. It can establish that those bytes are
internally consistent and describe the expected run and job as in progress;
it cannot establish when or where the caller captured them. It returns
`verified_bytes_only` plus validated start components and byte digests. The
later private launcher must perform the two live fetches, record its
observation time at the second fetch, exclusively retain the raw observation
receipt, and compute `observation_sha256` from that retained receipt before
any signing step.

## Revisions and affected contracts

- Base: `1a811399f024a63f8e4e5c63938d8dac8e1832a2`, PR #251 merge. The fresh
  checkout's origin is `https://github.com/lucas-albers-lz4/codeql-openwrt.git`;
  the canonical `main` ref resolved to this same SHA during preflight.
- Candidate: this uncommitted working tree, based on the exact base above.
- Affected contracts: v3 issued-chain empty-head validation; v2 reservation
  and discovery-archive replay; `default-branch-start-<run>-<attempt>` ZIP
  contents and receipt; the default-branch scan workflow contract suite.
- The completed-run reconciler retains its completed-run contract and its
  permissive scan-artifact selection. The new early-artifact reader applies
  its own exact ten-member contract.

## Source-first oracle and controls

The early ZIP must contain exactly one regular file for each of the nine
`default_branch_start_artifact.SOURCES` paths and one root-level `receipt.json`.
The downloaded ZIP stores those relative paths at its root; the exact run and
attempt are bound by the artifact name and receipt. No directory, extra,
duplicate, encrypted, traversing, or nonregular member is eligible. The receipt must
bind each of the nine source files by exact byte count and SHA-256. The
manifest inventory digest must match `inventory.json`; the claim, identity,
manifest, checkpoints and gap must then replay against the archived intake
origin and exact pending reservation.

The canonical run and unique `released-default-branch-scan` job must name the
approved consumer head, workflow-dispatch on `main`, exact run and attempt,
`in_progress`, and a null conclusion. The one-page jobs and artifacts
listings must be complete. The early artifact must be unexpired, run-linked,
named for the exact attempt, and match the ZIP's digest and size. A second
run/jobs byte pair must again show the same run, attempt, head and job ID live.
The private v3 issued head must be empty.

Synthetic tests cover a valid positive plus completed-run, forged valid-format
triplet, changed source despite a recomputed receipt, policy mismatch, stale
issued head, duplicate/extra/symlink ZIP members, incomplete or ambiguous API
listings, attempt/head/job mismatch, and changed recheck identity. The captured
completed run `45875169837` is also a local negative-only input when its raw
bytes are available; it is never used to issue a start.

## Gate and resource budget

`tools.test_default_branch_live_observation` runs in the `contract` job of
`.github/workflows/default-branch-commit-scan.yml`. The gate also runs
`actionlint` and `git diff --check` locally. The suite uses synthetic fixtures;
when the ignored local capture exists, one optional test also parses its actual
95,093,559-byte checkpoint pair and checks completed-run rejection. No CodeQL
database, upstream source checkout, network request or credential is needed.
Expected runtime is under five minutes and peak memory below 1 GiB, bounded by
the existing 128 MiB ZIP expansion ceiling plus the small discovery replay
fixture. The function writes no report artifact; it returns an in-process
`verified_bytes_only` mapping with the validated components and raw-byte
digests. Unit fixtures are removed after the test run.

## Known limit

`verified_bytes_only` is not a freshness assertion, a signed start, proof of
scan completion, or queue state transition. The future launcher and its exact
second-fetch receipt remain outside this slice.
