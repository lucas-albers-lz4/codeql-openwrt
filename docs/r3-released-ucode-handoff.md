# Released ucode R3 Linux handoff

The lock pins immutable producer prerelease `v0.1.0-rc.1` at commit
`131605a726b7a79eb926886d07bf44eb721fe450`. The archive was
independently downloaded after publication and hashed before the lock was
filled. Pull requests with this populated lock run the live Linux handoff;
the offline contract job runs as well. This page describes the acceptance
contract, while the hosted R3 result must be inspected separately before
claiming a released handoff.

The lock reviewer must independently record the release tag, full tag commit,
release asset URL and SHA-256, manifest and pinned-commit verifier hashes,
extractor and CodeQL executable hashes, QL pack names/versions/lock hashes, and
default suite digest. `release.expected_prerelease` is an explicit boolean pin
for GitHub's release status; the first versioned producer release is expected
to be a prerelease. The runner requires GitHub's `isImmutable` field to be
true, `draft` to be false, and `prerelease` to match that lock value. The Git
tag target, outer asset and CodeQL archive digests are checked before
extraction.
It fetches the bundle verifier from the exact producer commit and checks its
digest. The published producer release includes the versioned publication contract
and verifier options used here. The runner requires `artifact_kind: versioned-release` and the exact tag
in the bundle manifest.

The source-first oracle is `r3-openvpn-source-oracle.json`. Each historical LuCI
commit is fetched into its own checkout and checked for HEAD, clean status,
Git blob and SHA-256. Source bytes are copied verbatim to the proposed installed
path in a separate stage. Actual package-installed bytes remain unverified.
Each case gets separate database, output and caches. The runner checks exact
plain routing, one successful extracted file, zero extraction errors, exact
resolved default-suite query IDs and the SARIF result multiset. It generates
the acceptance manifest before database creation, then passes actual SARIF,
same-job receipt and stage bytes to `tools/sarif_accept.py`. The parent expects
one warning at 71:115–132; the fixed case expects zero results. This is a
bounded historical regression, not a current-corpus or runtime safety claim.

Run with `python3 -B tools/r3_linux_handoff.py docs/r3-release-lock.json
<new-run-root> <run-id>` on Ubuntu 24.04. The run root must be new and have at
least 15 GiB free. GNU `time -v` records wall time, exit and peak RSS for each
external command. All temporary paths, HOME and writable caches are run-owned.
The CI artifact retains the raw SARIF, decoded diagnostics, routing decisions,
accepted consumer record, command logs and normalized receipt; database and
downloaded archives stay only on the ephemeral runner. An unpopulated lock,
failed command, unexpected warning, mismatched identity or parser rejection
fails the job. The same job also prepares a historical event-triage manifest before database
creation, without `expected_results`, and passes each case's actual released
suite SARIF and producer receipt to the event consumer. It requires
`triage_required` with the predeclared OpenVPN parent location and `clean_scan`
for the fixed source. This is a historical consumer drill; it does not claim
an incoming upstream event or Gate 8 completion. The Tailscale historical
matrix remains a separate producer release regression because its testing
query is outside this default suite.
