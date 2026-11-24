# Released ucode R3 Linux handoff

This job is prepared but cannot pass until `r3-release-lock.json` is filled from
an immutable producer GitHub Release. Its current null pins deliberately fail
before any network access or database creation. Pull requests run only the
offline contract job while all release pins are null. A partially populated
lock fails; once all pins are populated, pull requests run the full live
handoff. Manual dispatch with a null lock fails. A CI candidate artifact is
not accepted as a release.

The lock reviewer must independently record the release tag, full tag commit,
release asset URL and SHA-256, manifest and pinned-commit verifier hashes,
extractor and CodeQL executable hashes, QL pack names/versions/lock hashes, and
default suite digest. The runner checks GitHub's `isImmutable` release field,
the Git tag target, outer asset and CodeQL archive digests before extraction.
It fetches the bundle verifier from the exact producer commit and checks its
digest. Producer draft PR #158 adds the versioned publication contract and
verifier options used here; its review, release policy and publication remain
open. The runner requires `artifact_kind: versioned-release` and the exact tag
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
fails the job. The Tailscale historical matrix remains a separate producer
release regression because its testing query is outside this default suite.
