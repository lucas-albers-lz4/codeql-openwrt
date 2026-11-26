# Historical direct-commit released Linux runner

`tools/direct_commit_corpus_linux.py` accepts the immutable R3 release lock,
historical direct-commit corpus manifest, identity receipt, admission check,
candidate inventory, clean source/control checkouts, and a fresh R3 handoff
root and run ID. It invokes the existing released corpus runner with a
separate five-input direct-commit context. Before any extraction, that runner
rebuilds the manifest from the pinned historical policy and exact source
objects, compares every manifest field, and requires 112 selected paths,
11 exclusions, `kind=direct_commit`, no PR number and the historical policy
digest. The ordinary three-input PR event and frozen v0.6 paths retain their
existing validators.

The R3 handoff must have completed in the same clean consumer checkout and
run ID. The runner then copies the pinned release bundle and dependencies
into a new run-owned directory, fetches exact source pins, checks selected
and excluded source bytes, compares routing identities and successful-file
diagnostics, runs the default suite, emits SARIF and invokes the event triage
consumer. It snapshots the validated manifest bytes into its run-owned
directory before using their digest in preflight, coverage and the final
receipt. The direct run uses its own `direct-commit-corpus` directory and
receipt/coverage schemas, separate from PR event runs.

The frozen `direct-commit-openvpn-alert-v1.json` oracle requires exactly one
released SARIF result at the source-first OpenVPN rule and location. Other
results remain visible for triage. Zero results, a moved location or a
duplicate known result fail this historical run; no success receipt is
written. A fixed/no-alert control requires a separate contract, and this
wrapper rejects `control-corpus` reuse for a direct-commit context.

This adapter makes a released historical scan possible; source-first
manifest validation and unit tests alone do not prove one occurred. The
historical identity probe did not replay live linked gap/checkpoint bytes.
Actual installed IPK bytes, a clean/no-alert control and live Gate 8 remain
separate evidence requirements.
