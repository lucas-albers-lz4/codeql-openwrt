# Offline consumer graph prerequisite

This experimental library is not an issuer and has no queue, signing, or CLI
entry point. `check_scan` expects a manifest already independently replayed by
`current_corpus_linux.validate_event_manifest`, and a separately pinned and
verified release lock. It does not perform either operation. It reads the
scan's fixed paths, rejects duplicate JSON keys and symlinked artifacts,
checks the actual manifest bytes against the caller-replayed object and links
them to preflight, coverage, and corpus receipts. It reconstructs the coverage
rows and consumer input from the manifest and lock, compares decoded
successful-file and error diagnostics and routes to that oracle, and calls the
actual `sarif_accept.triage` implementation on the retained SARIF, input and
producer receipt. Its computed triage must equal the retained triage and
corpus status. It also checks run/release identities, command success and
required labels, selected command executables, arguments and output paths,
and the relevant artifact digest links. The caller supplies the trusted consumer
revision for cross-checking; it is not independently verified here.

This is only an offline consistency check. Caller-controlled files and command
receipts can be fabricated; path checks do not prevent concurrent substitution.
It does not authenticate execution, freeze artifacts, verify all command argv or
lock and release, resolve a fresh event, replay the manifest, recheck Git/source state, bind or compare a distinct control,
verify an assertion, inspect a queue reservation, enforce predecessor CAS, or
issue any attestation. A valid MAC on invented data would remain insufficient.
Integrating this library alone into a signer would be unsafe. The release lock
at the pinned base has null fields, so a real released run cannot yet pass the
required R3 preflight. See the ledger same-job issuer contract before building
an issuing path.

The tests use synthetic files and invoke the real consumer implementation. They
are not evidence that CodeQL or an actual scan ran.
