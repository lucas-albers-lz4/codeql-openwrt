# Issue 93 bounded actual-run evidence

This directory is a portable evidence export, not a runnable recipe. **Do not replay these commands and present the replay as the historical execution.** The original execution was observed on 2026-11-15 under the approved fixed recipe; the launch and approval digests are recorded in `capture/`. Any new run is new evidence and requires a fresh approval/context, separate output root, and separate audit.

## Files and byte status

`artifacts/` contains routing, all three BQRS/CSV result pairs, and the actual consumer JSON. `capture/artifact-digests.json` gives each published file's SHA-256/size and the original scratch-file SHA-256/size. The routing JSON, BQRS files, and extracted CSV have local attempt paths redacted in the published copies; their original byte streams were retained in the execution scratch evidence and their original digests are recorded. They are therefore **not byte-identical exports**. `errors.csv`, `table.csv`, and `comparison.json` are byte-identical raw outputs. Receipts and command trace redact machine-local absolute roots; they are metadata, not raw stdout streams.

`receipts/` contains per-stage stdout, stderr, exit statuses and the actual shell trace, where present. Separate files remain separate; no merged transcript substitutes for output bytes. `capture/launch.json` binds the observed launch return code/timing and parent supervisor results. `capture/approval-and-inventory.json` binds the external parent approval digest, approval-context digest, input inventory identifiers and before/after checks. `capture/phase-status.json` lists actual phase exits. The external approval accepted the disclosed reused extractor; preparation's `execution_authorized=false` field is retained as a historical preparation field and does not negate the separate approval.

## Reproduction/verification

To verify the portable export, run `sha256sum -c SHA256SUMS` from this directory. `capture/artifact-digests.json` additionally links redacted published bytes to the original raw SHA-256 values. Independently review `audit/summary.md` and `audit/verified-outcomes.json`; they summarize a separate audit, rather than generating outputs. The launch timestamp, recipe hash, recipe-block hash, approved consumer commit and producer merge/tree relationship are recorded in the metadata. No full database, dependencies, compilation caches, source archive, full input inventories, or complete private scratch capture is copied.

## Scope and limits

Producer `d54c17a8cefc43ef9cde36d65558c986348aa7b2` was merged, but execution used a PR-head export independently verified to have identical complete Git tree `b259eb7fb16cbfe6669a8e434d6493c90b393fdb`; it was not a merge checkout. Consumer actually executed was `804d1386c54f4c273ca593e5dd2051636aa19245`. This evidence-only commit follows that consumer and was not executed. Extractor is reused, byte-pinned preparation, not rebuilt; no build attestation. No OS/runtime/cryptographic execution attestation. Three source-only matches are not denials or an ACL/security conclusion. Hashes demonstrate consistency of retained bytes, not cryptographic execution provenance.
