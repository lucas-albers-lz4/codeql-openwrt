# Reproduction guide

## Scope

This guide describes the approved a3 run. It does not authorize a new run. The run observed one bounded typed handoff. It does not attest to runtime behavior, reachability, authorization impact, or general completeness. Coverage is `partial`.

The executed producer was `ae946190661eb221bc1f562fdba02088ef83de2d` (tree `14fa1a38950e3b5b66bc89fabfb283b1371ba6bf`). The executed consumer was `7f532ac6ab527ee1bf07711fd7942dc4be381b48` (tree `50e58c72e553c24a7d9ef9ae03eeabb294c6e02e`). The approval applies only to the a3 packet and one bounded observed run. See `attempt/approval-content.md`.

## Pinned source and setup references

- [Producer repository at the executed commit](https://github.com/lucas-albers-lz4/codeql-ucode/tree/ae946190661eb221bc1f562fdba02088ef83de2d)
- [Producer README](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ae946190661eb221bc1f562fdba02088ef83de2d/README.md)
- [Extractor pack creation script](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ae946190661eb221bc1f562fdba02088ef83de2d/scripts/create-extractor-pack.sh)
- [Extractor source](https://github.com/lucas-albers-lz4/codeql-ucode/tree/ae946190661eb221bc1f562fdba02088ef83de2d/extractor)
- [Pinned effect query](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ae946190661eb221bc1f562fdba02088ef83de2d/ql/src/m4/SetBlockDetectEffectTable.ql)
- [Pinned successful-extraction query](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ae946190661eb221bc1f562fdba02088ef83de2d/ql/src/diagnostics/SuccessfullyExtractedFiles.ql)
- [Pinned extraction-error query](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ae946190661eb221bc1f562fdba02088ef83de2d/ql/src/diagnostics/ExtractionErrors.ql)

The run used CodeQL CLI 2.27.4. It reused a generated extractor and materialized dependencies. Their exact byte provenance is not authenticated. They are not included in this evidence package. See `packet/provenance.json`, `packet/extractor-pack-inventory.json`, and `packet/resolved-packs-inventory.json`.

## Original approved launcher

The independent audit recorded this clean outer launch on 2026-11-15 at 08:46:16.924320 UTC. Its completion result was exit code 0 at 08:47:25.831146 UTC. The launch used the reviewed bootstrap, manifest digest, acknowledgment digest, and isolated interpreter flags.

```sh
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/python3.13 -I -S -B /root/workspace/workflow-design/live-handoff/issue89-typed-ae946190-7f532ac-a3/trusted/bootstrap.py --packet /root/workspace/workflow-design/live-handoff/issue89-typed-ae946190-7f532ac-a3/trusted --manifest /root/workspace/workflow-design/live-handoff/issue89-typed-ae946190-7f532ac-a3/packet-manifest.json --manifest-sha256 047bfd055820e2512a4b01b4722229e137cba734c4a9a694c50a1edd0ad05dd1 --ack /root/workspace/workflow-design/live-handoff/issue89-typed-ae946190-7f532ac-a3/approval-ack.json --ack-sha256 316a0690c389809b680766e6533e95f05ce820c967e7fe44a4cd8179ee586558
```

The command above is a historical record. The fixed absolute paths do not resolve to this evidence directory. Relocate the packet only after independent review. Then review every changed path, inventory, command, and approval digest before any new run. Do not run the old command unchanged.

## Stages and command semantics

The 15 exact argv vectors, working directories, and environments are in `packet/config.json`. The observed argv, exit status, timing, and separate stdout/stderr digests are in `attempt/logs/*.receipt.json`. Do not infer exact commands from this summary.

The order was: three `resolve library-path` calls; database init; indexing; finalization; three query runs; three BQRS CSV decodes; export; typed import; identical reimport. The exact command names and order are recorded in the packet orchestrator and receipts.

All three resolution and query commands used `--additional-packs` with the inventoried resolved-pack root, `--no-default-compilation-cache`, and explicit external `--compilation-cache` and `--common-caches` paths. Each decode used `bqrs decode --format=csv`. Export and import used `/usr/bin/python3.13 -E -S -B`. Import used `policy.setblock_table --typed-json`. Init, index, finalize, export, import, and reimport flags are preserved verbatim in the receipts and config.

All 15 stages returned exit code 0. The run created one effect row, one successful-extraction row, zero extraction-error rows, and one typed record. Both retained reports changed only at their target rows. Reimport produced byte-identical reports.

## Synthetic tests

`tests/a3-synthetic-normal.log` and `tests/a3-synthetic-optimized.log` are the actual a3 synthetic test logs. Each reports 34 tests passing. These tests validate runner controls with synthetic fixtures and stub subprocesses. They are not live CodeQL, exporter, or importer results.

## Replay limits

The packet uses fixed absolute paths for the original producer, consumer, CodeQL distribution, source, and attempt. It cannot run unchanged from this repository. A new replay needs fresh paths and independent review of the relocated packet.

The generated extractor and dependencies were reused. Their exact byte provenance is not authenticated, and their bytes are not included here. The database and output roots were fresh for the observed run. The full OS, native library, and descendant-tool runtime closure is not proved.

Hashes and receipts establish consistency. They are not signatures, host attestation, or proof against a malicious process. No live OpenWrt, uhttpd, or rpcd execution occurred. No runtime attestation or authorization finding is claimed.
