# Issue #89 typed handoff evidence

This directory preserves evidence from the approved, observed typed handoff. It records the producer and consumer commits that ran. This evidence-only commit did not run in that handoff.

## Executed revisions and approval

| Item | Value |
|---|---|
| Producer commit | `ae946190661eb221bc1f562fdba02088ef83de2d` |
| Producer tree | `14fa1a38950e3b5b66bc89fabfb283b1371ba6bf` |
| Producer archive SHA-256 | `02b6ba5b341ba8767cb174a175af1d504b2396d9dbceb776e5b367e2129082cb` |
| Consumer commit | `7f532ac6ab527ee1bf07711fd7942dc4be381b48` |
| Consumer tree | `50e58c72e553c24a7d9ef9ae03eeabb294c6e02e` |
| Consumer archive SHA-256 | `3c11037e2daedcf115794a8843452178e9e1d19534f58a01b719b68ed6a1c7c6` |
| Approved packet manifest SHA-256 | `047bfd055820e2512a4b01b4722229e137cba734c4a9a694c50a1edd0ad05dd1` |
| External approval acknowledgment SHA-256 | `316a0690c389809b680766e6533e95f05ce820c967e7fe44a4cd8179ee586558` |
| Bootstrap SHA-256 | `6e91c66a9f7c856f01c376687947634e0037ca966349f7e3dc7035b580e5620c` |
| Python interpreter SHA-256 | `889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9` |

The copied approval files are in `attempt/`. The packet manifest binds the approved packet. `packet/` contains the execution recipe, config, oracles, provenance, and key inventories. It is a selected copy, not the complete approved packet.

## Execution record

The attempt has 15 stage receipts and 45 separate raw stdout and stderr files. Each receipt preserves the actual argv, working directory, environment, exit status, timing, and stream hashes. The stages were three library resolutions, database init, index, finalize, three queries, three decodes, export, import, and reimport.

All 15 commands returned exit code 0. The attempt retained the three BQRS files and decoded CSV files. It also retained typed exporter stdout, before/after/reimport report bytes, routing, the source archive, and a finalized database inventory. The live database itself is not included.

The exact argv for each stage is in its `attempt/logs/*.receipt.json` file. The approved command configuration is in `packet/config.json`. These paths describe the original environment. They are evidence, not a promise that the old commands can run unchanged from this repository.

## Observed result

The effect query returned one row. The successful-extraction query returned one row. The extraction-error query returned zero rows. The exporter returned one typed record.

The source hash is `6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e`. The preserved source archive hash is `c3a841f0f08290af2c73624d376008f109de5a39211e42ae48ac3c5e173d5ab8`. The source bytes came from a prior fetch and were reused in this run.

Routing selected one `plain_route_selected` result at `usr/share/rpcd/ucode/luci`. The route reason was `rpcd_raw_mode_full_path`. Excluded, uncertain, duplicate, and markup counts were zero. Finalization removed the original routing tree. The index receipt binds the retained routing file by hash.

Both retained reports changed from CSV revision `step3:setblock-table-v1` to typed revision `step3:setblock-typed-import-v1`. The target row changed in each report. The other 60 rows stayed unchanged. Both reimported reports match their post-import bytes exactly.

The retained grants include the primary `luci-mod-system-mounts` grant and supplementary `root` grant. The unauthenticated `setBlockDetect` decision remains a deny. No unauthenticated grant was emitted. Required unknowns remain present.

The independent audit re-decoded all three BQRS artifacts. The resulting CSV bytes matched the retained CSV files. It also checked exact headers, values, source paths, JSON types, grants, denies, report transitions, and reimport identity.

## Test results

The independent audit ran both complete Python unit suites from clean archives of the executed commits. Raw output and receipts are in `tests/`.

- Consumer: 850 tests passed. Command: `/usr/bin/python3.13 -E -S -B -m unittest discover -s policy/tests -t . -v`.
- Producer: 47 tests passed. Command: `/usr/bin/python3.13 -E -S -B -m unittest discover -s tests -v`.

The consumer suite ran against the exact executed consumer commit. The producer suite ran against the exact executed producer commit. These are Python unit suites. This evidence does not claim that all Rust or CodeQL smoke suites ran during the independent audit.

## Limits

Coverage is `partial`. This run does not establish general analysis completeness, runtime reachability, or an authorization violation. It did not execute live OpenWrt, uhttpd, or rpcd services. It does not authenticate producer output or attest to a hostile host.

The generated extractor and materialized dependencies were reused prepared bytes. The run did not prove that the extractor was rebuilt from the merged producer commit. The database and query outputs were fresh, but the full toolchain and runtime were not rebuilt. OS, native library, and descendant-tool runtime closure remain unproved.

Hashes and receipts show consistency. They are not signatures or cryptographic attestation. Coverage remains partial, and this evidence does not close broader issue #65.

## Integrity and files

`SHA256SUMS` lists the SHA-256 digest of every other file in this directory. It includes exact hashes for raw receipts, streams, artifacts, packet files, and test output.

- `attempt/artifacts/`: retained output bytes, including before, after, and reimport reports.
- `attempt/logs/`: all raw stage receipts and separate stdout/stderr streams.
- `attempt/approved-manifest.json`: approved packet manifest.
- `attempt/approval-ack.json`: external approval acknowledgment.
- `attempt/approval-binding.json`: manifest and acknowledgment digest binding.
- `packet/`: selected approved recipe, config, oracle, provenance, and input inventory files.
- `tests/`: independent 850-test and 47-test output, receipts, and retained transition analysis.

This evidence-only commit changes no producer or consumer inputs that were executed. It does not assert that this later commit was executed.
