# Proposed SARIF acceptance boundary

`tools/sarif_accept.py` is an offline, fail-closed prototype for an eventual fresh CodeQL-to-OpenWrt CI handoff. It reads SARIF v2.1.0, an independently prepared source-first manifest, a producer run receipt, and a staged source root. It prints accepted result identities without modifying policy reports.

```sh
python3 -B tools/sarif_accept.py \
  --sarif <fresh-result.sarif> \
  --manifest <source-first-manifest.json> \
  --receipt <same-job-producer-receipt.json> \
  --source-root <staged-files>
```

The manifest schema is `ucode-sarif-acceptance-v1`. It supplies `producer` (`sha`, `pack_sha256`, `codeql_version`, `suite_sha256`), `sources` with relative `%SRCROOT%` URI and SHA-256, exact `expected_extracted` file identities, `expected_rules` (the exact resolved suite rule set), `expected_sarif_descriptors` (the exact descriptor set CodeQL emits for that scenario), and an exact `expected_results` multiset of rule ID, URI, SARIF start/end line/column and effective level. CodeQL can resolve a diagnostic query yet omit it from SARIF descriptors when it has no SARIF result; the observed two-diagnostic default suite emitted an empty descriptor list. Expected SARIF columns use `utf16CodeUnits`; a source oracle's byte-inclusive end column needs explicit review and conversion to SARIF's exclusive end column. Historical vulnerable and fixed versions use separate manifests and databases.

The receipt schema is `ucode-sarif-run-v1`. It repeats the producer identity, records nonempty `run_id`, `sarif_sha256`, exact `successful_files`, `extraction_errors`, `resolved_rules`, and command argv/exits. The verifier rejects failed commands, extraction errors, source hash differences, missing/duplicate extracted files, unknown or missing rules, unsafe URIs, invalid locations, and any missing or additional result. It requires a CodeQL SARIF run whose tool version agrees with the manifest. A result can omit `level`; the verifier uses its rule descriptor's default level.

This prototype **does not authenticate** a fabricated receipt or prove that the supplied SARIF came from CodeQL. The future Linux CI job must hash the actual producer checkout, pack and suite, run extraction and the resolved default suite on the staged bytes, generate the receipt from its actual commands and complete diagnostics, and pass the same SARIF bytes to this verifier in that job. The current consumer's CSV and typed setBlockDetect adapters are separate contracts; this prototype does not change them. It does not map package source to installed bytes or scan incoming upstream revisions yet.

Nine focused acceptance and rejection tests run with:

```sh
python3 -B -m unittest policy.tests.test_sarif_accept -v
```

Offline shape probes against the experimental OpenVPN and Tailscale explicit-query SARIF files succeeded with constructed receipts. Those probes establish parser compatibility with the observed SARIF fields only. Neither is a fresh consumer handoff or default-suite release result.

A separate local macOS handoff used fresh CodeQL databases for the historical
OpenVPN parent and fix plus pinned LuCI `swconfig`, resolved a draft default
suite, and passed its actual SARIF bytes to this parser in a disposable
consumer checkout. The parser accepted one parent alert at 71:115–132 and
empty fixed and `swconfig` results. The orchestrator generated manifests from
pinned source before extraction and receipts from decoded diagnostic paths,
resolved query metadata, command exits and SARIF bytes. This is local
contract evidence; it does not pin a released producer artifact, run Linux
CI, map installed package bytes or scan incoming upstream revisions.

The [R3 OpenVPN source oracle](r3-openvpn-source-oracle.json) pins the parent
and fixed LuCI commits, blobs and source hashes before a versioned producer
release is chosen. It records one parent SARIF result and zero fixed results,
with exact stage paths and suite-rule expectations. Its producer identity is
unset until an immutable release is published and independently pinned.
