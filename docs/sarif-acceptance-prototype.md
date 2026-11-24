# Proposed SARIF acceptance boundary

`tools/sarif_accept.py` is an offline, fail-closed prototype for an eventual fresh CodeQL-to-OpenWrt CI handoff. It reads SARIF v2.1.0, an independently prepared source-first manifest, a producer run receipt, and a staged source root. It prints accepted result identities without modifying policy reports.

```sh
python3 -B tools/sarif_accept.py \
  --sarif <fresh-result.sarif> \
  --manifest <source-first-manifest.json> \
  --receipt <same-job-producer-receipt.json> \
  --source-root <staged-files>
```

The manifest schema is `ucode-sarif-acceptance-v1`. It supplies `producer` (`sha`, `pack_sha256`, `codeql_version`, `suite_sha256`), `sources` with relative `%SRCROOT%` URI and SHA-256, exact `expected_extracted` file identities, `required_rules`, and an exact `expected_results` multiset of rule ID, URI, SARIF start/end line/column and effective level. Expected SARIF columns use `utf16CodeUnits`; a source oracle's byte-inclusive end column needs explicit review and conversion to SARIF's exclusive end column. Historical vulnerable and fixed versions use separate manifests and databases.

The receipt schema is `ucode-sarif-run-v1`. It repeats the producer identity, records nonempty `run_id`, `sarif_sha256`, exact `successful_files`, `extraction_errors`, `resolved_rules`, and command argv/exits. The verifier rejects failed commands, extraction errors, source hash differences, missing/duplicate extracted files, unknown or missing rules, unsafe URIs, invalid locations, and any missing or additional result. It requires a CodeQL SARIF run whose tool version agrees with the manifest. A result can omit `level`; the verifier uses its rule descriptor's default level.

This prototype **does not authenticate** a fabricated receipt or prove that the supplied SARIF came from CodeQL. The future Linux CI job must run the pinned producer, generate the receipt from its actual commands and diagnostics, and pass the same SARIF bytes to this verifier in that job. The current consumer's CSV and typed setBlockDetect adapters are separate contracts; this prototype does not change them. It does not map package source to installed bytes or scan incoming upstream revisions yet.

Seven focused rejection tests run with:

```sh
python3 -B -m unittest policy.tests.test_sarif_accept -v
```

Offline shape probes against the experimental OpenVPN and Tailscale explicit-query SARIF files succeeded with constructed receipts. Those probes establish parser compatibility with the observed SARIF fields only. Neither is a fresh consumer handoff or default-suite release result.
