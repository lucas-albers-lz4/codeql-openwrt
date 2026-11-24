# Bounded current-source Linux gate

This gate runs after the released-producer OpenVPN parent/fix handoff in the
same Ubuntu job. It reuses that job's pinned immutable release and CodeQL
CLI, then creates an independent run directory, source checkouts, database,
cache, `HOME`, `TMPDIR` and outputs. The release lock must be populated;
an all-null lock skips the live job on PRs, and partial locks fail.

The frozen [source manifest](current-corpus-source-v0.6.json) has SHA-256
`9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490`.
Its status and boundaries retain their **pre-run oracle wording** so the
source expectation is not rewritten after observing results. The later local macOS run is separate evidence; this job will supply the Linux result.
It selects 128 source files at exact LuCI, OpenWrt and packages-feed commits:
65 LuCI, 51 OpenWrt and 12 packages-feed. Expected routes are 93 plain and
35 markup-inconclusive. The 17 wifi-scripts Ucode files assume
`CONFIG_WIFI_SCRIPTS_UCODE=y`; package configuration and installed bytes
are not verified. Thirteen excluded identities remain outside the selected
denominator.

The runner checks clean pinned source checkouts, Git blobs and SHA-256 for
every selected file, excluded source bytes, exact staged hashes and unique
proposed installed paths before extraction. It checks each route tuple and
successful extracted identity with multiplicity, zero extraction errors,
then emits `out/coverage-v0.6.json` with every selected source, route,
extraction count and the 13 explicit exclusions. It records markup-model
inconclusiveness separately from extraction success. It checks the
released suite rule IDs, and the actual SARIF through the consumer's
strict `sarif_accept.py` in the same job. The initial baseline is **zero**
direct-rule alerts, as observed in the refined local macOS v0.6 source-staged run. A Linux
alert fails this gate for source review; zero alerts do not prove source
safety or comprehensive query coverage.

The preceding R3 receipt is trusted as part of this one CI job's execution
chain. Its JSON alone cannot authenticate an independent run; the workflow
must execute R3 successfully immediately before this script.

GNU `time -v` records wall time and peak RSS for each command. The artifact
retains the current-corpus preflight, command log, coverage, routing/diagnostic/SARIF
outputs, accepted consumer record and terminal receipt or failure. This
first Linux job establishes a bounded source-staged scan and cost; it does
not complete installed-byte provenance, broader package selection,
incoming-change selection or maintainer-ready MVP gates.
