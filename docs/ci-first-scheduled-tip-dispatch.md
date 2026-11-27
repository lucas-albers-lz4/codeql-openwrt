# Scheduled default-tip CodeQL scans (internal pilot)

The existing daily read-only discovery runs at 07:17 UTC. When that **scheduled**
run completes successfully, `ci-first-scheduled-tip-dispatch.yml` reads its
retained checkpoint and first-parent gap. For each changed OpenWrt or LuCI
default branch, it requests one existing
`default-branch-commit-scan.yml` run for the **latest observed tip**. An
unchanged repository requests nothing. The cap is two requests per dispatcher
attempt.
Pull-request contract runs and manual discovery runs cannot dispatch scans.

The dispatcher fetches and checks the current and predecessor GitHub Actions
run API records and named artifacts. It requires exact run IDs, attempts,
repository, workflow path, completed-success status, and scheduled current
event. It compares both checkpoint digests and the gap digest, replays the
retained first-parent gap, then verifies the selected tip/tree/parent chain.
Its only write permission is `actions: write` in the dispatch job; the scan
workflow keeps `actions: read` and `contents: read`. The dispatcher does not
check out or execute upstream source. The contract and dispatch jobs use the
same immutable dispatcher commit, retained in the artifact. Each downstream scan independently
rechecks the linked discovery records, canonical Git objects, source-first
manifest, pinned release, extraction identities, SARIF and consumer result.

The dispatcher artifact records the exact input plan and each API dispatch
attempt. A successful dispatch API response means the request was accepted;
it does not identify or prove a downstream run. Delivery is **at least once**:
a dispatcher rerun or a failure after one of two accepted requests can launch
duplicate read-only scans. Their distinct run/attempt artifacts must be
reviewed separately. Review the downstream `default-branch-scan-*`
artifact and job summary for selected/extracted/excluded files, errors,
`default-suite.sarif`, `triage.json`, timings and failure status. The SARIF is
an Actions artifact; this pilot does not upload GitHub Code Scanning alerts.

This is a daily default-branch pilot, not PR-time coverage. Only the latest
observed tip in each changed repository is scanned; intermediate commits,
transient issues fixed between polls, PR heads and packages-feed tips are
outside this trigger. The frozen v0.6 source policy covers 128 selected and
13 excluded source-staged paths. A new candidate or unsupported route must
remain visible as a failed/partial scan, not silently count as clean. The
historical OpenVPN positive/fix regression remains a separate release check.
