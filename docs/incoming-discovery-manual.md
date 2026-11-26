# Manual incoming discovery pilot

`Incoming read-only discovery` inventories observed open PR heads and default
tips in `openwrt/openwrt` and `openwrt/luci`. It runs `tools/incoming_poll.py`
on a clean Linux runner and retains the complete request/decision receipt.
It does not dispatch CodeQL scans, resolve PR trees, authenticate queue
completion or claim that every upstream transition was seen.

For the first run, manually dispatch the workflow on the reviewed consumer
commit with `genesis=true` and no previous run ID or SHA. For each later run,
set `genesis=false`, `previous_run_id` and `previous_run_attempt` from the last
**successful** discovery run, and `previous_sha256` to the SHA-256 of that
run's `decisions.json`. The workflow verifies the earlier run's identity and
success, downloads its named artifact, checks the digest and validates the
checkpoint before any new upstream API request. If the artifact expired or
any check fails, stop and investigate; do not silently start a new genesis.

The artifact `incoming-discovery-<run-id>-<attempt>` contains `run-input.json`
after valid input preparation and, on success, `decisions.json`,
`decisions.sha256` and `poll/decisions.json`. A failed preparation or poll
retains `workflow-failure.json`; a poll failure also retains
`poll/failure.json` when the poller could write one. A checkout or contract-job
failure can prevent artifact creation entirely. Failed runs are never valid
predecessors. Artifacts expire after 30 days;
before that point, decide how to maintain durable checkpoint custody. The
current workflow has no schedule or automatic dispatch and does not advance a
shared queue. Its `capacity=1` selects at most one observation for *review*;
this can be a default tip rather than a PR head. Because v3 has no completion
transition, the same prior selected identity can retain retry priority on
later polls. Selection is not a scan result or a fair scan scheduler.

Review selected identities against a fresh canonical upstream API response
before passing an exact head and control SHA to
`incoming-event-preflight.yml`. A moved head, new candidate path, extraction
failure, no alert and known alert are separate outcomes. The manual scan must
retain exact source, route, extraction and SARIF evidence and be triaged by a
human. The clean incoming drill and historical OpenVPN positive currently
prove different pieces; neither is the Gate 8 incoming known-alert positive.
