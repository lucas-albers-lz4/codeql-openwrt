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

## Prepare an exact PR scan input

Fetch the canonical PR response to a run-owned file, then prepare inputs from
the retained discovery checkpoint. For example, with an observed OpenWrt PR
head:

```sh
gh api repos/openwrt/openwrt/pulls/26930 > "$RUN_DIR/pr.json"
python3 -B -m tools.discovery_pr_dispatch \
  --checkpoint "$RUN_DIR/decisions.json" \
  --api-response "$RUN_DIR/pr.json" \
  --repository openwrt/openwrt --number 26930 \
  --source-sha 2f82044239460846ad4948493ac077bfdf7ae72c \
  --output "$RUN_DIR/dispatch-inputs.json"
```

The helper requires that exact head in the checkpoint and that the supplied
PR API response still has the same open PR, head, base, branch and repository
identities. It returns `prepared_only` and proposes the API-reported base SHA
as a control candidate. It can prepare a backlog observation for an
explicit manual drill; it does not claim that the poller's selected slot was
issued. It does not authenticate the operator's API file. The actual
checkpoint validator checks schema, row identities and retained response
digests. The helper replays the retained request sequence to require that
the chosen PR event is in the current API snapshot, but it does not
authenticate the original fetch or validate the full selection policy.
This is an operator candidate preparation step rather than scan
authorization. The actual
`incoming-event-preflight.yml` dispatch must fetch a fresh PR response,
resolve source and control trees, check the source-first oracle, then run the
released scan and consumer. A moved head or base requires a new discovery
decision; do not silently use a different SHA.
