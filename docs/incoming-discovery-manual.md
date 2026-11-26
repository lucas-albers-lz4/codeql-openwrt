# Scheduled read-only incoming discovery pilot

`Incoming read-only discovery` inventories observed open PR heads and default
tips in `openwrt/openwrt` and `openwrt/luci`. It runs `tools/incoming_poll.py`
on a clean Linux runner and retains the complete request/decision receipt. The
workflow can run by manual dispatch and once daily at 07:17 UTC. Pull requests
run contract tests only. Discovery does not dispatch CodeQL scans, resolve PR
trees, authenticate queue completion or claim that every upstream transition
was seen.

Seed the history with a manual run on reviewed `main` and `genesis=true`, with
no previous run ID or SHA. A scheduled run never starts a genesis: it requires
the latest successful manual or scheduled discovery run. The first scheduled
attempt before that seed fails visibly and retains a failure artifact. A
scheduled successor resolves the latest successful run automatically from the
canonical Actions API, downloads that exact run/attempt artifact, verifies its
run metadata and `run-input.json`, checks `decisions.sha256` against the
downloaded `decisions.json`, and validates the checkpoint before making any
upstream discovery request. Manual successors still require
`genesis=false`, the latest successful run ID/attempt (which may be manual or
scheduled), and the exact `decisions.json` SHA-256. If the artifact expired or
any check fails, stop and investigate; do not silently start a new genesis.

The discovery job runs only from `main` and serializes main discovery attempts.
It retains separate `workflow_dispatch` and `schedule` Actions API responses
and a combined `discovery-history-api.json`. Each event query is bounded to
100 runs; more history, an active competing run, a rerun or a stale manual
predecessor requires explicit custody reconciliation. `discovery_latest_predecessor.py`
checks the event filters before resolving the latest successful run, so PR
contract runs cannot silently enter the checkpoint chain.
The `run-input.json` v2 receipt records the trigger, current and predecessor
run identities, exact checkpoint digest, and hashes of the combined history,
both event-filtered history responses and predecessor run API response. This
binds the schedule to the same checkpoint lineage as manual discovery. It
relies on canonical Actions API responses and does not make the 30-day artifact
retention durable.

The artifact `incoming-discovery-<run-id>-<attempt>` contains `run-input.json`
and both raw event-filtered API responses plus their combined history after
valid preparation and, on success,
`decisions.json`, `decisions.sha256` and `poll/decisions.json`. A successful
non-genesis run also retains `gap/gap.json` and `gap/gap.sha256`, after offline
replay of the exact retained compare responses. A non-fast-forward, truncated
or unverifiable gap fails the workflow and retains `gap/failure.json` when
available. A failed preparation or poll retains `workflow-failure.json`; a
poll failure also retains `poll/failure.json` when the poller could write one.
Failed runs are never valid predecessors, so the next run still extends the
last successful checkpoint. A checkout or contract-job failure can prevent
artifact creation entirely. Artifacts expire after 30 days; this remains an
operator-maintained checkpoint, not durable queue custody.

The scheduled mode is discovery-only. The earlier hosted snapshot made 82
successful upstream API requests; use each new receipt to measure actual
request counts and API headroom rather than treating that observation as an
upper bound. The workflow retains first-parent gap records, but it does not
persist their commits as scan backlog. Its `capacity=1` selects at most one
observed identity for *review*; this can be a default tip rather than a PR
head. Because v3 has no completion transition, the same prior selected
identity can retain retry priority on later polls. Selection is not a scan
result or a fair scan scheduler.

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
decision; do not silently use a different SHA. Scheduled discovery does not
automatically run this PR scan or the default-branch direct-commit scan and
does not establish PR-time coverage.
