# Offline default-branch backlog intake

Implementation packet and operator instructions for the bounded intake
prototype, based on clean `main` commit
`d66030c04f00d0ce9196876d74515641be8e42af`.

## Decision and scope

`tools/default_branch_backlog_intake.py` stores the first-parent commits from
one linked successful discovery interval in an operator-owned SQLite database.
It uses a separate `DBI1` application ID and schema. It does not call or modify
`incoming_queue.py`, make a scan reservation, dispatch a workflow, record a
scan outcome, or mark a commit covered.

The database cursor names the last successfully ingested checkpoint. Intake
requires the supplied predecessor run, attempt and checkpoint digest to match
that cursor; on first use the exact supplied predecessor is recorded as a
bootstrap boundary in the same transaction as the successor. The whole gap is
replayed before writing. All rows, the cursor update and a hash-chained receipt
are committed in one `BEGIN IMMEDIATE` transaction. A repeated exact intake
returns its prior receipt. A changed repeat, conflicting commit identity or
stale predecessor fails closed. An empty successor advances the cursor and
adds an empty receipt; it does not remove earlier pending commits.
Before a new transaction, the tool reconciles every stored intake and pending
commit row against its receipt and checks the cursor against the last receipt.
Missing earlier rows therefore stop later intake instead of silently shrinking
the backlog. It rejects extra SQLite schema objects such as triggers and repeats
the reconciliation after writes, before committing the intake transaction.

Each backlog row contains repository, ref, one-based first-parent ordinal,
commit, tree, parent, its source gap/checkpoint digests, and a fixed
`pending` status. Stable ordering is `(intake receipt_seq, repository, ref,
ordinal)`. The schema has no reservation, start, completion, scan, or coverage
state.

## Custody boundary and limits

The caller supplies the exact artifact ZIP bytes and retained run/artifact API
JSON. The tool requires a successful matching workflow run and attempt, the
exact `incoming-discovery-<run>-<attempt>` artifact name and ID, an unexpired
artifact, the published `sha256:` ZIP digest, matching artifact size and run
linkage, and matching run-input/checkpoint/gap identities. It validates the
exact sidecar names and replays both checkpoint decisions and the full linked
first-parent gap. For v2 discovery artifacts it also checks that the bundled
predecessor API identifies the supplied predecessor and replays the captured
mixed manual/scheduled run history to verify latest-successful selection. The
separate raw manual and scheduled responses must reconstruct the combined
history exactly; selected run identities must match their API records.

This is explicitly `offline_retained_api_metadata` intake. The tool does not
fetch GitHub API responses, authenticate their capture origin, or authenticate
the ZIP download source. The API records and ZIP can be fabricated together;
the `custody` field and SQLite receipt retain this limitation. Use a trusted
operator session to capture the canonical API responses and ZIP, then keep
those raw bytes beside the result. This intake is an internal backlog
observation, not authenticated queue authority or coverage evidence. A later
trusted custody/issuer path must independently authenticate the live API and
artifact before any scan transition.

The receipt hash chain is internal tamper evidence only. It is not keyed or
signed, and a party able to rewrite the database can recompute it. Keep the
whole database and its private archive under one operator account; back it up
as one unit. This prototype does not define recovery after database loss or
operator replacement.

Only after validating the complete linked input are exact ZIPs and their
run/artifact API JSON copied to private mode-0600 files
under `archives/<run>-<attempt>/`; run directories and store root must be
operator-owned mode 0700. Archive files are retained indefinitely by this
prototype. The operator owns their review, backup and deletion policy. GitHub
discovery artifacts expire after 30 days, so archive them before expiry. A
missing, expired or digest-mismatched artifact cannot advance the cursor.
Large raw files, databases and caches stay out of Git.

## Operator use

Capture inputs with an authenticated `gh` session and preserve the exact
responses and archive ZIP. For each run, use `gh api` for the canonical run
endpoint and artifact metadata endpoint; download the exact named artifact by
ID to a ZIP file. The run response must name the discovery workflow on `main`
with a successful completion; the artifact record must include its digest.
Keep these files in an operator-controlled incoming directory. The following
example uses only read commands and local storage commands; use the actual run
IDs and artifact IDs from the linked checkpoint pair:

```sh
umask 077
mkdir -m 700 /private/operator/default-branch-backlog
gh api repos/lucas-albers-lz4/codeql-openwrt/actions/runs/45790907027 \
  > /private/operator/previous-run.json
gh api repos/lucas-albers-lz4/codeql-openwrt/actions/artifacts/15103055535 \
  > /private/operator/previous-artifact.json
gh api repos/lucas-albers-lz4/codeql-openwrt/actions/artifacts/15103055535/zip \
  > /private/operator/previous.zip
```

Repeat for the successor, then run the intake with all six files:

```sh
python3 -B -m tools.default_branch_backlog_intake \
  --private-root /private/operator/default-branch-backlog \
  --previous-zip /private/operator/previous.zip \
  --previous-run-api /private/operator/previous-run.json \
  --previous-artifacts-api /private/operator/previous-artifact.json \
  --current-zip /private/operator/current.zip \
  --current-run-api /private/operator/current-run.json \
  --current-artifacts-api /private/operator/current-artifact.json
```

The private root must already exist and be mode 0700. The database is created
there as `default-branch-backlog.sqlite3`; a preexisting file must be the exact
private schema. Source files are checked for symlinks, hardlinks, owner,
regular-file type and byte bounds before read. ZIP members are bounded,
unique regular files from the discovery artifact contract. The database path
and inode are checked before and after SQLite opens it.

Inspect pending backlog order and receipts locally with SQLite:

```sql
SELECT b.repository, b.ref, b.ordinal, b.commit_sha, b.tree_sha,
       b.first_parent_sha, i.receipt_seq
FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
WHERE b.status = 'pending'
ORDER BY i.receipt_seq, b.repository, b.ref, b.ordinal;

SELECT receipt_seq, previous_hash, receipt_hash, body_json
FROM receipts ORDER BY receipt_seq;
```

These rows remain pending until a separately reviewed dispatch/completion
design exists. Never interpret this table as evidence that any commit was
analyzed.

## Bounds, oracle and regression gate

The intake accepts ZIP files up to 64 MiB, API JSON files up to 16 MiB, at
most 256 ZIP entries and 128 MiB expanded content. Each linked compare is
bounded to 100 commits by `default_branch_gap.py`; this tool accepts at most
that bound per repository. It does no CodeQL extraction, query or scan.

The source-first oracle is the exact ordered `first_parent_commits` returned
by replaying the linked gap response against both checkpoint byte digests.
The tests cover a seven-commit interval and an empty successor, with the empty
successor preserving all seven pending identities. They also cover checkpoint
and ZIP tampering, wrong predecessor linkage, exact-repeat idempotence,
conflicting duplicate identities, transaction rollback, receipt chaining and
private path/hardlink rejection.

The local regression command is:

```sh
python3 -B -m unittest tools.test_default_branch_backlog_intake -v
```

The same test is wired into the `contract` job of
`.github/workflows/incoming-discovery-manual.yml`, which runs on pull requests
touching `tools/**`. That is the planned hosted gate; it has not run on this
uncommitted checkout. The test fixtures are synthetic schema-valid ZIPs and
do not authenticate a hosted run. A separate operator rehearsal with actual
canonical ZIPs/API responses is still required before relying on this tool.
