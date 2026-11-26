# Read-only default-branch reservation claim reconciliation

`tools/default_branch_reservation_reconcile.py` checks whether one retained
scan claim corresponds to the operator's existing v2 reservation action and
its exact intake origin. It reads the backlog with SQLite `mode=ro`, starts one
read transaction, verifies the full intake receipt and action chains, and does
not change the backlog database.

The operator supplies the completed scan run ID and attempt. The tool uses the
operator's authenticated `gh api` session to fetch the canonical run, complete
jobs page and complete artifact page; it requires the exact
`default-branch-scan-<run>-<attempt>` artifact, downloads its ZIP within the
64 MiB bound, and re-fetches all three API responses around the download. It
checks the API digest and ZIP size, then validates bounded ZIP members. It
retains the API responses and ZIP in a new mode-0700 directory under the
operator's mode-0700 work root. The JSON result records each `gh api` endpoint,
exact command, byte count, SHA-256, exit status and elapsed time, along with the
re-fetch equality result.

The tool reads the exact private archive paths named by the chained intake
receipt. It verifies each archived file's owner, mode, type, link count and
digest; replays intake run/artifact identities, run-input checkpoint
decisions, linked discovery history and the first-parent gap; and compares the
replayed rows with both the receipt and reserved pending row. It then replays
the scan's identity receipt, manifest, linked checkpoint/gap hashes, claim
triplet and execution identity. The three scan ZIP members
`previous/decisions.json`, `current/decisions.json`, and
`current/gap/gap.json` must equal the exact bytes in the private discovery
archives.

The result uses `status: claim_reconciled_read_only` only when the exact claim
triplet, source identity, linked discovery origin and local reservation action
match. An absent or failed claim, a forged triplet, a policy/head mismatch, an
incomplete API page, or any byte mismatch fails closed. In particular,
`policy.consumer_commit` must equal the canonical scan run head and the
manifest consumer head. A claim cannot pass when the local policy names a
different consumer commit, even if its triplet is otherwise valid.

## Authority boundary

This reconciliation does not authorize a scan or write a reservation start,
completion, scan result, retry, coverage state, or outcome. It does not say
whether the scan passed its consumer or whether findings exist.

The local action hash, policy digest and operator name are unkeyed claims. A
user who can rewrite the database can replace the action and recompute its
hash chain. The check can show correspondence between the scan claim and the
current local records; it cannot authenticate who created those records or
whether the policy was approved.

GitHub artifact metadata associates the downloaded artifact with a workflow
run. It does not identify the job that uploaded it. Requiring the expected
completed scan job on the same run is therefore a same-run inference, and the
result states this limit. The private discovery ZIP/API files are replayed and
shown to correspond to the receipt bytes retained by intake; the historical
capture origin remains unauthenticated by this local ledger.

## Operator use

The backlog root must already contain `default-branch-backlog.sqlite3` under
its operator-owned mode-0700 directory. Create a separate private work root
for downloaded evidence:

```sh
umask 077
mkdir -m 700 /private/operator/default-branch-reconciliation
python3 -B -m tools.default_branch_reservation_reconcile \
  --private-root /private/operator/default-branch-backlog \
  --work-root /private/operator/default-branch-reconciliation \
  --run-id <completed-scan-run-id> --attempt <run-attempt>
```

The command requires the exact run and attempt, a complete one-page jobs and
artifact listing of at most 100 records, a completed `released-default-branch-scan`
job, and the exact scan artifact name. It retains captured API and ZIP bytes
in its work directory even when validation fails. The database is opened
read-only and the tool verifies that its identity and modification metadata
remain unchanged before returning.

## Regression gate

Run the focused contract tests with:

```sh
python3 -B -m unittest tools.test_default_branch_reservation_reconcile -v
```

The tests build synthetic discovery archives and a separate disposable v2
backlog under `work/`. They cover a matching claim, a forged triplet, modified
claim origin and identity, a policy consumer mismatch, failed and absent
claims, wrong run/attempt/job/artifact metadata, incomplete listings, ZIP
digest/size/member controls, modified scan checkpoint/gap bytes, local action
tampering, and byte-for-byte database immutability. They are wired into the
`contract` job of `.github/workflows/default-branch-commit-scan.yml` and do not
contact GitHub.
