# Queue-only default-branch reservation

This is the first reservation increment for the private default-branch commit
backlog described in [the intake contract](default-branch-backlog-intake.md).
It adds a queue-only reservation action. It does not start or dispatch a scan,
accept a run ID, sign an action, record a completion or outcome, or change a
backlog row from `pending`.

## Explicit migration

The intake tool continues to create the pending-only v1 schema. Reservation
requires a deliberate one-time migration of the existing
`default-branch-backlog.sqlite3` in the same operator-owned mode-0700 private
root:

```sh
python3 -B -m tools.default_branch_backlog_reservation \
  --private-root /private/operator/default-branch-backlog --migrate-v1
```

Migration refuses any schema other than the exact v1 backlog tables and
validates the receipt chain and every intake/commit row before its transaction.
It creates the v2 queue identity, empty action chain and action head; it does
not rewrite or replace the v1 receipts, intakes, cursor or backlog rows. DDL,
the version change and post-migration equality checks share one transaction.
An interrupted migration rolls back. A v2 database is not silently migrated
again or treated as a new empty store.

Read the current CAS predecessor after migration or after every accepted
action:

```sh
python3 -B -m tools.default_branch_backlog_reservation \
  --private-root /private/operator/default-branch-backlog --head
```

The initial action head is sequence `0` and 64 zeroes. Store the returned
sequence and digest with the operator's work notes; each writer must supply
both exact values. `BEGIN IMMEDIATE` serializes writers, and the head row is
updated with a conditional compare-and-swap in the same transaction as the
new immutable action. `--head` reads the receipt chain and action head from one
SQLite read snapshot, so it cannot combine values from before and after a
concurrent reservation commit.

## Exact reservation input

Prepare a mode-0600, singly linked policy JSON file in private operator-owned
storage. Its only accepted fields are:

```json
{
  "schema": "default-branch-backlog-reservation-policy-v1",
  "consumer_commit": "<40 lowercase hex characters>",
  "workflow": ".github/workflows/default-branch-commit-scan.yml",
  "release_lock_sha256": "<SHA-256 of docs/r3-release-lock.json bytes>"
}
```

The tool hashes the exact policy-file bytes, checks the release-lock digest,
and copies the immutable R3 tag, commit, asset digest and manifest digest from
that lock into the action. The action also binds the operator-supplied
identity, UTC expiry (at most seven days), exact pending row key and immutable
intake origin: receipt sequence/hash, discovery run/attempts, artifact IDs and
ZIP digests, checkpoint digests, gap digest, repository/ref, ordinal, commit,
tree and first parent. The consumer commit and policy digest are recorded as
the operator's claimed inputs. Any format-valid consumer policy file with the
required fields can be supplied; this offline queue does not authenticate its
approval or the supplied operator name.

Repository and ref are taken from the exact intake row. The tool does not
force `main` for both repositories: the intake/poller contract accepts the
API-reported default branch with its bounded branch-name syntax. The current
defaults are `openwrt/openwrt:main` and `openwrt/luci:master`.

## Trust boundary

The queue, policy file and release lock are local operator inputs. Policy and
release-lock paths are checked for symlink components, owner, regular-file
type and hardlinks before reading; the policy additionally must be mode 0600.
Before SQLite opens, the store must be an existing operator-owned mode-0700
directory and the database a mode-0600, singly linked regular DELETE-journal
SQLite file without sidecars. A private root prevents other OS users from
replacing those paths but does not defend against another process running as
the same operator. The tool makes no GitHub requests and receives no workflow
token or signer key. Its hash chains are unkeyed local tamper evidence; they
do not authenticate intake capture, policy approval, operator identity or a
scan.

Inspect a candidate row with SQLite before preparing the exact CLI arguments:

```sql
SELECT b.repository, b.ref, b.ordinal, b.commit_sha, b.tree_sha,
       b.first_parent_sha, b.intake_id, i.receipt_seq
FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
WHERE b.status = 'pending'
ORDER BY i.receipt_seq, b.repository, b.ref, b.ordinal;
```

Then reserve only that exact row, supplying the current action head from
`--head`:

```sh
python3 -B -m tools.default_branch_backlog_reservation \
  --private-root /private/operator/default-branch-backlog --reserve \
  --expected-action-sequence 0 \
  --expected-action-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --repository openwrt/openwrt --ref main --ordinal 2 \
  --commit-sha <commit> --tree-sha <tree> --first-parent-sha <parent> \
  --intake-id <intake-id> --receipt-seq <sequence> \
  --policy /private/operator/reservation-policy.json \
  --release-lock docs/r3-release-lock.json \
  --operator <operator-identity> --expires-at 2026-11-27T12:00:00Z
```

Every identity and origin value is compared with the pending row and its
receipt chain inside the reservation transaction. A stale identity, policy
digest mismatch, duplicate or conflicting reservation, occupied pilot slot,
expired reservation, or stale action head fails without appending an action.
Only one reservation is supported in this increment; until a separately
reviewed transition exists, an expired reservation still occupies the slot.
The append-only action table has SQLite update/delete guards and a hash chain.
This provides local tamper evidence, not authentication against an operator
who can rewrite the database and recompute the chain.

The result status is `reserved_only`. It is not a claim that a workflow was
dispatched or a scan ran. The seven historical manual scans from the rehearsal
predate queue issuance and cannot be attached as starts or outcomes. Start,
completion, retry, recovery, authentication and automatic dispatch remain
separate work.

The focused local checks, including migration of a two-intake seven-row v1
store, duplicate/conflict rejection, stale identity/head rejection, expiry,
and concurrent CAS writers, run with:

```sh
python3 -B -m unittest tools.test_default_branch_backlog_reservation -v
```

The test creates its own ignored `work/` database and does not use or modify an
operator rehearsal store.
