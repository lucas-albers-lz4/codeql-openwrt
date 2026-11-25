# Local incoming queue prototype

This offline prototype uses one SQLite database on a local filesystem as the
single authoritative queue. A transaction locks the writer, compares the
caller-supplied predecessor sequence and digest to the current head, then
reconciles a complete `incoming-poll-v3` genesis snapshot and records the
new immutable transition document and digest. Retain and back up the entire
SQLite database; restrict write access to one operator. A missing database
must not be treated as a replacement genesis after loss: restore a verified
backup. SQLite transactions do not authenticate discovery or protect against
an operator modifying or replacing the database. Do not use multiple copies,
unreliable network filesystems, or schedule this prototype.

The snapshot is a complete observed set, not the poller's chained checkpoint,
which also retains old events. An absent subject is marked `not_observed`,
not proven closed; a changed event for a subject is marked `superseded`.
Events remain in history and reappearance reactivates them. PR identity is repository, PR number and head commit; a base-only change
invalidates any in-flight reservation and returns the same identity to pending
without resetting its start count. Other inconsistent metadata and duplicate
subjects fail closed. Discovery is not an atomic
upstream snapshot and intermediate changes can be missed.

Each selection reserves a slot; a separately attested start increments the
attempt count. Pending identities with fewer attested starts always precede those with
more; buckets share selection within an attempt count. A reserved, never-started identity blocks new retry reservations until it is
started or explicitly recovered. Other never-started pending identities can
continue. Abandoned reservations remain visible. This has
no scan dispatch or verified production receipt issuer. It does not meet Gate 8 or demonstrate a released
scan. The first-seen timestamp is the queue's observation time, not event age.
Capacity and interval remain unset pending Linux cost measurements.

Run `python3 -B tools/incoming_queue.py --help`; genesis requires
`--expected-sequence -1`, later transitions require the exact prior sequence
and SHA-256 printed by the command. The complete documents and their digests
are stored in `history`; the database is the authority, not printed output.
Run tests with `python3 -B tools/test_incoming_queue.py -v` and
`python3 -B -m unittest tools.test_incoming_poll`.

The `apply_attested` Python API accepts a start, failure, completion or recovery payload
with an HMAC-SHA256 over canonical JSON using an externally provisioned secret
of at least 32 bytes. The signer is a trust boundary: the MAC authenticates a
holder of that key, not that a scan actually ran. No production signer, key
management, trusted workflow integration, or artifact-byte verification exists.
Completion's claimed resolved commit/tree and lock, manifest, extraction,
SARIF and control digests plus consumer disposition are structurally checked;
the signer must independently validate the actual artifacts and clean control.
Each claim binds the persistent queue ID and the digest of the transition
that created its reservation, as well as the event and reservation sequence.
Failures retain their category and return to pending; all transitions compare
the current predecessor. A reservation is distinct from a signed start, and
only signed starts increment attempt counts. There is no automatic expiry: an authorized signer can recover a reserved
item or an identified started run. Before recovering a started run, the owner
must stop it and establish that it cannot publish an outcome; the transaction
invalidates its reservation and rejects late results. An old database schema
is rejected and has no migration. A restored database keeps its queue ID;
operator storage controls must prevent concurrent use of copied databases. A stale or superseded reservation cannot complete. A signed
completion is final for that event, not a replacement for triage.

Replay of the retained 1,851-event v3 snapshot (SHA-256
`91bc6fa58b155206d3b7a2d6e3284d58d34c04a385e7e86ab70e5d6cabe5e95a`)
selected 1,000 and then 851 distinct reservations with capacity 1,000. Zero
starts or scans occurred. This offline replay verifies reservation coverage,
not scan-attempt coverage or authenticated completion on the real events.
