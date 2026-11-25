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
Events remain in history and reappearance reactivates them. Inconsistent
metadata and duplicate subjects fail closed. Discovery is not an atomic
upstream snapshot and intermediate changes can be missed.

Each selection reserves an attempt and increments its count even if no scan
runs. Pending identities with fewer reservations always precede those with
more; buckets share selection within an attempt count. Failed or abandoned
reservations therefore cannot starve never-attempted identities, but an
operator must interpret reservation counts accordingly. This has no completion
or retry-outcome interface, no scan dispatch, no authenticated scan receipts,
and no alert disposition. It does not meet Gate 8 or demonstrate a released
scan. The first-seen timestamp is the queue's observation time, not event age.
Capacity and interval remain unset pending Linux cost measurements.

Run `python3 -B tools/incoming_queue.py --help`; genesis requires
`--expected-sequence -1`, later transitions require the exact prior sequence
and SHA-256 printed by the command. The complete documents and their digests
are stored in `history`; the database is the authority, not printed output.
Run tests with `python3 -B tools/test_incoming_queue.py -v` and
`python3 -B -m unittest tools.test_incoming_poll`.
