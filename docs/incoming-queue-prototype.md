# Local incoming queue prototype

This offline prototype uses one SQLite database on a local filesystem as the
single authoritative queue. A transaction locks the writer, compares the
caller-supplied predecessor sequence and digest to the current head, then
reconciles a complete `incoming-poll-v3` discovery snapshot and records the
new immutable transition document and digest. Retain and back up the entire
SQLite database; restrict write access to one operator. A missing database
must not be treated as a replacement genesis after loss: restore a verified
backup. SQLite transactions do not authenticate discovery or protect against
an operator modifying or replacing the database. Do not use multiple copies,
unreliable network filesystems, or schedule this prototype.
The store path must be absolute beneath an operator-owned private directory
with no symlink components. Every ancestor must be owned by root or the
operator and not writable by group or others, except a root-owned sticky
temporary directory such as `/tmp`. Store and sidecar files must be
private regular files with one hard link at open time. These checks cannot
detect copied stores or interference by another process under the same user;
the single-operator rule still applies. First creation requires `--create`, reserves a new filename
exclusively, and rejects an existing store; resume requires the existing
initialized database and never creates a replacement. SQLite opens in
read/write existing-file mode and rejects WAL stores. An interrupted first
creation may leave an uninitialized file that requires explicit operator
inspection and cleanup; it is never silently treated as a new genesis.

For a genesis snapshot the queue replays retained API requests and requires
the decisions to equal the poller's full plan from an empty predecessor. For
a successor, it requires the exact prior checkpoint file, verifies its digest
against both the successor and the most recent discovery snapshot in queue
history, then replays current requests and the full decision plan. Only the
*current* observed set enters queue reconciliation. The poller's successor
decisions retain old pending events, including superseded heads; they must not
be treated as a complete current set. A successor cannot initialize an empty
queue or be applied twice. Request replay checks internal consistency of
retained bytes and poller decisions, not the authenticity of the original
GitHub fetch or artifact custody. An absent subject is marked `not_observed`,
not proven closed; a changed event for a subject is marked `superseded`.
Events remain in history and reappearance reactivates them. PR identity is repository, PR number and head commit; a base-only change
requires recovery of any in-flight reservation first and returns the same
identity to pending without resetting its start count. Other inconsistent metadata and duplicate
subjects fail closed. Discovery is not an atomic
upstream snapshot and intermediate changes can be missed.

Each selection reserves a slot; a separately attested start increments the
attempt count. Pending identities with fewer attested starts always precede those with
more; buckets share selection within an attempt count. A retry cannot start while any pending or reserved first attempt remains.
If new first attempts exceed available slots, reconciliation deterministically
preempts as many unstarted retry reservations as needed, records their IDs in
the transition, and invalidates their reservation digests. Started work is
never preempted and must finish or be safely recovered.
A reserved, never-started identity also blocks new retry reservations until it
is started or explicitly recovered. Capacity bounds the total of reserved and
started work, across polls; lowering it below outstanding work fails closed.
If an in-flight event changes or disappears, reconciliation fails until the
operator safely recovers that work. Other never-started pending identities can
continue. Abandoned reservations remain visible. This has
no scan dispatch or verified production receipt issuer. It does not meet Gate 8 or demonstrate a released
scan. The first-seen timestamp is the queue's observation time, not event age.
Capacity and interval remain unset pending Linux cost measurements.

Run `python3 -B tools/incoming_queue.py --help`; genesis requires
`--create --expected-sequence -1`, later transitions omit `--create` and require the exact prior sequence
and SHA-256 printed by the command. A successor additionally requires
`--previous-snapshot <exact-prior-decisions.json>` and that the previous
discovery checkpoint was already reconciled into the same queue;
queue actions between discoveries do not break that snapshot link. The
complete documents and their digests
are stored in `history`; the database is the authority, not printed output.
Queue history written by the earlier v2 prototype lacks a stored discovery
observation time. The supplied prior checkpoint also provides that time for
the first successor. A missing or mismatched prior file fails closed. Older
queue transitions did not replay their prior checkpoints, so this does not
retroactively prove that legacy decision rows came from their retained API
responses. Only the current successor's observations are reconciled.
Run tests with `python3 -B tools/test_incoming_queue.py -v` and
`python3 -B -m unittest tools.test_incoming_poll`.

The `apply_attested` Python API accepts a start, failure, completion or recovery payload
with an HMAC-SHA256 over canonical JSON using an externally provisioned secret
of at least 32 bytes. The signer is a trust boundary: the MAC authenticates a
holder of that key, not that a scan actually ran. No production signer, key
management, trusted workflow integration, or artifact-byte verification exists.
The v2 completion payload requires `schema: incoming-queue-completion-v2`,
`issuer_receipt_sha256`, and an exact `job` object containing protected
workflow identity, job identity, numeric run ID, and positive run attempt.
The same job object is required at start and stored with the active run;
failure and completion must match it. The action transition records
`incoming-queue-action-v2`. The claimed resolved commit/tree and lock,
manifest, extraction, SARIF, control and issuer receipt digests plus consumer
disposition are structurally checked. The issuer receipt digest must name
canonical frozen receipt bytes whose schema binds the event receipt, triage,
full artifact inventory, workflow revision and issuer revision. The queue
does not read those bytes and cannot tell whether a syntactically valid digest
is fabricated. A valid MAC over fabricated evidence is therefore still
accepted by this prototype; only a trusted same-job issuer could reject it.
Each claim binds the persistent queue ID and the digest of the transition
that created its reservation, as well as the event and reservation sequence.
Failures retain their category and return to pending; all transitions compare
the current predecessor. A reservation is distinct from a signed start, and
only signed starts increment attempt counts. There is no automatic expiry: an authorized signer can recover a reserved
item or an identified started run. Before recovering a started run, the owner
must stop it and establish that it cannot publish an outcome; the transaction
invalidates its reservation and rejects late results. Store schema
`incoming-queue-store-v2` and the `started_job` column reject old populated
databases; there is no automatic migration. Existing queue history must not
be silently upgraded because v1 completion records did not bind receipt or
job identity. A restored database keeps its queue ID;
operator storage controls must prevent concurrent use of copied databases. A stale or superseded reservation cannot complete. A signed
completion is final for that event, not a replacement for triage.

An earlier version replayed the retained 1,851-event v3 snapshot (SHA-256
`91bc6fa58b155206d3b7a2d6e3284d58d34c04a385e7e86ab70e5d6cabe5e95a`)
and selected 1,000 then 851 distinct reservations without starting scans.
That replay predates the global in-flight capacity bound and is not a result
of this version. This version needs attested starts and outcomes or recovery
before capacity becomes available for another selection. No full-checkpoint
scan-attempt coverage or authenticated completion has been demonstrated.
