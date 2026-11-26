# Offline default-branch issued-action primitives

`tools/default_branch_backlog_issued.py` adds a deliberate v2→v3 migration and
a first signed `start` action primitive. It is an internal module with no CLI,
key-file reader or GitHub client. It must not be used as a live issuer until a
separate operator verifier derives its attestation from fresh canonical API
and artifact bytes and an independently approved policy.

Migration checks the exact v2 schema, intake receipts, pending rows,
reservation action chain and action head in one `BEGIN IMMEDIATE` transaction.
It snapshots and preserves every v1/v2 row and existing schema object, adds
only `issued_actions`, `issued_head` and append-only guards, and sets schema
version 3. It does not change the one-reservation limit or any backlog status.
The earlier v1→v2 migration remains a separate deliberate step.

The start primitive requires exactly one pending, unexpired reservation and an
empty issued head. It checks the supplied structured attestation against that
reservation's queue ID, action digest, source identity, intake origin, policy
digest, consumer commit and release-lock digest, and compares an explicit
approved consumer/release-lock pair. Its transaction uses expected-head CAS
to append sequence 1 only once. The action envelope is sorted compact UTF-8
JSON with a trailing newline; its HMAC-SHA256 domain is
`codeql-openwrt/default-branch-issued-action-v1` followed by a newline. The
stored document includes the MAC and has its own SHA-256 action digest.

These checks bind bytes supplied to the primitive. They do not authenticate
the caller's observation time, GitHub run/job/artifact digests, early ZIP or
policy approval. A format-valid forged attestation could be signed by a
caller that has the key. The future private launcher must control both the
key and the construction of those fields, recheck the job while it is in
progress, and reject completed or stale attempts before invoking this module.
No prior completed run can receive a retrospective start. Completion,
failure/retry transitions, durable custody and automatic dispatch are later
work.

The focused module tests use disposable SQLite roots and byte keys. Run:

```sh
python3 -B -m unittest tools.test_default_branch_backlog_intake tools.test_default_branch_backlog_capture tools.test_default_branch_backlog_reservation tools.test_default_branch_backlog_issued -q
python3 -O -B -m unittest tools.test_default_branch_backlog_intake tools.test_default_branch_backlog_capture tools.test_default_branch_backlog_reservation tools.test_default_branch_backlog_issued -q
```
