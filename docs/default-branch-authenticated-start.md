# Authenticated private start preflight

`tools.default_branch_authenticated_start.verify_authenticated_start(private_root,
key)` accepts a pre-created private root and raw key bytes. It has no command
line interface, key-file reader, network access, queue writer or terminal
signer. The caller must keep the key outside the checkout and pass only bytes.

The function reads a bounded snapshot through a checked, no-follow database
file descriptor under the operator-owned private root. It rejects unsafe root
and database paths, nonregular or multiply linked store files, and SQLite
sidecars before deserializing those bytes in an in-memory, query-only SQLite
connection. It rechecks the live file identity and sidecars before returning.
The snapshot verifies the intake, reservation and issued chains, the
sequence-one HMAC, exact zero predecessor, issued head and reservation binding.
Sequence two is rejected. It then reads the retained
observation directory through no-follow directory descriptors, requiring
exactly the receipt and six start files. The signed observation digest binds
the receipt; the receipt and signed start bind each raw API body and early ZIP
by byte length and SHA-256. The existing start-evidence verifier also checks
run, job, artifact, attempt and timing consistency.

The returned `authenticated_start` mapping names the queue, reservation,
source, run, job, early artifact, start digest, observation digest and six raw
digests. Its scope is
`authenticated_sequence_one_start_and_retained_observation_only`; the explicit
completed-scan and final-proof fields are false. This local preflight does not
authenticate a later GitHub observation or establish a scan outcome.

A valid HMAC over a valid older store cannot expose rollback by itself. An
independent durable head checkpoint must be reconciled before a production
terminal action. The intake chain is checked for internal consistency, but a
later self-consistent intake tail is not bound by the sequence-one HMAC. This
preflight does not re-read the approved policy file or release-lock bytes; it
checks their attested digests only against the reservation binding. The retained API
bytes do not authenticate their live capture provenance, and this check does
not validate the early ZIP member structure. A future issuer must use the raw
bytes from the same verified invocation or rehash every handoff, then recheck
the exact head and reservation inside its terminal CAS.

`tools.test_default_branch_authenticated_start` uses a real synthetic v3
issuer and retained observation. Its positive and near-miss controls cover
wrong key, signed malformed API, byte tamper, head drift, sequence two,
substitution, sidecars before and after snapshot, extra entry, symlink and
hardlink. The test is wired into the hosted `contract` job of
`default-branch-commit-scan.yml`. These are offline fixtures, not live
issuer or scan evidence.
