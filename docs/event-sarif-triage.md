# Incoming event SARIF triage contract

The frozen historical and first current-corpus gates use
`ucode-sarif-acceptance-v1` with source-first exact result tuples. An incoming
source event can yield a new alert whose location was not known before the
scan. For that case, `sarif_accept.py --event-triage` uses the separate
`ucode-sarif-event-triage-v1` manifest schema. It checks producer, CodeQL and
suite identities; every selected source hash and extracted-file multiset;
successful commands, zero extraction errors, SARIF invocation/rule
descriptors, and result locations within selected sources. It retains every
result tuple with multiplicity and reports `triage_required` when any result
exists, or `clean_scan` when none exists. A clean scan is not a safety claim.

The event manifest must omit `expected_results`; it cannot create an
"expected" alert list from the SARIF it just observed. A result retained for
triage is not an accepted exception or verified security issue. Unknown rules,
unselected source URIs, malformed locations, source-byte drift or failed
producer commands still fail closed. The scanner must pass its actual fresh
SARIF and receipt to this consumer in the same job. Unit tests cover this
contract; no released event scanner has yet supplied a live packet.
