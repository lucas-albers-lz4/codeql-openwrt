# UCI helper observation and consumer inventory boundary

## Decision

At consumer base `1f01e0a1529b5edf0f9b2e7d6215712bf87e994a`, keep the existing six-row, non-exhaustive UCI consumer catalog as-is. Do not add a consumer fact from producer observation `ucode d398198` alone. The producer observation establishes a bounded syntactic source shape in pinned LuCI `controller/admin/uci.uc`: the `ubus_call('uci', 'commit', ...)` site is associated with a same-file helper whose `ubus.call` arguments refer to the corresponding lexical formals. This does not prove that their runtime values are preserved or that the call executes. It does not establish the runtime object, authorization, persistence, or the concrete `config` value at the call site. The value comes from a dynamic `changes` result in the surrounding controller logic, so the observation has no sound exact `uci_config` key for joining to a particular consumer row.

This is an explicit stop condition: only add a config-specific relationship if a separate source-backed observation establishes a literal or otherwise reviewed exact config identity and the exact `(corpus_revision, profile, uci_config)` join succeeds. Unknown/dynamic config stays unresolved. Do not infer a consumer relationship from the UCI helper itself.

## Existing consumer-side facts

The catalog in `policy/uci_consumers.py` at the base contains one pinned source-backed consumer for each of the six `uci_config` assets: `dropbear`, `rpcd`, `uhttpd`, `system`, `firewall`, and `network`. It is intentionally non-exhaustive. Its source refs identify specific consumers at pinned OpenWrt component revisions; they are independent provenance for consumer identities, not proof that any service is running. The `asset_id` points to the separate default backing-file inventory. These facts are not derived from the LuCI UCI helper observation.

Producer contract reference: `codeql-ucode` commit `d398198` (`docs/issue-53-uci-inventory.md`, `ql/src/inventory/UciHelperObservation.ql`). Consumer contract reference: `docs/pack-contract.md`, section “UCI consumers”, and `policy/uci_consumers.py`. Producer and consumer observations must remain separate evidence families.

## Independently specified controls

Expected producer positive: on the pinned `controller/admin/uci.uc`, the exact source call `uci.commit` is associated with the top-level `ubus_call` helper and its syntactic `ubus.call(object, method, args)` forwarding, where each argument refers to the corresponding lexical formal. This is not proof of runtime value preservation or execution, and it is not a config identity result.

Expected producer negatives: `uci.changes`, `session.set`, a property read, a shadowed or unrelated helper, an unknown/computed operation, or reordered/non-formal forwarding must not qualify. Direct cursor calls are a separate family: no `cursor().set`, `.commit`, or `.delete` evidence is inferred from the ubus helper observation.

Expected consumer positive: each existing config asset has its explicitly listed pinned consumer row, and an exact join on the current lock-derived corpus revision, `luci-ssl-25.12`, and a known config such as `system` returns its row.

Expected consumer negatives: unknown or dynamic config, mismatched corpus revision, or mismatched profile returns no row and remains unresolved rather than proving absence. A direct file grant for `/etc/config/<name>` must not satisfy the UCI ubus `set` gate; a UCI grant must not satisfy direct `file.write` or `file.remove`. These are synthetic gate controls, not deployment login claims.

## Existing verification and limits

The producer PR's `docs/issue-53-uci-inventory.md` records the pinned controller's fresh single-file extraction at producer revision `8375887`, with exact call-pair observations and zero extraction errors. The paired positive/negative controls were added and recorded separately in the later producer work. The report explicitly limits the result to a syntactic source observation: it is not interprocedural data flow, proof of runtime value preservation, or proof of execution.

The existing consumer test `policy/tests/test_uci_consumers.py` checks catalog rows against the six known assets, checks artifact schema and exact join-key behavior, and independently exercises synthetic UCI and direct-file gates. Its `test_bounded_system_option_expectation` also distinguishes an intended operation from the ACL's broader config-level grant. These tests validate the consumer contract but do not validate producer-to-consumer config identity, since the producer observation has no such identity.

No runtime service state, active binding, actual request execution, effective policy grant, direct cursor write, or security result is asserted here.
