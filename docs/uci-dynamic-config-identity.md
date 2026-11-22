# Pinned LuCI UCI config identity boundary

## Decision

Do not attach a `uci_consumer` row to the pinned LuCI controller commit
observation. Its config value remains unknown for consumer joining. The
producer observation establishes a bounded syntactic helper association, not a
config value or runtime data flow.

## Source inspection

The inspected producer fixture is
`ql/test/uci-helper-observation/uci.uc` at ucode producer commit `d398198`
(branch `wave/uci-helper-observation` subsequently retains this evidence at
`374b035`). It is a byte-for-byte copy of LuCI
`modules/luci-base/ucode/controller/admin/uci.uc` at pinned LuCI commit
`b2e0be4b46ec0fd43394c081fa7c50657af14011`; the recorded source blob is
`c38a42b10bfefbaa31741feae9395abd8a1f8e40`, SHA-256
`ac75cfef7d74f87ed7f957778004a7bf486c76df699398c215795b4947e0c93e`.
Rechecking the fixture bytes:

```sh
git -C /path/to/codeql-ucode show \
  d398198:ql/test/uci-helper-observation/uci.uc | shasum -a 256
git -C /path/to/codeql-ucode show \
  d398198:ql/test/uci-helper-observation/uci.uc | nl -ba | sed -n '20,85p;136,148p'
```

In that source, `uci_apply(false)` obtains `changes` from
`ubus_call('uci', 'changes', ...)` at line 76, loops over its keys with
`for (let config in changes)` at line 78, and passes that loop variable in the
`config` property of the `ubus_call('uci', 'commit', ...)` at line 79. The
separate revert loop at lines 144–145 has the same dynamic-key shape. The
rollback apply and confirm calls carry no config field. Source inspection
found no literal config argument or other statically config-specific path into
the line 79 commit call. The local helper at lines 25–32 forwards its lexical
formals to `ubus.call`; that fact does not resolve the value supplied by
`changes`. The other `config` read at line 49 is `config?.apply?.rollback`,
used to set an apply timeout; it does not supply a config name to the commit
call.

The existing producer extraction and diagnostics are reused, not rerun. The
retained evidence in producer `docs/issue-53-uci-inventory.md` and
`scripts/uci-helper-observation-smoke.py` records a fresh extraction of this
pinned source, exact selected-file identity, zero reported extraction errors,
and positive/negative syntax controls for the helper association. It does not
assert a `config` value, prove runtime value preservation, or establish that
the call executes. This inspection adds no extraction result.

## Independent consumer boundary

At consumer base `ad241b90638d269b36aa06dd1ed48032a9a03fb7`,
`policy/uci_consumers.py` contains six independent, source-backed rows, for
`dropbear`, `rpcd`, `uhttpd`, `system`, `firewall`, and `network`. Their exact
join key is `(corpus_revision, profile, uci_config)`. Existing
`policy/tests/test_uci_consumers.py::test_future_join_exact_keys_and_unknown`
specifies the positive control (`system` returns its one catalog row) and
negative controls (unknown or null config, changed corpus revision, and
changed profile return no row). Those consumer checks are independent of the
controller observation and do not prove that the controller supplied any of
those six names.

## Stop condition and future controls

Keep the config unknown until an independently reviewed, source-backed
observation identifies the exact config at the same call site and an exact
join using the pinned consumer context succeeds. A dynamic key from the
`changes` result cannot be equated to one catalog config without assuming
runtime response contents or request history. Catalog membership alone is
not such evidence.

Any future producer-to-consumer linkage should include independent controls:

- Positive: a bounded source case with an exact config identity at the
  observed commit site (for example, a reviewed literal config at that site),
  followed by exactly one matching consumer row at the pinned join key.
- Negative: the current loop-derived config remains unresolved; unrelated
  literal config values elsewhere in the file do not qualify; unknown/null
  config, and mismatched revision or profile, produce no join.

Synthetic positive controls can validate the proposed observer and join
behavior, but cannot upgrade this dynamic controller call to a source-backed
config identity. Until those conditions hold, retain unknown and add no
consumer relationship.
