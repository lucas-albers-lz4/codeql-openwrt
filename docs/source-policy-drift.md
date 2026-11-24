# Bounded source-policy drift report

`tools/source_policy_drift.py` compares a clean, full-SHA OpenWrt or LuCI checkout
with the `mvp-bounded-corpus-v0.4` manifest. The manifest is an explicit input;
the reviewed ledger copy at `planning/mvp-bounded-corpus-v0.4.json` had SHA-256
`1e25cf9c2adc40c854502fed8d1ccc0977a3c4825d6ee4a1c0a543ffe0a76699` when this
implementation was prepared. Pass the manifest for each upstream checkout; the
script selects only entries whose `repo` matches the argument.

```sh
python3 -B tools/source_policy_drift.py baseline-v0.4.json luci /path/to/clean-luci-checkout FULL_40_HEX_SHA drift.json
```

The report re-resolves Git blob IDs and SHA-256 content hashes for all baseline
selected and excluded source paths in that repository. It carries package owner,
configuration condition, exclusion reason and expected route forward. Missing
paths, content changes, renames and changed added `.uc`/`.ut`/extensionless
paths fail closed with exit 1. Invalid identities, dirty checkouts and invalid
inputs fail with exit 2. Exit 0 means only that this bounded comparison found no
drift.

This is an incremental source-policy check, not the full dynamic selector in
the incoming-CI design. It inspects baseline identities plus candidate paths in
the event commit's first-parent diff. It does not find unmodified new candidate
paths already present outside that diff, infer installation from recipes,
evaluate package conditions, or identify every candidate naming convention.
It does not run extraction or CodeQL and does not establish Gate 8. Candidate
heuristics are intentionally conservative and can require human review.

Mechanical tests:

```sh
python3 -B -m unittest policy.tests.test_source_policy_drift -v
```
