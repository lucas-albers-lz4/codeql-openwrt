# Pack and interchange contract

## Repos

- `codeql-openwrt` (this tree): corpus, schema, policy-facts, JS inventory, Track A, Alloy, reports.
- `codeql-ucode`: extractor and QL packs `lucas-albers-lz4/ucode-all`, `lucas-albers-lz4/ucode-queries`.

## `producer` vs milestone

| Milestone | `producer` |
| --- | --- |
| M0 corpus / lockfile / profile | `corpus` |
| JS inventory | `step1` |
| Track A | `track_a` |
| M2 policy evaluator | `policy_facts` |
| M3 queries, effects, reports | `step3` |
| Alloy (only after promotion) | `step4` |

Joins require identical `corpus_revision`, `profile`, and `analysis_revision`.

## M1 extraction

The stock CodeQL driver matches **basename only**. Until M4 routing, extract with literal `file_globs: ["luci"]`. M3 may add extra literal basenames or a catch-all `"*"` on a pre-filtered file list. Do not extract markup in M0–M3.

## cgi-backup

C, not ucode. Synthetic `handler_effect` from policy-facts when that ingress is promoted. Alloy `producer: step4` only after Alloy promotion.
