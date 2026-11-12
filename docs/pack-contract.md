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

Joins require identical `corpus_revision` and `profile`. `analysis_revision` is producer-local (M2 `policy:ubus-getfeatures-v1`, M3 `step3:getfeatures-v1`, M4 `step3:request-args-exec-v1`). Cross-producer joins (`policy_grant` ↔ `handler_effect` / `taint_path`) match on those two fields plus the shared join keys (`entrypoint_id`, `ingress`, `ubus_object`, `method`) and `evidence_refs` record ids. Do not require two producers to share one `analysis_revision` string.

M2 writes `policy/grants.json` (`policy_grant` / `fact`) and `policy/policy_decisions.json` for `/ubus` `luci.getFeatures` only. Do not emit `alloy_input.json` or `producer: step4` in M2.

## M1 extraction

The stock CodeQL driver matches **basename only**. M1 uses literal `file_globs: ["luci"]`. M3 adds taint fixture basenames. M4 may add further literal basenames (`sys.uc` for installed luci.sys) or a catch-all `"*"` on a pre-filtered file list. Do not extract markup in M0–M3; do not staff Alloy/markup/Track A here.

## cgi-backup

C, not ucode. Synthetic `handler_effect` from policy-facts when that ingress is promoted. Alloy `producer: step4` only after Alloy promotion.
