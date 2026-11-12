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

Joins require identical `corpus_revision` and `profile`. `analysis_revision` is producer-local (M2 `policy:ubus-luci-exec-methods-v2` / `policy:cgi-backup-v1`, M3 `step3:getfeatures-v1`, M4 `step3:request-args-exec-v1` / `step3:luci-fixed-exec-v1` / `step3:luci-sys-fixed-exec-v1`). Cross-producer joins (`policy_grant` ↔ `handler_effect` / `taint_path`) match on those two fields plus the shared join keys (`entrypoint_id`, `ingress`, and either `ubus_object`/`method` or `cgi_endpoint`) and `evidence_refs` record ids. Do not require two producers to share one `analysis_revision` string.

The luci `/ubus` emitter writes `policy/grants.json` and `policy/policy_decisions.json` for `luci.getFeatures` plus the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`. It does not emit `alloy_input.json`, `producer: step4`, `file.exec`, cgi-io exec/upload/download, `hostapd.*`, or `setInitAction`. cgi-backup is a separate policy-facts emitter (`policy:cgi-backup-v1`) that appends `cgi_io` grants and a synthetic `handler_effect`.

M3/M4 collect `/ubus` luci rows in `reports/handler_effects.json`. That file does not rewrite luci `grants.json` rows. Join the inventoried exec-method grants on the ubus keys above; unauthenticated is a non-join (deny) for those methods except `getFeatures`. `setInitAction` has an effect and no M2 grant. Do not invent dispatcher effects here.

## M1 extraction

The stock CodeQL driver matches **basename only**. M1 uses literal `file_globs: ["luci"]`. M3 adds taint fixture basenames. M4 may add further literal basenames (`sys.uc` for installed luci.sys) or a catch-all `"*"` on a pre-filtered file list. Do not extract markup in M0–M3; do not staff Alloy/markup/Track A here.

## cgi-backup

C, not ucode. Policy-facts emits a synthetic `handler_effect` / `fact` (`ingress=cgi_io`, `cgi_endpoint=cgi-backup`, `sink_kind=sensitive_backup_read`) from the pinned cgi-io `main_backup` gate: `session.access(sid, "cgi-io", "backup", "read")`. C double: `policy/c_double/cgi_backup.c`. Pin: cgi-io `31cb3c89`. This slice does not emit cgi-exec, cgi-upload, cgi-download, dispatcher, or `authorization_violation`. Alloy `producer: step4` only after Alloy promotion.
