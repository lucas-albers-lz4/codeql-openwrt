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

Joins require identical `corpus_revision` and `profile`. `analysis_revision` is producer-local (M2 `policy:ubus-luci-exec-methods-v2` / `policy:cgi-backup-v1` / `policy:cgi-upload-v1` / `policy:cgi-download-v1` / `policy:cgi-exec-v1`, M3 `step3:getfeatures-v1`, M4 `step3:request-args-exec-v1` / `step3:luci-fixed-exec-v1` / `step3:luci-sys-fixed-exec-v1`). Cross-producer joins (`policy_grant` ↔ `handler_effect` / `taint_path`) match on those two fields plus the shared join keys (`entrypoint_id`, `ingress`, and either `ubus_object`/`method` or `cgi_endpoint`) and `evidence_refs` record ids. Do not require two producers to share one `analysis_revision` string.

The luci `/ubus` emitter writes `policy/grants.json` and `policy/policy_decisions.json` for `luci.getFeatures` plus the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`. It does not emit `alloy_input.json`, `producer: step4`, `file.exec`, `hostapd.*`, or `setInitAction`. cgi-backup / cgi-upload / cgi-download / cgi-exec are separate policy-facts emitters that append `cgi_io` grants and synthetic `handler_effect` rows. Upload and download are conjunctive cgi-io plus file ACL gates. cgi-exec models the cgi-io exec read gate only, not `file.exec` of a command or `execv`.

M3/M4 collect `/ubus` luci rows in `reports/handler_effects.json`. That file does not rewrite luci `grants.json` rows. Join the inventoried exec-method grants on the ubus keys above; unauthenticated is a non-join (deny) for those methods except `getFeatures`. `setInitAction` has an effect and no M2 grant. Do not invent dispatcher effects here.

## M1 extraction

The stock CodeQL driver matches **basename only**. M1 uses literal `file_globs: ["luci"]`. M3 adds taint fixture basenames. M4 may add further literal basenames (`sys.uc` for installed luci.sys) or a catch-all `"*"` on a pre-filtered file list. Do not extract markup in M0–M3; do not staff Alloy/markup/Track A here.

## cgi-io (C, not ucode)

Policy-facts emits synthetic `handler_effect` / `fact` rows from pinned cgi-io `31cb3c89`:

| Endpoint | `analysis_revision` | Gate | `sink_kind` | C double |
| --- | --- | --- | --- | --- |
| cgi-backup | `policy:cgi-backup-v1` | `session.access(sid, "cgi-io", "backup", "read")` | `sensitive_backup_read` | `policy/c_double/cgi_backup.c` |
| cgi-upload | `policy:cgi-upload-v1` | cgi-io `upload` write **and** `file` write of `canonicalize_path(filename)` | `file_write` | `policy/c_double/cgi_upload.c` |
| cgi-download | `policy:cgi-download-v1` | cgi-io `download` read **and** `file` read of `canonicalize_path(path)` | `file_read` | `policy/c_double/cgi_download.c` |
| cgi-exec | `policy:cgi-exec-v1` | `session.access(sid, "cgi-io", "exec", "read")` only (not `file.exec` / `execv`) | `exec` | `policy/c_double/cgi_exec.c` |

Joins use the lockfile `corpus_revision`. This catalog does not emit dispatcher or `authorization_violation`. Alloy `producer: step4` only after Alloy promotion. Do not invent a luci-ssl `setInitAction` grant.
