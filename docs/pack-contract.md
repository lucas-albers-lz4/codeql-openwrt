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

Joins require identical `corpus_revision` and `profile`. `analysis_revision` is producer-local (M2 `policy:ubus-luci-exec-methods-v2` / `policy:cgi-backup-v1` / `policy:cgi-upload-v1` / `policy:cgi-download-v1` / `policy:cgi-exec-v1` / `policy:cgi-exec-file-v1` / `policy:cgi-exec-status-v1` / `policy:ubus-file-exec-v1` / `policy:ubus-file-exec-ifup-v1` / `policy:ubus-file-exec-kill-v1` / `policy:ubus-file-exec-mounts-v1` / `policy:ubus-file-exec-list-backup-v1` / `policy:no-ubusauth-v1`, M3 `step3:getfeatures-v1`, M4 `step3:request-args-exec-v1` / `step3:luci-fixed-exec-v1` / `step3:luci-sys-fixed-exec-v1` / `inventory:realtime-password-quoted-locals-v1` / `inventory:luci-ssl-files-v1`). Cross-producer joins (`policy_grant` ↔ `handler_effect` / `taint_path`) match on those two fields plus the shared join keys (`entrypoint_id`, `ingress`, and either `ubus_object`/`method` or `cgi_endpoint`) and `evidence_refs` record ids. Do not require two producers to share one `analysis_revision` string. Routing `files[]` records join on exact `corpus_revision` + inventory `profile` + `fs_path` and are not grant rows. A variant may explicitly declare routing-only base inventory ownership with `files_inventory_profile` and `files_inventory_inheritance: "routing_only"`; this resolves only routing records and never retags records or inherits authorization/effect rows. All policy grants, decisions and effect joins still require the requesting profile exactly. See [file-routing.md](file-routing.md#routing-only-inheritance).

The luci `/ubus` emitter writes `policy/grants.json` and `policy/policy_decisions.json` for `luci.getFeatures` plus the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`. It does not emit `alloy_input.json`, `producer: step4`, `file.exec`, `hostapd.*`, or `setInitAction`. cgi-backup / cgi-upload / cgi-download / cgi-exec are separate policy-facts emitters that append `cgi_io` grants and synthetic `handler_effect` rows. Upload and download are conjunctive cgi-io plus file ACL gates. cgi-exec models the cgi-io exec read gate only (`policy:cgi-exec-v1`). File.exec of the three luci-ssl libexec helpers is a separate policy-facts emitter (`policy:cgi-exec-file-v1`); it does not model `execv` or arbitrary commands. luci-mod-status `dmesg` / nft / iptables / firewall-init cgi-exec file.exec is `policy:cgi-exec-status-v1` (JS `fs.exec_direct` callers at luci `b2e0be4b`). ubus `file.exec` of luci-mod-status `iptables -Z` / `ip6tables -Z` and routes `ip` is `policy:ubus-file-exec-v1` (JS `fs.exec` callers at luci `b2e0be4b` via rpcd-mod-file); it does not model `execv` or unrestricted commands. ubus `file.exec` of luci-mod-network-config `/sbin/ifup` / `/sbin/ifdown` / `/sbin/wifi` is `policy:ubus-file-exec-ifup-v1` (JS `fs.exec` callers at luci `b2e0be4b`); inventoried ACLs grant those bare executables. ubus `file.exec` of luci-mod-status-processes `/bin/kill` is `policy:ubus-file-exec-kill-v1` (JS `fs.exec` caller at luci `b2e0be4b`); inventoried ACLs grant the bare executable. ubus `file.exec` of luci-mod-system-mounts `/bin/umount` / `/sbin/block` is `policy:ubus-file-exec-mounts-v1` (JS `fs.exec` callers at luci `b2e0be4b`); inventoried ACLs grant those bare executables and reuse the existing read/write mounts fixture. ubus `file.exec` of luci-mod-system-flash `/sbin/sysupgrade --list-backup` is `policy:ubus-file-exec-list-backup-v1` (JS `fs.exec` caller at luci `b2e0be4b`); inventoried ACLs grant the cmdline and reuse the existing list-read flash fixture. Profile `luci-ssl-25.12-no-ubusauth` (`policy:no-ubusauth-v1`) is a distinct uhttpd `option no_ubusauth 1` variant: it records `/ubus` JSON-RPC skip of `uh_ubus_allowed` and does not emit luci-ssl ACL grants. It does not rewrite the luci emitter. cgi-io and dispatcher `admin/ubus` are unchanged.

M3/M4 collect `/ubus` luci rows in `reports/handler_effects.json`. That file does not rewrite luci `grants.json` rows. Join the inventoried exec-method grants on the ubus keys above; unauthenticated is a non-join (deny) for those methods except `getFeatures`. `setInitAction` has an effect and no M2 grant. Do not invent dispatcher effects here.

## M1 extraction

The stock CodeQL driver matches **basename only**. M1 uses literal `file_globs: ["luci"]`. M3 adds taint fixture basenames. M4 may add further literal basenames (`sys.uc` for installed luci.sys) or a catch-all `"*"` on a pre-filtered file list. Do not extract markup in M0–M3; do not staff Alloy/markup/Track A here.

luci-ssl `files[]` at pin `b2e0be4b` is inventoried from `luci.mk` (`ucode/` → `/usr/share/ucode/luci/`, `htdocs/` → `/www/`, `root/` → `/`, luci-base postinst `ucode_prefix`, src-install `version.uc` / `core.so`). Routing classification follows this repository's [file-routing.md](file-routing.md#classification-order) on those installed paths (`inventory:luci-ssl-files-v1`). Markup stays `markup_not_modeled`. The extractor seven-case gate remains `codeql-ucode` work and is not claimed from the inventory. See [reports/m4-luci-ssl-files.md](../reports/m4-luci-ssl-files.md).

## cgi-io (C, not ucode)

Policy-facts emits synthetic `handler_effect` / `fact` rows from pinned cgi-io `31cb3c89`:

| Endpoint | `analysis_revision` | Gate | `sink_kind` | C double |
| --- | --- | --- | --- | --- |
| cgi-backup | `policy:cgi-backup-v1` | `session.access(sid, "cgi-io", "backup", "read")` | `sensitive_backup_read` | `policy/c_double/cgi_backup.c` |
| cgi-upload | `policy:cgi-upload-v1` | cgi-io `upload` write **and** `file` write of `canonicalize_path(filename)` | `file_write` | `policy/c_double/cgi_upload.c` |
| cgi-download | `policy:cgi-download-v1` | cgi-io `download` read **and** `file` read of `canonicalize_path(path)` | `file_read` | `policy/c_double/cgi_download.c` |
| cgi-exec | `policy:cgi-exec-v1` | `session.access(sid, "cgi-io", "exec", "read")` only (not `execv`) | `exec` | `policy/c_double/cgi_exec.c` |
| cgi-exec file.exec helpers | `policy:cgi-exec-file-v1` | cgi-io exec read **and** `file` exec of canonicalized cmdline or executable, bounded to `/usr/libexec/{syslog-wrapper,luci-peeraddr,package-manager-call}` | `file_exec` | `policy/c_double/cgi_exec_file.c` |
| cgi-exec file.exec status | `policy:cgi-exec-status-v1` | same conjunct, bounded to luci-mod-status `fs.exec_direct` commands (`/bin/dmesg`, `/usr/sbin/nft`, iptables/ip6tables `-t *`, `*-save`, `/etc/init.d/firewall restart`) | `file_exec` | `policy/c_double/cgi_exec_status.c` |

Joins use the lockfile `corpus_revision`. This catalog does not emit dispatcher or `authorization_violation`. Alloy `producer: step4` only after Alloy promotion. Do not invent a luci-ssl `setInitAction` grant.

## ubus `file.exec` (C, not ucode)

Policy-facts `policy:ubus-file-exec-v1` emits synthetic `handler_effect` / `fact` rows from pinned rpcd-mod-file `file.c` @ `d99f703` plus uhttpd `uh_ubus_allowed`. Gate: `session.access` scope=ubus object=file function=exec, then `rpc_file_access` of the canonicalized executable or, on miss, the cmdline (executable first). Bounded to luci-mod-status `fs.exec` callers at luci `b2e0be4b`: `iptables -Z`, `ip6tables -Z`, routes.js `/sbin/ip -[46] …`, routesj.js `/sbin/ip -[46] -j …`. C double: `policy/c_double/ubus_file_exec.c`. Does not model `execv`, live PATH search, diagnostics ping, ifup/ifdown/wifi, or `/bin/kill`.

Policy-facts `policy:ubus-file-exec-ifup-v1` uses the same conjunctive HTTP `/ubus` `file.exec` gate, bounded to luci-mod-network-config write `fs.exec` callers at luci `b2e0be4b`: `interfaces.js` `/sbin/ifup` / `/sbin/ifdown`, `wireless.js` `/sbin/wifi up`. C double: `policy/c_double/ubus_file_exec_ifup.c`. Inventoried ACLs grant the bare executables; extra tokens are `intended_access` for the write fixture, not `authorization_violation` and not a PoC. Does not model `execv`, live PATH search, diagnostics ping, or `/bin/kill`.

Policy-facts `policy:ubus-file-exec-kill-v1` uses the same conjunctive HTTP `/ubus` `file.exec` gate, bounded to luci-mod-status-processes write `fs.exec` of `/bin/kill` at luci `b2e0be4b`: `processes.js` `handleSignal`. C double: `policy/c_double/ubus_file_exec_kill.c`. Inventoried ACLs grant the bare executable; extra tokens are `intended_access` for the write fixture, not `authorization_violation` and not a PoC. The read `luci-mod-status-processes` fixture has `luci.getProcessList` without ubus `file.exec`. Does not model `execv`, live PATH search, diagnostics ping, ifup/ifdown/wifi, or flash.js sysupgrade/firstboot. luci-mod-system-mounts umount/block is `policy:ubus-file-exec-mounts-v1`.

Policy-facts `policy:ubus-file-exec-mounts-v1` uses the same conjunctive HTTP `/ubus` `file.exec` gate, bounded to luci-mod-system-mounts write `fs.exec` callers at luci `b2e0be4b`: `mounts.js` `handleUmount` `/bin/umount` and `handleMountAll` `/sbin/block mount`. C double: `policy/c_double/ubus_file_exec_mounts.c`. Inventoried ACLs grant the bare executables; extra tokens are `intended_access` for the existing read/write mounts fixture, not `authorization_violation` and not a PoC. Does not model `execv`, live PATH search, diagnostics ping, cron (`ubus` `file.write` not `file.exec`), or flash.js write sysupgrade/firstboot. luci-mod-system-flash `sysupgrade --list-backup` is `policy:ubus-file-exec-list-backup-v1`.

Policy-facts `policy:ubus-file-exec-list-backup-v1` uses the same conjunctive HTTP `/ubus` `file.exec` gate, bounded to luci-mod-system-flash read `fs.exec` of `/sbin/sysupgrade --list-backup` at luci `b2e0be4b`: `flash.js` `handleBackupList`. C double: `policy/c_double/ubus_file_exec_list_backup.c`. Inventoried ACLs grant the cmdline, not the bare executable; extra tokens are `PERMISSION_DENIED`, not `authorization_violation` and not a PoC. Reuses the existing list-read flash fixture. Write sysupgrade/firstboot stay unstaffed (write ACLs exist but the fixture is list-read only). Does not model `execv`.

## uhttpd `no_ubusauth` (profile variant)

Profile `luci-ssl-25.12` has `no_ubusauth=0`. Profile `luci-ssl-25.12-no-ubusauth` shares `corpus/lock.json` (same `corpus_revision`) and sets `option no_ubusauth 1` (`uhttpd -a`). For a valid call array, pinned uhttpd `ubus.c` rewrites an empty SID string to `UH_UBUS_DEFAULT_SID` and skips `uh_ubus_allowed` / `session.access`. Null or omitted SID slots cause later strings to shift in the typed libubox array parser and the ordinary call fails parse. Object lookup occurs before the gate and can return `ERROR_OBJECT`; an allow only describes the gate, not the plugin result. The same flag also skips uhttpd authorization for `/call/<object>` and GET subscriptions; those paths are outside this JSON-RPC slice. Unauthenticated deny on `luci-ssl-25.12` stays deny; skip-allows on the variant are HTTP-gate facts (`unassessed`), not invented luci-ssl grants, not `path_found`, and not `authorization_violation`. Parse still requires object, function, and a `BLOBMSG_TYPE_TABLE` data parameter. C double: `policy/c_double/uh_ubus_policy.c`.
