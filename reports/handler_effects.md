# Canonical `handler_effects.json`

Join catalog for modeled `/ubus` `luci` privileged sinks plus the synthetic cgi-io backup/upload/download/exec effects and synthetic ubus `file.exec` effects. Producer files under `reports/` remain the query snapshots for luci rows (block-device / sysfixtime rows are transcribed from the pinned plugin, not a new query; luci.sys status popens are transcribed from pinned `sys.uc`, not a new query); cgi-io rows are policy-facts (`policy:cgi-backup-v1` / `policy:cgi-upload-v1` / `policy:cgi-download-v1` / `policy:cgi-exec-v1` / `policy:cgi-exec-file-v1` / `policy:cgi-exec-status-v1`); ubus `file.exec` rows are policy-facts (`policy:ubus-file-exec-v1` / `policy:ubus-file-exec-ifup-v1` / `policy:ubus-file-exec-kill-v1` / `policy:ubus-file-exec-mounts-v1` / `policy:ubus-file-exec-list-backup-v1`); ubus `system.reboot` / `rc.init` / `rc.list` / `system.board` / `system.info` / `luci.getVersion` / `luci.getUnixtime` rows are policy-facts (`policy:ubus-system-reboot-v1` / `policy:ubus-rc-init-v1` / `policy:ubus-rc-list-v1` / `policy:ubus-system-board-v1` / `policy:ubus-system-info-v1` / `policy:ubus-luci-getversion-v1` / `policy:ubus-luci-getunixtime-v1`). This file is the one `handler_effect` list consumers should join against `policy/grants.json`.

Findings are evidence, not proof. This catalog does not emit `authorization_violation` or dispatcher effects. `shellquote` and `basename` are not sanitizers. `canonicalize_path` is not a taint sanitizer.

## Sources

| Source | What was collected |
| --- | --- |
| [findings.json](findings.json) | `getFeatures` → `callPackageVersionCheck('netifd')` → named `popen` |
| [m4-getfeatures-direct-exec.json](m4-getfeatures-direct-exec.json) | `getFeatures.call` hostapd / wpa_supplicant `system`, dnsmasq / odhcpd / ipset `popen` |
| [m4-findings.json](m4-findings.json) | five request.args exec sinks, projected from existing `taint_path` rows (no new query) |
| [m4-block-device-exec.json](m4-block-device-exec.json) | `getBlockDevices` / `setBlockDetect` fixed `/sbin/block` exec plus `setLocaltime` sysfixtime |
| [m4-luci-sys-status-exec.json](m4-luci-sys-status-exec.json) | `getConntrackList` / `getProcessList` luci.sys fixed popen |
| [m4-luci-sys-init-action-findings.json](m4-luci-sys-init-action-findings.json) | `luci.sys` `init_action` → builtin `system` (no M2 grant) |
| policy-facts `cgi_backup` | synthetic `cgi-backup` → `sensitive_backup_read` (C, not ucode) |
| [m2-cgi-upload-effect.json](m2-cgi-upload-effect.json) | synthetic `cgi-upload` → conjunctive `file_write` (C, not ucode) |
| [m2-cgi-download-effect.json](m2-cgi-download-effect.json) | synthetic `cgi-download` → conjunctive `file_read` (C, not ucode) |
| [m2-cgi-exec-effect.json](m2-cgi-exec-effect.json) | synthetic `cgi-exec` → cgi-io exec read gate only (C, not ucode) |
| [m2-cgi-exec-file-effect.json](m2-cgi-exec-file-effect.json) | synthetic `cgi-exec` file.exec of three luci-ssl libexec helpers (C, not ucode) |
| [m2-cgi-exec-status-effect.json](m2-cgi-exec-status-effect.json) | synthetic `cgi-exec` file.exec of luci-mod-status dmesg/nft/iptables/firewall-init (C, not ucode) |
| [m2-ubus-file-exec-effect.json](m2-ubus-file-exec-effect.json) | synthetic ubus `file.exec` of luci-mod-status iptables `-Z` / routes `ip` (C, not ucode) |
| [m2-ubus-file-exec-ifup-effect.json](m2-ubus-file-exec-ifup-effect.json) | synthetic ubus `file.exec` of luci-mod-network-config ifup/ifdown/wifi (C, not ucode) |
| [m2-ubus-file-exec-kill-effect.json](m2-ubus-file-exec-kill-effect.json) | synthetic ubus `file.exec` of luci-mod-status-processes `/bin/kill` (C, not ucode) |
| [m2-ubus-file-exec-mounts-effect.json](m2-ubus-file-exec-mounts-effect.json) | synthetic ubus `file.exec` of luci-mod-system-mounts umount/`block mount` (C, not ucode) |
| [m2-ubus-file-exec-list-backup-effect.json](m2-ubus-file-exec-list-backup-effect.json) | synthetic ubus `file.exec` of luci-mod-system-flash `sysupgrade --list-backup` (C, not ucode) |
| [m2-ubus-system-reboot-effect.json](m2-ubus-system-reboot-effect.json) | synthetic ubus `system.reboot` of luci-mod-system-reboot (C, not ucode) |
| [m2-ubus-rc-init-effect.json](m2-ubus-rc-init-effect.json) | synthetic ubus `rc.init` of luci-mod-system-init / luci-mod-system-config (C, not ucode) |
| [m2-ubus-rc-list-effect.json](m2-ubus-rc-list-effect.json) | synthetic ubus `rc.list` of luci-mod-system-init / luci-mod-system-config (C, not ucode) |
| [m2-ubus-system-board-effect.json](m2-ubus-system-board-effect.json) | synthetic ubus `system.board` of luci-mod-status-index (C, not ucode) |
| [m2-ubus-system-info-effect.json](m2-ubus-system-info-effect.json) | synthetic ubus `system.info` of luci-mod-status-index (C, not ucode) |
| [m2-ubus-luci-getversion-effect.json](m2-ubus-luci-getversion-effect.json) | synthetic ubus `luci.getVersion` of luci-mod-status-index (C, not ucode) |
| [m2-ubus-luci-getunixtime-effect.json](m2-ubus-luci-getunixtime-effect.json) | synthetic ubus `luci.getUnixtime` of luci-mod-status-index (C, not ucode) |

Not collected: synthetic taint fixtures, `taint_path` / `backend_method` rows, shellquote barrier `no_path` rows, same-function-local quoting inventory ([m4-realtime-password-quoted-locals.json](m4-realtime-password-quoted-locals.json)), luci-ssl `files[]` routing classification ([m4-luci-ssl-files.json](m4-luci-ssl-files.json)), dispatcher. Helper `exec_helper_inventory` rows stay in the files inventory; this catalog holds the cgi-exec file.exec effects those helpers join.

## Grant ↔ effect joins

Cross-producer joins (`policy_grant` ↔ `handler_effect`) match **identical** `corpus_revision` and `profile`, plus `ingress`, `entrypoint_id`, and either `ubus_object`/`method` or `cgi_endpoint`, and the grant `record_id` in the effect's `evidence_refs`. `analysis_revision` stays producer-local (`policy:ubus-luci-exec-methods-v2` / `policy:cgi-backup-v1` / `policy:cgi-upload-v1` / `policy:cgi-download-v1` / `policy:cgi-exec-v1` / `policy:cgi-exec-file-v1` / `policy:cgi-exec-status-v1` / `policy:ubus-file-exec-v1` / `policy:ubus-file-exec-ifup-v1` / `policy:ubus-file-exec-kill-v1` / `policy:ubus-file-exec-mounts-v1` / `policy:ubus-file-exec-list-backup-v1` / `policy:ubus-system-reboot-v1` / `policy:ubus-rc-init-v1` / `policy:ubus-rc-list-v1` / `policy:ubus-system-board-v1` / `policy:ubus-system-info-v1` / `policy:ubus-luci-getversion-v1` / `policy:ubus-luci-getunixtime-v1` vs `step3:*`) and is **not** a join key. See [docs/pack-contract.md](../docs/pack-contract.md).

Catalog copies add the delegated / root grant ids on `evidence_refs` so both session classes that actually hold the grant join. Producer snapshots may still list only the first assessed session.

### `#12` request.args exec-method grants

Unauthenticated `/ubus` is a **non-join** (M2 deny). Delegated module sessions and stock root `*` join as `intended_access`.

| Method | `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- | --- |
| `getSwconfigFeatures` | `getSwconfigFeatures.swconfig.popen` | `policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigFeatures` | `policy:grant:root:ubus_http:luci.getSwconfigFeatures` | no-join (`policy:decision:unauthenticated-getSwconfigFeatures-deny`) |
| `getSwconfigPortState` | `getSwconfigPortState.swconfig.popen` | `policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigPortState` | `policy:grant:root:ubus_http:luci.getSwconfigPortState` | no-join (`policy:decision:unauthenticated-getSwconfigPortState-deny`) |
| `getRealtimeStats` | `getRealtimeStats.luci-bwc.popen` | `policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats` | `policy:grant:root:ubus_http:luci.getRealtimeStats` | no-join (`policy:decision:unauthenticated-getRealtimeStats-deny`) |
| `setPassword` | `setPassword.busybox-passwd.system` | `policy:grant:luci-mod-system-config:ubus_http:luci.setPassword` | `policy:grant:root:ubus_http:luci.setPassword` | no-join (`policy:decision:unauthenticated-setPassword-deny`) |
| `setLocaltime` | `setLocaltime.date.system` | `policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime` | `policy:grant:root:ubus_http:luci.setLocaltime` | no-join (`policy:decision:unauthenticated-setLocaltime-deny`) |

Those five effects are handler sinks collected from the existing request.args inventory. The analyzer observes `shellquote` on the swconfig / luci-bwc / passwd paths without treating it as a global sanitizer. `localtime` / `sprintf %d` on `setLocaltime` are not sanitizers. Runtime quoting is preserved through same-function `getRealtimeStats` `flags` and `setPassword` `u`/`p`; the analyzer's direct-template barrier does not track those locals; quoting inventory is [m4-realtime-password-quoted-locals.md](m4-realtime-password-quoted-locals.md), not extra catalog sinks.

### Fixed plugin-body exec (`luci-mod-system-mounts` + sysfixtime)

`getBlockDevices` and `setBlockDetect` are **fixed** plugin-body exec (`call: function()`, no `request.args`, not `luci.sys`). Unauthenticated is a **non-join**. `setLocaltime.sysfixtime.system` is a second sink on the already-granted `setLocaltime` method (literal `/etc/init.d/sysfixtime restart`); it joins the same `#12` grants, not a new method grant.

| Method | `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- | --- |
| `getBlockDevices` | `getBlockDevices.block-info.popen` | `policy:grant:luci-mod-system-mounts:ubus_http:luci.getBlockDevices` | `policy:grant:root:ubus_http:luci.getBlockDevices` | no-join (`policy:decision:unauthenticated-getBlockDevices-deny`) |
| `setBlockDetect` | `setBlockDetect.block-detect.system` | `policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect` | `policy:grant:root:ubus_http:luci.setBlockDetect` | no-join (`policy:decision:unauthenticated-setBlockDetect-deny`) |
| `setLocaltime` | `setLocaltime.sysfixtime.system` | `policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime` | `policy:grant:root:ubus_http:luci.setLocaltime` | no-join (`policy:decision:unauthenticated-setLocaltime-deny`) |

### luci.sys status popen (`luci-mod-status-realtime` + `luci-mod-status-processes`)

`getConntrackList` and `getProcessList` are **fixed** luci.sys helper exec (`call: function()`, no `request.args`). The plugin methods are thin wrappers. Unauthenticated is a **non-join**. `getConntrackList` joins the existing `luci-mod-status-realtime` session (ACL already listed it next to `getRealtimeStats`), not a new session class. The `luci-mod-status-processes` fixture for `getProcessList` is read-only. Write `file.exec` `/bin/kill` is the separate M2 slice `policy:ubus-file-exec-kill-v1`. QL for these helpers waits on `codeql-ucode#12`.

| Method | `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- | --- |
| `getConntrackList` | `getConntrackList.conntrack.popen` | `policy:grant:luci-mod-status-realtime:ubus_http:luci.getConntrackList` | `policy:grant:root:ubus_http:luci.getConntrackList` | no-join (`policy:decision:unauthenticated-getConntrackList-deny`) |
| `getProcessList` | `getProcessList.busybox-top.popen` | `policy:grant:luci-mod-status-processes:ubus_http:luci.getProcessList` | `policy:grant:root:ubus_http:luci.getProcessList` | no-join (`policy:decision:unauthenticated-getProcessList-deny`) |

### `getFeatures` grants (pre-#12, still join)

| `effect_id` | Grants |
| --- | --- |
| `getFeatures.callPackageVersionCheck.popen` | `policy:grant:unauthenticated:ubus_http:luci.getFeatures`, `policy:grant:root:ubus_http:luci.getFeatures` |
| `getFeatures.hostapd.system` | same |
| `getFeatures.wpasupplicant.system` | same |
| `getFeatures.dnsmasq.popen` | same |
| `getFeatures.odhcpd.popen` | same |
| `getFeatures.ipset.popen` | same |

Fixed helpers for stock unauthenticated feature probing: **intended_access**, not BAC or RCE.

### No grant

`luci.sys.init_action.system` (`setInitAction`) stays **unassessed**. M2 does not emit a luci-ssl grant for this method. `basename` is not a sanitizer. Do not invent a grant to complete the join.

### cgi-backup (policy-facts synthetic)

`cgi-backup.sysupgrade.create-backup` (`sink_kind=sensitive_backup_read`). cgi-io `main_backup` @ `31cb3c89` checks `session.access(sid, "cgi-io", "backup", "read")` only; it does not fork sysupgrade in this oracle. Unauthenticated `/cgi-bin/cgi-backup` is a **non-join** (403). Fixture `luci-mod-system-flash` and stock root `*` join as `intended_access`. A backup read is not a violation because the role lacks write. `shellquote` and `basename` are not sanitizers (no user path; fixed sysupgrade argv).

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `cgi-backup.sysupgrade.create-backup` | `policy:grant:luci-mod-system-flash:cgi_io:cgi-backup` | `policy:grant:root:cgi_io:cgi-backup` | no-join (`policy:decision:unauthenticated-cgi-backup-deny`) |

### cgi-upload / cgi-download (policy-facts synthetic, conjunctive)

cgi-io `main_upload` / `main_download` @ `31cb3c89` require the cgi-io ACL **and** a `file` ACL on `canonicalize_path(...)`. A cgi-io grant without the file grant cannot authorize. `../` is collapsed before the file ACL. Unauthenticated is a **non-join**. Catalog rows are copies of [m2-cgi-upload-effect.json](m2-cgi-upload-effect.json) and [m2-cgi-download-effect.json](m2-cgi-download-effect.json); `corpus_revision` is the lockfile hash.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `cgi-upload.canonicalize-path.write` | `policy:grant:luci-base:cgi_io:cgi-upload` | `policy:grant:root:cgi_io:cgi-upload` | no-join (`policy:decision:unauthenticated-cgi-upload-deny`) |
| `cgi-download.canonicalize-path.read` | `policy:grant:luci-mod-system-flash:cgi_io:cgi-download` | `policy:grant:root:cgi_io:cgi-download` | no-join (`policy:decision:unauthenticated-cgi-download-deny`) |

The `luci-base` upload fixture is a **write** login (not stock). The `luci-mod-system-flash` fixture is `list read` only, so its ACL group's upload write is not in session. cgi-upload failures are Status 200 JSON, not HTTP 403.

### cgi-exec (policy-facts synthetic, session gate only)

cgi-io `main_exec` @ `31cb3c89` checks `session.access(sid, "cgi-io", "exec", "read")` before command parsing. This catalog row is that gate only: it does **not** model `execv`. File.exec of the three luci-ssl libexec helpers is the next section. Unauthenticated is a **non-join** (403). Fixture `luci-mod-network-config` and stock root `*` join as `intended_access`. Catalog copy: [m2-cgi-exec-effect.json](m2-cgi-exec-effect.json).

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `cgi-exec.session-access.exec` | `policy:grant:luci-mod-network-config:cgi_io:cgi-exec` | `policy:grant:root:cgi_io:cgi-exec` | no-join (`policy:decision:unauthenticated-cgi-exec-deny`) |

### cgi-exec file.exec helpers (policy-facts synthetic, conjunctive)

cgi-io `main_exec` still requires `file.exec` of the canonicalized cmdline or executable. This catalog models that conjunct only for `/usr/libexec/{syslog-wrapper,luci-peeraddr,package-manager-call}`. `lookup_executable` PATH search and `execv` are not modeled. Unauthenticated is a **non-join**. A cgi-io exec grant without the helper file ACL is a **non-join**. Catalog copy: [m2-cgi-exec-file-effect.json](m2-cgi-exec-file-effect.json). Join keys use `entrypoint_id` `cgi_io:cgi-exec:<fs_path>` plus `cgi_endpoint=cgi-exec`.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `cgi-exec.syslog-wrapper.file-exec` | `policy:grant:luci-mod-status-logs:cgi_io:cgi-exec:syslog-wrapper` | `policy:grant:root:cgi_io:cgi-exec:syslog-wrapper` | no-join |
| `cgi-exec.luci-peeraddr.file-exec` | `policy:grant:luci-mod-network-config:cgi_io:cgi-exec:luci-peeraddr` | `policy:grant:root:cgi_io:cgi-exec:luci-peeraddr` | no-join |
| `cgi-exec.package-manager-call.file-exec` | `policy:grant:luci-app-package-manager:cgi_io:cgi-exec:package-manager-call` | `policy:grant:root:cgi_io:cgi-exec:package-manager-call` | no-join |

### cgi-exec file.exec luci-mod-status (policy-facts synthetic, conjunctive)

Same cgi-io `main_exec` file.exec conjunct as the libexec helpers, bounded to commands the pinned status views reach via `fs.exec_direct`. dmesg / nft / `*-save` / firewall restart are exact cmdlines. iptables/ip6tables listing uses a trailing `-t *` glob; extra tokens on that glob are `intended_access` for the firewall fixture, not `authorization_violation` and not a PoC. Bare executable fallback is not granted. A read-only firewall fixture has cgi-io exec but not write `file.exec` of `/etc/init.d/firewall restart`. `iptables -Z` is `fs.exec` (ubus `file.exec`) and is not this slice. Catalog copy: [m2-cgi-exec-status-effect.json](m2-cgi-exec-status-effect.json).

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `cgi-exec.dmesg.file-exec` | `policy:grant:luci-mod-status-logs:cgi_io:cgi-exec:dmesg` | `policy:grant:root:cgi_io:cgi-exec:dmesg` | no-join |
| `cgi-exec.nft.file-exec` | `policy:grant:luci-mod-status-firewall:cgi_io:cgi-exec:nft` | `policy:grant:root:cgi_io:cgi-exec:nft` | no-join |
| `cgi-exec.iptables.file-exec` | `policy:grant:luci-mod-status-firewall:cgi_io:cgi-exec:iptables` | `policy:grant:root:cgi_io:cgi-exec:iptables` | no-join |
| `cgi-exec.ip6tables.file-exec` | `policy:grant:luci-mod-status-firewall:cgi_io:cgi-exec:ip6tables` | `policy:grant:root:cgi_io:cgi-exec:ip6tables` | no-join |
| `cgi-exec.iptables-save.file-exec` | `policy:grant:luci-mod-status-firewall:cgi_io:cgi-exec:iptables-save` | `policy:grant:root:cgi_io:cgi-exec:iptables-save` | no-join |
| `cgi-exec.ip6tables-save.file-exec` | `policy:grant:luci-mod-status-firewall:cgi_io:cgi-exec:ip6tables-save` | `policy:grant:root:cgi_io:cgi-exec:ip6tables-save` | no-join |
| `cgi-exec.firewall-init.file-exec` | `policy:grant:luci-mod-status-firewall:cgi_io:cgi-exec:firewall-init` | `policy:grant:root:cgi_io:cgi-exec:firewall-init` | no-join |

### ubus file.exec luci-mod-status (policy-facts synthetic, conjunctive)

HTTP `/ubus` `file.exec` (rpcd-mod-file `rpc_file_exec_run` @ `d99f703`) requires `uh_ubus_allowed` file/exec **and** `rpc_file_access` of the canonicalized executable or, on miss, the cmdline. Executable is checked first (reverse of cgi-io). Bounded to luci-mod-status `fs.exec` callers at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant those cmdlines, not the bare executables. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. A ubus `file.exec` grant without the matching file ACL is a **non-join**. Catalog copy: [m2-ubus-file-exec-effect.json](m2-ubus-file-exec-effect.json). Join keys use `entrypoint_id` `ubus_http:file.exec:<fs_path>` (routes JSON uses `…/sbin/ip:-j`) plus `ubus_object=file` / `method=exec`. Does not model `execv`, live PATH search, diagnostics ping, ifup/ifdown/wifi, or `/bin/kill`.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `file.exec.iptables` | `policy:grant:luci-mod-status-firewall:ubus_http:file.exec:iptables` | `policy:grant:root:ubus_http:file.exec:iptables` | no-join |
| `file.exec.ip6tables` | `policy:grant:luci-mod-status-firewall:ubus_http:file.exec:ip6tables` | `policy:grant:root:ubus_http:file.exec:ip6tables` | no-join |
| `file.exec.ip` | `policy:grant:luci-mod-status-routes:ubus_http:file.exec:ip` | `policy:grant:root:ubus_http:file.exec:ip` | no-join |
| `file.exec.ip-json` | `policy:grant:luci-mod-status-routes-json:ubus_http:file.exec:ip-json` | `policy:grant:root:ubus_http:file.exec:ip-json` | no-join |

### ubus file.exec luci-mod-network-config ifup (policy-facts synthetic, conjunctive)

Same conjunctive HTTP `/ubus` `file.exec` gate. Bounded to luci-mod-network-config write `fs.exec` callers at luci `b2e0be4b`: `interfaces.js` `/sbin/ifup` / `/sbin/ifdown`, `wireless.js` `/sbin/wifi up`. Inventoried luci-ssl ACLs grant the bare executables; extra tokens are `intended_access` for the write fixture, not `authorization_violation` and not a PoC. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The read `luci-mod-network-config` fixture has ubus `file.exec` without the write file ACL and is a **non-join**. Catalog copy: [m2-ubus-file-exec-ifup-effect.json](m2-ubus-file-exec-ifup-effect.json). Join keys use `entrypoint_id` `ubus_http:file.exec:<fs_path>` plus `ubus_object=file` / `method=exec`. Does not model `execv`, live PATH search, diagnostics ping, or `/bin/kill`.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `file.exec.ifup` | `policy:grant:luci-mod-network-config-write:ubus_http:file.exec:ifup` | `policy:grant:root:ubus_http:file.exec:ifup` | no-join |
| `file.exec.ifdown` | `policy:grant:luci-mod-network-config-write:ubus_http:file.exec:ifdown` | `policy:grant:root:ubus_http:file.exec:ifdown` | no-join |
| `file.exec.wifi` | `policy:grant:luci-mod-network-config-write:ubus_http:file.exec:wifi` | `policy:grant:root:ubus_http:file.exec:wifi` | no-join |

### ubus file.exec luci-mod-status-processes kill (policy-facts synthetic, conjunctive)

Same conjunctive HTTP `/ubus` `file.exec` gate. Bounded to luci-mod-status-processes write `fs.exec` of `/bin/kill` at luci `b2e0be4b`: `processes.js` `handleSignal`. Inventoried luci-ssl ACLs grant the bare executable; extra tokens are `intended_access` for the write fixture, not `authorization_violation` and not a PoC. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The read `luci-mod-status-processes` fixture has `luci.getProcessList` without ubus `file.exec` and is a **non-join**. Catalog copy: [m2-ubus-file-exec-kill-effect.json](m2-ubus-file-exec-kill-effect.json). Join keys use `entrypoint_id` `ubus_http:file.exec:/bin/kill` plus `ubus_object=file` / `method=exec`. Does not model `execv`, live PATH search, diagnostics ping, ifup/ifdown/wifi, or flash.js sysupgrade/firstboot. luci-mod-system-mounts umount/block is `policy:ubus-file-exec-mounts-v1`.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `file.exec.kill` | `policy:grant:luci-mod-status-processes-write:ubus_http:file.exec:kill` | `policy:grant:root:ubus_http:file.exec:kill` | no-join |

### ubus file.exec luci-mod-system-mounts umount/block (policy-facts synthetic, conjunctive)

Same conjunctive HTTP `/ubus` `file.exec` gate. Bounded to luci-mod-system-mounts write `fs.exec` callers at luci `b2e0be4b`: `mounts.js` `handleUmount` `/bin/umount`, `handleMountAll` `/sbin/block mount`. Inventoried luci-ssl ACLs grant the bare executables; extra tokens are `intended_access` for the existing read/write mounts fixture, not `authorization_violation` and not a PoC. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. A ubus `file.exec` grant without the matching file ACL is a **non-join**. Catalog copy: [m2-ubus-file-exec-mounts-effect.json](m2-ubus-file-exec-mounts-effect.json). Join keys use `entrypoint_id` `ubus_http:file.exec:<fs_path>` plus `ubus_object=file` / `method=exec`. Reuses the existing `luci-mod-system-mounts` session already used for `getBlockDevices` / `setBlockDetect`; those luci object popen/system of `/sbin/block` stay on the luci grants. Does not model `execv`, live PATH search, diagnostics ping, cron (`ubus` `file.write` not `file.exec`), or flash.js write sysupgrade/firstboot. luci-mod-system-flash `sysupgrade --list-backup` is `policy:ubus-file-exec-list-backup-v1`.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `file.exec.umount` | `policy:grant:luci-mod-system-mounts:ubus_http:file.exec:umount` | `policy:grant:root:ubus_http:file.exec:umount` | no-join |
| `file.exec.block` | `policy:grant:luci-mod-system-mounts:ubus_http:file.exec:block` | `policy:grant:root:ubus_http:file.exec:block` | no-join |

### ubus file.exec luci-mod-system-flash sysupgrade --list-backup (policy-facts synthetic, conjunctive)

Same conjunctive HTTP `/ubus` `file.exec` gate. Bounded to luci-mod-system-flash read `fs.exec` of `/sbin/sysupgrade --list-backup` at luci `b2e0be4b`: `flash.js` `handleBackupList`. Inventoried luci-ssl ACLs grant the cmdline, not the bare executable; extra tokens are `PERMISSION_DENIED`, not `authorization_violation` and not a PoC. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. A ubus `file.exec` grant without the matching file ACL is a **non-join**. Catalog copy: [m2-ubus-file-exec-list-backup-effect.json](m2-ubus-file-exec-list-backup-effect.json). Join keys use `entrypoint_id` `ubus_http:file.exec:/sbin/sysupgrade:--list-backup` plus `ubus_object=file` / `method=exec`. Reuses the existing `luci-mod-system-flash` list-read session already used for cgi-backup / cgi-download. Does not model `execv`, live PATH search, diagnostics ping, cron (`ubus` `file.write` not `file.exec`), or flash.js write sysupgrade/firstboot (write ACLs exist but the fixture is list-read only). reboot.js `system.reboot` is `policy:ubus-system-reboot-v1`.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `file.exec.list-backup` | `policy:grant:luci-mod-system-flash:ubus_http:file.exec:list-backup` | `policy:grant:root:ubus_http:file.exec:list-backup` | no-join |

### ubus system.reboot luci-mod-system-reboot (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `reboot.js` `rpc.declare` of `system.reboot` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `system` / `reboot` to `luci-mod-system-reboot` write. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The list-read flash fixture and other system fixtures without `system.reboot` are **non-joins**. Catalog copy: [m2-ubus-system-reboot-effect.json](m2-ubus-system-reboot-effect.json). Join keys use `entrypoint_id` `ubus_http:system.reboot` plus `ubus_object=system` / `method=reboot`. An allow is the HTTP gate, not procd `reboot()`. `rpc-sys.reboot` is a different object. `file.exec` of `/sbin/reboot` is unused by `reboot.js`; flash.js `/sbin/reboot` stays unstaffed. Does not invent a write flash login.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `system.reboot` | `policy:grant:luci-mod-system-reboot:ubus_http:system.reboot` | `policy:grant:root:ubus_http:system.reboot` | no-join |

### ubus rc.init luci-mod-system-init (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `startup.js` / `system.js` `rpc.declare` of `rc.init` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `rc` / `init` to `luci-mod-system-init` write and to the existing `luci-mod-system-config` write fixture. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The reboot fixture and other system fixtures without `rc.init` are **non-joins**. Catalog copy: [m2-ubus-rc-init-effect.json](m2-ubus-rc-init-effect.json). Join keys use `entrypoint_id` `ubus_http:rc.init` plus `ubus_object=rc` / `method=init`. An allow is the HTTP gate, not rpcd `rc.c` `execl`. `rc.list` is `policy:ubus-rc-list-v1`. Do not invent a `setInitAction` luci-ssl grant.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `rc.init` | `policy:grant:luci-mod-system-init:ubus_http:rc.init` | `policy:grant:root:ubus_http:rc.init` | no-join |

The existing `luci-mod-system-config` write fixture also joins (`policy:grant:luci-mod-system-config:ubus_http:rc.init`).

### ubus rc.list luci-mod-system-init (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `startup.js` / `system.js` `rpc.declare` of `rc.list` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `rc` / `list` to `luci-mod-system-init` read and `luci-mod-system-config` read. Write fixtures also match because rpcd write implies read. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The reboot fixture and other system fixtures without `rc.list` are **non-joins**. Catalog copy: [m2-ubus-rc-list-effect.json](m2-ubus-rc-list-effect.json). Join keys use `entrypoint_id` `ubus_http:rc.list` plus `ubus_object=rc` / `method=list`. An allow is the HTTP gate, not rpcd `rc.c` directory scan. `rc.init` stays on `policy:ubus-rc-init-v1`. The read fixture cannot pass `rc.init`. Do not invent a `setInitAction` luci-ssl grant.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `rc.list` | `policy:grant:luci-mod-system-init-read:ubus_http:rc.list` | `policy:grant:root:ubus_http:rc.list` | no-join |

The existing write `luci-mod-system-init` and `luci-mod-system-config` fixtures also join (`policy:grant:luci-mod-system-init:ubus_http:rc.list`, `policy:grant:luci-mod-system-config:ubus_http:rc.list`).

### ubus system.board luci-mod-status-index (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `10_system.js` `rpc.declare` of `system.board` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `system` / `board` to `luci-mod-status-index` read. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The reboot fixture and other system fixtures without `system.board` are **non-joins**. Catalog copy: [m2-ubus-system-board-effect.json](m2-ubus-system-board-effect.json). Join keys use `entrypoint_id` `ubus_http:system.board` plus `ubus_object=system` / `method=board`. An allow is the HTTP gate, not procd `board_info`. `system.info` is a different method on the same ACL (`policy:ubus-system-info-v1`). `system.reboot` stays on `policy:ubus-system-reboot-v1`. `luci.getVersion` / `getUnixtime` stay luci object methods. Do not invent luci object grants.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `system.board` | `policy:grant:luci-mod-status-index:ubus_http:system.board` | `policy:grant:root:ubus_http:system.board` | no-join |

### ubus system.info luci-mod-status-index (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `10_system.js` `rpc.declare` of `system.info` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `system` / `info` to `luci-mod-status-index` read. Unauthenticated is a **non-join** (`ERROR_ACCESS`). Missing SID is `ERROR_PARSE`. The reboot fixture and other system fixtures without `system.info` are **non-joins**. Catalog copy: [m2-ubus-system-info-effect.json](m2-ubus-system-info-effect.json). Join keys use `entrypoint_id` `ubus_http:system.info` plus `ubus_object=system` / `method=info`. An allow is the HTTP gate, not the procd `system.info` handler. `system.board` stays on `policy:ubus-system-board-v1`. `system.reboot` stays on `policy:ubus-system-reboot-v1`. `luci.getVersion` / `getUnixtime` stay luci object methods. Do not invent luci object grants. Do not invent a `luci-mod-status-index-storage` login.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `system.info` | `policy:grant:luci-mod-status-index:ubus_http:system.info` | `policy:grant:root:ubus_http:system.info` | no-join |

### ubus luci.getVersion luci-mod-status-index (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `10_system.js` `rpc.declare` of `luci.getVersion` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `luci` / `getVersion` to `luci-mod-status-index` read. Unauthenticated is a **non-join** (`ERROR_ACCESS`; unauthenticated grants only `luci.getFeatures`). Missing SID is `ERROR_PARSE`. The reboot fixture and other system fixtures without `luci.getVersion` are **non-joins**. Catalog copy: [m2-ubus-luci-getversion-effect.json](m2-ubus-luci-getversion-effect.json). Join keys use `entrypoint_id` `ubus_http:luci.getVersion` plus `ubus_object=luci` / `method=getVersion`. An allow is the HTTP gate, not the luci-base `getVersion` handler. Does not rewrite the luci exec-methods emitter. `system.board` stays on `policy:ubus-system-board-v1`. `system.info` stays on `policy:ubus-system-info-v1`. `luci.getUnixtime` / `getOdhcp6cStats` are other luci object methods and are not this slice. Do not invent extra ACL. Do not invent a `luci-mod-status-index-storage` login.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `luci.getVersion` | `policy:grant:luci-mod-status-index:ubus_http:luci.getVersion` | `policy:grant:root:ubus_http:luci.getVersion` | no-join |

### ubus luci.getUnixtime luci-mod-status-index (policy-facts synthetic)

HTTP `/ubus` gate only. Bounded to `10_system.js` `rpc.declare` of `luci.getUnixtime` at luci `b2e0be4b`. Inventoried luci-ssl ACLs grant ubus `luci` / `getUnixtime` to `luci-mod-status-index` read. Unauthenticated is a **non-join** (`ERROR_ACCESS`; unauthenticated grants only `luci.getFeatures`). Missing SID is `ERROR_PARSE`. The reboot fixture and other system fixtures without `luci.getUnixtime` are **non-joins**. Catalog copy: [m2-ubus-luci-getunixtime-effect.json](m2-ubus-luci-getunixtime-effect.json). Join keys use `entrypoint_id` `ubus_http:luci.getUnixtime` plus `ubus_object=luci` / `method=getUnixtime`. An allow is the HTTP gate, not the luci-base `getUnixtime` handler. Does not rewrite the luci exec-methods emitter. `luci.getVersion` stays on `policy:ubus-luci-getversion-v1`. `getOdhcp6cStats` is another luci object method and is not this slice. `luci-mod-system-config` / `system.js` also grant `getUnixtime` and are not this slice. Do not invent extra ACL.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `luci.getUnixtime` | `policy:grant:luci-mod-status-index:ubus_http:luci.getUnixtime` | `policy:grant:root:ubus_http:luci.getUnixtime` | no-join |

## Out of this file

- dispatcher / `menu.d` routes
- luci-ssl `files[]` routing classification ([m4-luci-ssl-files.md](m4-luci-ssl-files.md))
- remaining ubus `file.exec` without a matching luci-ssl grant + caller pair in this catalog (`/bin/ping` via `fs.exec_direct` with no cgi-io on luci-mod-network-diagnostics; crontab.js `fs.exec` of cron reload has file.exec of the cmdline but ubus `file.write` not `file.exec`; luci-mod-system flash.js write sysupgrade/firstboot stay unstaffed — write ACLs exist but the flash fixture is list-read only; flash.js tar `-tzf` and `/sbin/reboot` stay unstaffed)
- `authorization_violation` / BrokenAccessControl `path_found`
- Alloy `producer: step4`
