# Canonical `handler_effects.json`

Join catalog for modeled `/ubus` `luci` privileged sinks plus the synthetic cgi-io backup/upload/download/exec effects. Producer files under `reports/` remain the query snapshots for luci rows (block-device / sysfixtime rows are transcribed from the pinned plugin, not a new query; luci.sys status popens are transcribed from pinned `sys.uc`, not a new query); cgi-io rows are policy-facts (`policy:cgi-backup-v1` / `policy:cgi-upload-v1` / `policy:cgi-download-v1` / `policy:cgi-exec-v1` / `policy:cgi-exec-file-v1` / `policy:cgi-exec-status-v1`). This file is the one `handler_effect` list consumers should join against `policy/grants.json`.

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

Not collected: synthetic taint fixtures, `taint_path` / `backend_method` rows, shellquote barrier `no_path` rows, same-function-local quoting inventory ([m4-realtime-password-quoted-locals.json](m4-realtime-password-quoted-locals.json)), luci-ssl `files[]` routing classification ([m4-luci-ssl-files.json](m4-luci-ssl-files.json)), dispatcher. Helper `exec_helper_inventory` rows stay in the files inventory; this catalog holds the cgi-exec file.exec effects those helpers join.

## Grant ↔ effect joins

Cross-producer joins (`policy_grant` ↔ `handler_effect`) match **identical** `corpus_revision` and `profile`, plus `ingress`, `entrypoint_id`, and either `ubus_object`/`method` or `cgi_endpoint`, and the grant `record_id` in the effect's `evidence_refs`. `analysis_revision` stays producer-local (`policy:ubus-luci-exec-methods-v2` / `policy:cgi-backup-v1` / `policy:cgi-upload-v1` / `policy:cgi-download-v1` / `policy:cgi-exec-v1` / `policy:cgi-exec-file-v1` / `policy:cgi-exec-status-v1` vs `step3:*`) and is **not** a join key. See [docs/pack-contract.md](../docs/pack-contract.md).

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

`getConntrackList` and `getProcessList` are **fixed** luci.sys helper exec (`call: function()`, no `request.args`). The plugin methods are thin wrappers. Unauthenticated is a **non-join**. `getConntrackList` joins the existing `luci-mod-status-realtime` session (ACL already listed it next to `getRealtimeStats`), not a new session class. The `luci-mod-status-processes` fixture is read-only; write `file.exec` `/bin/kill` is not emitted. QL for these helpers waits on `codeql-ucode#12`.

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

## Out of this file

- dispatcher / `menu.d` routes
- luci-ssl `files[]` routing classification ([m4-luci-ssl-files.md](m4-luci-ssl-files.md))
- ubus `file.exec` (rpcd-mod-file), including `iptables.js` `handleCounterReset` and routes `ip`
- `authorization_violation` / BrokenAccessControl `path_found`
- Alloy `producer: step4`
