# Canonical `handler_effects.json`

Join catalog for modeled `/ubus` `luci` privileged sinks plus the synthetic cgi-backup effect. Producer files under `reports/` remain the query snapshots for luci rows (block-device / sysfixtime rows are transcribed from the pinned plugin, not a new query); cgi-backup is policy-facts (`policy:cgi-backup-v1`). This file is the one `handler_effect` list consumers should join against `policy/grants.json`.

Findings are evidence, not proof. This catalog does not emit `authorization_violation`, cgi-exec/upload/download, or dispatcher effects. `shellquote` and `basename` are not sanitizers.

## Sources

| Source | What was collected |
| --- | --- |
| [findings.json](findings.json) | `getFeatures` → `callPackageVersionCheck('netifd')` → named `popen` |
| [m4-getfeatures-direct-exec.json](m4-getfeatures-direct-exec.json) | `getFeatures.call` hostapd / wpa_supplicant `system`, dnsmasq / odhcpd / ipset `popen` |
| [m4-findings.json](m4-findings.json) | five request.args exec sinks, projected from existing `taint_path` rows (no new query) |
| [m4-block-device-exec.json](m4-block-device-exec.json) | `getBlockDevices` / `setBlockDetect` fixed `/sbin/block` exec plus `setLocaltime` sysfixtime |
| [m4-luci-sys-init-action-findings.json](m4-luci-sys-init-action-findings.json) | `luci.sys` `init_action` → builtin `system` (no M2 grant) |
| policy-facts `cgi_backup` | synthetic `cgi-backup` → `sensitive_backup_read` (C, not ucode) |

Not collected: synthetic taint fixtures, `taint_path` / `backend_method` rows, shellquote barrier `no_path` rows, cgi-exec/upload/download, dispatcher.

## Grant ↔ effect joins

Cross-producer joins (`policy_grant` ↔ `handler_effect`) match **identical** `corpus_revision` and `profile`, plus `ingress`, `entrypoint_id`, and either `ubus_object`/`method` or `cgi_endpoint`, and the grant `record_id` in the effect's `evidence_refs`. `analysis_revision` stays producer-local (`policy:ubus-luci-exec-methods-v2` / `policy:cgi-backup-v1` vs `step3:*`) and is **not** a join key. See [docs/pack-contract.md](../docs/pack-contract.md).

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

Those five effects are handler sinks collected from the existing request.args inventory. `shellquote` on the swconfig / luci-bwc / passwd paths is observed, not a sanitizer. `localtime` / `sprintf %d` on `setLocaltime` are not sanitizers.

### Fixed plugin-body exec (`luci-mod-system-mounts` + sysfixtime)

`getBlockDevices` and `setBlockDetect` are **fixed** plugin-body exec (`call: function()`, no `request.args`, not `luci.sys`). Unauthenticated is a **non-join**. `setLocaltime.sysfixtime.system` is a second sink on the already-granted `setLocaltime` method (literal `/etc/init.d/sysfixtime restart`); it joins the same `#12` grants, not a new method grant.

| Method | `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- | --- |
| `getBlockDevices` | `getBlockDevices.block-info.popen` | `policy:grant:luci-mod-system-mounts:ubus_http:luci.getBlockDevices` | `policy:grant:root:ubus_http:luci.getBlockDevices` | no-join (`policy:decision:unauthenticated-getBlockDevices-deny`) |
| `setBlockDetect` | `setBlockDetect.block-detect.system` | `policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect` | `policy:grant:root:ubus_http:luci.setBlockDetect` | no-join (`policy:decision:unauthenticated-setBlockDetect-deny`) |
| `setLocaltime` | `setLocaltime.sysfixtime.system` | `policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime` | `policy:grant:root:ubus_http:luci.setLocaltime` | no-join (`policy:decision:unauthenticated-setLocaltime-deny`) |

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

`cgi-backup.sysupgrade.create-backup` (`sink_kind=sensitive_backup_read`). cgi-io `main_backup` @ `31cb3c89` checks `session.access(sid, "cgi-io", "backup", "read")` only; it does not fork sysupgrade in this oracle. Unauthenticated `/cgi-bin/cgi-backup` is a **non-join** (403). Fixture `luci-mod-system-flash` and stock root `*` join as `intended_access`. A backup read is not a violation because the role lacks write. `shellquote` and `basename` are not sanitizers (no user path; fixed sysupgrade argv). cgi-exec/upload/download are not this slice.

| `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- |
| `cgi-backup.sysupgrade.create-backup` | `policy:grant:luci-mod-system-flash:cgi_io:cgi-backup` | `policy:grant:root:cgi_io:cgi-backup` | no-join (`policy:decision:unauthenticated-cgi-backup-deny`) |

## Out of this file

- cgi-exec / cgi-upload / cgi-download synthetic effects
- dispatcher / `menu.d` routes
- `authorization_violation` / BrokenAccessControl `path_found`
- Alloy `producer: step4`
