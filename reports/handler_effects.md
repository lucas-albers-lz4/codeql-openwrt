# Canonical `handler_effects.json`

Join catalog for modeled `/ubus` `luci` privileged sinks. Producer files under `reports/` remain the query snapshots; this file is the one `handler_effect` list consumers should join against `policy/grants.json`.

Findings are evidence, not proof. This slice does not emit `authorization_violation`, cgi-io, or dispatcher effects. `shellquote` and `basename` are not sanitizers.

## Sources

| Source | What was collected |
| --- | --- |
| [findings.json](findings.json) | `getFeatures` → `callPackageVersionCheck('netifd')` → named `popen` |
| [m4-getfeatures-direct-exec.json](m4-getfeatures-direct-exec.json) | `getFeatures.call` hostapd / wpa_supplicant `system`, dnsmasq / odhcpd / ipset `popen` |
| [m4-findings.json](m4-findings.json) | five request.args exec sinks, projected from existing `taint_path` rows (no new query) |
| [m4-luci-sys-init-action-findings.json](m4-luci-sys-init-action-findings.json) | `luci.sys` `init_action` → builtin `system` (no M2 grant) |

Not collected: synthetic taint fixtures, `taint_path` / `backend_method` rows, shellquote barrier `no_path` rows, cgi-io, dispatcher.

## Grant ↔ effect joins

Cross-producer joins (`policy_grant` ↔ `handler_effect`) match **identical** `corpus_revision` and `profile`, plus `ingress`, `entrypoint_id`, `ubus_object`, `method`, and the grant `record_id` in the effect's `evidence_refs`. `analysis_revision` stays producer-local (`policy:ubus-luci-exec-methods-v1` vs `step3:*`) and is **not** a join key. See [docs/pack-contract.md](../docs/pack-contract.md).

Catalog copies add the `#12` / root grant ids on `evidence_refs` so both session classes that actually hold the grant join. Producer snapshots may still list only the first assessed session.

### `#12` exec-method grants

Unauthenticated `/ubus` is a **non-join** (M2 deny). Delegated module sessions and stock root `*` join as `intended_access`.

| Method | `effect_id` | Delegated grant | Root grant | Unauthenticated |
| --- | --- | --- | --- | --- |
| `getSwconfigFeatures` | `getSwconfigFeatures.swconfig.popen` | `policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigFeatures` | `policy:grant:root:ubus_http:luci.getSwconfigFeatures` | no-join (`policy:decision:unauthenticated-getSwconfigFeatures-deny`) |
| `getSwconfigPortState` | `getSwconfigPortState.swconfig.popen` | `policy:grant:luci-mod-network-config:ubus_http:luci.getSwconfigPortState` | `policy:grant:root:ubus_http:luci.getSwconfigPortState` | no-join (`policy:decision:unauthenticated-getSwconfigPortState-deny`) |
| `getRealtimeStats` | `getRealtimeStats.luci-bwc.popen` | `policy:grant:luci-mod-status-realtime:ubus_http:luci.getRealtimeStats` | `policy:grant:root:ubus_http:luci.getRealtimeStats` | no-join (`policy:decision:unauthenticated-getRealtimeStats-deny`) |
| `setPassword` | `setPassword.busybox-passwd.system` | `policy:grant:luci-mod-system-config:ubus_http:luci.setPassword` | `policy:grant:root:ubus_http:luci.setPassword` | no-join (`policy:decision:unauthenticated-setPassword-deny`) |
| `setLocaltime` | `setLocaltime.date.system` | `policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime` | `policy:grant:root:ubus_http:luci.setLocaltime` | no-join (`policy:decision:unauthenticated-setLocaltime-deny`) |

Those five effects are handler sinks collected from the existing request.args inventory. `shellquote` on the swconfig / luci-bwc / passwd paths is observed, not a sanitizer. `localtime` / `sprintf %d` on `setLocaltime` are not sanitizers.

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

## Out of this file

- cgi-io synthetic effects (`cgi-backup` and siblings) — later ingress
- dispatcher / `menu.d` routes
- `authorization_violation` / BrokenAccessControl `path_found`
- Alloy `producer: step4`
