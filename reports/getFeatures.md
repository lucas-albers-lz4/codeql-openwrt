# M3 evidence: `/ubus` `luci.getFeatures`

Findings are evidence, not proof. Wrapper AST/CFG/dataflow libraries are not imported; models walk generated TreeSitter nodes.

## Selected chain

`getFeatures.call` → same-file `callPackageVersionCheck('netifd')` → named `popen` imported from `'fs'` (opkg and apk branches). No `request.args` taint on that helper (`GetFeaturesHelperTaint.ql` is empty).

Assessment for stock unauthenticated feature probing: **intended_access**. The helper interpolates a literal package name through `shellquote`. Reaching `popen` here is not BAC or RCE.

## Synthetic taint controls

| Fixture | Expected | Result |
| --- | --- | --- |
| `taint_pos` | `request.args.cmd` → `popen` | `path_found` |
| `taint_neg` | unused `request.args.cmd`; `popen` of a fixed string | `no_path` |

## Other luci `popen` / `system` (unassessed)

Nine named `fs` `popen` calls and six builtin `system()` calls exist in the plugin. Four `popen` sites take `request.args` (switch helpers). Those methods are **unassessed** in this slice. `getFeatures` also calls builtin `system()` for hostapd/wpa_supplicant probes (template strings); expected-capabilities already lists them as unmodeled branches.

## Coverage

See `docs/m3-coverage.json`. M2 `grants.json` is joined when that PR lands; this report does not claim a live `session.access` check inside the plugin (there is none on the default `getFeatures` body).
