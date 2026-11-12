# M4 evidence: `getFeatures.call` direct `popen` / `system`

These are **call reachability** records (`handler_effect` / `fact`), not taint paths. `getFeatures.call` takes no `request.args`. Each sink interpolates a fixed command or a closed `wifi_features` token through a template.

| Line | Kind | Command |
| --- | --- | --- |
| 268 | `system` | `/usr/sbin/hostapd -v${feature}` for `feature` in a literal list |
| 275 | `system` | `/usr/sbin/wpa_supplicant -v${feature}` for the same list |
| 278 | `popen` | `dnsmasq --version` |
| 294 | `popen` | `odhcpd -h` |
| 315 | `popen` | `ipset --help` |

The netifd `callPackageVersionCheck` popens stay on the M3 `GetFeaturesPopen` records. Assessment: **intended_access** for stock unauthenticated feature probing. Reaching these sinks is not BAC or RCE.

Loop bodies over `wifi_features` are not unrolled; the query reports the `system()` call sites once each.
