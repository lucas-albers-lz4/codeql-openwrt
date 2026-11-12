# M4: luci-ssl `files[]` via `luci.mk` (routing inventory)

Inventory/report only, transcribed from luci pin `b2e0be4b`. This fills the profile stub that previously listed only the first-endpoint rpcd plugin. Classifications follow plan section 2 rule order on **installed** paths. This is not the codeql-ucode extractor seven-case gate and does not claim extraction of the broader corpus.

`shellquote` and `basename` are not sanitizers. Unauthenticated deny stays deny. Root `*` is unchanged `intended_access`. This slice does not rewrite the luci emitter, does not invent luci-ssl grants, and does not claim `path_found`. Dispatcher / `menu.d`, Alloy, markup extraction, Track A, and `setInitAction` are not staffed.

## `luci.mk` copy rules (pin `b2e0be4b`)

| Source dir | Installed |
| --- | --- |
| `ucode/` | `/usr/share/ucode/luci/` |
| `htdocs/` | `/www/` |
| `root/` | `/` |
| luci-base `src/` install | `/usr/lib/ucode/luci/core.so` and generated `/usr/share/ucode/luci/version.uc` |
| luci-base postinst | uhttpd `ucode_prefix` `/cgi-bin/luci=/usr/share/ucode/luci/uhttpd.uc` |

The postinst mapping is not a second copy of `htdocs/cgi-bin/luci`. Stock luci-ssl therefore has both a shebang CGI at `/www/cgi-bin/luci` and a markup uhttpd prefix onto `uhttpd.uc`. Neither dispatcher path is analyzed here.

## luci-ssl package closure (`CONFIG_IPV6=y`)

`luci-ssl` → `luci-light` + `luci-app-package-manager` (+ mbedtls C libs, not luci.mk).
`luci-light` → `luci-mod-admin-full` + `luci-app-firewall` + `luci-theme-bootstrap` + `luci-proto-ppp` + `luci-proto-ipv6` + `rpcd-mod-rrdns` + `uhttpd`.
`luci-mod-admin-full` → `luci-base` + `luci-mod-status` + `luci-mod-system` + `luci-mod-network`.

`luci-mod-admin-full` is a meta package (Makefile only).

## Plan section 2 rule order

1. `/usr/share/rpcd/ucode/*` → **plain** (rpcd `raw_mode`)
2. `.ut` → **markup**
3. shebang `^#!.*\bucode\b` → **plain**
4. content `(?m)^\s*\{[%{#]` → **markup** (before `.uc` fallback)
5. `.uc` / `.ucode` → **plain**
6. remaining `/usr/share/ucode/**` → **uncertain**

## luci-ssl hits vs the extractor seven-case gate

The seven-case gate is extractor work in `codeql-ucode`. luci-ssl at this pin supplies only the cases that actually exist:

| Gate case | Present in luci-ssl? | Evidence |
| --- | --- | --- |
| shebang-less extensionless plugin | yes | `/usr/share/rpcd/ucode/luci` |
| `.uc` under rpcd | **no** | only the extensionless `luci` plugin |
| shebang `/usr/libexec/*` ucode | **no** | libexec helpers are `#!/bin/sh`; shebang ucode is `/www/cgi-bin/luci` |
| ordinary `.ut` | yes | `template/header.ut` and siblings |
| tagged `.uc` | yes | `uhttpd.uc` starts with `{%` |
| `.ut` named plugin under rpcd | **no** | not in tree |
| extensionless `/usr/share/ucode/` | yes | theme symlinks `bootstrap-dark` / `bootstrap-light` |

Do not invent missing gate files.

## Counts

Routing records in [m4-luci-ssl-files.json](m4-luci-ssl-files.json): 10 plain, 12 markup (`markup_not_modeled`), 2 uncertain. Three `exec_helper_inventory` rows (`shell_not_analyzed`) for `/usr/libexec/{syslog-wrapper,luci-peeraddr,package-manager-call}`.

Not listed per-file (not ucode routing): 87 JS files under `htdocs/` (Track A not staffed), `menu.d` JSON (dispatcher not staffed), ACL JSON already mirrored as M2 fixtures, `luci-bwc.c` / `core.so` / `rpcd-mod-*` (`c_plugin_not_analyzed`).

Remaining luci object **exec** methods at this pin: none except `setInitAction` (no luci-ssl delegated grant; not staffed). `getMountPoints` / `getLEDs` / `getUSBDevices` and the other granted readers are file/UCI/ubus, not exec.

See `reports/m4-luci-ssl-files-coverage.json`.
