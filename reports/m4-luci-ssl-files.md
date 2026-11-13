# M4: luci-ssl `files[]` via `luci.mk` (routing inventory)

Inventory/report only, transcribed from luci pin `b2e0be4b`. This fills the profile stub that previously listed only the first-endpoint rpcd plugin. Classifications follow this repository's [installed-file routing contract](../docs/file-routing.md#classification-order) on **installed** paths. This is not the codeql-ucode extractor seven-case gate and does not claim extraction of the broader corpus.

Routing classifies source format and does not assess runtime quoting or command safety. Unauthenticated deny stays deny. Root `*` is unchanged `intended_access`. This slice does not rewrite the luci emitter, does not invent luci-ssl grants, and does not claim `path_found`. Dispatcher / `menu.d`, Alloy, markup extraction, Track A, and `setInitAction` are not staffed.

## `luci.mk` copy rules (pin `b2e0be4b`)

| Source dir | Installed |
| --- | --- |
| `ucode/` | `/usr/share/ucode/luci/` |
| `htdocs/` | `/www/` |
| `root/` | `/` |
| luci-base `src/` install | `/usr/lib/ucode/luci/core.so` and generated `/usr/share/ucode/luci/version.uc` |
| luci-base postinst | uhttpd `ucode_prefix` `/cgi-bin/luci=/usr/share/ucode/luci/uhttpd.uc` |

The postinst mapping is not a second copy of `htdocs/cgi-bin/luci`. The package installs the shebang CGI at `/www/cgi-bin/luci`; its postinst can configure a uhttpd prefix onto markup `uhttpd.uc` when the runtime/configuration conditions hold. Which dispatcher is active on a live image is unassessed. Neither dispatcher path is analyzed here.

## luci-ssl package closure (`CONFIG_IPV6=y`)

`luci-ssl` → `luci-light` + `luci-app-package-manager` (+ mbedtls C libs, not luci.mk).
`luci-light` → `luci-mod-admin-full` + `luci-app-firewall` + `luci-theme-bootstrap` + `luci-proto-ppp` + `luci-proto-ipv6` + `rpcd-mod-rrdns` + `uhttpd`.
`luci-mod-admin-full` → `luci-base` + `luci-mod-status` + `luci-mod-system` + `luci-mod-network`.
`luci-mod-network` → `luci-base` + **`luci-lib-uqr`** (+ native `rpcd-mod-iwinfo`). The uqr package uses `luci.mk` to install `htdocs/luci-static/resources/uqr.js` as `/www/luci-static/resources/uqr.js`. It is JavaScript evidence with Track A unstaffed, so it adds no ucode routing row.

`luci-mod-admin-full` is a meta package (Makefile only).

## Routing classification order

The normative, self-contained policy is [docs/file-routing.md](../docs/file-routing.md#classification-order); the implementation is `corpus/luci_ssl_files.py::classify_installed`.

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

Routing records in [m4-luci-ssl-files.json](m4-luci-ssl-files.json): 10 plain, 12 markup (`markup_not_modeled`), 2 uncertain. Three `exec_helper_inventory` rows for `/usr/libexec/{syslog-wrapper,luci-peeraddr,package-manager-call}`: `#!/bin/sh` helpers reached via `fs.exec_direct` → cgi-exec. Session/file.exec gates are `policy:cgi-exec-file-v1`. luci-mod-status dmesg/nft/iptables/firewall-init `fs.exec_direct` commands join `policy:cgi-exec-status-v1`. luci-mod-status iptables/ip6tables `-Z` and routes `ip` `fs.exec` commands join `policy:ubus-file-exec-v1`. luci-mod-network-config ifup/ifdown/wifi `fs.exec` commands join `policy:ubus-file-exec-ifup-v1`. luci-mod-status-processes `/bin/kill` `fs.exec` commands join `policy:ubus-file-exec-kill-v1`. luci-mod-system-mounts umount/`block mount` `fs.exec` commands join `policy:ubus-file-exec-mounts-v1`. luci-mod-system-flash `sysupgrade --list-backup` `fs.exec` commands join `policy:ubus-file-exec-list-backup-v1`. luci-mod-system-reboot `system.reboot` joins `policy:ubus-system-reboot-v1`. Helper-internal commands are transcribed, not executed.

Outside ucode routing: 88 JS files under `htdocs/`, counted per package with Track A unstaffed. The coverage JSON lists `uqr.js` explicitly as dependency/install evidence; the other JS assets are not individually listed. Also excluded: `menu.d` JSON (dispatcher not staffed), ACL JSON already mirrored as M2 fixtures, and `luci-bwc.c` / `core.so` / `rpcd-mod-*` (`c_plugin_not_analyzed`).

Remaining luci object **exec** methods at this pin: none except `setInitAction` (no luci-ssl delegated grant; not staffed). `getMountPoints` / `getLEDs` / `getUSBDevices` and the other granted readers are file/UCI/ubus, not exec. `system.reboot` is `policy:ubus-system-reboot-v1` (not a luci object method).

## Routing-only profile inheritance

The noauth variant explicitly sets `files_inventory_profile: "luci-ssl-25.12"` and `files_inventory_inheritance: "routing_only"`. `find_routing_record` resolves only routing rows by exact `corpus_revision`, that declared inventory profile, and `fs_path`; returned rows retain their base inventory profile. Grants, decisions, helper inventory and handler effects are excluded from this resolver. Their joins still require the requesting profile exactly. See the [routing-only inheritance contract](../docs/file-routing.md#routing-only-inheritance).

The coverage JSON includes the complete transitive LuCI dependency graph, per-package JavaScript counts totaling 88, and the pinned source/install evidence for `uqr.js`.

See `reports/m4-luci-ssl-files-coverage.json`.
