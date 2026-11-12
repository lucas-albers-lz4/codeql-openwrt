# codeql-openwrt

Pipeline repo for static analysis of OpenWrt 25.12 LuCI: corpus lockfile, interchange schema, policy-facts, and evidence reports.

The ucode CodeQL language pack lives in [codeql-ucode](https://github.com/lucas-albers-lz4/codeql-ucode) (`lucas-albers-lz4/ucode-all`, `lucas-albers-lz4/ucode-queries`).

First slice: `/ubus` → `luci.getFeatures` → `callPackageVersionCheck('netifd')` → named `popen` from `'fs'`. Findings are evidence, not proof.

See [docs/pack-contract.md](docs/pack-contract.md), `corpus/lock.json`, and [policy/README.md](policy/README.md) for the M2 `/ubus` luci policy oracle (`getFeatures` plus inventoried exec methods) and the cgi-io C oracles (`cgi-backup` `sensitive_backup_read`, conjunctive `cgi-upload` `file_write`, conjunctive `cgi-download` `file_read`, `cgi-exec` session exec read gate).

Canonical handler effects and grant joins: [reports/handler_effects.md](reports/handler_effects.md).

M4 request.args inventory: [reports/m4-request-args.md](reports/m4-request-args.md).
M4 fixed `/sbin/block` exec and `setLocaltime` sysfixtime: [reports/m4-block-device-exec.md](reports/m4-block-device-exec.md).
M4 luci.sys status popen: [reports/m4-luci-sys-status-exec.md](reports/m4-luci-sys-status-exec.md). `getConntrackList` / `getProcessList` are fixed argv; QL waits on codeql-ucode#12.
M4 getFeatures direct helpers: [reports/m4-getfeatures-direct-exec.md](reports/m4-getfeatures-direct-exec.md).
M4 `shellquote` complete-argument barrier: [reports/m4-shellquote.md](reports/m4-shellquote.md). `shellquote` is not a global sanitizer.
M4 imported callee: [reports/m4-imported-callee.md](reports/m4-imported-callee.md). `setInitAction` → `luci.sys` `init_action` is `inconclusive` under the M3 extract set (`unresolved_call`).
M4 luci.sys: [reports/m4-luci-sys-init-action.md](reports/m4-luci-sys-init-action.md). `init_action` reaches builtin `system` with interpolated `name`/`action`; `basename` is not a sanitizer.
