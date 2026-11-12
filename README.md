# codeql-openwrt

Pipeline repo for static analysis of OpenWrt 25.12 LuCI: corpus lockfile, interchange schema, policy-facts, and evidence reports.

The ucode CodeQL language pack lives in [codeql-ucode](https://github.com/lucas-albers-lz4/codeql-ucode) (`lucas-albers-lz4/ucode-all`, `lucas-albers-lz4/ucode-queries`).

First slice: `/ubus` → `luci.getFeatures` → `callPackageVersionCheck('netifd')` → named `popen` from `'fs'`. Findings are evidence, not proof.

See [docs/pack-contract.md](docs/pack-contract.md), `corpus/lock.json`, and [policy/README.md](policy/README.md) for the M2 `/ubus` `luci.getFeatures` oracle.

M4 request.args inventory: [reports/m4-request-args.md](reports/m4-request-args.md).
M4 getFeatures direct helpers: [reports/m4-getfeatures-direct-exec.md](reports/m4-getfeatures-direct-exec.md).
M4 `shellquote` complete-argument barrier: [reports/m4-shellquote.md](reports/m4-shellquote.md). `shellquote` is not a global sanitizer.
M4 imported callee: [reports/m4-imported-callee.md](reports/m4-imported-callee.md). `setInitAction` → `luci.sys` `init_action` is `inconclusive` / `unresolved_call`.
