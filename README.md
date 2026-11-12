# codeql-openwrt

Pipeline repo for static analysis of OpenWrt 25.12 LuCI: corpus lockfile, interchange schema, policy-facts, and evidence reports.

The ucode CodeQL language pack lives in [codeql-ucode](https://github.com/lucas-albers-lz4/codeql-ucode) (`lucas-albers-lz4/ucode-all`, `lucas-albers-lz4/ucode-queries`).

First slice: `/ubus` → `luci.getFeatures` → `callPackageVersionCheck('netifd')` → named `popen` from `'fs'`. Findings are evidence, not proof.

See [docs/pack-contract.md](docs/pack-contract.md), `corpus/lock.json`, and [policy/README.md](policy/README.md) for the M2 `/ubus` `luci.getFeatures` oracle.
