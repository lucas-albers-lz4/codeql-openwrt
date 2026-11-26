# Three LuCI app package batch (source-first candidate)

This candidate compares three independently selected LuCI packages: `luci-app-ddns`, `luci-app-advanced-reboot`, and `luci-app-wifihistory`. It uses a clean OpenWrt `4e9642517b48bae612ff10fb72fb9199e559500e` checkout, LuCI `cb87fe60e1e2e052af36a93647f2264577829e0a`, and packages feed `07e0d16305d2b5903b37ad7913e33e18795f81a`. The embedded [source oracle](source-oracle.json) is pinned by SHA-256 `05906176f0830f311e2872d9d4b7743825cb80dfe1cb89af22673feac212d72a`; source-first documentation and producer hashes are in the retained packet `coverage-wave-work/issue173-app-batch-source-20261126/` in the paired workspace.

The workflow has an offline pull request contract job and a manually triggered experiment job that depends on it. This candidate has not been dispatched, and no package build has run. Reconcile the previous core and app/service package runs, review the exact commands and config, and obtain the applicable owner gate before a dispatch.

## Scope and evidence boundaries

The runner resolves the two source feeds, checks the exact app and dependency recipe symlinks, fixes the x86_64 target and app package symbols, records `.config`, `feeds.conf`, resolved dependency modes (`m` or `y`), `CONFIG_USE_MUSL=y`, `CONFIG_LUCI_JSMIN`, and `CONFIG_LUCI_CSSTIDY`, and builds the selected app targets serially in one fresh Linux tree. `luci-base` and the three selected apps must resolve to `m`; each runtime dependency must resolve exactly once to `m` or `y`; `CONFIG_PER_FEED_REPO=y` is mandatory. It requires the exact x86_64 per-feed path and versioned `Architecture: all` filename, records the initial and post-build raw NUL-delimited stage and IPK path inventories, retains each selected app IPK separately under a fixed name, and writes a separate receipt. The built archive must be exactly `bin/packages/x86_64/luci/<package>_<projected-version>_all.ipk`; the retained copy must byte-match it. Receipt writes use an exclusive create below the fresh run output root. After each later package build, both inventories and retained-byte equality must remain unchanged. After each selected package build, it re-resolves and re-compares every package built so far, requiring byte-identical receipts, stage/IPK paths and bytes, source feeds and config inputs. The final successful build therefore rechecks all three selected packages. It does not treat dependency or translation packages as selected app outputs.

The comparator binds the clean pinned packages feed and exact `net/ddns-scripts/Makefile` Git blob (`c0f6aef5047bd4b07f1e1708557bdf41ff763c34`, SHA-256 `eaf326cffdd5436c0fe039030b40279a24ab2b7104dc7ddd5fa014957c66177b`), the LuCI recipes/feed links, Git blob/mode/source bytes, prepared copies when available, stage files, archive members, package control name/version/architecture, and source projections. IPKs are parsed without extraction. Duplicate/unsafe archive paths, unsupported archive entry types, mismatched membership, modes, controls, prepared bytes or stage/IPK bytes fail closed. Package membership expectations cover the pinned source rows plus the recipe-generated Advanced Reboot file; any additional file fails. The recorded stage and IPK hashes are observations, not proof of root-image installation or runtime behavior.

There are four selected Ucode source paths, four JavaScript assets, three ACL files and two shell-shaped negative controls across this batch. Their package bytes and membership remain unobserved until an authorized run. The WiFi History init script and Advanced Reboot uci-defaults file are recorded as shell controls. Candidate classification does not establish execution, routing, reachability, authorization or security coverage.

Advanced Reboot's pinned `Build/Prepare` concatenates 44 sorted device JSON files as a JSON array under `LC_ALL=C`, checks for the literal `"device"`, and removes both the input `devices/` directory and `devices.disabled/`. Preflight independently recomputes the projected merge digest from pinned Git files. If run, the comparator checks the generated prepared `devices.json`, stage and IPK bytes/mode against that projection, and confirms the source directories are absent. Since the recipe deletes individual inputs, no post-Prepare prepared copy exists for each input; only their pinned source identities and the generated output can be compared. The expected output mode `0644` depends on `umask 022`.

Advanced Reboot has one JavaScript asset, DDNS has two, and WiFi History has one. When the resolved `CONFIG_LUCI_JSMIN` is disabled, their packaged bytes must equal source bytes. When enabled, the package bytes and stage/IPK agreement are recorded, while the transformation's provenance remains unknown. `CONFIG_LUCI_CSSTIDY` is retained in config facts; this selected source inventory contains no CSS files. `luci.mk` may separately create `luci-i18n-*` packages from tracked `po/` catalogs; those identities are projected in the source packet but their output IPKs are not established here and must remain separate from the selected app outputs.

The selected app recipes project `Architecture: all`; their actual controls are unknown until observed. Recipe dependencies include `ddns-scripts`, `jshn`, `rpcd-mod-iwinfo`, `ucode`, `ucode-mod-fs`, `ucode-mod-ubus`, and `luci-base`; the runner selects dependency symbols for resolver/build context but retains no dependency package as an app result. Verify exact resolution and feed paths in any future run.

## Offline checks

```sh
python3 -B -m unittest discover -s tools/luci-app-module-batches -p 'test_*.py' -v
python3 -O -B -m unittest discover -s tools/luci-app-module-batches -p 'test_*.py' -v
python3 -B -m unittest discover -s tools/luci-base-inventory -p 'test_*.py' -v
bash -n tools/luci-app-module-batches/run.sh
bash -n tools/luci-app-module-batches/batch-order.sh
```

The source oracle can be checked against a clean pinned LuCI checkout with:

```sh
python3 -B tools/luci-app-module-batches/compare.py --preflight --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages"
```

No package output, build, or workflow dispatch was run while preparing this candidate.
