# Installed-file routing contract

This repository defines the following inventory routing policy. It is self-contained and does not depend on an external plan. `corpus/luci_ssl_files.py::classify_installed` implements this order for installed paths and recorded source evidence. It classifies source format only; it does not establish extraction, ingress reachability, command safety, or authorization.

## Installed paths

At luci pin `b2e0be4b46ec0fd43394c081fa7c50657af14011`, `luci.mk` copies package `ucode/` contents to `/usr/share/ucode/luci/`, `htdocs/` contents to `/www/`, and `root/` contents to `/`. The luci-base `src/Makefile` additionally installs generated `version.uc` and native `core.so`. The luci-base postinst may configure the uhttpd ucode prefix when its runtime/configuration conditions hold; an install rule is not proof of the active dispatcher on a live image.

## Classification order

Apply the first matching rule to the installed path, first-line shebang, and recorded content prefix:

1. Every path under `/usr/share/rpcd/ucode/` is **plain**, reflecting the rpcd raw-mode plugin intake. This overrides extensions and markup markers.
2. A path ending in `.ut` is **markup**, including a `.ut` file with a ucode shebang.
3. A first-line shebang matching `^#!.*\bucode\b` is **plain**.
4. A content prefix matching `(?m)^\s*\{[%{#]` is **markup**. This precedes the `.uc` fallback.
5. A path ending in `.uc` or `.ucode` is **plain**.
6. A remaining path under `/usr/share/ucode/` is **uncertain**. Unresolved symlink targets are not followed to claim extraction.

If no rule matches, the path has no ucode routing classification in this slice; `classify_installed` raises `ValueError`. JavaScript and shell helpers are recorded separately as unstaffed evidence. **Markup** is `markup_not_modeled`; classification does not claim a markup extractor. The seven synthetic extractor cases are listed in the report only to distinguish cases present in the pinned package set from absent ones; this inventory does not pass the codeql-ucode extractor gate.

## Routing-only inheritance

A profile owns routing records when its `files_inventory_profile` equals its `profile`. A variant may explicitly reference its `base_profile` with both:

- `files_inventory_profile` equal to that base profile;
- `files_inventory_inheritance: "routing_only"`.

`routing_inventory_profile` validates this declaration. `find_routing_record` then selects only `record_type: "routing"` with exact equality of `corpus_revision`, the declared inventory profile, and `fs_path`. It returns the original record with its original `profile`; it never retags records. Missing keys do not match, and duplicate routing keys are rejected.

For `luci-ssl-25.12-no-ubusauth`, installed-file routing resolves to the explicitly declared `luci-ssl-25.12` inventory because the setting changes the HTTP auth gate rather than the installed file set. This inheritance applies solely to routing lookup. It does not resolve `policy_grant`, `policy_decision`, `handler_effect`, `taint_path`, or `exec_helper_inventory` rows. Authorization and effect joins retain the requesting profile and require exact profile equality; the base profile's grants and decisions are never inherited.

## Pinned source evidence

- [luci.mk install rules](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/luci.mk)
- [luci-base postinst](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-base/Makefile)
- [luci-base generated/native installs](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-base/src/Makefile)
- [luci-mod-network dependency on luci-lib-uqr](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-mod-network/Makefile)
- [luci-lib-uqr JavaScript source](https://github.com/openwrt/luci/blob/b2e0be4b46ec0fd43394c081fa7c50657af14011/libs/luci-lib-uqr/htdocs/luci-static/resources/uqr.js)
