# V2 source-model inputs

The LuCI Makefiles are unmodified bytes from openwrt/luci commit
`b2e0be4b46ec0fd43394c081fa7c50657af14011`, at respectively
`modules/luci-mod-system/Makefile`, `modules/luci-base/Makefile`,
`modules/luci-mod-admin-full/Makefile`, `collections/luci-ssl/Makefile`, and
`collections/luci-light/Makefile`. `feeds.conf.default` comes from openwrt/openwrt
commit `4e9642517b48bae612ff10fb72fb9199e559500e`. The v2 consumer pins their
SHA-256 values independently. They describe source recipes and feed selection,
not an installed package or a build result.
The `uhttpd.Makefile`, `uhttpd.config`, `uhttpd.init`, and `ubus.default`
files are unmodified bytes from that OpenWrt commit under
`package/network/services/uhttpd/` (`Makefile` and `files/` respectively).
The source model assumes the defaults script ran while the prefix was absent
and that the plugin is present; those are not observations of deployment.
