#!/usr/bin/env bash
# Exact package identities are required; no wildcard winner is permitted.
check_feed_links() {
  [[ $(realpath "$1/feeds/luci") == "$2" && $(realpath "$1/feeds/packages") == "$3" ]] || return 1
  for pkg in luci-mod-status luci-mod-network luci-mod-system luci-mod-admin-full; do
    [[ $(realpath "$1/package/feeds/luci/$pkg") == "$2/modules/$pkg" ]] || return 1
  done
}
find_package_stage() {
  find "$1/build_dir" -type d -path "*/$2/ipkg-*/$2" -print0
}
find_package_ipk() {
  find "$1/bin/packages" -type f -name "$2_*.ipk" -print0
}
