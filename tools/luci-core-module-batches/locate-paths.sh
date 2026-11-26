#!/usr/bin/env bash
# Exact package identities are required; no wildcard winner is permitted.
check_feed_links() {
  [[ $(realpath "$1/feeds/luci") == "$2" && $(realpath "$1/feeds/packages") == "$3" ]] || return 1
  local pkg
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

# The runner and tests share this real serial target loop. luci-mod-admin-full
# remains a resolver/recipe dependency context and is never a selected output.
run_package_batches() {
  local openwrt=$1 luci=$2 packages_root=$3 callback=$4 pkg
  local -a selected=(luci-mod-status luci-mod-network luci-mod-system)
  for pkg in "${selected[@]}"; do
    check_feed_links "$openwrt" "$luci" "$packages_root"
    "$callback" "$pkg"
  done
}
