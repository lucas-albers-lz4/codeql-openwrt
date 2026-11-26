#!/usr/bin/env bash
# Input checks and selected serial loop shared by the runner and offline tests.
check_inputs() {
  local openwrt=$1 luci=$2 packages_root=$3 name
  [[ $(realpath "$openwrt/feeds/luci") == "$luci" && $(realpath "$openwrt/feeds/packages") == "$packages_root" ]]
  for name in luci-app-ddns luci-app-advanced-reboot luci-app-wifihistory; do
    [[ $(realpath "$openwrt/package/feeds/luci/$name") == "$luci/applications/$name" ]]
  done
  [[ $(realpath "$openwrt/package/feeds/packages/ddns-scripts") == "$packages_root/net/ddns-scripts" ]]
}

run_kernel_prelude() {
  local callback=$1
  "$callback" kernel-compile target/linux/compile
  "$callback" kernel-package-compile package/kernel/linux/compile
}

run_app_batches() {
  local openwrt=$1 luci=$2 packages_root=$3 callback=$4 name
  local -a selected=(luci-app-ddns luci-app-advanced-reboot luci-app-wifihistory)
  for name in "${selected[@]}"; do
    "$callback" "$name"
  done
}
