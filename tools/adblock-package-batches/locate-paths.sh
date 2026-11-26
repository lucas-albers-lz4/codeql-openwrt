#!/usr/bin/env bash
# The source-pinned service recipe uses OpenWrt's default PKG_BUILD_DIR name.
find_service_stage() {
  find "$1/build_dir" -type f -path '*/adblock-fast-1.2.4/ipkg-*/adblock-fast/lib/adblock-fast/adblock-fast.uc' -print0
}
find_service_ipk() {
  # Per-feed bin/packages is required by config; uniqueness is mandatory.
  find "$1/bin/packages" -type f -name 'adblock-fast_*.ipk' -print0
}
