#!/usr/bin/env bash
# Manual candidate only. Review this script and reconcile other builds before any invocation.
set -Eeuo pipefail
umask 022
HERE=$(cd "$(dirname "$0")" && pwd -P)
RUN=${1:?pass an absent absolute run directory}
. "$HERE/run-root.sh"
create_run_root "$RUN"
export TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/home/.cache"
exec > >(tee "$RUN/output/run.log") 2>&1
trap 's=$?; printf "exit=%s line=%s\n" "$s" "$LINENO"; exit "$s"' EXIT
set -x
[[ $(uname -s) == Linux ]]
uname -a
cat /etc/os-release
git --version
make --version
python3 --version
gcc --version
/usr/bin/time --version
df -h "$RUN"
free -h
sha256sum "$HERE"/{run.sh,run-root.sh,locate-paths.sh,compare.py,source-oracle.json} "$HERE"/../luci-base-inventory/{archive.py,compare.py}
timed() { local name=$1; shift; printf 'command:'; printf ' %q' "$@"; printf '\n'; /usr/bin/time -v -o "$RUN/output/$name.time" "$@"; }
timed clone-openwrt git clone https://git.openwrt.org/openwrt/openwrt.git "$RUN/openwrt"
timed checkout-openwrt git -C "$RUN/openwrt" checkout --detach 4e9642517b48bae612ff10fb72fb9199e559500e
timed clone-luci git clone --single-branch --branch openwrt-25.12 https://git.openwrt.org/project/luci.git "$RUN/luci"
timed checkout-luci git -C "$RUN/luci" checkout --detach cb87fe60e1e2e052af36a93647f2264577829e0a
timed clone-packages git clone https://git.openwrt.org/feed/packages.git "$RUN/packages"
timed checkout-packages git -C "$RUN/packages" checkout --detach 07e0d16305d2b5903b37ad7913e33e18795f81a4
for repo in openwrt luci packages; do
  git -C "$RUN/$repo" rev-parse HEAD HEAD^{tree}
  git -C "$RUN/$repo" status --porcelain=v1 --untracked-files=all > "$RUN/output/$repo.status-before"
  [[ ! -s "$RUN/output/$repo.status-before" ]]
done
python3 -B "$HERE/compare.py" --preflight --run-root "$RUN" --openwrt "$RUN/openwrt" --luci "$RUN/luci" --packages "$RUN/packages" > "$RUN/output/source-preflight.json"
sha256sum "$RUN/openwrt/rules.mk" "$RUN/luci/luci.mk" "$RUN/luci/modules/luci-mod-status/Makefile" "$RUN/luci/modules/luci-mod-network/Makefile" "$RUN/luci/modules/luci-mod-system/Makefile" > "$RUN/output/recipe-digests.txt"
cd "$RUN/openwrt"
printf 'src-link luci ../../luci\nsrc-link packages ../../packages\n' > feeds.conf
timed feeds-update ./scripts/feeds update luci packages
timed feeds-install ./scripts/feeds install -a
. "$HERE/locate-paths.sh"
check_feed_links "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
[[ $(realpath package/feeds/luci/luci-mod-status) == "$RUN/luci/modules/luci-mod-status" ]]
[[ $(realpath package/feeds/luci/luci-mod-network) == "$RUN/luci/modules/luci-mod-network" ]]
[[ $(realpath package/feeds/luci/luci-mod-system) == "$RUN/luci/modules/luci-mod-system" ]]
printf 'CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-mod-status=m\nCONFIG_PACKAGE_luci-mod-network=m\nCONFIG_PACKAGE_luci-mod-system=m\nCONFIG_PER_FEED_REPO=y\nCONFIG_USE_APK=n\n' > .config
cp .config "$RUN/output/config-input"
timed defconfig make defconfig
cp .config "$RUN/output/config-final"
sha256sum .config feeds.conf > "$RUN/output/build-input-digests.txt"
CONFIG_SHA=$(sha256sum .config | cut -d' ' -f1)
python3 -B "$HERE/compare.py" --preflight --run-root "$RUN" --openwrt "$RUN/openwrt" --luci "$RUN/luci" --packages "$RUN/packages" > "$RUN/output/config-source-preflight.json"
./scripts/feeds list -s > "$RUN/output/feeds-list-s"
./scripts/feeds list -fs > "$RUN/output/feeds-list-fs"
timed tools-install make -j2 tools/install V=s
timed toolchain-install make -j2 toolchain/install V=s

build_core_package() {
  local pkg=$1
  sha256sum -c "$RUN/output/build-input-digests.txt"
  check_feed_links "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
  sha256sum -c "$RUN/output/recipe-digests.txt"
  timed "build-$pkg" make -j1 "package/feeds/luci/$pkg/compile" V=s
  find_package_stage "$RUN/openwrt" "$pkg" > "$RUN/output/$pkg.stages.nul"
  find_package_ipk "$RUN/openwrt" "$pkg" > "$RUN/output/$pkg.ipks.nul"
  mapfile -d '' stages < "$RUN/output/$pkg.stages.nul"
  mapfile -d '' ipks < "$RUN/output/$pkg.ipks.nul"
  [[ ${#stages[@]} == 1 && ${#ipks[@]} == 1 ]]
  cp "${ipks[0]}" "$RUN/output/$pkg.ipk"
  cmp "${ipks[0]}" "$RUN/output/$pkg.ipk"
  timed "compare-$pkg" python3 -B "$HERE/compare.py" --run-root "$RUN" --openwrt "$RUN/openwrt" --luci "$RUN/luci" --packages "$RUN/packages" --package "$pkg" --stage "${stages[0]}" --built-ipk "${ipks[0]}" --ipk "$RUN/output/$pkg.ipk" --config-sha256 "$CONFIG_SHA" --receipt "$RUN/output/$pkg.json"
  sha256sum "$RUN/output/$pkg.ipk" > "$RUN/output/$pkg.ipk.sha256"
  check_feed_links "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
  sha256sum -c "$RUN/output/recipe-digests.txt"
}
packages=(luci-mod-status luci-mod-network luci-mod-system)
run_package_batches "$RUN/openwrt" "$RUN/luci" "$RUN/packages" build_core_package
# After the final package build, re-resolve and recompare all three outputs.
for pkg in "${packages[@]}"; do
  find_package_stage "$RUN/openwrt" "$pkg" > "$RUN/output/$pkg.stages-after.nul"
  find_package_ipk "$RUN/openwrt" "$pkg" > "$RUN/output/$pkg.ipks-after.nul"
  cmp "$RUN/output/$pkg.stages.nul" "$RUN/output/$pkg.stages-after.nul"
  cmp "$RUN/output/$pkg.ipks.nul" "$RUN/output/$pkg.ipks-after.nul"
  mapfile -d '' stages < "$RUN/output/$pkg.stages-after.nul"
  mapfile -d '' ipks < "$RUN/output/$pkg.ipks-after.nul"
  [[ ${#stages[@]} == 1 && ${#ipks[@]} == 1 ]]
  cmp "${ipks[0]}" "$RUN/output/$pkg.ipk"
  timed "recheck-$pkg" python3 -B "$HERE/compare.py" --run-root "$RUN" --openwrt "$RUN/openwrt" --luci "$RUN/luci" --packages "$RUN/packages" --package "$pkg" --stage "${stages[0]}" --built-ipk "${ipks[0]}" --ipk "$RUN/output/$pkg.ipk" --config-sha256 "$CONFIG_SHA" --receipt "$RUN/output/$pkg-after.json"
  python3 -B - "$RUN/output/$pkg.json" "$RUN/output/$pkg-after.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f: a=json.load(f)
with open(sys.argv[2]) as f: b=json.load(f)
if a != b: raise SystemExit('package evidence changed after later batch')
PY
done
for repo in luci packages; do
  git -C "$RUN/$repo" status --porcelain=v1 --untracked-files=all > "$RUN/output/$repo.status-after"
  [[ ! -s "$RUN/output/$repo.status-after" ]]
done
git -C "$RUN/openwrt" status --porcelain=v1 --untracked-files=no > "$RUN/output/openwrt.tracked-status-after"
[[ ! -s "$RUN/output/openwrt.tracked-status-after" ]]
sha256sum -c "$RUN/output/build-input-digests.txt"
sha256sum -c "$RUN/output/recipe-digests.txt"
