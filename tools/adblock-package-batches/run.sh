#!/usr/bin/env bash
# Reviewed-manifest candidate only. Never run while an earlier build is unreconciled.
set -Eeuo pipefail
umask 022
HERE=$(cd "$(dirname "$0")" && pwd -P)
RUN=${1:?pass an absent absolute run directory}
[[ "$RUN" = /* && ! -e "$RUN" && $(realpath -m "$RUN") == "$RUN" ]] || { echo 'run path must be absent, absolute and physical' >&2; exit 2; }
mkdir -p "$RUN"/{tmp,home,output}
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
sha256sum "$HERE"/{run.sh,batch-order.sh,locate-paths.sh,compare.py,app-oracle.json,service-oracle.json} "$HERE"/../luci-base-inventory/{archive.py,compare.py}
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
python3 -B "$HERE/compare.py" --preflight --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages"
[[ $(sha256sum "$RUN/openwrt/rules.mk" | cut -d' ' -f1) == 11a51c7597da4d013e24b3e670e6760f2392e258b90951bba2db2b91154edef5 ]]
cd "$RUN/openwrt"
printf 'src-link luci ../../luci\nsrc-link packages ../../packages\n' > feeds.conf
timed feeds-update ./scripts/feeds update luci packages
timed feeds-install ./scripts/feeds install -a
check_feed_links() {
  [[ $(realpath feeds/luci) == "$RUN/luci" && $(realpath feeds/packages) == "$RUN/packages" ]]
  [[ $(realpath package/feeds/luci/luci-app-adblock-fast) == "$RUN/luci/applications/luci-app-adblock-fast" ]]
  [[ $(realpath package/feeds/packages/adblock-fast) == "$RUN/packages/net/adblock-fast" ]]
}
check_feed_links
printf 'CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=m\nCONFIG_PACKAGE_adblock-fast=m\nCONFIG_PACKAGE_luci-app-adblock-fast=m\nCONFIG_PER_FEED_REPO=y\nCONFIG_USE_APK=n\n' > .config
cp .config "$RUN/output/config-input"
timed defconfig make defconfig
cp .config "$RUN/output/config-final"
sha256sum .config feeds.conf > "$RUN/output/build-input-digests.txt"
CONFIG_SHA=$(sha256sum .config | cut -d' ' -f1)
python3 -B "$HERE/compare.py" --preflight --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA"
./scripts/feeds list -s > "$RUN/output/feeds-list-s"
./scripts/feeds list -fs > "$RUN/output/feeds-list-fs"
timed tools-install make -j2 tools/install V=s
timed toolchain-install make -j2 toolchain/install V=s
sha256sum -c "$RUN/output/build-input-digests.txt"
# The service goes first. Its exact IPK and stage are checked again after the app.
. "$HERE/batch-order.sh"
. "$HERE/locate-paths.sh"
build_service() {
check_feed_links
sha256sum -c "$RUN/output/build-input-digests.txt"
timed build-service make -j1 package/feeds/packages/adblock-fast/compile V=s
find_service_stage "$RUN/openwrt" > "$RUN/output/service-stages.nul"
find_service_ipk "$RUN/openwrt" > "$RUN/output/service-ipks.nul"
mapfile -d '' service_stage < "$RUN/output/service-stages.nul"
mapfile -d '' service_ipk < "$RUN/output/service-ipks.nul"
[[ ${#service_stage[@]} == 1 && ${#service_ipk[@]} == 1 ]]
SERVICE_STAGE=${service_stage[0]%/lib/adblock-fast/adblock-fast.uc}
cp "${service_ipk[0]}" "$RUN/output/adblock-fast.ipk"
cmp "${service_ipk[0]}" "$RUN/output/adblock-fast.ipk"
timed compare-service-before python3 -B "$HERE/compare.py" --kind service --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA" --stage "$SERVICE_STAGE" --ipk "$RUN/output/adblock-fast.ipk" --receipt "$RUN/output/service-before.json"
sha256sum "$RUN/output/adblock-fast.ipk" > "$RUN/output/service-before.sha256"
}
build_app() {
check_feed_links
sha256sum -c "$RUN/output/build-input-digests.txt"
timed build-app make -j1 package/feeds/luci/luci-app-adblock-fast/compile V=s
}
verify_service() {
check_feed_links
sha256sum -c "$RUN/output/build-input-digests.txt"
sha256sum -c "$RUN/output/service-before.sha256"
find_service_stage "$RUN/openwrt" > "$RUN/output/service-stages-after.nul"
find_service_ipk "$RUN/openwrt" > "$RUN/output/service-ipks-after.nul"
cmp "$RUN/output/service-stages.nul" "$RUN/output/service-stages-after.nul"
cmp "$RUN/output/service-ipks.nul" "$RUN/output/service-ipks-after.nul"
cmp "${service_ipk[0]}" "$RUN/output/adblock-fast.ipk"
timed compare-service-after python3 -B "$HERE/compare.py" --kind service --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA" --stage "$SERVICE_STAGE" --ipk "$RUN/output/adblock-fast.ipk" --receipt "$RUN/output/service-after.json"
cmp "$RUN/output/service-before.json" "$RUN/output/service-after.json"
}
finish_app() {
check_feed_links
find build_dir -type f -path '*/luci-app-adblock-fast/root/usr/share/rpcd/ucode/luci.adblock-fast' -print0 > "$RUN/output/app-prepared.nul"
find build_dir -type f -path '*/luci-app-adblock-fast/ipkg-*/luci-app-adblock-fast/usr/share/rpcd/ucode/luci.adblock-fast' -print0 > "$RUN/output/app-stages.nul"
find bin/packages -type f -name 'luci-app-adblock-fast_*.ipk' -print0 > "$RUN/output/app-ipks.nul"
mapfile -d '' app_prepared < "$RUN/output/app-prepared.nul"
mapfile -d '' app_stage < "$RUN/output/app-stages.nul"
mapfile -d '' app_ipk < "$RUN/output/app-ipks.nul"
[[ ${#app_prepared[@]} == 1 && ${#app_stage[@]} == 1 && ${#app_ipk[@]} == 1 ]]
APP_PREPARED=${app_prepared[0]%/root/usr/share/rpcd/ucode/luci.adblock-fast}
APP_STAGE=${app_stage[0]%/usr/share/rpcd/ucode/luci.adblock-fast}
cp "${app_ipk[0]}" "$RUN/output/luci-app-adblock-fast.ipk"
cmp "${app_ipk[0]}" "$RUN/output/luci-app-adblock-fast.ipk"
timed compare-app python3 -B "$HERE/compare.py" --kind app --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA" --prepared "$APP_PREPARED" --stage "$APP_STAGE" --ipk "$RUN/output/luci-app-adblock-fast.ipk" --receipt "$RUN/output/app.json"
sha256sum "$RUN/output/adblock-fast.ipk" "$RUN/output/luci-app-adblock-fast.ipk" > "$RUN/output/ipk-digests.txt"
for repo in luci packages; do
  git -C "$RUN/$repo" status --porcelain=v1 --untracked-files=all > "$RUN/output/$repo.status-after"
  [[ ! -s "$RUN/output/$repo.status-after" ]]
done
git -C "$RUN/openwrt" status --porcelain=v1 --untracked-files=no > "$RUN/output/openwrt.tracked-status-after"
[[ ! -s "$RUN/output/openwrt.tracked-status-after" ]]
sha256sum -c "$RUN/output/build-input-digests.txt"
}
run_batches
