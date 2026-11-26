#!/usr/bin/env bash
# Candidate only: do not run until prior builds are reconciled and this exact runner is reviewed.
set -Eeuo pipefail
umask 022
HERE=$(cd "$(dirname "$0")" && pwd -P)
RUN=${1:?pass an absent absolute run directory}
[[ "$RUN" == /* && ! -e "$RUN" && $(realpath -m "$RUN") == "$RUN" ]] || { echo 'run path must be absent, absolute and physical' >&2; exit 2; }
mkdir "$RUN"
mkdir "$RUN/tmp" "$RUN/home" "$RUN/output"
export TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/home/.cache" LC_ALL=C
exec > >(tee "$RUN/output/run.log") 2>&1
trap 's=$?; printf "exit=%s line=%s\n" "$s" "$LINENO"; exit "$s"' EXIT
set -x
[[ $(uname -s) == Linux ]]
uname -a; cat /etc/os-release; git --version; make --version; python3 --version; gcc --version; /usr/bin/time --version; df -h "$RUN"; free -h
sha256sum "$HERE"/{run.sh,batch-order.sh,compare.py,kernel-evidence.py,source-oracle.json} "$HERE/../luci-base-inventory"/{archive.py,compare.py} "$HERE/../luci-statistics-batch/kernel.py"
timed() { local label=$1; shift; printf 'command:'; printf ' %q' "$@"; printf '\n'; /usr/bin/time -v -o "$RUN/output/$label.time" "$@"; }
timed_capture() {
  local label=$1 status=0; shift
  printf 'command:'; printf ' %q' "$@"; printf '\n'
  /usr/bin/time -v -o "$RUN/output/$label.time" "$@" > "$RUN/output/$label.stdout" 2> "$RUN/output/$label.stderr" || status=$?
  cat "$RUN/output/$label.stdout"
  cat "$RUN/output/$label.stderr" >&2
  return "$status"
}
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
. "$HERE/batch-order.sh"
check_inputs "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
cat > .config <<'EOF'
CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_USE_MUSL=y
CONFIG_PACKAGE_luci-base=m
CONFIG_PACKAGE_luci-app-ddns=m
CONFIG_PACKAGE_luci-app-advanced-reboot=m
CONFIG_PACKAGE_luci-app-wifihistory=m
CONFIG_PACKAGE_ddns-scripts=m
CONFIG_PACKAGE_jshn=m
CONFIG_PACKAGE_rpcd-mod-iwinfo=m
CONFIG_PACKAGE_ucode=m
CONFIG_PACKAGE_ucode-mod-fs=m
CONFIG_PACKAGE_ucode-mod-ubus=m
CONFIG_PER_FEED_REPO=y
CONFIG_USE_APK=n
EOF
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
build_kernel_phase() {
  local label=$1 target=$2 make_status=0
  check_inputs "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
  sha256sum -c "$RUN/output/build-input-digests.txt"
  python3 -B "$HERE/compare.py" --preflight --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA"
  timed_capture "$label" make -j2 "$target" V=s || make_status=$?
  if [[ "$label" == kernel-compile && make_status -eq 0 ]]; then
    python3 -B "$HERE/kernel-evidence.py" capture --run-root "$RUN" --config-sha256 "$CONFIG_SHA"
  elif [[ "$label" == kernel-package-compile ]]; then
    python3 -B "$HERE/kernel-evidence.py" snapshot-package --run-root "$RUN"
  fi
  python3 -B "$HERE/kernel-evidence.py" diagnostics --run-root "$RUN" --phase "$label"
  if (( make_status != 0 )); then return "$make_status"; fi
  if [[ "$label" == kernel-package-compile ]]; then
    python3 -B "$HERE/kernel-evidence.py" validate-package --run-root "$RUN" --config-sha256 "$CONFIG_SHA"
  elif [[ "$label" != kernel-compile ]]; then
    return 2
  fi
  check_inputs "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
  sha256sum -c "$RUN/output/build-input-digests.txt"
  python3 -B "$HERE/compare.py" --preflight --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA"
}
run_kernel_prelude build_kernel_phase
locate_and_compare() {
  local name=$1 receipt=$2 version=$3
  local stage="$RUN/openwrt/build_dir/target-x86_64_musl/$name/ipkg-all/$name"
  local build="$RUN/openwrt/build_dir/target-x86_64_musl/$name"
  local built="$RUN/openwrt/bin/packages/x86_64/luci/${name}_${version}_all.ipk"
  local ipk="$RUN/output/$name.ipk"
  [[ -d "$stage" && ! -L "$stage" && -d "$build" && ! -L "$build" ]]
  [[ $(realpath "$stage") == "$stage" && $(realpath "$build") == "$build" ]]
  [[ -f "$built" && ! -L "$built" ]]
  [[ $(realpath "$built") == "$built" && ! -L "$built" ]]
  [[ $(realpath "$RUN/output") == "$RUN/output" && ! -L "$RUN/output" ]]
  [[ $(realpath -m "$ipk") == "$ipk" && ! -e "$ipk" && ! -L "$ipk" ]]
  (set -o noclobber; find "$RUN/openwrt/build_dir" \( -type d -o -type l \) -path "*/ipkg-all/$name" -print0 > "$RUN/output/$name.stage-paths.nul")
  local -a found_stages; mapfile -d '' found_stages < "$RUN/output/$name.stage-paths.nul"
  [[ ${#found_stages[@]} == 1 && "${found_stages[0]}" == "$stage" ]]
  (set -o noclobber; find "$RUN/openwrt/bin/packages" \( -type f -o -type l \) -name "${name}_*.ipk" -print0 > "$RUN/output/$name.ipk-paths.nul")
  local -a found_ipks; mapfile -d '' found_ipks < "$RUN/output/$name.ipk-paths.nul"
  [[ ${#found_ipks[@]} == 1 && "${found_ipks[0]}" == "$built" ]]
  (set -o noclobber; cat "$built" > "$ipk")
  cmp "$built" "$ipk"
  timed "compare-$name" python3 -B "$HERE/compare.py" --package "$name" --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA" --prepared "$build" --stage "$stage" --built-ipk "$built" --ipk "$ipk" --receipt "$RUN/output/$receipt.json"
  sha256sum "$ipk" > "$RUN/output/$receipt.ipk.sha256"
}
BUILT=()
recheck_all() {
  local trigger=$1 name
  check_inputs "$RUN/openwrt" "$RUN/luci" "$RUN/packages"; sha256sum -c "$RUN/output/build-input-digests.txt"
  python3 -B "$HERE/kernel-evidence.py" recheck --run-root "$RUN"
  for name in "${BUILT[@]}"; do
    local version
    case "$name" in
      luci-app-ddns) version=26.280.64158~a450f0d ;;
      luci-app-advanced-reboot) version=1.1.2-r6 ;;
      luci-app-wifihistory) version=26.040.14621~ff57b23 ;;
      *) return 2 ;;
    esac
    local stage="$RUN/openwrt/build_dir/target-x86_64_musl/$name/ipkg-all/$name"
    local build="$RUN/openwrt/build_dir/target-x86_64_musl/$name"
    local built="$RUN/openwrt/bin/packages/x86_64/luci/${name}_${version}_all.ipk"
    [[ -d "$stage" && ! -L "$stage" && -f "$built" && ! -L "$built" ]]
    [[ $(realpath "$stage") == "$stage" && $(realpath "$build") == "$build" && $(realpath "$built") == "$built" ]]
    (set -o noclobber; find "$RUN/openwrt/build_dir" \( -type d -o -type l \) -path "*/ipkg-all/$name" -print0 > "$RUN/output/$name.stage-paths-after-$trigger.nul")
    cmp "$RUN/output/$name.stage-paths.nul" "$RUN/output/$name.stage-paths-after-$trigger.nul"
    (set -o noclobber; find "$RUN/openwrt/bin/packages" \( -type f -o -type l \) -name "${name}_*.ipk" -print0 > "$RUN/output/$name.ipk-paths-after-$trigger.nul")
    cmp "$RUN/output/$name.ipk-paths.nul" "$RUN/output/$name.ipk-paths-after-$trigger.nul"
    cmp "$built" "$RUN/output/$name.ipk"
    timed "compare-$name-after-$trigger" python3 -B "$HERE/compare.py" --package "$name" --run-root "$RUN" --luci "$RUN/luci" --packages "$RUN/packages" --config-root "$RUN/openwrt" --config-sha256 "$CONFIG_SHA" --prepared "$build" --stage "$stage" --built-ipk "$built" --ipk "$RUN/output/$name.ipk" --receipt "$RUN/output/$name-after-$trigger.json"
    cmp "$RUN/output/$name.json" "$RUN/output/$name-after-$trigger.json"
  done
}
build_app_package() {
  local name=$1 version
  check_inputs "$RUN/openwrt" "$RUN/luci" "$RUN/packages"
  sha256sum -c "$RUN/output/build-input-digests.txt"
  timed "build-$name" make -j1 "package/feeds/luci/$name/compile" V=s
  case "$name" in
    luci-app-ddns) version=26.280.64158~a450f0d ;;
    luci-app-advanced-reboot) version=1.1.2-r6 ;;
    luci-app-wifihistory) version=26.040.14621~ff57b23 ;;
    *) return 2 ;;
  esac
  locate_and_compare "$name" "$name" "$version"
  BUILT+=("$name")
  recheck_all "$name"
}
run_app_batches "$RUN/openwrt" "$RUN/luci" "$RUN/packages" build_app_package
for repo in luci packages; do git -C "$RUN/$repo" status --porcelain=v1 --untracked-files=all > "$RUN/output/$repo.status-after"; [[ ! -s "$RUN/output/$repo.status-after" ]]; done
git -C "$RUN/openwrt" status --porcelain=v1 --untracked-files=no > "$RUN/output/openwrt.tracked-status-after"; [[ ! -s "$RUN/output/openwrt.tracked-status-after" ]]
sha256sum -c "$RUN/output/build-input-digests.txt"
