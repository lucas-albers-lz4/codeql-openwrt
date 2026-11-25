#!/usr/bin/env bash
# Manually dispatched Linux-only experiment; never share writable build state.
set -Eeuo pipefail
umask 022
HERE=$(cd "$(dirname "$0")" && pwd)
RUN=${1:?new absolute run directory required}
[[ $RUN = /* && ! -e $RUN && $RUN != *' '* ]] || { echo 'run directory must be absent, absolute and contain no spaces' >&2; exit 2; }
mkdir -p "$RUN"/{output,home,tmp}
export HOME="$RUN/home" TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/home/.cache"
exec > >(tee "$RUN/output/run.log") 2>&1
active_phase=
resources() { { df -h "$RUN"; free -h; } > "$RUN/output/$1-resources" 2>&1; }
trap 's=$?; if [[ -n $active_phase ]]; then resources "$active_phase-after" || :; fi; printf "exit=%s line=%s\n" "$s" "$LINENO"; exit "$s"' EXIT
set -x
[[ $(uname -s) == Linux ]]
touch "$RUN/CaseProbe"; [[ ! -e "$RUN/caseprobe" ]]; rm "$RUN/CaseProbe"
uname -a
cat /etc/os-release
df -h "$RUN"
free -h
git --version
make --version
python3 --version
gcc --version
/usr/bin/time --version
sha256sum "$HERE"/{run.sh,compare.py,oracle.json} "$HERE/../installed-byte/compare.py"
timed() { local name=$1; shift; printf 'command:'; printf ' %q' "$@"; printf '\n'; /usr/bin/time -v -o "$RUN/output/$name.time" "$@"; }
for variant in y n; do
  active_phase="$variant-prepare"
  resources "$active_phase-before"
  root="$RUN/$variant"
  mkdir -p "$root"/{home,tmp}
  export HOME="$root/home" TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/home/.cache"
  timed "$variant-clone" git clone https://git.openwrt.org/openwrt/openwrt.git "$root/openwrt"
  timed "$variant-checkout" git -C "$root/openwrt" checkout --detach 4e9642517b48bae612ff10fb72fb9199e559500e
  cd "$root/openwrt"
  [[ $(git rev-parse HEAD) == 4e9642517b48bae612ff10fb72fb9199e559500e ]]
  git rev-parse HEAD HEAD^{tree} > "$RUN/output/$variant-revision"
  git status --porcelain=v1 --untracked-files=all > "$RUN/output/$variant-status-before"
  [[ ! -s "$RUN/output/$variant-status-before" ]]
  git ls-files -s package/network/config/wifi-scripts > "$RUN/output/$variant-source-blobs"
  find package/network/config/wifi-scripts -type f -print0 | sort -z | xargs -0 sha256sum > "$RUN/output/$variant-source-hashes"
  sha256sum feeds.conf.default > "$RUN/output/$variant-feeds-default-hash"
  # No external feeds: the selected package is in the pinned core tree.
  : > feeds.conf
  printf 'CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_wifi-scripts=m\nCONFIG_USE_APK=n\nCONFIG_WIFI_SCRIPTS_UCODE=%s\n' "$variant" > .config
  cp .config "$RUN/output/$variant-config-input"
  timed "$variant-defconfig" make defconfig
  cp .config "$RUN/output/$variant-config-final"
  sha256sum .config feeds.conf > "$RUN/output/$variant-build-input-hashes"
  resources "$active_phase-after"
  active_phase=
done
# Resolve and compare both configurations before either costly bootstrap.
python3 -B - "$HERE/compare.py" "$RUN/output/y-config-final" "$RUN/output/n-config-final" <<'PYCONFIG'
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location('wifi_compare', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.compare_configs({True: pathlib.Path(sys.argv[2]), False: pathlib.Path(sys.argv[3])})
PYCONFIG
cmp "$RUN/output/y-source-blobs" "$RUN/output/n-source-blobs"
cmp "$RUN/output/y-source-hashes" "$RUN/output/n-source-hashes"
for variant in y n; do
  active_phase="$variant-build"
  resources "$active_phase-before"
  root="$RUN/$variant"
  export HOME="$root/home" TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/home/.cache"
  cd "$root/openwrt"
  sha256sum -c "$RUN/output/$variant-build-input-hashes"
  timed "$variant-tools" make -j2 tools/install V=s
  timed "$variant-toolchain" make -j2 toolchain/install V=s
  timed "$variant-build" make -j1 package/network/config/wifi-scripts/compile V=s
  find build_dir -type d -path '*/ipkg-*/wifi-scripts' -print0 > "$RUN/output/$variant-stages.nul"
  find bin -type f -name 'wifi-scripts_*.ipk' -print0 > "$RUN/output/$variant-ipks.nul"
  mapfile -d '' stages < "$RUN/output/$variant-stages.nul"
  mapfile -d '' archives < "$RUN/output/$variant-ipks.nul"
  [[ ${#stages[@]} == 1 && ${#archives[@]} == 1 ]]
  printf '%s\n' "${stages[0]}" > "$RUN/output/$variant-stage-path"
  cp "${archives[0]}" "$RUN/output/$variant-wifi-scripts.ipk"
  cmp "${archives[0]}" "$RUN/output/$variant-wifi-scripts.ipk"
  sha256sum "${archives[0]}" "$RUN/output/$variant-wifi-scripts.ipk" > "$RUN/output/$variant-ipk-hashes"
  git status --porcelain=v1 --untracked-files=no > "$RUN/output/$variant-status-after"
  [[ ! -s "$RUN/output/$variant-status-after" ]]
  sha256sum -c "$RUN/output/$variant-source-hashes"
  sha256sum -c "$RUN/output/$variant-build-input-hashes"
  resources "$active_phase-after"
  active_phase=
done
read -r stage_y < "$RUN/output/y-stage-path"
read -r stage_n < "$RUN/output/n-stage-path"
timed compare python3 -B "$HERE/compare.py" --source "$RUN/y/openwrt" --stage-y "$RUN/y/openwrt/$stage_y" --stage-n "$RUN/n/openwrt/$stage_n" --ipk-y "$RUN/output/y-wifi-scripts.ipk" --ipk-n "$RUN/output/n-wifi-scripts.ipk" --config-y "$RUN/output/y-config-final" --config-n "$RUN/output/n-config-final" --receipt "$RUN/output/byte-comparison.json"
