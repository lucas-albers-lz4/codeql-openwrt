#!/usr/bin/env bash
# Manual Linux-only package-member experiment. Every writable path is run-owned.
set -Eeuo pipefail
umask 022

HERE=$(cd "$(dirname "$0")" && pwd)
RUN=${1:?pass a new absolute run directory}
[[ "$RUN" = /* && ! -e "$RUN" && "$RUN" != *' '* ]] || {
  echo 'run path must be absolute, absent, and contain no spaces' >&2
  exit 2
}
mkdir -p "$RUN"/{home,tmp,output,cache}
export HOME="$RUN/home"
export TMPDIR="$RUN/tmp"
export XDG_CACHE_HOME="$RUN/cache/xdg"
export CCACHE_DIR="$RUN/cache/ccache"
export CCACHE_DISABLE=1
export GIT_CONFIG_GLOBAL="$RUN/home/.gitconfig"
mkdir -p "$XDG_CACHE_HOME" "$CCACHE_DIR"

exec > >(tee -a "$RUN/output/run.log") 2>&1
status_written=0
trap 'rc=$?; printf "exit=%s line=%s\n" "$rc" "$LINENO"; if [[ $status_written == 0 ]]; then if (( rc == 124 || rc >= 128 )); then printf "status=incomplete\nexit=%s\n" "$rc" > "$RUN/output/run-status.txt"; else printf "status=FAIL\nexit=%s\n" "$rc" > "$RUN/output/run-status.txt"; fi; fi; exit "$rc"' EXIT
set -x

fail_preflight() {
  printf 'status=not run / preflight blocked\nreason=%s\n' "$1" > "$RUN/output/run-status.txt"
  status_written=1
  echo "PRE-FLIGHT BLOCKED: $1" >&2
  exit 78
}

fail_run() {
  printf 'status=FAIL\nreason=%s\n' "$1" > "$RUN/output/run-status.txt"
  status_written=1
  echo "EXPERIMENT FAIL: $1" >&2
  exit 1
}

record_resources() {
  local name=$1
  {
    date --utc --iso-8601=seconds
    df -h "$RUN"
    df -B1 --output=source,size,used,avail,pcent,target "$RUN"
    free -h
    free -b
  } > "$RUN/output/$name.resources" 2>&1
}

mark_status() {
  local value=$1 reason=$2
  printf 'status=%s\nreason=%s\n' "$value" "$reason" > "$RUN/output/run-status.txt"
  status_written=1
}

timed() {
  local name=$1
  shift
  local rc=0
  printf 'phase=%s command:' "$name"
  printf ' %q' "$@"
  printf '\n'
  /usr/bin/time -v -o "$RUN/output/$name.time" "$@" > "$RUN/output/$name.log" 2>&1 || rc=$?
  tail -n 80 "$RUN/output/$name.log"
  printf 'phase=%s exit=%s\n' "$name" "$rc"
  if (( rc != 0 )); then
    if (( rc == 124 || rc >= 128 )); then
      mark_status 'incomplete' "$name timed out or was interrupted (exit $rc)"
    elif [[ $name == network-download-root || $name == clone-openwrt ||
            $name == checkout-openwrt || $name == clone-packages ||
            $name == checkout-packages ]]; then
      mark_status 'not run / preflight blocked' "$name failed before package build (exit $rc)"
    elif grep -Eiq 'failed to download|download[^[:cntrl:]]*failed|could not resolve|temporary failure in name resolution|connection (timed out|refused|reset)|network is unreachable|wget:.*(failed|unable|timed out)|curl: \(' "$RUN/output/$name.log"; then
      mark_status 'incomplete' "$name encountered a network/download failure (exit $rc)"
    else
      mark_status 'FAIL' "$name failed (exit $rc)"
    fi
  fi
  return "$rc"
}

timed_with_deadline() {
  local name=$1
  local deadline=$2
  shift 2
  local remaining=$((deadline - $(date +%s)))
  if (( remaining <= 0 )); then
    printf 'phase=%s exceeded combined phase budget before launch\n' "$name" >&2
    return 124
  fi
  timed "$name" timeout --kill-after=30s "${remaining}s" "$@"
}

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail_preflight 'requires Linux x86_64'
for tool in git make python3 gcc g++ clang flex bison gawk gettext rsync swig unzip file wget curl ar tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail_preflight "required host tool is missing: $tool"
done
[[ -x /usr/bin/time ]] || fail_preflight 'GNU /usr/bin/time is missing'

DISK_AVAILABLE=$(df --output=avail -B1 "$RUN" | tail -n 1 | tr -d '[:space:]')
MEM_AVAILABLE=$(awk '$1 == "MemAvailable:" { printf "%.0f", $2 * 1024 }' /proc/meminfo)
MIN_DISK=$((85 * 1024 * 1024 * 1024))
MIN_MEMORY=$((8 * 1024 * 1024 * 1024))
printf 'preflight_disk_available_bytes=%s\npreflight_disk_required_bytes=%s\n' "$DISK_AVAILABLE" "$MIN_DISK" | tee "$RUN/output/resource-preflight.txt"
printf 'preflight_memory_available_bytes=%s\npreflight_memory_required_bytes=%s\n' "$MEM_AVAILABLE" "$MIN_MEMORY" | tee -a "$RUN/output/resource-preflight.txt"
record_resources preflight
(( DISK_AVAILABLE >= MIN_DISK )) || fail_preflight "free disk is below 85 GiB ($DISK_AVAILABLE bytes available)"
(( MEM_AVAILABLE >= MIN_MEMORY )) || fail_preflight "available memory is below 8 GiB ($MEM_AVAILABLE bytes available)"

uname -a
cat /etc/os-release
git --version
make --version
python3 --version
gcc --version
g++ --version
clang --version
tar --version
ar --version
/usr/bin/time --version
sha256sum "$HERE"/{run.sh,compare.py,oracle.json,test_compare.py} > "$RUN/output/implementation-digests.txt"
cat "$RUN/output/implementation-digests.txt"
REPO_ROOT=$(cd "$HERE/../.." && pwd)
git -C "$REPO_ROOT" rev-parse HEAD 'HEAD^{tree}' > "$RUN/output/codeql-openwrt.identity"
git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all > "$RUN/output/codeql-openwrt.status"
[[ ! -s "$RUN/output/codeql-openwrt.status" ]] || fail_run 'workflow checkout is dirty'

# Check actual network reachability before compiling host tools/toolchains.
if ! timed network-download-root curl --fail --silent --show-error --location --max-time 30 --head https://downloads.openwrt.org/; then
  mark_status 'not run / preflight blocked' 'OpenWrt download root was unreachable before bootstrap'
  exit 78
fi

record_resources source-checkout-before
timed clone-openwrt git clone --no-checkout https://git.openwrt.org/openwrt/openwrt.git "$RUN/openwrt"
timed checkout-openwrt git -C "$RUN/openwrt" checkout --detach 4e9642517b48bae612ff10fb72fb9199e559500e
timed clone-packages git clone --no-checkout https://git.openwrt.org/feed/packages.git "$RUN/packages"
timed checkout-packages git -C "$RUN/packages" checkout --detach 07e0d16305d2b5903b37ad7913e33e18795f81a4

OPENWRT="$RUN/openwrt"
PACKAGES="$RUN/packages"
for repo in openwrt packages; do
  if [[ $repo == openwrt ]]; then root=$OPENWRT; else root=$PACKAGES; fi
  git -C "$root" rev-parse HEAD 'HEAD^{tree}' > "$RUN/output/$repo.identity"
  git -C "$root" status --porcelain=v1 --untracked-files=all > "$RUN/output/$repo.status-before"
  [[ ! -s "$RUN/output/$repo.status-before" ]] || fail_run "$repo checkout is dirty before configuration"
done
[[ $(git -C "$OPENWRT" rev-parse HEAD) == 4e9642517b48bae612ff10fb72fb9199e559500e ]] || fail_run 'OpenWrt pin mismatch'
[[ $(git -C "$PACKAGES" rev-parse HEAD) == 07e0d16305d2b5903b37ad7913e33e18795f81a4 ]] || fail_run 'packages feed pin mismatch'

git -C "$PACKAGES" ls-tree -rl 07e0d16305d2b5903b37ad7913e33e18795f81a4 -- \
  net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc \
  net/adblock-fast/files/lib/adblock-fast/cli.uc \
  utils/uvol/files/blockdev_common.uc \
  utils/uvol/files/uci.uc \
  utils/uvol/files/lvm.uc \
  utils/uvol/files/ubi.uc \
  utils/uvol/files/uvol \
  net/adblock-fast/tests/lib/mocklib.uc \
  net/adblock-fast/tests/lib/mocklib/ubus.uc \
  net/adblock-fast/tests/lib/mocklib/uci.uc > "$RUN/output/source-git-tree.txt"
sha256sum \
  "$OPENWRT/feeds.conf.default" \
  "$PACKAGES/net/adblock-fast/Makefile" \
  "$PACKAGES/utils/uvol/Makefile" \
  "$PACKAGES/net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc" \
  "$PACKAGES/net/adblock-fast/files/lib/adblock-fast/cli.uc" \
  "$PACKAGES/utils/uvol/files/blockdev_common.uc" \
  "$PACKAGES/utils/uvol/files/uci.uc" \
  "$PACKAGES/utils/uvol/files/lvm.uc" \
  "$PACKAGES/utils/uvol/files/ubi.uc" \
  "$PACKAGES/utils/uvol/files/uvol" \
  "$PACKAGES/net/adblock-fast/tests/lib/mocklib.uc" \
  "$PACKAGES/net/adblock-fast/tests/lib/mocklib/ubus.uc" \
  "$PACKAGES/net/adblock-fast/tests/lib/mocklib/uci.uc" > "$RUN/output/source-digests.txt"

cd "$OPENWRT"
printf 'src-link packages %s\n' "$PACKAGES" > feeds.conf
timed feeds-update ./scripts/feeds update packages
timed feeds-install ./scripts/feeds install -p packages adblock-fast uvol
cat > .config <<'EOF'
CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_PACKAGE_adblock-fast=m
CONFIG_PACKAGE_uvol=m
# CONFIG_PACKAGE_autopart is not set
CONFIG_USE_APK=n
EOF
cp .config "$RUN/output/config-input"
timed defconfig make defconfig
cp .config "$RUN/output/config-final"
cp feeds.conf "$RUN/output/feeds.conf"
sha256sum "$OPENWRT/.config" "$OPENWRT/feeds.conf" > "$RUN/output/build-input-digests.txt"
./scripts/feeds list -s > "$RUN/output/feed-package-list.txt"
grep -E '^(CONFIG_(TARGET_x86|TARGET_x86_64|PACKAGE_(adblock-fast|uvol|autopart|ucode|ucode-mod-fs|ucode-mod-uci|ucode-mod-ubus|ucode-mod-uloop|ucode-mod-math|blockd|curl|resolveip|gawk|grep|sed|coreutils-sort)|BUSYBOX_DEFAULT_|USE_APK|PER_FEED_REPO))' .config > "$RUN/output/package-config-selection.txt" || true
{
  for pkg in adblock-fast uvol; do
    recipe=$(readlink -f "package/feeds/packages/$pkg/Makefile")
    printf '\n[%s] %s\n' "$pkg" "$recipe"
    grep -nE '^(PKG_VERSION|PKG_RELEASE|.*PKGARCH|.*DEPENDS)' "$recipe"
  done
} > "$RUN/output/package-recipe-metadata.txt"

timed source-oracle-preflight python3 -B "$HERE/compare.py" \
  --openwrt "$OPENWRT" --packages "$PACKAGES" --run-root "$RUN" --preflight

record_resources bootstrap-before
HOST_TOOL_DEADLINE=$(( $(date +%s) + 60 * 60 ))
timed_with_deadline tools-install "$HOST_TOOL_DEADLINE" make -j2 tools/install V=s
record_resources tools-install-after
timed_with_deadline toolchain-install "$HOST_TOOL_DEADLINE" make -j2 toolchain/install V=s
record_resources bootstrap-after

PACKAGE_DEADLINE=$(( $(date +%s) + 10 * 60 ))
timed_with_deadline adblock-fast-build "$PACKAGE_DEADLINE" make -j1 NO_DEPS=1 package/feeds/packages/adblock-fast/compile V=s
timed_with_deadline uvol-build "$PACKAGE_DEADLINE" make -j1 NO_DEPS=1 package/feeds/packages/uvol/compile V=s
record_resources package-build-after

for metadata in .packagedeps .packageinfo .targetinfo .packageauxvars; do
  source="$OPENWRT/tmp/$metadata"
  if [[ -f "$source" && ! -L "$source" ]]; then
    cp -- "$source" "$RUN/output/tmp-$metadata"
    sha256sum "$source" > "$RUN/output/tmp-$metadata.sha256"
  else
    printf 'status=absent\n' > "$RUN/output/tmp-$metadata.status"
  fi
done

mkdir -p "$RUN/output/retained"
for package in adblock-fast uvol; do
  find "$OPENWRT/bin" -type f -name "${package}_*.ipk" -print0 > "$RUN/output/$package-ipk-paths.nul"
  mapfile -d '' archives < "$RUN/output/$package-ipk-paths.nul"
  [[ ${#archives[@]} == 1 ]] || {
    printf 'expected exactly one %s IPK, found %s\n' "$package" "${#archives[@]}" >&2
    exit 1
  }
  cp -- "${archives[0]}" "$RUN/output/retained/$package.ipk"
  cmp -- "${archives[0]}" "$RUN/output/retained/$package.ipk"
  sha256sum "${archives[0]}" "$RUN/output/retained/$package.ipk" > "$RUN/output/$package-ipk-digests.txt"
done

git -C "$PACKAGES" rev-parse HEAD 'HEAD^{tree}' > "$RUN/output/packages.identity-after"
git -C "$PACKAGES" status --porcelain=v1 --untracked-files=all > "$RUN/output/packages.status-after"
[[ ! -s "$RUN/output/packages.status-after" ]] || { echo 'packages feed became dirty' >&2; exit 1; }
git -C "$OPENWRT" rev-parse HEAD 'HEAD^{tree}' > "$RUN/output/openwrt.identity-after"
git -C "$OPENWRT" status --porcelain=v1 --untracked-files=no > "$RUN/output/openwrt.tracked-status-after"
[[ ! -s "$RUN/output/openwrt.tracked-status-after" ]] || { echo 'tracked OpenWrt source changed' >&2; exit 1; }
sha256sum -c "$RUN/output/source-digests.txt"
sha256sum -c "$RUN/output/build-input-digests.txt"

record_resources comparison-before
COMPARE_DEADLINE=$(( $(date +%s) + 5 * 60 ))
timed_with_deadline comparison "$COMPARE_DEADLINE" python3 -B "$HERE/compare.py" \
  --openwrt "$OPENWRT" --packages "$PACKAGES" --run-root "$RUN"
record_resources comparison-after

printf 'status=PASS package-member comparison only\n' > "$RUN/output/run-status.txt"
status_written=1
printf 'PASS: package source -> staging -> IPK member comparison complete\n'
printf 'No rootfs/image, CodeQL extraction/query, runtime, or security claim follows.\n'
