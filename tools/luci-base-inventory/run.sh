#!/usr/bin/env bash
# Manual, isolated Linux experiment. All paths and outputs belong to this run.
set -Eeuo pipefail
umask 022
HERE=$(cd "$(dirname "$0")" && pwd)
RUN=${1:?pass a new absolute run directory}
[[ "$RUN" = /* && ! -e "$RUN" ]] || { echo 'run path must be absolute and absent' >&2; exit 2; }
mkdir -p "$RUN"/{home,tmp,output}
export TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/home/.cache"
exec > >(tee "$RUN/output/run.log") 2>&1
trap 's=$?; printf "exit=%s line=%s\n" "$s" "$LINENO"; exit "$s"' EXIT
set -x
[[ $(uname -s) == Linux ]]
touch "$RUN/CaseProbe"
[[ ! -e "$RUN/caseprobe" ]]
rm "$RUN/CaseProbe"
uname -a
cat /etc/os-release
df -h "$RUN"
free -h
git --version
make --version
python3 --version
gcc --version
/usr/bin/time --version
sha256sum "$HERE"/compare.py "$HERE"/archive.py "$HERE"/run.sh "$HERE"/source-first-oracle.json
# Each operation and its status, elapsed time and maximum RSS are retained.
timed() { local name=$1; shift; printf 'command:'; printf ' %q' "$@"; printf '\n'; /usr/bin/time -v -o "$RUN/output/$name.time" "$@"; }
timed clone-openwrt git clone https://git.openwrt.org/openwrt/openwrt.git "$RUN/openwrt"
timed checkout-openwrt git -C "$RUN/openwrt" checkout --detach 4e9642517b48bae612ff10fb72fb9199e559500e
timed clone-luci git clone --single-branch --branch openwrt-25.12 https://git.openwrt.org/project/luci.git "$RUN/luci"
timed checkout-luci git -C "$RUN/luci" checkout --detach cb87fe60e1e2e052af36a93647f2264577829e0a
timed clone-packages git clone https://git.openwrt.org/feed/packages.git "$RUN/packages"
timed checkout-packages git -C "$RUN/packages" checkout --detach 07e0d16305d2b5903b37ad7913e33e18795f81a4
for repo in openwrt luci packages; do
  git -C "$RUN/$repo" rev-parse HEAD HEAD^{tree}
  git -C "$RUN/$repo" status --porcelain=v1 --untracked-files=all | tee "$RUN/output/$repo.status-before"
  [[ ! -s "$RUN/output/$repo.status-before" ]]
done
# Fail before toolchain work if the reviewed oracle or source recipes drift.
PYTHONPATH="$HERE" python3 -B -c 'import pathlib, sys, compare; compare.preflight_oracle(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))' "$HERE/source-first-oracle.json" "$RUN/luci"
sha256sum "$RUN/openwrt/feeds.conf.default" "$RUN/luci/luci.mk" "$RUN/luci/modules/luci-base/Makefile" "$RUN/luci/modules/luci-base/ucode/http.uc" "$RUN/luci/modules/luci-base/ucode/template/header.ut" > "$RUN/output/source-digests.txt"
cd "$RUN/openwrt"
printf 'src-link luci ../../luci\nsrc-link packages ../../packages\n' > feeds.conf
sha256sum feeds.conf
# Feed setup and defconfig can download/build host prerequisites.
timed feeds-update ./scripts/feeds update luci packages
timed feeds-install ./scripts/feeds install -a
printf 'CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=m\nCONFIG_USE_APK=n\n' > .config
cp .config "$RUN/output/config-input"
timed defconfig make defconfig
cp .config "$RUN/output/config-final"
sha256sum .config feeds.conf > "$RUN/output/build-input-digests.txt"
PYTHONPATH="$HERE" python3 -B -c 'import pathlib, compare; compare.build_inputs(pathlib.Path("."))'
./scripts/feeds list -s > "$RUN/output/feeds-list-s"
./scripts/feeds list -fs > "$RUN/output/feeds-list-fs"
[[ $(realpath feeds/luci) == "$RUN/luci" && $(realpath feeds/packages) == "$RUN/packages" ]]
[[ $(realpath package/feeds/luci/luci-base) == "$RUN/luci/modules/luci-base" ]]
# A fresh package compile target does not bootstrap host tools or the
# cross-toolchain. Build those explicitly before the package target.
timed tools-install make -j2 tools/install V=s
timed toolchain-install make -j2 toolchain/install V=s
# OpenWrt's recursive + recipes execute even under make -n. Use one real,
# verbose, serial package build so a dependency failure is retained in run.log.
timed build make -j1 package/feeds/luci/luci-base/compile V=s
# Resolve each path uniquely, never select an arbitrary glob match.
find build_dir -type f -path '*/luci-base/ucode/http.uc' -print0 > "$RUN/output/prepared-paths.nul"
find build_dir -type f -path '*/luci-base/ipkg-*/luci-base/usr/share/ucode/luci/http.uc' -print0 > "$RUN/output/staged-paths.nul"
find bin/packages -type f -name 'luci-base_*.ipk' -print0 > "$RUN/output/ipk-paths.nul"
mapfile -d '' prepared < "$RUN/output/prepared-paths.nul"
mapfile -d '' staged < "$RUN/output/staged-paths.nul"
mapfile -d '' archives < "$RUN/output/ipk-paths.nul"
[[ ${#prepared[@]} == 1 && ${#staged[@]} == 1 && ${#archives[@]} == 1 ]]
PREPARED=${prepared[0]%/ucode/http.uc}
STAGED=${staged[0]%/usr/share/ucode/luci/http.uc}
IPKDIR=$(dirname "${archives[0]}")
# Pinned luci.mk findrev(1) uses last non-po commit of luci-base.
version_line=$(git -C "$RUN/luci/modules/luci-base" log -1 --format='%ct %h' --abbrev=7 -- . ':(exclude)po')
read -r secs commit <<< "$version_line"
[[ "$secs" =~ ^[0-9]+$ && "$commit" =~ ^[0-9a-f]{7,40}$ ]]
VERSION="$(date --utc --date="@$secs" +%y.%j).$(printf '%05d' "$((secs % 86400))")~$commit"
printf 'resolved PKG_SRC_VERSION=%s\n' "$VERSION"
[[ "$VERSION" == "26.317.52279~1c75ea4" ]]
cp "${archives[0]}" "$RUN/output/luci-base.ipk"
sha256sum "${archives[0]}" "$RUN/output/luci-base.ipk" > "$RUN/output/ipk-digests.txt"
cmp "${archives[0]}" "$RUN/output/luci-base.ipk"
for repo in openwrt luci packages; do
  git -C "$RUN/$repo" rev-parse HEAD HEAD^{tree}
  git -C "$RUN/$repo" status --porcelain=v1 --untracked-files=all > "$RUN/output/$repo.status-after"
done
[[ ! -s "$RUN/output/luci.status-after" && ! -s "$RUN/output/packages.status-after" ]]
git -C "$RUN/openwrt" status --porcelain=v1 --untracked-files=no > "$RUN/output/openwrt.tracked-status-after"
[[ ! -s "$RUN/output/openwrt.tracked-status-after" ]]
sha256sum -c "$RUN/output/source-digests.txt"
sha256sum -c "$RUN/output/build-input-digests.txt"
timed compare python3 -B "$HERE/compare.py" --oracle "$HERE/source-first-oracle.json" --openwrt "$RUN/openwrt" --luci "$RUN/luci" --packages "$RUN/packages" --prepared-root "$PREPARED" --staging-root "$STAGED" --ipk-dir "$IPKDIR" --retained-ipk "$RUN/output/luci-base.ipk" --package-version "$VERSION" --receipt "$RUN/output/byte-comparison.json"
