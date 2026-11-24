#!/usr/bin/env python3
"""Fail-closed comparison of pinned LuCI source, prepared/staged files and IPK members."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
from pathlib import PurePosixPath
import subprocess
import tarfile
import time

PINS = {
    "openwrt": "4e9642517b48bae612ff10fb72fb9199e559500e",
    "luci": "b2e0be4b46ec0fd43394c081fa7c50657af14011",
    "packages": "07e0d16305d2b5903b37ad7913e33e18795f81a4",
}
FILES = {
    "http.uc": ("modules/luci-base/ucode/http.uc", "usr/share/ucode/luci/http.uc"),
    "header.ut": ("modules/luci-base/ucode/template/header.ut", "usr/share/ucode/luci/template/header.ut"),
}


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def pinned_clean(name: str, repo: pathlib.Path) -> dict:
    rev = git(repo, "rev-parse", "HEAD")
    # OpenWrt necessarily creates many untracked build files. Reject tracked
    # edits there while allowing those generated artifacts; source feeds must
    # remain completely clean.
    dirty = git(repo, "status", "--porcelain=v1",
                "--untracked-files=no" if name == "openwrt" else "--untracked-files=all")
    if rev != PINS[name] or dirty:
        raise ValueError(f"{name} checkout mismatch: HEAD={rev}, dirty={bool(dirty)}")
    return {"sha": rev, "dirty": False, "tree": git(repo, "rev-parse", "HEAD^{tree}")}


def sha_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_under(path: pathlib.Path, root: pathlib.Path, label: str) -> pathlib.Path:
    resolved, base = path.resolve(strict=True), root.resolve(strict=True)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"{label} must resolve under OpenWrt checkout: {resolved}") from exc
    return resolved


def read_regular_under(path: pathlib.Path, root: pathlib.Path, label: str) -> bytes:
    require_under(path, root, label)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path.read_bytes()


def build_inputs(openwrt: pathlib.Path) -> dict:
    config = openwrt / ".config"
    feeds = openwrt / "feeds.conf"
    if not config.is_file() or not feeds.is_file():
        raise ValueError("required OpenWrt .config and feeds.conf must exist")
    config_bytes = config.read_bytes()
    all_lines = [line.strip() for line in config_bytes.decode(errors="replace").splitlines()]
    config_lines = set(all_lines)
    for symbol in ("CONFIG_TARGET_x86", "CONFIG_TARGET_x86_64",
                   "CONFIG_PACKAGE_luci-base", "CONFIG_USE_APK", "CONFIG_PER_FEED_REPO"):
        assignments = [line for line in all_lines if line.startswith(symbol + "=") or
                       line == f"# {symbol} is not set"]
        if len(assignments) > 1:
            raise ValueError(f"duplicate config assignment: {symbol}")
    required_config = {
        "CONFIG_TARGET_x86=y",
        "CONFIG_TARGET_x86_64=y",
        "CONFIG_PACKAGE_luci-base=m",
    }
    missing = sorted(required_config - config_lines)
    if missing:
        raise ValueError(f"OpenWrt .config missing required target/package symbols: {missing}")
    if not ({"CONFIG_USE_APK=n", "# CONFIG_USE_APK is not set"} & config_lines):
        raise ValueError("OpenWrt .config must disable CONFIG_USE_APK for IPK output")
    feed_lines = [line.strip() for line in feeds.read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    # feeds.conf paths become symlinks below OpenWrt's feeds/ directory, so
    # sibling checkouts require two parent traversals from feeds/.
    expected_feeds = ["src-link luci ../../luci", "src-link packages ../../packages"]
    if feed_lines != expected_feeds:
        raise ValueError(f"feeds.conf must contain exactly {expected_feeds}; got {feed_lines}")
    return {
        "config": {"path": ".config", "sha256": sha_file(config)},
        "feeds": {"path": "feeds.conf", "sha256": sha_file(feeds)},
        "per_feed_repo": next((line for line in all_lines if line.startswith("CONFIG_PER_FEED_REPO=") or
                               line == "# CONFIG_PER_FEED_REPO is not set"), None),
    }


def require_feed_links(openwrt: pathlib.Path, luci: pathlib.Path,
                       packages: pathlib.Path) -> dict:
    resolved = {}
    for name, source in (("luci", luci), ("packages", packages)):
        link = openwrt / "feeds" / name
        if not link.exists():
            raise ValueError(f"missing installed {name} feed path: {link}")
        actual, expected = link.resolve(strict=True), source.resolve(strict=True)
        if actual != expected:
            raise ValueError(f"installed {name} feed resolves to {actual}, expected pinned source {expected}")
        resolved[name] = str(actual)
    return resolved


def member_name(raw: str) -> str:
    if raw in (".", "./"):
        return ""
    name = raw[2:] if raw.startswith("./") else raw
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or "\\" in name or
            any(part in (".", "..") for part in name.split("/")) or
            path.as_posix() != name):
        raise ValueError(f"unsafe IPK tar member: {raw}")
    return name


def ipk_parts(ipk: pathlib.Path | bytes) -> dict[str, bytes]:
    data = ipk.read_bytes() if isinstance(ipk, pathlib.Path) else ipk
    if not data.startswith(b"\x1f\x8b"):
        raise ValueError("pinned OpenWrt IPK is not gzip-compressed outer tar")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as outer:
        parts = {}
        for member in outer.getmembers():
            name = member_name(member.name)
            if name in parts:
                raise ValueError(f"duplicate outer IPK member: {name}")
            if not member.isfile():
                raise ValueError(f"outer IPK member is not a regular file: {name}")
            stream = outer.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read outer IPK member: {name}")
            parts[name] = stream.read()
    if set(parts) != {"debian-binary", "data.tar.gz", "control.tar.gz"} or parts["debian-binary"] != b"2.0\n":
        raise ValueError("outer IPK members differ from pinned ipkg-build format")
    return parts


def ipk_data_members(ipk: pathlib.Path | bytes) -> dict[str, bytes]:
    parts = ipk_parts(ipk)
    with tarfile.open(fileobj=io.BytesIO(parts["data.tar.gz"]), mode="r:gz") as tar:
        result = {}
        for member in tar.getmembers():
            name = member_name(member.name)
            if name == "":
                if not member.isdir():
                    raise ValueError("inner IPK root is not a directory")
                continue
            if name not in {v[1] for v in FILES.values()}:
                continue
            if name in result:
                raise ValueError(f"duplicate IPK data member: {name}")
            if not member.isfile():
                raise ValueError(f"IPK member is not a regular file: {name}")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read IPK member: {name}")
            result[name] = stream.read()
    return result


def ipk_control_fields(ipk: pathlib.Path | bytes) -> dict[str, str]:
    parts = ipk_parts(ipk)
    control_bytes = None
    with tarfile.open(fileobj=io.BytesIO(parts["control.tar.gz"]), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = member_name(member.name)
            if name == "":
                if not member.isdir():
                    raise ValueError("control IPK root is not a directory")
                continue
            if name != "control":
                continue
            if control_bytes is not None or not member.isfile():
                raise ValueError("duplicate or nonregular IPK control file")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError("cannot read IPK control file")
            control_bytes = stream.read()
    if control_bytes is None:
        raise ValueError("IPK control file missing")
    fields = {}
    for line in control_bytes.decode("utf-8").splitlines():
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in fields:
            raise ValueError(f"duplicate IPK control field: {key}")
        fields[key] = value.strip()
    if not all(fields.get(key) for key in ("Package", "Version", "Architecture")):
        raise ValueError("IPK control missing package/version/architecture")
    return {key: fields[key] for key in ("Package", "Version", "Architecture")}


def require_ipk_files(members: dict[str, bytes]) -> None:
    for installed_path in (v[1] for v in FILES.values()):
        if installed_path not in members:
            raise ValueError(f"missing IPK member: {installed_path}")


def validate_header_bytes(source: bytes, prepared: bytes, staged: bytes,
                          ipk: bytes, package_version: str) -> None:
    if b"{# PKG_VERSION #}" not in source:
        raise ValueError("pinned header.ut no longer has the expected version token")
    if prepared != source:
        raise ValueError("prepared header.ut differs from pinned source before package substitution")
    expected = source.replace(b"{# PKG_VERSION #}", package_version.encode())
    if staged != expected or ipk != staged:
        raise ValueError("header.ut staging/IPK does not match the inspected version substitution")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openwrt", type=pathlib.Path, required=True)
    ap.add_argument("--luci", type=pathlib.Path, required=True)
    ap.add_argument("--packages", type=pathlib.Path, required=True)
    ap.add_argument("--prepared-root", type=pathlib.Path, required=True, help="PKG_BUILD_DIR, containing ucode/")
    ap.add_argument("--staging-root", type=pathlib.Path, required=True, help="luci-base package install staging root")
    ap.add_argument("--ipk-dir", type=pathlib.Path, required=True, help="the configured target's luci package output directory")
    ap.add_argument("--retained-ipk", type=pathlib.Path, required=True, help="run-owned exact archive retained with the receipt")
    ap.add_argument("--package-version", required=True, help="resolved PKG_VERSION or PKG_SRC_VERSION passed to SubstituteVersion")
    ap.add_argument("--receipt", type=pathlib.Path, required=True)
    args = ap.parse_args()
    started = time.monotonic()
    try:
        pins = {n: pinned_clean(n, getattr(args, n)) for n in PINS}
        openwrt = args.openwrt.resolve(strict=True)
        inputs = build_inputs(openwrt)
        inputs["resolved_feeds"] = require_feed_links(openwrt, args.luci, args.packages)
        prepared_root = require_under(args.prepared_root, openwrt, "prepared root")
        staging_root = require_under(args.staging_root, openwrt, "staging root")
        ipk_dir = require_under(args.ipk_dir, openwrt, "IPK directory")
        if not prepared_root.is_dir() or not staging_root.is_dir() or not ipk_dir.is_dir():
            raise ValueError("prepared, staging and IPK paths must be existing directories")
        prepared_rel = prepared_root.relative_to(openwrt).parts
        ipk_rel = ipk_dir.relative_to(openwrt).parts
        if (len(prepared_rel) < 3 or prepared_rel[0] != "build_dir" or
                prepared_root.name != "luci-base" or
                staging_root.name != "luci-base" or
                not staging_root.parent.name.startswith("ipkg-") or
                staging_root.parent.parent != prepared_root or
                len(ipk_rel) < 3 or ipk_rel[:2] != ("bin", "packages")):
            raise ValueError("prepared, staging or IPK directory layout differs from pinned recipe")
        ipks = sorted(args.ipk_dir.glob("luci-base_*.ipk"))
        if len(ipks) != 1 or not ipks[0].is_file() or ipks[0].is_symlink():
            raise ValueError(f"expected exactly one luci-base_*.ipk, found {[p.name for p in ipks]}")
        original_ipk = read_regular_under(ipks[0], ipk_dir, "IPK archive")
        if args.retained_ipk.name != "luci-base.ipk":
            raise ValueError("retained IPK artifact name differs")
        ipk_bytes = read_regular_under(args.retained_ipk, args.receipt.parent, "retained IPK archive")
        if original_ipk != ipk_bytes:
            raise ValueError("retained IPK bytes differ from build output")
        members = ipk_data_members(ipk_bytes)
        require_ipk_files(members)
        control = ipk_control_fields(ipk_bytes)
        stage_arch = staging_root.parent.name.removeprefix("ipkg-")
        if (control["Package"] != "luci-base" or control["Version"] != args.package_version or
                control["Architecture"] != stage_arch or
                ipks[0].name != f"luci-base_{args.package_version}_{stage_arch}.ipk"):
            raise ValueError("IPK control/filename differs from pinned package/version/stage architecture")
        rows = {}
        for label, (source_path, installed_path) in FILES.items():
            source = subprocess.check_output(["git", "-C", str(args.luci), "show", f"{PINS['luci']}:{source_path}"])
            prepared_path = prepared_root / source_path.removeprefix("modules/luci-base/")
            staged_path = staging_root / installed_path
            prepared = read_regular_under(prepared_path, prepared_root, "prepared " + label)
            staged = read_regular_under(staged_path, staging_root, "staged " + label)
            ipk = members[installed_path]
            if label == "http.uc" and not (source == prepared == staged == ipk):
                raise ValueError("direct-copy http.uc bytes differ across source/prepared/staged/IPK")
            if label == "header.ut":
                validate_header_bytes(source, prepared, staged, ipk, args.package_version)
            rows[label] = {
                "source_git_path": source_path,
                "source_git_blob_oid": git(args.luci, "rev-parse", f"{PINS['luci']}:{source_path}"),
                "installed_path": installed_path,
                "sha256": {"source_git_blob_bytes": sha(source), "prepared": sha(prepared),
                           "package_staging": sha(staged), "ipk_member": sha(ipk)},
                "equal": {"source_prepared": source == prepared, "prepared_staging": prepared == staged,
                          "staging_ipk": staged == ipk},
            }
        receipt = {
            "status": "PASS", "scope": "experimental luci-base file-byte mapping only",
            "pins": pins, "build_inputs": inputs, "package_version": args.package_version,
            "ipk": {"path": str(ipks[0]), "sha256": sha(ipk_bytes),
                    "control": control,
                    "control_archive_sha256": sha(ipk_parts(ipk_bytes)["control.tar.gz"])},
            "files": rows, "elapsed_seconds": round(time.monotonic() - started, 6),
            "timing_scope": "comparison helper only; excludes extraction/build/package",
        }
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        receipt = {"status": "FAIL", "error": str(exc),
                   "elapsed_seconds": round(time.monotonic() - started, 6),
                   "timing_scope": "comparison helper only; excludes extraction/build/package"}
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 1
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        raise SystemExit(f"FAIL CLOSED: {exc}")
