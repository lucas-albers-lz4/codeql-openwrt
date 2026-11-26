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
import archive

PINS = {
    "openwrt": "4e9642517b48bae612ff10fb72fb9199e559500e",
    "luci": "cb87fe60e1e2e052af36a93647f2264577829e0a",
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


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()



# Updated only after the source-first oracle has been independently frozen.
ORACLE_SHA256 = "5fe8593458900f5eca20e20de5e68e1d7cba079fd985e93ec53bff5551b5f999"
EXPECTED_VERSION = "26.317.52279~1c75ea4"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def checked_file(root, relative):
    path = root
    parts = pathlib.PurePosixPath(relative).parts
    if not parts or any(p in ("", ".", "..") for p in parts) or relative.startswith("/"):
        raise ValueError(f"unsafe source/stage path: {relative}")
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink in source/stage path: {path}")
    if not path.is_file():
        raise ValueError(f"missing regular source/stage file: {path}")
    return path.read_bytes(), path.stat().st_mode & 0o7777


def preflight_oracle(oracle_path, luci):
    data = oracle_path.read_bytes()
    if sha(data) != ORACLE_SHA256:
        raise ValueError("source-first oracle digest differs")
    oracle = json.loads(data, object_pairs_hook=unique_object)
    pinned_clean("luci", luci)
    if oracle["source_inventory"]["source"]["commit"] != PINS["luci"]:
        raise ValueError("oracle source pin differs")
    for path, expected in oracle["source_inventory"]["recipe_file_sha256"].items():
        body, _ = checked_file(luci, path)
        if sha(body) != expected:
            raise ValueError(f"recipe digest differs: {path}")
    return oracle


def recognized_shebang(first):
    if not first.startswith(b"#!"):
        return False
    words = first[2:].decode("utf-8", errors="replace").split()
    if not words:
        return False
    if words[0].rsplit("/", 1)[-1] == "ucode":
        return True
    if words[0] not in ("/usr/bin/env", "/bin/env") or len(words) < 2:
        return False
    command = words[1]
    if command == "-S":
        if len(words) < 3:
            return False
        command = words[2]
    command = command.strip("\"'").removeprefix("-S").strip("\"'")
    return command.rsplit("/", 1)[-1] == "ucode"


def compare_candidates(oracle, luci, prepared, staged, members, version):
    if version != EXPECTED_VERSION:
        raise ValueError("package version differs from source-first oracle")
    if oracle["source_inventory"]["source"]["commit"] != PINS["luci"]:
        raise ValueError("oracle source pin differs")
    selected = oracle["selected_source_candidates"]
    unknown = oracle["unknown_extensionless_candidates"]
    generated = oracle["generated_expected_members"]
    if (len(selected), len(unknown), len(generated)) != (17, 3, 1):
        raise ValueError("oracle candidate counts differ")
    paths = [r["expected_package_member_path"] for r in selected + unknown]
    paths += [r["path"] for r in generated]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate oracle member path")
    result = []
    for row in selected + unknown:
        src = row["source_path"]
        if not src.startswith("modules/luci-base/"):
            raise ValueError("unexpected oracle source prefix")
        member = row["expected_package_member_path"]
        source = subprocess.check_output(["git", "-C", str(luci), "show", f"{PINS['luci']}:{src}"])
        if sha(source) != row["sha256"] or git(luci, "rev-parse", f"{PINS['luci']}:{src}") != row["git_blob"]:
            raise ValueError(f"source identity differs: {src}")
        found = members.get(member)
        if found is None and row in unknown and member != "etc/init.d/ucitrack":
            result.append({"source": src, "installed_path": member, "status": "unknown absent"})
            continue
        if found is None or found["type"] != "file":
            raise ValueError(f"missing candidate member: {member}")
        prep, prep_mode = checked_file(prepared, src.removeprefix("modules/luci-base/"))
        stage, stage_mode = checked_file(staged, member)
        if prep != source:
            raise ValueError(f"prepared source differs: {src}")
        expected_sha = row.get("transform", {}).get("expected_member_sha256_from_pinned_source_and_recipe", row["sha256"])
        if sha(stage) != expected_sha or stage != found["bytes"]:
            raise ValueError(f"stage/IPK candidate bytes differ: {member}")
        if prep_mode != int(row["git_mode"][-3:], 8) or stage_mode != row["expected_member_mode_bits"] or found["mode"] != stage_mode:
            raise ValueError(f"candidate mode differs: {member}")
        if member == "etc/init.d/ucitrack" and (not source.startswith(b"#!/bin/sh") or recognized_shebang(source.split(b"\n", 1)[0])):
            raise ValueError("shell near miss differs")
        status = "excluded shell control" if member == "etc/init.d/ucitrack" else "unknown present" if row in unknown else "selected present"
        result.append({"source": src, "installed_path": member, "status": status, "source_sha256": sha(source), "prepared_sha256": sha(prep), "staged_sha256": sha(stage), "ipk_sha256": sha(found["bytes"]), "mode": format(found["mode"], "04o")})
    gen = generated[0]
    path = gen["path"]
    found = members.get(path)
    if found is None or found["type"] != "file":
        raise ValueError("missing generated version.uc")
    staged_bytes, mode = checked_file(staged, path)
    prepared_bytes, prepared_mode = checked_file(prepared, "src/version.uc")
    expected = gen["expected_bytes_utf8"].encode()
    if prepared_bytes != expected or prepared_mode != gen["expected_mode_bits_under_umask_022"] or staged_bytes != expected or found["bytes"] != expected or mode != gen["expected_mode_bits_under_umask_022"] or found["mode"] != mode:
        raise ValueError("generated version.uc differs")
    result.append({"installed_path": path, "status": "generated", "prepared_sha256": sha(prepared_bytes), "staged_sha256": sha(staged_bytes), "ipk_sha256": sha(found["bytes"]), "mode": format(mode, "04o")})
    known = set(paths)
    for path, entry in members.items():
        if entry["type"] != "file" or path in known:
            continue
        data = entry["bytes"]
        first = data.split(b"\n", 1)[0]
        if path.endswith((".uc", ".ucode", ".ut")) or path.startswith("usr/share/rpcd/ucode/") or (path.startswith(("usr/share/ucode/", "usr/lib/ucode/")) and not pathlib.PurePosixPath(path).suffix) or recognized_shebang(first):
            raise ValueError(f"unexpected Ucode candidate: {path}")
    return result


def control_from_rows(rows):
    entry = rows.get("control")
    if entry is None or entry["type"] != "file":
        raise ValueError("IPK control file missing or nonregular")
    fields = {}
    for line in entry["bytes"].decode("utf-8").splitlines():
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in fields:
            raise ValueError(f"duplicate IPK control field: {key}")
        fields[key] = value.strip()
    if not all(fields.get(key) for key in ("Package", "Version", "Architecture")):
        raise ValueError("IPK control missing package/version/architecture")
    return {key: fields[key] for key in ("Package", "Version", "Architecture")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--oracle", type=pathlib.Path, required=True)
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
        oracle = preflight_oracle(args.oracle, args.luci)
        control_rows, members, archive_sha = archive.read_ipk(ipk_bytes)
        rows = compare_candidates(oracle, args.luci, prepared_root, staging_root, members,
                                  args.package_version)

        control = control_from_rows(control_rows)
        stage_arch = staging_root.parent.name.removeprefix("ipkg-")
        if (control["Package"] != "luci-base" or control["Version"] != args.package_version or
                control["Architecture"] != "x86_64" or stage_arch != "x86_64" or
                ipks[0].name != f"luci-base_{args.package_version}_{stage_arch}.ipk"):
            raise ValueError("IPK control/filename differs from pinned package/version/stage architecture")
        receipt = {
            "status": "PASS", "scope": "experimental luci-base file-byte mapping only",
            "pins": pins, "build_inputs": inputs, "package_version": args.package_version,
            "ipk": {"path": str(ipks[0]), "sha256": sha(ipk_bytes),
                    "control": control,
                    "control_archive_sha256": archive_sha["control.tar.gz"]},
            "files": rows, "archive_data_members": archive.receipts(members),
            "archive_control_members": archive.receipts(control_rows),
            "oracle_sha256": ORACLE_SHA256, "elapsed_seconds": round(time.monotonic() - started, 6),
            "timing_scope": "comparison helper only; excludes extraction/build/package",
        }
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, EOFError) as exc:
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
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, EOFError) as exc:
        raise SystemExit(f"FAIL CLOSED: {exc}")
