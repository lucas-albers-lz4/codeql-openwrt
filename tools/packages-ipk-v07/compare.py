#!/usr/bin/env python3
"""Fail-closed source, package-stage, and IPK comparison for two v0.7 feed packages."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import time
import zlib


HERE = Path(__file__).resolve().parent
ORACLE_PATH = HERE / "oracle.json"
ORACLE = json.loads(ORACLE_PATH.read_text())
PINS = {name: value["commit"] for name, value in ORACLE["sources"].items()}
MAX_IPK_BYTES = 64 * 1024 * 1024
MAX_TAR_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TAR_ENTRIES = 10000
MAX_TAR_TOTAL_BYTES = 64 * 1024 * 1024
UCD_SUFFIXES = (".uc", ".ucode", ".ut")
UCD_ROOTS = ("usr/share/ucode/", "usr/share/rpcd/ucode/", "usr/lib/ucode/")
CONFIG_KEEP_PREFIXES = (
    "CONFIG_TARGET_x86",
    "CONFIG_PACKAGE_adblock-fast",
    "CONFIG_PACKAGE_uvol",
    "CONFIG_PACKAGE_autopart",
    "CONFIG_PACKAGE_ucode",
    "CONFIG_PACKAGE_blockd",
    "CONFIG_PACKAGE_curl",
    "CONFIG_PACKAGE_resolveip",
    "CONFIG_PACKAGE_gawk",
    "CONFIG_PACKAGE_grep",
    "CONFIG_PACKAGE_sed",
    "CONFIG_PACKAGE_coreutils-sort",
    "CONFIG_BUSYBOX_DEFAULT_",
    "CONFIG_USE_APK",
    "CONFIG_PER_FEED_REPO",
)


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def status_lines(repo: Path, *, include_untracked: bool) -> list[str]:
    args = ["status", "--porcelain=v1"]
    args.append("--untracked-files=all" if include_untracked else "--untracked-files=no")
    raw = subprocess.check_output(["git", "-C", str(repo), *args], text=True)
    return raw.splitlines()


def require_repo(repo: Path, name: str, *, include_untracked: bool) -> dict:
    pin = PINS[name]
    rev = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    dirty = status_lines(repo, include_untracked=include_untracked)
    expected_tree = ORACLE["sources"][name]["tree"]
    if rev != pin or tree != expected_tree or dirty:
        raise ValueError(
            f"{name} checkout mismatch: HEAD={rev}, tree={tree}, dirty={bool(dirty)}"
        )
    return {"commit": rev, "tree": tree, "dirty": False}


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    base = root.resolve(strict=True)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"{label} resolves outside its owned root: {resolved}") from exc
    return resolved


def read_regular_under(path: Path, root: Path, label: str) -> bytes:
    resolved = require_under(path, root, label)
    if path.is_symlink() or not path.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size > MAX_IPK_BYTES:
        raise ValueError(f"{label} exceeds {MAX_IPK_BYTES} bytes: {size}")
    return path.read_bytes()


def mode_text(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def config_assignments(lines: list[str], symbol: str) -> list[str]:
    return [line for line in lines if line.startswith(symbol + "=") or
            line == f"# {symbol} is not set"]


def build_inputs(openwrt: Path, packages: Path) -> dict:
    config_path = openwrt / ".config"
    feeds_path = openwrt / "feeds.conf"
    config_bytes = read_regular_under(config_path, openwrt, "OpenWrt .config")
    feeds_bytes = read_regular_under(feeds_path, openwrt, "OpenWrt feeds.conf")
    lines = [line.strip() for line in config_bytes.decode("utf-8", errors="replace").splitlines()]
    for symbol, value in ORACLE["build_config"]["required"].items():
        found = config_assignments(lines, symbol)
        if found != [f"{symbol}={value}"]:
            raise ValueError(f"unexpected OpenWrt config for {symbol}: {found}")
    for symbol in ORACLE["build_config"]["disabled"]:
        found = config_assignments(lines, symbol)
        if found != [f"# {symbol} is not set"] and found != [f"{symbol}=n"]:
            raise ValueError(f"OpenWrt config must disable {symbol}: {found}")

    expected_feed_line = f"src-link packages {packages.resolve(strict=True)}"
    feed_lines = [line.strip() for line in feeds_bytes.decode("utf-8").splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    if feed_lines != [expected_feed_line]:
        raise ValueError(f"feeds.conf must contain exactly {expected_feed_line!r}; got {feed_lines}")
    feed_link = openwrt / "feeds" / "packages"
    if not feed_link.is_symlink() or feed_link.resolve(strict=True) != packages.resolve(strict=True):
        raise ValueError("installed packages feed does not resolve to the pinned checkout")

    resolved_packages = {}
    for package_name, package in ORACLE["packages"].items():
        source_root = (packages / package["recipe"]).parent
        installed_link = openwrt / "package" / "feeds" / "packages" / package_name
        if not installed_link.is_symlink() or installed_link.resolve(strict=True) != source_root.resolve(strict=True):
            raise ValueError(f"installed package path does not resolve to pinned feed: {package_name}")
        resolved_packages[package_name] = str(installed_link.resolve(strict=True))

    selected = []
    for line in lines:
        if any(line.startswith(prefix) for prefix in CONFIG_KEEP_PREFIXES):
            selected.append(line)
    return {
        "config": {"path": ".config", "sha256": sha256(config_bytes),
                   "selected_lines": selected},
        "feeds": {"path": "feeds.conf", "sha256": sha256(feeds_bytes),
                  "resolved_packages_feed": str(feed_link.resolve(strict=True))},
        "resolved_package_paths": resolved_packages,
    }


def parse_git_tree_entry(repo: Path, path: str) -> tuple[str, str]:
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "ls-tree", "-z", PINS["packages"], "--", path]
    )
    entries = [entry for entry in raw.split(b"\0") if entry]
    if len(entries) != 1:
        raise ValueError(f"expected one source tree entry for {path}, got {len(entries)}")
    header, found_path = entries[0].split(b"\t", 1)
    mode, kind, oid = header.decode("ascii").split(" ")
    if found_path.decode("utf-8") != path or kind != "blob":
        raise ValueError(f"unexpected Git tree entry for {path}: {entries[0]!r}")
    return mode, oid


def expected_source_bytes(source: bytes, row: dict) -> bytes:
    transform = row["transform"]
    if transform is None:
        expected = source
    elif transform["kind"] == "replace-once":
        before, after = transform["before"].encode(), transform["after"].encode()
        if source.count(before) != 1:
            raise ValueError(f"source substitution is not uniquely applicable: {row['source_path']}")
        expected = source.replace(before, after, 1)
    else:
        raise ValueError(f"unsupported source transformation: {transform['kind']}")
    if sha256(expected) != row["expected_sha256"]:
        raise ValueError(f"predeclared transformed-byte oracle mismatch: {row['source_path']}")
    return expected


def verify_empty_build_hooks(recipe_bytes: bytes, package_name: str) -> list[str]:
    expected = ORACLE["packages"][package_name]["empty_build_hooks"]
    observed = []
    for hook in expected:
        pattern = rb"(?m)^define Build/" + hook.encode() + rb"\s*\nendef\s*$"
        if re.search(pattern, recipe_bytes) is None:
            raise ValueError(f"pinned {package_name} recipe no longer has empty Build/{hook}")
        observed.append(hook)
    prepare_behavior = ORACLE["packages"][package_name]["prepare_behavior"]
    if prepare_behavior == "default prepare with no PKG_SOURCE assignment":
        if re.search(rb"(?m)^\s*define Build/Prepare\b", recipe_bytes):
            raise ValueError(f"pinned {package_name} recipe unexpectedly overrides Build/Prepare")
        if re.search(rb"(?m)^\s*PKG_SOURCE\s*[:?+]?=", recipe_bytes):
            raise ValueError(f"pinned {package_name} recipe unexpectedly assigns PKG_SOURCE")
    elif prepare_behavior != "explicit empty Build/Prepare hook":
        raise ValueError(f"unsupported prepare behavior for {package_name}: {prepare_behavior}")
    return observed


def verify_source(packages: Path, path: str, blob: str, source_hash: str,
                  expected_mode: str, label: str) -> dict:
    tree_mode, tree_blob = parse_git_tree_entry(packages, path)
    if (tree_mode, tree_blob) != (expected_mode, blob):
        raise ValueError(f"pinned Git mode/blob changed for {path}: {(tree_mode, tree_blob)}")
    source_path = packages / path
    source = read_regular_under(source_path, packages, label)
    git_bytes = subprocess.check_output(
        ["git", "-C", str(packages), "show", f"{PINS['packages']}:{path}"]
    )
    if source != git_bytes:
        raise ValueError(f"working-tree source differs from pinned Git blob: {path}")
    if git_blob(source) != blob or sha256(source) != source_hash:
        raise ValueError(f"source bytes do not match pinned blob/SHA-256: {path}")
    actual_mode = mode_text(source_path.stat().st_mode)
    if actual_mode != expected_mode[-4:]:
        raise ValueError(f"source file mode differs from Git mode for {path}: {actual_mode}")
    return {"path": path, "git_blob": blob, "git_mode": expected_mode,
            "sha256": source_hash, "working_tree_mode": actual_mode}


def source_first_oracle(packages: Path) -> dict:
    rows = {}
    for package_name, package in ORACLE["packages"].items():
        package_rows = []
        for row in package["ucode_members"]:
            source_record = verify_source(
                packages, row["source_path"], row["git_blob"], row["source_sha256"],
                row["source_mode"], f"{package_name} source"
            )
            expected_bytes = expected_source_bytes((packages / row["source_path"]).read_bytes(), row)
            package_rows.append({
                "source": source_record,
                "member_path": row["member_path"],
                "recipe_source_operand": row["recipe_source_operand"],
                "install_destination_kind": row["install_destination_kind"],
                "expected_sha256": row["expected_sha256"],
                "expected_mode": row["member_mode"],
                "stage_mode": row["stage_mode"],
                "expected_size": len(expected_bytes),
                "transform": row["transform"],
            })
        controls = []
        for control in package["negative_controls"]:
            source_record = verify_source(
                packages, control["source_path"], control["git_blob"],
                control["source_sha256"], control["source_mode"], f"{package_name} control"
            )
            controls.append({
                "source": source_record,
                "expected_package_member": "absent",
                "forbidden_member_suffix": control["forbidden_member_suffix"],
            })
        recipe_path = packages / package["recipe"]
        recipe_bytes = read_regular_under(recipe_path, packages, f"{package_name} recipe")
        git_recipe = subprocess.check_output(
            ["git", "-C", str(packages), "show", f"{PINS['packages']}:{package['recipe']}"]
        )
        if recipe_bytes != git_recipe:
            raise ValueError(f"working-tree package recipe differs from pin: {package['recipe']}")
        empty_hooks = verify_empty_build_hooks(recipe_bytes, package_name)
        rows[package_name] = {
            "version": package["version"],
            "architecture": package["architecture"],
            "recipe": {"path": package["recipe"], "sha256": sha256(recipe_bytes)},
            "empty_build_hooks": empty_hooks,
            "prepare_behavior": package["prepare_behavior"],
            "declared_runtime_dependencies": package["declared_runtime_dependencies"],
            "ucode_members": package_rows,
            "negative_controls": controls,
        }
    return {
        "schema": "packages-feed-ipk-v07-source-oracle-v1",
        "scope": "source-first expected package data members; no build output inspected",
        "source_pins": {
            name: {"commit": pin, "tree": ORACLE["sources"][name]["tree"]}
            for name, pin in PINS.items()
        },
        "oracle_sha256": sha256(ORACLE_PATH.read_bytes()),
        "packages": rows,
    }


def normalize_member(raw: str, *, directory: bool = False) -> str:
    if "\x00" in raw or "\\" in raw:
        raise ValueError(f"unsafe archive member name: {raw!r}")
    if raw in (".", "./"):
        if not directory:
            raise ValueError("archive root entry is not a directory")
        return ""
    name = raw[2:] if raw.startswith("./") else raw
    if name.startswith("/"):
        raise ValueError(f"absolute archive member name: {raw!r}")
    if directory and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    if (not name or any(part in ("", ".", "..") for part in parts) or
            PurePosixPath(name).as_posix() != name):
        raise ValueError(f"unsafe archive member name: {raw!r}")
    return name


def bounded_gzip_decompress(data: bytes, label: str, max_uncompressed: int) -> bytes:
    if not data.startswith(b"\x1f\x8b"):
        raise ValueError(f"{label} is not gzip-compressed")
    decoder = zlib.decompressobj(wbits=31)
    output = bytearray()
    try:
        for offset in range(0, len(data), 64 * 1024):
            pending = data[offset:offset + 64 * 1024]
            while pending:
                request = min(64 * 1024, max_uncompressed + 1 - len(output))
                chunk = decoder.decompress(pending, request)
                output.extend(chunk)
                if len(output) > max_uncompressed:
                    raise ValueError(f"{label} exceeds bounded uncompressed size")
                pending = decoder.unconsumed_tail
        if not decoder.eof:
            raise ValueError(f"truncated {label} gzip stream")
        if decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError(f"trailing or concatenated data after {label} gzip stream")
        output.extend(decoder.flush(max_uncompressed + 1 - len(output)))
        if len(output) > max_uncompressed:
            raise ValueError(f"{label} exceeds bounded uncompressed size")
    except zlib.error as exc:
        raise ValueError(f"invalid {label} gzip stream: {exc}") from exc
    return bytes(output)


def raw_tar_headers(raw: bytes, label: str, *, max_member_bytes: int,
                    max_total_bytes: int) -> list[dict]:
    """Validate raw headers and trailer before tarfile can interpret extensions."""
    offset = 0
    headers = []
    names = set()
    total = 0
    while offset + 512 <= len(raw) and any(raw[offset:offset + 512]):
        try:
            header = tarfile.TarInfo.frombuf(raw[offset:offset + 512], "utf-8", "surrogateescape")
        except tarfile.TarError as exc:
            raise ValueError(f"invalid {label} raw tar header: {exc}") from exc
        is_directory = header.type == tarfile.DIRTYPE
        is_regular = header.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
        if header.size < 0 or header.size > min(max_member_bytes, MAX_TAR_MEMBER_BYTES):
            raise ValueError(f"invalid or oversized {label} member: {header.name!r}")
        if not (is_directory or is_regular):
            raise ValueError(f"non-regular {label} member: {header.name!r}")
        if is_directory and header.size != 0:
            raise ValueError(f"nonzero directory size in {label} tar: {header.name!r}")
        name = normalize_member(header.name, directory=is_directory)
        if name in names:
            raise ValueError(f"duplicate {label} member after normalization: {name!r}")
        names.add(name)
        total += header.size
        if total > min(max_total_bytes, MAX_TAR_TOTAL_BYTES):
            raise ValueError(f"{label} tar exceeds total uncompressed file size limit")
        headers.append({"raw_name": header.name, "name": name, "type": header.type,
                        "mode": header.mode, "size": header.size})
        if len(headers) > MAX_TAR_ENTRIES:
            raise ValueError(f"{label} tar has too many entries")
        offset += 512 + ((header.size + 511) // 512) * 512
        if offset > len(raw):
            raise ValueError(f"truncated {label} tar member")
    if len(raw) % 512 or len(raw) - offset < 1024 or any(raw[offset:]):
        raise ValueError(f"nonzero or truncated {label} tar trailer")
    return headers


def tar_entries(data: bytes, label: str, *, max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                max_total_bytes: int = MAX_TAR_TOTAL_BYTES) -> dict[str, dict]:
    """Read a bounded gzip tar without extraction, rejecting hidden/ambiguous entries."""
    max_uncompressed = max_total_bytes + MAX_TAR_ENTRIES * 1024 + 1024
    raw = bounded_gzip_decompress(data, label, max_uncompressed)
    raw_headers = raw_tar_headers(
        raw, label, max_member_bytes=max_member_bytes, max_total_bytes=max_total_bytes
    )
    result = {}
    raw_names = {}
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"invalid {label} tar: {exc}") from exc
    with archive:
        for count, member in enumerate(archive, start=1):
            if count > len(raw_headers):
                raise ValueError(f"{label} parser exposed more entries than raw headers")
            raw_header = raw_headers[count - 1]
            if member.name != raw_header["raw_name"] or member.type != raw_header["type"]:
                raise ValueError(f"{label} parser changed raw member identity")
            name = normalize_member(member.name, directory=member.isdir())
            if name in result:
                raise ValueError(
                    f"duplicate {label} member after normalization: {name!r} "
                    f"({raw_names[name]!r}, {member.name!r})"
                )
            is_directory = member.type == tarfile.DIRTYPE
            is_regular = member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
            if not (is_directory or is_regular):
                raise ValueError(f"non-regular {label} member: {member.name!r}")
            if is_directory:
                result[name] = {
                    "raw_name": member.name, "kind": "directory",
                    "mode": mode_text(member.mode), "size": 0, "sha256": None,
                    "bytes": None,
                }
                raw_names[name] = member.name
                continue
            if member.size < 0 or member.size > min(max_member_bytes, MAX_TAR_MEMBER_BYTES):
                raise ValueError(f"oversized {label} member {member.name!r}: {member.size}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read {label} member: {member.name!r}")
            body = stream.read(member.size + 1)
            if len(body) != member.size:
                raise ValueError(f"truncated or oversized {label} member: {member.name!r}")
            result[name] = {
                "raw_name": member.name, "kind": "regular", "mode": mode_text(member.mode),
                "size": member.size, "sha256": sha256(body), "bytes": body,
            }
            raw_names[name] = member.name
        if len(raw_headers) != len(result):
            raise ValueError(f"{label} raw header count differs from parsed entries")
    for name in result:
        parts = name.split("/") if name else []
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent in result and result[parent]["kind"] != "directory":
                raise ValueError(f"{label} file used as a directory: {parent!r}")
    return result


def ipk_parts(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_IPK_BYTES:
        raise ValueError(f"IPK exceeds {MAX_IPK_BYTES} bytes")
    if not data.startswith(b"\x1f\x8b"):
        raise ValueError("IPK is not a gzip-compressed outer tar")
    outer = tar_entries(data, "outer IPK", max_member_bytes=MAX_TAR_TOTAL_BYTES)
    parts = {}
    for name, entry in outer.items():
        if name == "":
            if entry["kind"] != "directory":
                raise ValueError("outer IPK root is not a directory")
            continue
        if entry["kind"] != "regular":
            raise ValueError(f"outer IPK member is not regular: {name}")
        parts[name] = entry["bytes"]
    if set(parts) != {"debian-binary", "data.tar.gz", "control.tar.gz"}:
        raise ValueError(f"unexpected outer IPK members: {sorted(parts)}")
    if parts["debian-binary"] != b"2.0\n":
        raise ValueError("unexpected debian-binary marker")
    return parts


def read_data_members(ipk_bytes: bytes) -> tuple[dict[str, dict], dict[str, bytes]]:
    parts = ipk_parts(ipk_bytes)
    entries = tar_entries(parts["data.tar.gz"], "IPK data", max_member_bytes=MAX_TAR_MEMBER_BYTES)
    members = {name: entry for name, entry in entries.items() if name}
    file_bytes = {name: entry["bytes"] for name, entry in members.items()
                  if entry["kind"] == "regular"}
    return members, file_bytes


def control_fields(ipk_bytes: bytes) -> dict[str, str]:
    parts = ipk_parts(ipk_bytes)
    entries = tar_entries(parts["control.tar.gz"], "IPK control",
                          max_member_bytes=4 * 1024 * 1024,
                          max_total_bytes=8 * 1024 * 1024)
    control = entries.get("control")
    if control is None or control["kind"] != "regular":
        raise ValueError("regular IPK control file missing")
    fields = {}
    for line in control["bytes"].decode("utf-8").splitlines():
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in fields:
            raise ValueError(f"duplicate IPK control field: {key}")
        fields[key] = value.strip()
    required = {key: fields.get(key) for key in ("Package", "Version", "Architecture")}
    if not all(required.values()):
        raise ValueError(f"IPK control metadata incomplete: {required}")
    return required


def is_ucode_looking(name: str, body: bytes) -> bool:
    if name.lower().endswith(UCD_SUFFIXES) or any(name.startswith(root) for root in UCD_ROOTS):
        return True
    first_line = body.splitlines()[0][:256] if body else b""
    return first_line.startswith(b"#!") and re.search(rb"(?<![A-Za-z0-9_])ucode(?![A-Za-z0-9_])", first_line) is not None


def negative_control_matches(entries: dict[str, dict], file_bytes: dict[str, bytes],
                             source_bytes: bytes, expected_sha256: str) -> dict:
    return {
        "sha256_matches": sorted(
            name for name, entry in entries.items()
            if entry["kind"] == "regular" and entry["sha256"] == expected_sha256
        ),
        "exact_content_matches": sorted(
            name for name, body in file_bytes.items() if source_bytes and source_bytes in body
        ),
    }


def ucode_member_names(entries: dict[str, dict]) -> set[str]:
    return {
        name for name, entry in entries.items()
        if entry["kind"] == "regular" and is_ucode_looking(name, entry["bytes"])
    }


def require_ucode_member_set(entries: dict[str, dict], expected: set[str], label: str) -> set[str]:
    actual = ucode_member_names(entries)
    if actual != expected:
        raise ValueError(
            f"{label} Ucode member set differs: "
            f"missing={sorted(expected-actual)}, extra={sorted(actual-expected)}"
        )
    return actual


def scan_stage_ucode_members(stage_root: Path) -> dict[str, dict]:
    entries = {}
    for path in stage_root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"non-regular package-stage entry: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"non-regular package-stage entry: {path}")
        rel = path.relative_to(stage_root).as_posix()
        body = read_regular_under(path, stage_root, f"package-stage entry {rel}")
        if is_ucode_looking(rel, body):
            entries[rel] = {"kind": "regular", "bytes": body}
    return entries


def package_build_version(package_name: str) -> str:
    return ORACLE["packages"][package_name]["version"].rsplit("-r", 1)[0]


def packaged_records(log_path: Path, run_root: Path, openwrt: Path,
                     package_name: str) -> tuple[Path, Path, list[str]]:
    """Resolve build outputs from OpenWrt's own ipkg-build completion record."""
    log = require_under(log_path, run_root, f"{package_name} build log")
    if log_path.is_symlink() or not log_path.is_file():
        raise ValueError(f"build log must be a regular non-symlink file: {log_path}")
    if log_path.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError(f"build log exceeds 1 GiB: {log_path}")
    package = ORACLE["packages"][package_name]
    expected_ipk_prefix = f"{package_name}_{package['version']}_"
    records = []
    pattern = re.compile(r"^Packaged contents of (\S+) into (\S+)$")
    with log.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            match = pattern.match(line.rstrip("\r\n"))
            if match and Path(match.group(2)).name.startswith(expected_ipk_prefix):
                records.append((Path(match.group(1)), Path(match.group(2)), line.rstrip()))
    if len(records) != 1:
        raise ValueError(f"expected one packaged-content record for {package_name}, found {records}")
    stage_path_raw, ipk_path_raw, line = records[0]
    stage_path = path_from_log(str(stage_path_raw), openwrt)
    ipk_path = path_from_log(str(ipk_path_raw), openwrt)
    stage_path = require_under(stage_path, openwrt, f"{package_name} logged package stage")
    ipk_path = require_under(ipk_path, openwrt, f"{package_name} logged IPK")
    if stage_path.is_symlink() or not stage_path.is_dir():
        raise ValueError(f"logged {package_name} stage is not a real directory: {stage_path}")
    if ipk_path.is_symlink() or not ipk_path.is_file():
        raise ValueError(f"logged {package_name} IPK is not a regular file: {ipk_path}")
    return stage_path, ipk_path, [line]


def validate_stage_layout(openwrt: Path, package_name: str, stage_root: Path) -> None:
    rel = stage_root.relative_to(openwrt)
    expected_build = f"{package_name}-{package_build_version(package_name)}"
    if (len(rel.parts) != 5 or rel.parts[0] != "build_dir" or
            not rel.parts[1].startswith("target-") or rel.parts[2] != expected_build or
            rel.parts[3] != "ipkg-all" or rel.parts[4] != package_name):
        raise ValueError(f"logged {package_name} staging path differs from pinned PKG_BUILD_DIR layout: {rel}")


def discover_ipks(openwrt: Path, package_name: str) -> list[Path]:
    base = openwrt / "bin"
    candidates = []
    if base.is_dir():
        version = ORACLE["packages"][package_name]["version"]
        for path in base.rglob(f"{package_name}_{version}_*.ipk"):
            if path.is_file() and not path.is_symlink():
                candidates.append(path)
    return sorted(path.resolve(strict=True) for path in candidates)


def path_from_log(value: str, openwrt: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else openwrt / path


def stage_install_log_lines(log_path: Path, run_root: Path, openwrt: Path,
                            source_operand: str, destination_kind: str,
                            stage_path: Path) -> list[str]:
    """Bind the recipe-relative source and destination operands to the logged IPK stage."""
    resolved = require_under(log_path, run_root, f"{log_path.name} build log")
    if log_path.is_symlink() or not log_path.is_file():
        raise ValueError(f"build log must be a regular non-symlink file: {log_path}")
    if log_path.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError(f"build log exceeds 1 GiB: {log_path}")
    if destination_kind not in ("file", "directory"):
        raise ValueError(f"unsupported recipe install destination kind: {destination_kind}")
    expected_source = PurePosixPath(source_operand)
    stage_file_rel = stage_path.relative_to(openwrt).as_posix()
    stage_parent_rel = PurePosixPath(stage_file_rel).parent.as_posix()
    if destination_kind == "file":
        destinations = {str(stage_path), stage_file_rel}
    else:
        destinations = {str(stage_path.parent), stage_parent_rel,
                        str(stage_path.parent) + "/", stage_parent_rel + "/"}
    matches = []
    with resolved.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if not re.search(r"(?:^|[;&|()\s])(install|cp)(?:\s|$)", line):
                continue
            try:
                tokens = shlex.split(line, comments=False, posix=True)
            except ValueError:
                tokens = line.split()
            commands = [i for i, token in enumerate(tokens)
                        if PurePosixPath(token).name in ("install", "cp")]
            if not commands:
                continue
            operands = tokens[commands[-1] + 1:]
            source_token = any(
                PurePosixPath(token) == expected_source or
                PurePosixPath(token).as_posix().endswith("/" + expected_source.as_posix())
                for token in operands
            )
            destination_token = any(
                token in destinations or token.rstrip("/") in destinations
                for token in operands
            )
            if source_token and destination_token:
                matches.append(line.rstrip())
    if len(matches) != 1:
        raise ValueError(
            f"verbose build log must have one source-to-IPK-stage install for "
            f"{source_operand} -> {stage_path}; found {matches}"
        )
    return matches


def write_stage_archive(openwrt: Path, run_root: Path, packages: dict[str, dict]) -> dict:
    archive_path = run_root / "output" / "stage-members.tar.gz"
    manifest_path = run_root / "output" / "stage-members.json"
    if archive_path.exists() or archive_path.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise ValueError("stage archive output already exists")
    members = []
    with archive_path.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for package_name, result in packages.items():
                    stage_root = require_under(openwrt / result["staging_root"],
                                               openwrt, f"retained {package_name} stage root")
                    for row in result["stage_comparisons"]:
                        stage_path = openwrt / row["stage_path"]
                        body = read_regular_under(stage_path, stage_root,
                                                  f"retained {package_name} stage member")
                        actual_hash = sha256(body)
                        actual_mode = mode_text(stage_path.stat().st_mode)
                        if actual_hash != row["stage_sha256"] or actual_mode != row["stage_mode"]:
                            raise ValueError(f"stage changed before archive capture: {package_name}:{row['member_path']}")
                        name = f"{package_name}/{row['member_path']}"
                        info = tarfile.TarInfo(name)
                        info.type = tarfile.REGTYPE
                        info.mode = int(actual_mode, 8)
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 0
                        info.size = len(body)
                        archive.addfile(info, io.BytesIO(body))
                        members.append({
                            "package": package_name,
                            "path": name,
                            "source_path": row["source_path"],
                            "sha256": actual_hash,
                            "mode": actual_mode,
                            "size": len(body),
                        })
    archive_bytes = read_regular_under(archive_path, run_root, "retained stage archive")
    manifest = {
        "schema": "packages-feed-ipk-v07-stage-members-v1",
        "archive": {"path": str(archive_path.relative_to(run_root)),
                    "sha256": sha256(archive_bytes), "format": "gzip USTAR tar, selected members only"},
        "members": members,
        "limits": ["contains selected package-stage bytes, not a root filesystem or image"],
    }
    write_json(manifest_path, run_root, manifest)
    return {"path": str(archive_path.relative_to(run_root)),
            "sha256": sha256(archive_bytes), "manifest": str(manifest_path.relative_to(run_root))}


def public_inventory(entries: dict[str, dict]) -> list[dict]:
    return [
        {key: entry[key] for key in ("raw_name", "kind", "mode", "size", "sha256")}
        | {"member_path": name}
        for name, entry in sorted(entries.items())
    ]


def compare_package(openwrt: Path, packages: Path, run_root: Path, package_name: str) -> dict:
    package = ORACLE["packages"][package_name]
    build_log = run_root / "output" / f"{package_name}-build.log"
    stage_root, logged_ipk_path, packaging_lines = packaged_records(
        build_log, run_root, openwrt, package_name
    )
    validate_stage_layout(openwrt, package_name, stage_root)
    stage_root = require_under(stage_root, openwrt, f"{package_name} staging root")

    expected_paths = {row["member_path"] for row in package["ucode_members"]}
    stage_records = []
    for row in package["ucode_members"]:
        rel = row["member_path"]
        stage_path = stage_root.joinpath(*PurePosixPath(rel).parts)
        staged = read_regular_under(stage_path, stage_root, f"{package_name} staged member {rel}")
        staged_mode = mode_text(stage_path.stat().st_mode)
        if sha256(staged) != row["expected_sha256"] or staged_mode != row["stage_mode"]:
            raise ValueError(f"package stage bytes/mode differ from oracle: {package_name}:{rel}")
        build_lines = stage_install_log_lines(
            build_log, run_root, openwrt, row["recipe_source_operand"],
            row["install_destination_kind"], stage_path
        )
        stage_records.append({
            "source_path": row["source_path"],
            "member_path": rel,
            "stage_path": str(stage_path.relative_to(openwrt)),
            "stage_sha256": sha256(staged),
            "stage_mode": staged_mode,
            "install_command_lines": build_lines,
            "separate_preparation": package["prepare_behavior"],
        })
    require_ucode_member_set(scan_stage_ucode_members(stage_root), expected_paths,
                             f"{package_name} package stage")

    ipks = discover_ipks(openwrt, package_name)
    if len(ipks) != 1:
        raise ValueError(f"expected exactly one {package_name} IPK in bin/, found {ipks}")
    ipk_path = ipks[0]
    if ipk_path != logged_ipk_path:
        raise ValueError(f"logged {package_name} IPK differs from unique package output: {logged_ipk_path}")
    ipk_data = read_regular_under(ipk_path, openwrt, f"{package_name} IPK")
    retained_path = run_root / "output" / "retained" / f"{package_name}.ipk"
    retained = read_regular_under(retained_path, run_root, f"retained {package_name} IPK")
    if retained != ipk_data:
        raise ValueError(f"retained {package_name} IPK differs from package output")
    fields = control_fields(ipk_data)
    expected_fields = {"Package": package_name, "Version": package["version"],
                       "Architecture": package["architecture"]}
    if fields != expected_fields:
        raise ValueError(f"{package_name} control metadata mismatch: {fields}")
    entries, file_bytes = read_data_members(ipk_data)
    ucode_members = require_ucode_member_set(entries, expected_paths, f"{package_name} IPK")

    member_records = []
    for row in package["ucode_members"]:
        name = row["member_path"]
        entry = entries.get(name)
        if entry is None or entry["kind"] != "regular":
            raise ValueError(f"missing or non-regular IPK Ucode member: {package_name}:{name}")
        if entry["sha256"] != row["expected_sha256"] or entry["mode"] != row["member_mode"]:
            raise ValueError(f"IPK bytes/mode differ from predeclared oracle: {package_name}:{name}")
        if file_bytes[name] != stage_root.joinpath(*PurePosixPath(name).parts).read_bytes():
            raise ValueError(f"package stage and IPK bytes differ: {package_name}:{name}")
        member_records.append({
            "source_path": row["source_path"],
            "source_sha256": row["source_sha256"],
            "source_mode": row["source_mode"],
            "member_path": name,
            "raw_tar_name": entry["raw_name"],
            "member_sha256": entry["sha256"],
            "member_mode": entry["mode"],
            "size": entry["size"],
            "transform": row["transform"],
        })

    excluded = []
    for control in package["negative_controls"]:
        suffix = control["forbidden_member_suffix"]
        present = sorted(name for name in entries
                         if name == suffix or name.endswith("/" + suffix))
        control_source = subprocess.check_output(
            ["git", "-C", str(packages), "show", f"{PINS['packages']}:{control['source_path']}"]
        )
        matches = negative_control_matches(
            entries, file_bytes, control_source, control["source_sha256"]
        )
        hash_paths = matches["sha256_matches"]
        content_paths = matches["exact_content_matches"]
        if present or hash_paths or content_paths:
            raise ValueError(
                f"negative-control mock content/path is present in {package_name} IPK: "
                f"suffix={present}, hash={hash_paths}, content={content_paths}"
            )
        excluded.append({
            "source_path": control["source_path"],
            "source_sha256": control["source_sha256"],
            "forbidden_member_suffix": suffix,
            "observed_members": present,
            "sha256_matches": hash_paths,
            "exact_content_matches": content_paths,
            "status": "absent",
        })

    return {
        "package": package_name,
        "ipk": {
            "path": str(ipk_path.relative_to(openwrt)),
            "sha256": sha256(ipk_data),
            "retained_path": str(retained_path.relative_to(run_root)),
            "control": fields,
        },
        "staging_root": str(stage_root.relative_to(openwrt)),
        "pkgdir_note": (
            "The pinned package-pack recipe may also invoke Package/install into "
            "PKG_BUILD_DIR/.pkgdir for root staging; this experiment compares the "
            "IPK IDIR named by the Packaged contents record."
        ),
        "packaging_log_record": packaging_lines,
        "stage_comparisons": stage_records,
        "ipk_ucode_members": member_records,
        "negative_controls": excluded,
        "data_member_count": len(entries),
        "data_member_inventory": public_inventory(entries),
    }


def write_json(path: Path, root: Path, value: dict) -> None:
    root = root.resolve(strict=True)
    parent = path.parent.resolve(strict=True)
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"receipt path is outside run root: {path}") from exc
    if path.exists() or path.is_symlink():
        raise ValueError(f"receipt path already exists: {path}")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_preflight(openwrt: Path, packages: Path, run_root: Path) -> dict:
    repo_ids = {
        "openwrt": require_repo(openwrt, "openwrt", include_untracked=False),
        "packages": require_repo(packages, "packages", include_untracked=True),
    }
    inputs = build_inputs(openwrt, packages)
    sources = source_first_oracle(packages)
    return {
        "schema": sources["schema"],
        "status": "source oracle prepared before package output inspection",
        "scope": sources["scope"],
        "repository_identities": repo_ids,
        "build_inputs": inputs,
        "oracle_sha256": sources["oracle_sha256"],
        "packages": sources["packages"],
        "limits": [
            "package source, staging, and IPK member bytes only",
            "no root filesystem or image installation is claimed",
            "no CodeQL extraction, query, runtime, or security result is claimed",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openwrt", type=Path, required=True)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--preflight", action="store_true",
                        help="write the source-first oracle before reading build outputs")
    args = parser.parse_args()
    started = time.monotonic()
    try:
        openwrt = args.openwrt.resolve(strict=True)
        packages = args.packages.resolve(strict=True)
        run_root = args.run_root.resolve(strict=True)
        inputs = run_preflight(openwrt, packages, run_root)
        if args.preflight:
            receipt_path = run_root / "output" / "source-oracle.json"
            write_json(receipt_path, run_root, inputs)
            print(f"PASS source-first oracle: {receipt_path}")
            return 0

        source_oracle_path = run_root / "output" / "source-oracle.json"
        source_oracle_bytes = read_regular_under(source_oracle_path, run_root,
                                                 "pre-build source oracle")
        source_oracle = json.loads(source_oracle_bytes)
        if source_oracle != inputs:
            raise ValueError("pre-build source oracle changed before package comparison")
        results = {}
        for package_name in ORACLE["packages"]:
            results[package_name] = compare_package(
                openwrt, packages, run_root, package_name
            )
        stage_archive = write_stage_archive(openwrt, run_root, results)
        result = {
            "schema": "packages-feed-ipk-v07-byte-comparison-v1",
            "status": "PASS",
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "base_openwrt": PINS["openwrt"],
            "packages_feed": PINS["packages"],
            "source_oracle_sha256": sha256(source_oracle_bytes),
            "oracle_sha256": sha256(ORACLE_PATH.read_bytes()),
            "scope": "seven selected source candidates' package-stage and IPK members",
            "packages": results,
            "stage_archive": stage_archive,
            "excluded": [
                "final root filesystem or image installation",
                "dependency-complete image construction",
                "CodeQL extraction, routing, queries, or SARIF",
                "runtime behavior or security coverage",
                "the remaining seven v0.7 source candidates",
                "a complete Gate 6 denominator",
            ],
        }
        receipt_path = run_root / "output" / "byte-comparison.json"
        write_json(receipt_path, run_root, result)
        print(f"PASS package-member byte comparison: {receipt_path}")
        return 0
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
