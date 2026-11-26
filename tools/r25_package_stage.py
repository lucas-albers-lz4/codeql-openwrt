#!/usr/bin/env python3
"""Validate and stage exact regular members from the pinned R2.5 IPKs."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "docs/r25-package-lock.json"
MAX_IPK_BYTES = 4 * 1024 * 1024
MAX_DATA_TAR_BYTES = 4 * 1024 * 1024
MAX_CONTROL_TAR_BYTES = 1024 * 1024
MAX_CONTROL_BYTES = 64 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_REGULAR_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_member_name(raw: str) -> str:
    """Normalize only the conventional ./ prefix and reject aliases/traversal."""
    need(isinstance(raw, str), "IPK member path is not text")
    if raw in (".", "./"):
        return ""
    name = raw[2:] if raw.startswith("./") else raw
    path = PurePosixPath(name)
    need(bool(name) and not path.is_absolute() and "\\" not in name and
         "\x00" not in name and all(part not in ("", ".", "..") for part in name.split("/")) and
         path.as_posix() == name,
         f"unsafe or noncanonical IPK member path: {raw!r}")
    return name


def validate_oracle(data: bytes, expected_sha256: str, profile: dict) -> tuple[dict, dict[str, dict]]:
    need(HEX64.fullmatch(expected_sha256 or "") is not None, "invalid oracle digest pin")
    need(digest(data) == expected_sha256, "source-first package oracle digest mismatch")
    oracle = json.loads(data)
    need(isinstance(oracle, dict) and set(oracle) == {"schema", "files"} and
         oracle.get("schema") == "ucode-installed-stage-v1", "unsupported package oracle")
    entries = oracle.get("files")
    need(isinstance(entries, list) and len(entries) == profile["oracle"]["regular_member_count"],
         "oracle regular-member count differs from package lock")
    expected: dict[str, dict] = {}
    routes = {"plain": 0, "markup": 0, "excluded": 0}
    for entry in entries:
        need(isinstance(entry, dict) and set(entry) == {"expect_success", "path", "route", "sha256"},
             "invalid package oracle entry")
        name = safe_member_name(entry.get("path", ""))
        need(name not in expected, f"duplicate oracle path: {name}")
        need(HEX64.fullmatch(entry.get("sha256", "")) is not None, f"invalid oracle hash: {name}")
        need(type(entry.get("expect_success")) is bool, f"invalid success expectation: {name}")
        route = entry.get("route")
        need(isinstance(route, dict) and set(route) == {
            "classification", "inconclusive_reason", "reason", "status"
        }, f"invalid route expectation: {name}")
        classification = route.get("classification")
        need(classification in routes, f"unsupported route classification: {name}")
        routes[classification] += 1
        need(entry["expect_success"] is (classification != "excluded"),
             f"success expectation conflicts with route: {name}")
        need(isinstance(route.get("reason"), str) and bool(route["reason"]),
             f"missing route reason: {name}")
        if classification == "plain":
            need(route["status"] == "plain_route_selected" and
                 route["inconclusive_reason"] is None, f"invalid plain route: {name}")
        elif classification == "markup":
            need(route["status"] == "inconclusive" and
                 route["inconclusive_reason"] == "markup_not_modeled",
                 f"invalid markup route: {name}")
        else:
            need(route["status"] == "excluded" and
                 route["inconclusive_reason"] is None, f"invalid excluded route: {name}")
        expected[name] = entry
    need(routes == profile["oracle"]["route_counts"],
         f"oracle route counts differ from package lock: {routes}")
    return oracle, expected


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo,
                 limit: int, label: str) -> bytes:
    need(member.isfile(), f"{label} is not a regular archive member")
    need(0 <= member.size <= limit, f"{label} exceeds byte budget")
    stream = archive.extractfile(member)
    need(stream is not None, f"cannot read {label}")
    data = stream.read(limit + 1)
    need(len(data) <= limit and len(data) == member.size,
         f"{label} size differs from its archive header or byte budget")
    return data


def _outer_parts(raw: bytes) -> dict[str, bytes]:
    need(raw.startswith(b"\x1f\x8b"), "IPK outer archive is not gzip-compressed")
    parts: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        count = 0
        for member in archive:
            count += 1
            need(count <= 16, "IPK outer archive exceeds member budget")
            name = safe_member_name(member.name)
            if not name:
                need(member.isdir(), "IPK outer root entry is not a directory")
                continue
            need(name not in parts, f"duplicate IPK outer member: {name}")
            limit = {"debian-binary": 16, "data.tar.gz": MAX_DATA_TAR_BYTES,
                     "control.tar.gz": MAX_CONTROL_TAR_BYTES}.get(name)
            need(limit is not None, f"unexpected IPK outer member: {name}")
            parts[name] = _read_member(archive, member, limit, f"IPK outer member {name}")
    need(set(parts) == {"debian-binary", "data.tar.gz", "control.tar.gz"},
         f"IPK outer member inventory mismatch: {sorted(parts)}")
    need(parts["debian-binary"] == b"2.0\n", "unsupported IPK format marker")
    return parts


def _control_fields(control_tar: bytes) -> dict[str, str]:
    raw_control = None
    with tarfile.open(fileobj=io.BytesIO(control_tar), mode="r:gz") as archive:
        count = 0
        for member in archive:
            count += 1
            need(count <= 128, "IPK control archive exceeds member budget")
            name = safe_member_name(member.name)
            if not name:
                need(member.isdir(), "IPK control root entry is not a directory")
                continue
            if not member.isdir() and not member.isfile():
                raise ValueError(f"nonregular IPK control member is unsupported: {name}")
            if name != "control":
                continue
            need(raw_control is None, "duplicate IPK control file")
            raw_control = _read_member(archive, member, MAX_CONTROL_BYTES, "IPK control file")
    need(raw_control is not None, "IPK control file missing")
    fields: dict[str, str] = {}
    for line in raw_control.decode("utf-8", "strict").splitlines():
        if line.startswith((" ", "\t")):
            continue
        need(":" in line, "malformed IPK control field")
        key, value = line.split(":", 1)
        need(key not in fields, f"duplicate IPK control field: {key}")
        fields[key] = value.strip()
    need(all(fields.get(key) for key in ("Package", "Version", "Architecture")),
         "IPK control package identity is incomplete")
    return {key: fields[key] for key in ("Package", "Version", "Architecture")}


def _regular_members(data_tar: bytes, expected: dict[str, dict]) -> tuple[dict[str, bytes], int]:
    members: dict[str, bytes] = {}
    seen: set[str] = set()
    directories = 0
    total_regular = 0
    member_count = 0
    with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:gz") as archive:
        for member in archive:
            member_count += 1
            need(member_count <= MAX_ARCHIVE_MEMBERS,
                 "IPK data archive exceeds member budget")
            name = safe_member_name(member.name)
            if not name:
                need(member.isdir(), "IPK data root entry is not a directory")
                continue
            need(name not in seen, f"duplicate IPK data member: {name}")
            seen.add(name)
            if member.isdir():
                need(name not in expected, f"expected regular IPK member is a directory: {name}")
                directories += 1
                continue
            if not member.isfile():
                raise ValueError(f"nonregular IPK data member is unsupported: {name}")
            need(name in expected, f"unexpected regular IPK member: {name}")
            need(0 <= member.size <= MAX_MEMBER_BYTES, f"IPK member exceeds byte budget: {name}")
            total_regular += member.size
            need(total_regular <= MAX_TOTAL_REGULAR_BYTES,
                 "IPK regular members exceed total byte budget")
            members[name] = _read_member(archive, member, MAX_MEMBER_BYTES, name)
    need(set(members) == set(expected),
         f"regular-member inventory mismatch: missing={sorted(set(expected)-set(members))} "
         f"extra={sorted(set(members)-set(expected))}")
    return members, directories


def _check_workspace_path(path: Path, workspace: Path, *, must_exist: bool) -> Path:
    workspace = Path(os.path.abspath(workspace))
    need(workspace.exists() and not workspace.is_symlink() and workspace.is_dir(),
         "package workspace must be a real directory")
    need(workspace.resolve(strict=True) == workspace,
         "package workspace path must not traverse an alias")
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(workspace)
    except ValueError as error:
        raise ValueError(f"package path must be inside the run-owned workspace: {path}") from error
    need(relative.parts, "package path cannot be the workspace root")
    current = workspace
    for index, part in enumerate(relative.parts):
        current = current / part
        final = index == len(relative.parts) - 1
        if not current.exists() and not current.is_symlink():
            if final:
                need(not must_exist, f"package input is missing: {current}")
                break
            raise ValueError(f"package path parent is missing: {current}")
        mode = current.lstat().st_mode
        need(not stat.S_ISLNK(mode), f"symlink in package path: {current}")
        if final:
            if must_exist:
                need(stat.S_ISREG(mode), f"package input is not a regular file: {current}")
                need(current.stat().st_nlink == 1, "package input has multiple hard links")
            else:
                need(False, f"package output already exists: {current}")
        else:
            need(stat.S_ISDIR(mode), f"package path parent is not a directory: {current}")
    return absolute


def _read_owned_ipk(path: Path, workspace: Path) -> bytes:
    checked = _check_workspace_path(path, workspace, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(checked, flags)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
             "package input changed type or acquired an alias before open")
        need(0 <= info.st_size <= MAX_IPK_BYTES, "IPK exceeds byte budget")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_IPK_BYTES + 1)
        need(len(data) <= MAX_IPK_BYTES and len(data) == info.st_size,
             "IPK size differs from file metadata or byte budget")
        return data
    finally:
        os.close(fd)


def _write_new_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
    finally:
        os.close(fd)


def _write_stage(workspace: Path, stage_root: Path,
                 members: dict[str, bytes]) -> None:
    stage_root = _check_workspace_path(stage_root, workspace, must_exist=False)
    stage_root.mkdir(mode=0o700)
    for name, data in sorted(members.items()):
        target = stage_root.joinpath(*PurePosixPath(name).parts)
        parent = stage_root
        for component in PurePosixPath(name).parts[:-1]:
            parent = parent / component
            if not parent.exists():
                parent.mkdir(mode=0o700)
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                 f"unsafe stage parent: {parent}")
        need(not target.exists() and not target.is_symlink(), f"duplicate stage target: {target}")
        _write_new_file(target, data)


def _write_receipt(workspace: Path, receipt_path: Path, data: bytes) -> None:
    receipt_path = _check_workspace_path(receipt_path, workspace, must_exist=False)
    _write_new_file(receipt_path, data)


def _load_lock(path: Path, *, profile_set: str = "historical") -> tuple[dict, bytes]:
    raw = path.read_bytes()
    lock = json.loads(raw)
    expected_schema = ("openwrt-r25-package-lock-v1" if profile_set == "historical" else
                       "openwrt-r25-current-luci-package-lock-v1" if profile_set == "current-luci" else None)
    need(expected_schema is not None and isinstance(lock, dict) and lock.get("schema") == expected_schema,
         "unsupported R2.5 package lock/profile set")
    need(lock.get("artifact_repository") == "lucas-albers-lz4/codeql-openwrt",
         "package artifact repository is not the reviewed consumer")
    producer = lock.get("producer")
    need(isinstance(producer, dict) and
         HEX64.fullmatch(producer.get("stage_helper", {}).get("sha256", "")) and
         HEX64.fullmatch(producer.get("runner", {}).get("sha256", "")),
         "producer interface source pins are incomplete")
    packages = lock.get("packages")
    allowed = ({"luci-base", "wifi-scripts-ucode-y"} if profile_set == "historical" else
               {"luci-base-cb87", "luci-app-adblock-fast", "luci-mod-status"})
    need(isinstance(packages, dict) and set(packages) == allowed,
         "package lock profile set changed")
    for package_id, profile in packages.items():
        need(isinstance(profile, dict) and isinstance(profile.get("ipk"), dict),
             f"package identity pin is missing: {package_id}")
        artifact = profile["ipk"]
        need(isinstance(artifact.get("sha256"), str) and
             HEX64.fullmatch(artifact["sha256"]) is not None and
             isinstance(artifact.get("archive_sha256"), str) and
             HEX64.fullmatch(artifact["archive_sha256"]) is not None and
             isinstance(artifact.get("filename"), str) and
             artifact["filename"] not in ("", ".", "..") and
             PurePosixPath(artifact["filename"]).name == artifact["filename"] and
             "/" not in artifact["filename"] and "\\" not in artifact["filename"] and
             type(artifact.get("run_id")) is int and artifact["run_id"] > 0 and
             type(artifact.get("artifact_id")) is int and artifact["artifact_id"] > 0 and
             isinstance(artifact.get("artifact_name"), str) and artifact["artifact_name"],
             f"package IPK/artifact pins are incomplete: {package_id}")
    return lock, raw


def stage_package_bytes(package_id: str, raw_ipk: bytes, profile: dict,
                        oracle_raw: bytes, workspace: Path,
                        stage_root: Path, receipt_path: Path,
                        *, package_lock_raw: bytes = b"",
                        provenance: dict | None = None) -> dict:
    oracle_info = profile.get("oracle", {})
    need(len(oracle_raw) <= MAX_DATA_TAR_BYTES,
         "source-first package oracle exceeds byte budget")
    oracle, expected = validate_oracle(oracle_raw, oracle_info.get("sha256", ""), profile)
    need(len(raw_ipk) <= MAX_IPK_BYTES, "IPK exceeds byte budget")
    expected_ipk_sha = profile.get("ipk", {}).get("sha256", "")
    need(digest(raw_ipk) == expected_ipk_sha, "IPK digest differs from independent package pin")
    outer = _outer_parts(raw_ipk)
    actual_control = _control_fields(outer["control.tar.gz"])
    expected_control = {"Package": profile.get("package", {}).get("name"),
                        "Version": profile.get("package", {}).get("version"),
                        "Architecture": profile.get("package", {}).get("architecture")}
    need(actual_control == expected_control,
         f"IPK control identity mismatch: {actual_control}")
    regular, directory_count = _regular_members(outer["data.tar.gz"], expected)
    for name, data in regular.items():
        need(digest(data) == expected[name]["sha256"], f"IPK member hash mismatch: {name}")

    stage_lexical = Path(os.path.abspath(stage_root))
    receipt_lexical = Path(os.path.abspath(receipt_path))
    need(receipt_lexical.suffix == ".json", "package-stage receipt must use a .json path")
    need(not receipt_lexical.is_relative_to(stage_lexical) and
         not stage_lexical.is_relative_to(receipt_lexical),
         "package-stage receipt and stage directory must be disjoint")
    _check_workspace_path(stage_lexical, workspace, must_exist=False)
    receipt_abs = _check_workspace_path(receipt_lexical, workspace, must_exist=False)
    _write_stage(workspace, stage_root, regular)
    route_counts = dict(profile["oracle"]["route_counts"])
    receipt = {
        "schema": "openwrt-r25-package-stage-receipt-v1",
        "package_id": package_id,
        "package": actual_control,
        "build_condition": profile.get("build_condition"),
        **(provenance or {}),
        "artifact": profile["ipk"],
        "ipk_sha256": digest(raw_ipk),
        "oracle_sha256": digest(oracle_raw),
        "package_lock_sha256": digest(package_lock_raw) if package_lock_raw else None,
        "regular_member_count": len(regular),
        "directory_entry_count": directory_count,
        "route_counts": route_counts,
        "selected_paths": sorted(name for name, entry in expected.items()
                                  if entry["route"]["classification"] != "excluded"),
        "markup_inconclusive_paths": sorted(name for name, entry in expected.items()
                                             if entry["route"]["classification"] == "markup"),
        "excluded_paths": sorted(name for name, entry in expected.items()
                                  if entry["route"]["classification"] == "excluded"),
        "files": [{"path": name, "sha256": digest(data)}
                  for name, data in sorted(regular.items())]
    }
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    _write_receipt(workspace, receipt_abs, receipt_bytes)
    return receipt


def stage_locked_package(package_id: str, ipk_path: Path, workspace: Path,
                         stage_root: Path, receipt_path: Path,
                         *, lock_path: Path = LOCK_PATH,
                         profile_set: str = "historical") -> dict:
    lock, lock_raw = _load_lock(lock_path, profile_set=profile_set)
    profile = lock["packages"].get(package_id)
    need(isinstance(profile, dict), f"unknown package profile: {package_id}")
    oracle_info = profile.get("oracle", {})
    oracle_path = ROOT / oracle_info.get("path", "")
    need(oracle_path.is_file() and not oracle_path.is_symlink(),
         "checked-in source-first package oracle is not a regular file")
    oracle_raw = oracle_path.read_bytes()
    # Parse and pin the source-first expectation before opening artifact bytes.
    validate_oracle(oracle_raw, oracle_info.get("sha256", ""), profile)
    raw_ipk = _read_owned_ipk(ipk_path, workspace)
    source_revisions = (profile.get("source_revisions") if profile_set == "current-luci"
                        else lock["producer"]["source_revisions"])
    provenance = {
        "source_revisions": source_revisions,
        "producer_fixture_commit": lock["producer"]["r25_fixture_commit"],
        "producer_stage_helper_sha256": lock["producer"]["stage_helper"]["sha256"],
        "producer_runner_sha256": lock["producer"]["runner"]["sha256"],
    }
    return stage_package_bytes(package_id, raw_ipk, profile, oracle_raw, workspace,
                               stage_root, receipt_path, package_lock_raw=lock_raw,
                               provenance=provenance)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, choices=("luci-base", "wifi-scripts-ucode-y"))
    parser.add_argument("--ipk", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path,
                        help="existing run-owned root containing downloaded IPKs and outputs")
    parser.add_argument("--stage", required=True, type=Path, help="new stage directory under workspace")
    parser.add_argument("--receipt", required=True, type=Path, help="new receipt path under workspace")
    parser.add_argument("--lock", type=Path, default=LOCK_PATH)
    args = parser.parse_args()
    try:
        receipt = stage_locked_package(args.package, args.ipk, args.workspace,
                                      args.stage, args.receipt, lock_path=args.lock)
    except Exception as error:
        parser.exit(1, f"package staging failed: {error}\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
