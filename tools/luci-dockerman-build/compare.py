#!/usr/bin/env python3
"""Source-first comparator for the pinned LuCI Dockerman main IPK."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "tools/luci-base-inventory"))
import archive
spec = importlib.util.spec_from_file_location("dockerman_base_compare", REPO / "tools/luci-base-inventory/compare.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

ORACLE = REPO / "tools/luci-app-metadata-probe/source-oracle.json"
ORACLE_SHA256 = "a5ab0a2b8f0099073a040b57ec4be3324a874d2f67ec3951a62a18cfa886cf4f"
LUCI_SHA = "cb87fe60e1e2e052af36a93647f2264577829e0a"
OPENWRT_SHA = "4e9642517b48bae612ff10fb72fb9199e559500e"
PACKAGES_SHA = "07e0d16305d2b5903b37ad7913e33e18795f81a4"
PACKAGE = "luci-app-dockerman"
VERSION = "26.134.50559~d5129a1"
DIRECT_DEPS = {"luci-base", "docker", "ttyd", "dockerd", "docker-compose", "ucode-mod-socket"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key: " + key)
        out[key] = value
    return out


def load_oracle(path=ORACLE):
    raw = Path(path).read_bytes()
    if digest(raw) != ORACLE_SHA256:
        raise ValueError("pinned LuCI source oracle digest differs")
    value = json.loads(raw, object_pairs_hook=unique)
    rows = [r for r in value["entries"] if r["package"] == PACKAGE and r["projected_member"]]
    if len(rows) != 22 or len({r["projected_member"] for r in rows}) != 22:
        raise ValueError("Dockerman selected projection must contain 22 unique paths")
    if sum(r["projected_member"].endswith(".uc") for r in rows) != 3:
        raise ValueError("Dockerman Ucode projection differs")
    return value


def pinned_blob(luci, row):
    path = row["source_path"]
    info = subprocess.check_output(["git", "-C", str(luci), "ls-tree", LUCI_SHA, "--", path]).decode().rstrip("\n")
    fields, sep, found_path = info.partition("\t")
    if not sep or found_path != path or fields.split() != [row["git_mode"], "blob", row["git_object"]]:
        raise ValueError("pinned Git identity differs: " + path)
    data = subprocess.check_output(["git", "-C", str(luci), "show", LUCI_SHA + ":" + path])
    if len(data) != row["bytes"] or digest(data) != row["sha256"]:
        raise ValueError("pinned source bytes differ: " + path)
    return data


def projected_version(luci):
    package_dir = Path(luci) / "applications/luci-app-dockerman"
    raw = subprocess.check_output(["git", "-C", str(package_dir), "log", "-1", "--format=%ct %h",
                                  "--abbrev=7", LUCI_SHA, "--", ".", ":(exclude)po"])
    parts = raw.decode().strip().split()
    if len(parts) != 2:
        raise ValueError("LuCI package findrev input is unavailable")
    stamp, short = int(parts[0]), parts[1]
    instant = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc)
    return f"{instant:%y.%j}.{stamp % 86400:05d}~{short}"


def declared_dependencies(recipe):
    import re
    text = recipe.decode()
    rows = text.splitlines()
    for index, row in enumerate(rows):
        if row.startswith("LUCI_DEPENDS:="):
            selected = [row.split(":=", 1)[1]]
            while selected[-1].rstrip().endswith("\\"):
                index += 1
                if index >= len(rows) or not rows[index].startswith(("\t", " ")):
                    raise ValueError("malformed LUCI_DEPENDS continuation")
                selected.append(rows[index])
            return set(re.findall(r"\+([A-Za-z0-9][A-Za-z0-9-]*)", "\n".join(selected)))
    raise ValueError("Dockerman recipe omits LUCI_DEPENDS")


def physical_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("expected a physical regular file: " + str(path))
    info = path.stat()
    if info.st_nlink != 1:
        raise ValueError("hard-linked package file: " + str(path))
    return path.read_bytes(), info.st_mode & 0o7777


def tree_files(root):
    found = set()
    for path in Path(root).rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in package tree: " + str(path))
        if path.is_file():
            found.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError("special object in package tree: " + str(path))
    return found


def tree_directories(root):
    found = set()
    for path in Path(root).rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in package tree: " + str(path))
        if path.is_dir():
            found.add(path.relative_to(root).as_posix())
    return found


def ancestors(paths):
    found = set()
    for path in paths:
        parts = path.split("/")
        found.update("/".join(parts[:i]) for i in range(1, len(parts)))
    return found


def expected_prepared(row):
    prefix = "applications/luci-app-dockerman/"
    source = row["source_path"]
    if not source.startswith(prefix):
        raise ValueError("source path outside selected package: " + source)
    return source[len(prefix):]


def compare(luci, prepared, stage, ipk, config):
    luci, prepared, stage = map(Path, (luci, prepared, stage))
    for path in (luci, prepared, stage):
        if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
            raise ValueError("source/prepared/stage directory must be physical: " + str(path))
    if subprocess.check_output(["git", "-C", str(luci), "rev-parse", "HEAD"]).decode().strip() != LUCI_SHA:
        raise ValueError("LuCI source revision differs")
    oracle = load_oracle()
    recipe = next(r for r in oracle["entries"] if r["source_path"] == "applications/luci-app-dockerman/Makefile")
    recipe_bytes = pinned_blob(luci, recipe)
    dependencies = declared_dependencies(recipe_bytes)
    if dependencies != DIRECT_DEPS:
        raise ValueError("Dockerman declared runtime dependency set differs")
    luci_mk = subprocess.check_output(["git", "-C", str(luci), "show", LUCI_SHA + ":luci.mk"])
    if digest(luci_mk) != oracle["luci_mk_sha256"]:
        raise ValueError("pinned luci.mk differs")
    if projected_version(luci) != VERSION:
        raise ValueError("source-derived Dockerman version differs")
    rows = [r for r in oracle["entries"] if r["package"] == PACKAGE and r["projected_member"]]
    expected = {r["projected_member"]: r for r in rows}
    config_lines = bytes(config).decode().splitlines()
    for symbol in ("CONFIG_LUCI_JSMIN", "CONFIG_LUCI_CSSTIDY"):
        forms = [x for x in config_lines if x.startswith(symbol + "=") or x == "# " + symbol + " is not set"]
        if forms not in ([symbol + "=n"], ["# " + symbol + " is not set"]):
            raise ValueError("source-equality requires disabled transform: " + symbol)
    control, members, outer = archive.read_ipk(bytes(ipk))
    fields = base.control_from_rows(control)
    if fields != {"Package": PACKAGE, "Version": VERSION, "Architecture": "all"}:
        raise ValueError("Dockerman IPK control identity differs")
    if any(path == "CONTROL" or path.startswith("CONTROL/") for path in members):
        raise ValueError("data archive aliases reserved CONTROL namespace")
    actual = {p for p, row in members.items() if row["type"] == "file"}
    if actual != set(expected):
        raise ValueError("Dockerman IPK member set differs: missing=%r extra=%r" %
                         (sorted(set(expected) - actual), sorted(actual - set(expected))))
    control_files = {p for p, row in control.items() if row["type"] == "file"}
    allowed_dirs = ancestors(actual | {"CONTROL/" + p for p in control_files}) | {"CONTROL"}
    archive_dirs = {p for p, row in members.items() if row["type"] == "directory" and p}
    if archive_dirs - allowed_dirs:
        raise ValueError("IPK contains unrelated directory entries: " + repr(sorted(archive_dirs - allowed_dirs)))
    if tree_files(stage) != actual | {"CONTROL/" + p for p in control_files}:
        raise ValueError("stage and IPK file sets differ")
    if tree_directories(stage) - allowed_dirs:
        raise ValueError("stage contains unrelated directories: " + repr(sorted(tree_directories(stage) - allowed_dirs)))
    for path in control_files:
        staged, mode = physical_file(stage / "CONTROL" / path)
        if staged != control[path]["bytes"] or mode != control[path]["mode"]:
            raise ValueError("staged control file differs: " + path)
    result_rows = []
    for member, row in sorted(expected.items()):
        source = pinned_blob(luci, row)
        prepared_bytes, prepared_mode = physical_file(prepared / expected_prepared(row))
        staged, stage_mode = physical_file(stage / member)
        archive_row = members[member]
        source_mode = int(row["git_mode"], 8) & 0o7777
        output_mode = int(row["source_mode_projected"], 8)
        if prepared_bytes != source or prepared_mode != source_mode:
            raise ValueError("prepared copy differs from source: " + member)
        if (stage_mode != output_mode or archive_row["mode"] != output_mode or
                staged != source or archive_row["bytes"] != source):
            raise ValueError("source, stage and IPK bytes/modes differ: " + member)
        result_rows.append({"member": member, "source_path": row["source_path"],
                            "git_blob": row["git_object"], "source_sha256": digest(source),
                            "source_mode": row["git_mode"], "prepared_sha256": digest(prepared_bytes),
                            "prepared_mode": format(prepared_mode, "04o"), "stage_sha256": digest(staged),
                            "stage_mode": format(stage_mode, "04o"), "ipk_sha256": digest(archive_row["bytes"]),
                            "ipk_mode": format(archive_row["mode"], "04o")})
    return {"package": fields, "source_oracle_sha256": ORACLE_SHA256, "source_revision": LUCI_SHA,
            "declared_runtime_dependencies": sorted(dependencies),
            "minifiers_disabled": True, "member_count": len(result_rows), "members": result_rows,
            "ipk_sha256": digest(bytes(ipk)), "outer_members": outer,
            "data_archive_members": archive.receipts(members),
            "control_archive_members": archive.receipts(control)}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--luci", type=Path, required=True)
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--ipk", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    oracle = load_oracle()
    if args.preflight:
        if args.luci.resolve(strict=True) == args.luci and subprocess.check_output(
                ["git", "-C", str(args.luci), "rev-parse", "HEAD"]).decode().strip() == LUCI_SHA:
            recipe = next(r for r in oracle["entries"] if r["source_path"] == "applications/luci-app-dockerman/Makefile")
            recipe_bytes = pinned_blob(args.luci, recipe)
            if declared_dependencies(recipe_bytes) != DIRECT_DEPS:
                raise ValueError("Dockerman declared runtime dependency set differs")
            luci_mk = subprocess.check_output(["git", "-C", str(args.luci), "show", LUCI_SHA + ":luci.mk"])
            if digest(luci_mk) != oracle["luci_mk_sha256"] or projected_version(args.luci) != VERSION:
                raise ValueError("pinned LuCI build recipe/version projection differs")
            for row in oracle["entries"]:
                if row["package"] == PACKAGE and row["projected_member"]:
                    pinned_blob(args.luci, row)
        else:
            raise ValueError("LuCI checkout path or pin differs")
        print(json.dumps({"source_oracle_sha256": ORACLE_SHA256, "selected_members": 22}, sort_keys=True))
        return
    if not all((args.prepared, args.stage, args.ipk, args.config, args.receipt)):
        raise ValueError("package comparison inputs are incomplete")
    receipt = compare(args.luci, args.prepared, args.stage, args.ipk.read_bytes(), args.config.read_bytes())
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
