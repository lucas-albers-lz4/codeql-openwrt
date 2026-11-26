#!/usr/bin/env python3
"""Read pinned LuCI Git blobs and one retained raw IPK. Prepared/stage stay out of scope."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from time import perf_counter_ns

PIN = "cb87fe60e1e2e052af36a93647f2264577829e0a"
TREE = "1d7bf89bc8708fca69d005b0690ca823c9071692"
ORACLE_SHA = "a5ab0a2b8f0099073a040b57ec4be3324a874d2f67ec3951a62a18cfa886cf4f"
PROFILE = {
    "luci-app-dockerman": ("26.134.50559~d5129a1", 22),
    "luci-app-statistics": ("26.205.85817~58d43e5", 126),
}

def need(condition, message):
    if not condition:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def checked(path, expected):
    p = Path(path)
    need(p.is_absolute() and p.resolve(strict=True) == p and p.is_file() and p.stat().st_nlink == 1,
         "input must be a physical regular file " + str(path))
    data = p.read_bytes()
    need(sha(data) == expected, "input SHA differs " + str(path))
    return data

def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate key " + key)
        result[key] = value
    return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", choices=PROFILE, required=True)
    ap.add_argument("--parser", type=Path, required=True)
    ap.add_argument("--parser-sha", required=True)
    ap.add_argument("--oracle", type=Path, required=True)
    ap.add_argument("--ipk", type=Path, required=True)
    ap.add_argument("--ipk-sha", required=True)
    ap.add_argument("--luci", type=Path, required=True)
    ap.add_argument("--git", type=Path, required=True)
    args = ap.parse_args()
    package = args.package
    version, count = PROFILE[package]
    p = args.luci
    need(p.is_absolute() and p.resolve(strict=True) == p and p.is_dir(), "nonphysical LuCI Git root")
    def git(*values):
        return subprocess.check_output([str(args.git), "-C", str(p), *values])

    start = perf_counter_ns()
    parser_bytes = checked(args.parser, args.parser_sha)
    archive = importlib.util.module_from_spec(importlib.util.spec_from_loader("reviewed_archive", loader=None))
    exec(compile(parser_bytes, str(args.parser), "exec"), archive.__dict__)
    oracle = json.loads(checked(args.oracle, ORACLE_SHA), object_pairs_hook=unique)
    raw = checked(args.ipk, args.ipk_sha)
    need(git("rev-parse", PIN, PIN + "^{tree}").decode().splitlines() == [PIN, TREE], "LuCI revision/tree differs")
    tree = {}
    for line in git("ls-tree","-rz",PIN,"--","applications/"+package).split(b"\0"):
        if not line:
            continue
        meta, path = line.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        need(kind == "blob", "non-blob entry")
        path = path.decode()
        need(path not in tree, "duplicate Git source path")
        tree[path] = (mode, blob)
    entries = [row for row in oracle["entries"] if row["package"] == package]
    need(set(tree) == {row["source_path"] for row in entries} and len(tree) == len(entries),
         "oracle source path inventory differs")
    selected = {row["projected_member"]:row for row in entries if row["projected_member"]}
    need(len(selected) == count, "oracle member count differs")
    controls, members, outer = archive.read_ipk(raw)
    fields = unique(re.findall(r"^([A-Za-z][A-Za-z-]+): (.*)$", controls["control"]["bytes"].decode(), re.M))
    need((fields["Package"], fields["Version"], fields["Architecture"]) == (package,version,"all"),
         "retained IPK control differs")
    regular = {name for name, member in members.items() if member["type"] == "file"}
    need(regular == set(selected), "retained IPK regular member set differs")
    need(not any(name == "CONTROL" or name.startswith("CONTROL/") for name in members), "reserved data namespace")
    for name, row in sorted(selected.items()):
        path = row["source_path"]
        mode, blob = tree[path]
        data = git("cat-file", "blob", blob)
        need(row["git_mode"] == mode and row["git_object"] == blob and row["bytes"] == len(data) and
             row["sha256"] == sha(data), "source identity differs " + name)
        need(members[name]["bytes"] == data and members[name]["mode"] == int(row["source_mode_projected"],8),
             "retained IPK bytes or mode differs " + name)
    elapsed = perf_counter_ns() - start
    print(json.dumps({
        "package": package, "version": version, "architecture": "all",
        "ipk_sha256": sha(raw), "oracle_source_rows": len(entries), "compared_member_count": count,
        "data_archive_rows": len(members), "control_archive_rows": len(controls),
        "luci_commit": PIN, "luci_tree": TREE, "oracle_sha256": ORACLE_SHA,
        "parser_sha256": args.parser_sha, "elapsed_perf_counter_ns": elapsed,
        "scope": "offline pinned Git selected-blob and retained IPK compare only; hosted build and original prepared/stage timings are outside this measurement",
    }, sort_keys=True))

if __name__ == "__main__":
    main()
