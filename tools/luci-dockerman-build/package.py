#!/usr/bin/env python3
"""Safely package a completed or partial Dockerman run output."""
import argparse
import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path
from pathlib import PurePosixPath

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
import sys
sys.path.insert(0, str(REPO / "tools/luci-app-metadata-probe"))
import check
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024


def inventory(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError("output root must be a physical directory")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_nlink != 1:
        raise ValueError("run output manifest is missing or unsafe")
    manifest_size = manifest_path.stat().st_size
    if not 0 < manifest_size <= MAX_MANIFEST:
        raise ValueError("run output manifest exceeds size limit")
    manifest = check.physical_file(manifest_path, root, True)
    value = check.json_object(manifest)
    check.need(value.get("process_group_quiescent") is True, "run output process group is not quiescent")
    check.need(not value.get("output_capture_errors"), "run output inventory contains capture errors")
    expected = value.get("output_sha256")
    check.need(isinstance(expected, dict), "manifest omits output SHA map")
    rows = {}
    total = 0
    for path in sorted(root.rglob("*")):
        check.need(not path.is_symlink(), "symlink in run output")
        if path.is_dir():
            continue
        check.need(path.is_file() and path.stat().st_nlink == 1, "nonregular or hardlinked run output")
        name = path.relative_to(root).as_posix()
        pure = PurePosixPath(name)
        check.need(str(pure) == name and not pure.is_absolute() and ".." not in pure.parts,
                   "unsafe run output path")
        total += path.stat().st_size
        check.need(total <= MAX_TOTAL, "run output exceeds 2 GiB archive cap")
        rows[name] = path
    check.need(set(rows) == set(expected) | {"manifest.json"}, "run output differs from frozen manifest")
    for name, path in rows.items():
        if name == "manifest.json":
            continue
        h = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        check.need(expected.get(name) == h.hexdigest(), "run output digest changed: " + name)
    return manifest, value, rows, total


def create(root, destination):
    destination = Path(destination)
    if (not destination.is_absolute() or destination.parent.resolve(strict=True) != destination.parent or
            destination.exists() or destination.is_symlink()):
        raise ValueError("archive destination must be fresh and physical")
    manifest_bytes, manifest, rows, total = inventory(root)
    archive_hash = hashlib.sha256()
    with destination.open("xb") as raw:
        class HashingWriter:
            def write(self, data):
                archive_hash.update(data)
                return raw.write(data)
            def tell(self):
                return raw.tell()
            def flush(self):
                return raw.flush()
        writer = HashingWriter()
        with tarfile.open(fileobj=writer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            names = [("manifest.json", None)] + [(name, path) for name, path in sorted(rows.items()) if name != "manifest.json"]
            for name, path in names:
                source = Path(root) / name
                info = source.stat() if name != "manifest.json" else None
                item = tarfile.TarInfo("dockerman/" + name)
                item.mode = stat.S_IMODE(info.st_mode) if info else 0o644
                item.size = info.st_size if info else len(manifest_bytes)
                item.mtime = 0
                item.uid = item.gid = 0
                item.uname = item.gname = ""
                if name == "manifest.json":
                    import io
                    tar.addfile(item, io.BytesIO(manifest_bytes))
                else:
                    expected = manifest["output_sha256"].get(name)
                    check.need(isinstance(expected, str), "streamed output is absent from original manifest")
                    class HashReader:
                        def __init__(self, stream):
                            self.stream, self.digest = stream, hashlib.sha256()
                        def read(self, size=-1):
                            data = self.stream.read(size)
                            self.digest.update(data)
                            return data
                    with source.open("rb") as stream:
                        reader = HashReader(stream)
                        tar.addfile(item, reader)
                    check.need(reader.digest.hexdigest() == expected, "output changed while creating evidence archive: " + name)
        raw.flush()
        os.fsync(raw.fileno())
    check.need((Path(root) / "manifest.json").read_bytes() == manifest_bytes, "output manifest changed while creating evidence archive")
    return {"archive_sha256": archive_hash.hexdigest(), "archive_bytes": destination.stat().st_size,
            "output_bytes": total, "size_cap_bytes": MAX_TOTAL}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    result = create(args.output_root, args.archive)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
