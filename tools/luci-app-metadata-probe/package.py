#!/usr/bin/env python3
"""Create a portable archive only from a fully inventoried safe probe output."""

import argparse
import io
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check

MAX_TOTAL = 128 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024


def collect(root):
    root = Path(root)
    check.need(
        root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(),
        "output root must be physical",
    )
    manifest_path = root / "manifest.json"
    check.need(
        not manifest_path.is_symlink()
        and manifest_path.is_file()
        and manifest_path.stat().st_nlink == 1
        and 0 < manifest_path.stat().st_size <= MAX_MANIFEST,
        "unsafe or oversized output manifest",
    )
    manifest = check.physical_file(manifest_path, root, True)
    value = check.json_object(manifest)
    check.need(value.get("process_group_quiescent") is True, "output process group not quiescent")
    check.need(not value.get("output_capture_errors"), "unsafe output inventory")
    expected = value.get("output_sha256")
    check.need(isinstance(expected, dict), "output manifest missing")
    paths = {}
    total = 0
    for path in sorted(root.rglob("*")):
        check.need(not path.is_symlink(), "symlink in output")
        if path.is_dir():
            continue
        check.need(path.is_file() and path.stat().st_nlink == 1, "unsafe file in output")
        name = path.relative_to(root).as_posix()
        pure = PurePosixPath(name)
        check.need(
            str(pure) == name and not pure.is_absolute() and ".." not in pure.parts,
            "unsafe output name",
        )
        total += path.stat().st_size
        check.need(total <= MAX_TOTAL, "output size limit exceeded")
        paths[name] = path
    check.need(set(paths) == set(expected) | {"manifest.json"}, "output inventory differs")
    check.need(paths["manifest.json"].stat().st_size == len(manifest), "manifest size changed")
    files = {"manifest.json": manifest}
    for name, path in paths.items():
        if name == "manifest.json":
            continue
        data = check.physical_file(path, root)
        check.need(expected.get(name) == check.digest(data), "output digest differs: " + name)
        files[name] = data
    return files


def create(root, destination):
    destination = Path(destination)
    check.need(
        destination.is_absolute()
        and destination.parent.resolve(strict=True) == destination.parent
        and not destination.exists()
        and not destination.is_symlink(),
        "archive path not fresh",
    )
    files = collect(root)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo("metadata/" + name)
            item.mode = 0o644
            item.size = len(data)
            item.mtime = 0
            item.uid = item.gid = 0
            archive.addfile(item, io.BytesIO(data))
    with destination.open("xb") as output:
        output.write(buffer.getvalue())
    return check.digest(buffer.getvalue())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps({"archive_sha256": create(args.output_root, args.archive)}, sort_keys=True))


if __name__ == "__main__":
    main()
