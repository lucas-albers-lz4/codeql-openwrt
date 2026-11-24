"""Validate database-local UCI candidates without conflating entity identity and span."""
from collections import Counter
from pathlib import Path, PurePosixPath

def source_paths(source, manifest):
    root = Path(source)
    if not root.is_absolute() or not root.is_dir() or root.resolve() != root:
        raise ValueError("source root must be a physical absolute directory")
    if not isinstance(manifest, list):
        raise ValueError("invalid manifest")
    paths = {}
    for entry in manifest:
        if not isinstance(entry, dict) or not isinstance(entry.get("source"), str):
            raise ValueError("invalid manifest entry")
        name = entry["source"]
        part = PurePosixPath(name)
        if not name or part.is_absolute() or "\\" in name or any(p in (".", "..") for p in name.split("/")) or str(part) != name:
            raise ValueError("invalid manifest path")
        path = root.joinpath(*part.parts)
        if not path.is_file() or path.resolve() != path or name in paths:
            raise ValueError("foreign or duplicate manifest path")
        paths[name] = path
    return paths


def normalize(rows, source, manifest):
    """Rows: id, absolute path, four coordinates, receiver, kind, known, property, assessment.

    Input must already be decoded to strings. Return a public tuple multiset; IDs
    are database-local evidence, not source-oracle identity.
    """
    by_path = {str(path): name for name, path in source_paths(source, manifest).items()}
    if len(by_path) != len(manifest) or not isinstance(rows, list):
        raise ValueError('invalid manifest or rows')
    ids = set()
    result = Counter()
    for row in rows:
        if not isinstance(row, list) or len(row) != 11 or any(not isinstance(v, str) for v in row):
            raise ValueError('invalid row')
        identity, path, sl, sc, el, ec, receiver, kind, known, prop, assessment = row
        if not identity or identity in ids:
            raise ValueError('empty or duplicate entity ID')
        ids.add(identity)
        if path not in by_path:
            raise ValueError('foreign path')
        if any(not v.isascii() or not v.isdecimal() or int(v) < 1 or str(int(v)) != v for v in (sl, sc, el, ec)):
            raise ValueError('invalid location')
        coords = tuple(map(int, (sl, sc, el, ec)))
        if coords[:2] > coords[2:]:
            raise ValueError('reversed location')
        if (receiver not in ('bare', 'L.uci') or kind not in ('dot', 'computed-index') or
                known not in ('true', 'false') or assessment != 'candidate' or
                (known == 'false' and (kind != 'computed-index' or prop != '<unknown>')) or
                (kind == 'dot' and (known != 'true' or not prop))):
            raise ValueError('invalid classification')
        result[(by_path[path], *coords, receiver, kind, known == 'true', prop)] += 1
    return result
