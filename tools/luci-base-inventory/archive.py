"""Read pinned-format IPKs without extracting, rejecting ambiguous archive entries."""
import gzip
import hashlib
import io
from pathlib import PurePosixPath
import tarfile


def canonical(name, directory=False):
    if name in ('.', './'):
        return ''
    if name.startswith('./'):
        name = name[2:]
    if directory and name.endswith('/'):
        name = name[:-1]
    if (not name or name.startswith('/') or '\\' in name or
            any(x in ('', '.', '..') for x in name.split('/')) or
            PurePosixPath(name).as_posix() != name):
        raise ValueError(f'unsafe archive path: {name!r}')
    return name


def members(data):
    rows = {}
    raw = gzip.decompress(data)
    # Inspect raw headers so tarfile cannot hide PAX or GNU name/sparse carriers.
    offset = 0
    while offset + 512 <= len(raw) and any(raw[offset:offset + 512]):
        header = tarfile.TarInfo.frombuf(raw[offset:offset + 512], 'utf-8', 'surrogateescape')
        if header.size < 0:
            raise ValueError(f'negative archive size: {header.name!r}')
        if header.type not in (tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE):
            raise ValueError(f'unsupported archive type: {header.name!r}')
        if header.isdir() and header.size != 0:
            raise ValueError(f'nonzero directory size: {header.name!r}')
        offset += 512 + ((header.size + 511) // 512) * 512
        if offset > len(raw):
            raise ValueError('truncated archive member')
    if len(raw) % 512 or len(raw) - offset < 1024 or any(raw[offset:]):
        raise ValueError('nonzero or truncated archive trailer')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        for item in tar:
            path = canonical(item.name, item.isdir())
            if path in rows:
                raise ValueError(f'duplicate archive path: {path!r}')
            if item.type not in (tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE) or item.sparse is not None:
                raise ValueError(f'unsupported archive type: {path!r}')
            if not path and not item.isdir():
                raise ValueError('archive root must be a directory')
            if item.mode & ~0o777:
                raise ValueError(f'unsupported archive mode: {path!r}')
            body = None
            if item.isfile():
                stream = tar.extractfile(item)
                if stream is None:
                    raise ValueError(f'unreadable archive member: {path!r}')
                body = stream.read()
                if len(body) != item.size:
                    raise ValueError(f'truncated archive member: {path!r}')
            rows[path] = {'type': 'directory' if item.isdir() else 'file',
                          'mode': item.mode, 'size': item.size, 'bytes': body}
        tail = raw[tar.offset:]
        if len(tail) < 1024 or len(raw) % 512 or any(tail):
            raise ValueError('nonzero or truncated archive trailer')
    # Files cannot also be ancestors of other members, even without explicit dirs.
    for path in rows:
        parts = path.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            if parent in rows and rows[parent]['type'] != 'directory':
                raise ValueError(f'file used as directory: {parent!r}')
    return rows


def read_ipk(data):
    outer = members(data)
    if set(outer) != {'debian-binary', 'control.tar.gz', 'data.tar.gz'}:
        raise ValueError('unexpected outer archive members')
    if any(x['type'] != 'file' for x in outer.values()):
        raise ValueError('outer archive members must be files')
    if outer['debian-binary']['bytes'] != b'2.0\n':
        raise ValueError('unexpected IPK format')
    control = members(outer['control.tar.gz']['bytes'])
    data_rows = members(outer['data.tar.gz']['bytes'])
    return control, data_rows, {p: hashlib.sha256(row["bytes"]).hexdigest() for p, row in outer.items()}


def receipts(rows):
    return [{'path': p, 'type': row['type'], 'mode': format(row['mode'], '04o'),
             'size': row['size'], 'sha256': hashlib.sha256(row['bytes']).hexdigest() if row['bytes'] is not None else None}
            for p, row in sorted(rows.items())]
