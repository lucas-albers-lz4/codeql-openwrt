#!/usr/bin/env python3
"""Trusted local launcher template; copy into the private operator directory.

Run this *private copy*, never a checkout copy, for a signing command. It
materializes the approved Git commit into a new private worktree with no
ignored bytecode, then executes its issuer entrypoint. It never reads the key.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


def need(ok, message):
    if not ok:
        raise ValueError(message)


def private_root(root):
    need(root.is_absolute(), 'private root must be absolute')
    cursor = Path(root.anchor)
    for part in root.parts[1:]:
        cursor = cursor / part
        info = cursor.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()) and
             not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
             'unsafe private-root ancestor')
    info = root.lstat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'private root must be operator owned mode 0700')


def private_file(path, root, *, max_bytes):
    need(path.parent == root, 'private file must be directly in root')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
         0 < before.st_size <= max_bytes, 'unsafe private file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
             'private file changed before read')
        raw = os.read(fd, max_bytes + 1)
        need(len(raw) == before.st_size, 'private file changed while reading')
        return raw
    finally:
        os.close(fd)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'duplicate policy key')
        value[key] = item
    return value


def prepare(checkout, root, commit):
    need(checkout.is_absolute() and checkout.is_dir() and not checkout.is_symlink(),
         'unsafe source checkout')
    # Plumbing reads object bytes only. Never checkout: checkout applies repository
    # filters, and a linked worktree would retain the caller's Git configuration.
    git_env = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
               'GIT_NO_REPLACE_OBJECTS': '1', 'HOME': str(root),
               'LC_ALL': 'C'}
    def git(*argv, data=None):
        return subprocess.check_output(
            ['git', '--no-replace-objects', '-C', str(checkout), *argv],
            input=data, env=git_env)
    kind = git('cat-file', '-t', commit).decode().strip()
    need(kind == 'commit', 'approved commit unavailable')
    target = root / ('issuer-source-' + uuid.uuid4().hex)
    target.mkdir(mode=0o700)
    entries = git('ls-tree', '-r', '-z', '--full-tree', commit).split(b'\0')
    need(1 < len(entries) <= 10000 and entries[-1] == b'', 'unsafe issuer tree')
    for entry in entries[:-1]:
        metadata, name = entry.split(b'\t', 1)
        mode, kind, oid = metadata.split(b' ')
        need(mode in (b'100644', b'100755') and kind == b'blob' and
             re.fullmatch(rb'[0-9a-f]{40}', oid), 'unsafe issuer tree entry')
        parts = name.decode('utf-8').split('/')
        need(all(part not in ('', '.', '..', '.git', '__pycache__') and
                 not part.endswith(('.pyc', '.pyo')) for part in parts),
             'unsafe issuer path')
        destination = target.joinpath(*parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        raw = git('cat-file', 'blob', oid.decode())
        need(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() ==
             oid.decode(), 'issuer object digest mismatch')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o700 if mode == b'100755' else 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
    (target / '.operator-approved-commit').write_text(commit + '\n')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--private-root', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('command', choices=('start', 'complete', 'failure'))
    parser.add_argument('issuer_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        private_root(args.private_root)
        need(Path(__file__).resolve().parent == args.private_root and
             not Path(__file__).is_symlink(),
             'launcher must be the private operator copy')
        private_file(Path(__file__), args.private_root, max_bytes=64 * 1024)
        raw = private_file(args.policy, args.private_root, max_bytes=4096)
        policy = json.loads(raw, object_pairs_hook=unique)
        need(type(policy) is dict and
             set(policy) == {'schema', 'consumer_commit', 'workflow', 'queue_id'} and
             policy['schema'] == 'incoming-operator-policy-v1' and
             isinstance(policy['consumer_commit'], str) and
             re.fullmatch(r'[0-9a-f]{40}', policy['consumer_commit']) and
             policy['workflow'] == '.github/workflows/incoming-event-preflight.yml',
             'invalid approved issuer policy')
        source = prepare(args.checkout, args.private_root,
                         policy['consumer_commit'])
        script = source / 'tools' / {
            'start': 'operator_queue_start.py',
            'complete': 'operator_queue_complete.py',
            'failure': 'operator_queue_failure.py'}[args.command]
        need(script.is_file() and not script.is_symlink(), 'missing issuer entrypoint')
        code = ('import runpy,sys; '
                'sys.path.insert(0,sys.argv[1]); '
                'sys.argv=[sys.argv[2]]+sys.argv[3:]; '
                'runpy.run_path(sys.argv[0],run_name="__main__")')
        environment = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin',
                       'HOME': str(args.private_root), 'TMPDIR': str(args.private_root),
                       'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1',
                       'OPERATOR_LAUNCH_COMMIT': policy['consumer_commit'],
                       'OPERATOR_LAUNCH_SOURCE': str(source)}
        for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN'):
            if name in os.environ:
                environment[name] = os.environ[name]
        os.execve(sys.executable,
                  [sys.executable, '-I', '-B', '-c', code,
                   str(source / 'tools'), str(script), *args.issuer_args],
                  environment)
    except (OSError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError, RecursionError) as exc:
        print('operator launcher rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
