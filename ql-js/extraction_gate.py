#!/usr/bin/env python3
"""Rebuild the pinned JS selection and check a newly created CodeQL database."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from corpus.luci_ssl_files import (  # noqa: E402
    LUCI_SSL_LUCI_PACKAGES, PACKAGE_DEPENDENCY_SOURCES,
)

PIN = 'b2e0be4b46ec0fd43394c081fa7c50657af14011'
CLI_VERSION = '2.27.4'


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def build_manifest(git_dir):
    lock = json.loads((ROOT / 'corpus/lock.json').read_text(encoding='utf-8'))
    if lock['profile'] != 'luci-ssl-25.12' or lock['repos']['luci']['sha'] != PIN:
        raise ValueError('profile or LuCI pin changed')
    rows = []
    for package in LUCI_SSL_LUCI_PACKAGES:
        base = str(Path(PACKAGE_DEPENDENCY_SOURCES[package]).parent / 'htdocs') + '/'
        raw = run(['git', '-C', str(git_dir), 'ls-tree', '-rz', '--full-tree', PIN, '--', base])
        for entry in raw.split(b'\0'):
            if not entry:
                continue
            header, rawpath = entry.split(b'\t', 1)
            mode, kind, blob = header.decode('ascii').split(' ')
            path = rawpath.decode('utf-8')
            if not path.endswith('.js'):
                continue
            if mode != '100644' or kind != 'blob' or not path.startswith(base):
                raise ValueError(f'unsupported tree entry: {path}')
            data = run(['git', '-C', str(git_dir), 'cat-file', 'blob', blob])
            rows.append({'package': package, 'source': path,
                         'installed': '/www/' + path[len(base):], 'mode': mode,
                         'blob': blob, 'sha256': hashlib.sha256(data).hexdigest()})
    rows.sort(key=lambda row: row['source'])
    if not rows or len({r['source'] for r in rows}) != len(rows) or len({r['installed'] for r in rows}) != len(rows):
        raise ValueError('empty or duplicate source/installed paths')
    return rows


def check_manifest(expected, actual):
    if not isinstance(expected, list) or not expected or expected != actual:
        raise ValueError('pinned manifest differs from reconstructed tree')


def tuples(document, width):
    if not isinstance(document, dict) or set(document) != {'#select'}:
        raise ValueError('invalid query result')
    table = document['#select']
    if not isinstance(table, dict) or set(table) != {'columns', 'tuples'}:
        raise ValueError('invalid query result table')
    if table['columns'] != [{'kind': 'String'}] * width or not isinstance(table['tuples'], list):
        raise ValueError('unexpected query result columns')
    rows = table['tuples']
    if any(not isinstance(row, list) or len(row) != width or any(not isinstance(v, str) for v in row) for row in rows):
        raise ValueError('unexpected query result row')
    return rows


def check_results(expected, files, errors):
    paths = [row[0] for row in tuples(files, 1)]
    if len(expected) != len(set(expected)) or Counter(paths) != Counter(expected):
        raise ValueError(f'extracted file mismatch: missing={list((Counter(expected)-Counter(paths)).elements())}, extra={list((Counter(paths)-Counter(expected)).elements())}')
    failures = tuples(errors, 3)
    if failures:
        raise ValueError(f'JavaScript parse errors: {failures}')


def check_staged(source, rows):
    actual = sorted(str(p.relative_to(source)) for p in source.rglob('*') if p.is_file())
    if actual != sorted(r['source'] for r in rows):
        raise ValueError('staged source file set differs from manifest')
    for row in rows:
        path = source / row['source']
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError(f'staged source bytes differ: {row["source"]}')


def codeql_results(codeql, packs, source, out, allow_minified=True):
    env = os.environ.copy()
    env['CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES'] = 'true' if allow_minified else 'false'
    commands = [[codeql, 'database', 'create', str(out / 'db'), '--language=javascript', f'--source-root={source}', '--threads=2', '--ram=3072']]
    for name in ('files', 'errors'):
        commands += [[codeql, 'query', 'run', str(HERE / (name + '.ql')), '--database', str(out / 'db'), '--additional-packs=' + str(packs), '--output', str(out / (name + '.bqrs')), '--threads=2', '--ram=3072'],
                     [codeql, 'bqrs', 'decode', str(out / (name + '.bqrs')), '--format=json', '--entities=url,string', '--output', str(out / (name + '.json'))]]
    with (out / 'commands.log').open('w', encoding='utf-8') as log:
        log.write('CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES=' + env['CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES'] + '\n')
        for cmd in commands:
            log.write(json.dumps(cmd) + '\n')
            log.flush()
            subprocess.run(cmd, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    return tuple(json.loads((out / (name + '.json')).read_text(encoding='utf-8')) for name in ('files', 'errors'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--luci-git', type=Path, required=True)
    parser.add_argument('--codeql', type=Path, required=True)
    parser.add_argument('--packs', type=Path, required=True, help='additional packs root containing codeql/javascript-all 3.0.0')
    parser.add_argument('--output', type=Path, required=True, help='new directory for source, database and evidence')
    args = parser.parse_args()
    codeql = str(args.codeql.resolve(strict=True))
    packs = args.packs.resolve(strict=True)
    version = run([codeql, 'version']).decode('utf-8')
    if f'toolchain release {CLI_VERSION}.' not in version:
        raise ValueError('wrong CodeQL CLI version')
    resolution = json.loads(run([codeql, 'resolve', 'packs', '--format=json', '--additional-packs=' + str(packs)]))
    found = resolution['steps'][0]['scans'][0]['found']['codeql/javascript-all']
    if found['version'] != '3.0.0':
        raise ValueError('wrong javascript-all pack version')
    rows = build_manifest(args.luci_git.resolve(strict=True))
    check_manifest(json.loads((HERE / 'manifest.json').read_text(encoding='utf-8')), rows)
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'
    source.mkdir()
    for row in rows:
        target = source / row['source']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(run(['git', '-C', str(args.luci_git), 'cat-file', 'blob', row['blob']]))
    check_staged(source, rows)
    (out / 'toolchain.txt').write_text(version + '\n' + json.dumps(found, indent=2) + '\n', encoding='utf-8')
    files, errors = codeql_results(codeql, packs, source, out)
    check_staged(source, rows)
    check_results([str(source / r['source']) for r in rows], files, errors)
    evidence_files = ('manifest.json', 'extraction_gate.py', 'files.ql', 'errors.ql', 'qlpack.yml', 'codeql-pack.lock.yml')
    hashes = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in evidence_files}
    hashes.update({name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ('corpus/lock.json', 'corpus/luci_ssl_files.py')})
    (out / 'ACCEPTED.json').write_text(json.dumps({'luci_pin': PIN, 'files': len(rows), 'input_sha256': hashes, 'scope': 'TopLevel membership and JSParseError only'}, indent=2) + '\n', encoding='utf-8')
    print(f'Accepted {len(rows)} pinned files; evidence: {out}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f'REJECTED: {exc}', file=sys.stderr)
        sys.exit(1)
