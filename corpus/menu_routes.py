"""Pinned menu.d source declarations, not a dispatcher or policy evaluator."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from corpus.luci_ssl_files import (
    LUCI_PIN, PROFILE, LUCI_SSL_LUCI_PACKAGES, PACKAGE_DEPENDENCY_SOURCES,
)

ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / 'corpus/lock.json'
UNKNOWN = [
    'Runtime file order, duplicate-route merge precedence and cache state are unassessed.',
    'Parent/child auth inheritance, wildcard dispatch and dependency evaluation are unassessed.',
    'Declarations do not establish installed availability, HTTP reachability or authorization.',
    'Lua controller semantics: lua_not_analyzed.',
    'Sentinel SID rewriting and checked session.access results are not modeled.',
    'Markup extraction, taint and policy/effect joins are not performed.',
]


def strict_json(raw):
    """Reject ambiguous documents rather than choose a duplicate-key winner."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError('non-JSON constant: ' + value)

    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=constant)


def observe_documents(documents):
    """Retain independent file contributions without merging or inheritance."""
    rows = []
    for source, raw in sorted(documents.items()):
        document = strict_json(raw)
        if not isinstance(document, dict):
            raise ValueError('menu document must be an object: ' + source)
        for route, spec in sorted(document.items()):
            if not isinstance(spec, dict):
                raise ValueError('menu declaration must be an object: ' + source)
            rows.append({'source': source, 'route': route,
                         'json_pointer': '/' + route.replace('~', '~0').replace('/', '~1'),
                         'spec': spec})
    return rows


def git(repo, *args):
    return subprocess.run(['git', '--no-replace-objects', '-C', str(repo), *args],
                          check=True, capture_output=True, timeout=30).stdout


def collect(repo, *, lockfile=LOCKFILE):
    """Observe committed blobs in the existing pinned LuCI-only closure."""
    lock_raw = lockfile.read_bytes()
    lock = strict_json(lock_raw)
    if lock['profile'] != PROFILE or lock['repos']['luci']['sha'] != LUCI_PIN:
        raise ValueError('profile or LuCI pin changed')
    if git(repo, 'rev-parse', LUCI_PIN + '^{commit}').decode().strip() != LUCI_PIN:
        raise ValueError('source commit does not match pin')
    documents, files, package_scope = {}, [], []
    evidence_paths = {'luci.mk', 'modules/luci-base/ucode/dispatcher.uc',
                      'modules/luci-base/ucode/controller/admin/index.uc',
                      'modules/luci-base/ucode/uhttpd.uc'}
    for package in LUCI_SSL_LUCI_PACKAGES:
        makefile = PACKAGE_DEPENDENCY_SOURCES[package]
        evidence_paths.add(makefile)
        base = str(Path(makefile).parent / 'root/usr/share/luci/menu.d') + '/'
        raw_tree = git(repo, 'ls-tree', '-rz', '--full-tree', LUCI_PIN, '--', base)
        selected = []
        for entry in raw_tree.split(b'\0'):
            if not entry:
                continue
            header, path_raw = entry.split(b'\t', 1)
            mode, kind, blob = header.decode('ascii').split()
            path = path_raw.decode('utf-8')
            relative = path.removeprefix(base)
            if not path.startswith(base) or '/' in relative or not relative.endswith('.json'):
                continue
            if mode != '100644' or kind != 'blob':
                raise ValueError('unsupported menu tree entry: ' + path)
            data = git(repo, 'cat-file', 'blob', blob)
            documents[path] = data
            selected.append(path)
            files.append({'package': package, 'source': path,
                          'installed': '/usr/share/luci/menu.d/' + relative,
                          'source_blob': blob, 'mode': mode, 'bytes': len(data),
                          'sha256': hashlib.sha256(data).hexdigest()})
        package_scope.append({'package': package, 'makefile': makefile,
                              'menu_sources': sorted(selected)})
    files.sort(key=lambda row: row['source'])
    if not files or len({row['installed'] for row in files}) != len(files):
        raise ValueError('empty corpus or installed-path collision')
    by_source = {row['source']: row for row in files}
    declarations = observe_documents(documents)
    for row in declarations:
        row['source_blob'] = by_source[row['source']]['source_blob']
        row['installed'] = by_source[row['source']]['installed']
    counts = Counter(row['route'] for row in declarations)
    evidence = []
    for path in sorted(evidence_paths):
        data = git(repo, 'show', LUCI_PIN + ':' + path)
        evidence.append({'source': path,
                         'source_blob': git(repo, 'rev-parse', LUCI_PIN + ':' + path).decode().strip(),
                         'sha256': hashlib.sha256(data).hexdigest()})
    return {
        'kind': 'menu_route_source_inventory', 'version': 1,
        'evidence_need': 'M4:menu-route-declaration-provenance',
        'profile': PROFILE, 'corpus_revision': 'sha256:' + hashlib.sha256(lock_raw).hexdigest(),
        'luci_pin': LUCI_PIN, 'luci_url': lock['repos']['luci']['url'],
        'source_tree': git(repo, 'rev-parse', LUCI_PIN + '^{tree}').decode().strip(),
        'scope_inputs_sha256': {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ('corpus/luci_ssl_files.py', 'corpus/menu_routes.py')},
        'selection': 'Existing reviewed static LuCI-only luci-ssl closure; direct menu.d/*.json in root/ only.',
        'ordering': 'Source path then literal route key; presentation only, not runtime precedence.',
        'semantics': 'unassessed', 'runtime_executed': False,
        'package_scope': package_scope, 'source_evidence': evidence,
        'files': files, 'declarations': declarations,
        'counts': {'source_files': len(files), 'declarations': len(declarations),
                   'distinct_route_keys': len(counts)},
        'duplicate_route_keys': sorted(route for route, count in counts.items() if count > 1),
        'unknowns': UNKNOWN,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--luci-git', type=Path, required=True)
    args = parser.parse_args()
    document = collect(args.luci_git)
    sys.stdout.buffer.write((json.dumps(document, indent=2, ensure_ascii=False,
                                       allow_nan=False) + '\n').encode('utf-8'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print('REJECTED: ' + str(exc), file=sys.stderr)
        sys.exit(1)
