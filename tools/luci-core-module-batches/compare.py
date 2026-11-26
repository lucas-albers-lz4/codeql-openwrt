#!/usr/bin/env python3
"""Fail-closed source/prepared/stage/IPK inventory for three pinned LuCI modules."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
BASE_DIR = HERE.parent / 'luci-base-inventory'
sys.path.insert(0, str(BASE_DIR))
import archive
spec = importlib.util.spec_from_file_location('luci_base_compare', BASE_DIR / 'compare.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

ORACLE_SHA256 = 'afa112d09dce539a3e51845cd0786938194cb8c8af7d4c67d9713361b83693a5'
PINS = {'openwrt': '4e9642517b48bae612ff10fb72fb9199e559500e',
        'luci': 'cb87fe60e1e2e052af36a93647f2264577829e0a',
        'packages': '07e0d16305d2b5903b37ad7913e33e18795f81a4'}
PACKAGE_NAMES = ('luci-mod-status', 'luci-mod-network', 'luci-mod-system')
DEPENDENCY_NAMES = ('luci-base', 'libiwinfo', 'rpcd-mod-iwinfo', 'luci-lib-uqr')
ADMIN_FULL_PATH = 'modules/luci-mod-admin-full/Makefile'
ADMIN_FULL_BLOB = 'b376b35e55622803f2088a7491c3e1679578c4e5'
ADMIN_FULL_SHA256 = 'c64544d6700cc3068b8708f84b66dfdcdc2f49730cc99aae2d3c75fbdd130205'
SYSTEM_ACL = 'usr/share/rpcd/acl.d/luci-mod-system.json'
STATUS_MARKUP = 'usr/share/ucode/luci/template/admin_status/index.ut'
STATUS_SHELL = 'usr/libexec/syslog-wrapper'
NETWORK_SHELL = ('etc/uci-defaults/50_luci-mod-admin-full', 'usr/libexec/luci-peeraddr')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def pinned_clean(name: str, repo: Path) -> dict:
    rev = git(repo, 'rev-parse', 'HEAD')
    status = git(repo, 'status', '--porcelain=v1',
                 '--untracked-files=no' if name == 'openwrt' else '--untracked-files=all')
    if rev != PINS[name] or status:
        raise ValueError(f'{name} checkout pin/cleanliness differs: {rev}, dirty={bool(status)}')
    return {'sha': rev, 'tree': git(repo, 'rev-parse', 'HEAD^{tree}'), 'dirty': False}


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'duplicate JSON key: {key}')
        out[key] = value
    return out


def source_blob(repo: Path, path: str, mode: str, blob: str, sha256: str) -> bytes:
    if path.startswith('/') or any(x in ('', '.', '..') for x in path.split('/')):
        raise ValueError(f'unsafe oracle source path: {path!r}')
    tree = git(repo, 'ls-tree', PINS['luci'], '--', path).split('\t', 1)
    if len(tree) != 2 or tree[1] != path or tree[0].split() != [mode, 'blob', blob]:
        raise ValueError(f'source Git identity differs: {path}')
    body = subprocess.check_output(['git', '-C', str(repo), 'show', f"{PINS['luci']}:{path}"])
    if digest(body) != sha256:
        raise ValueError(f'source byte digest differs: {path}')
    return body


def load_oracle(path: Path) -> dict:
    raw = path.read_bytes()
    if digest(raw) != ORACLE_SHA256:
        raise ValueError('source-first oracle SHA-256 differs')
    obj = json.loads(raw, object_pairs_hook=unique_object)
    if obj.get('schema') != 'issue173-core-module-source-oracle-v1' or obj.get('luci_commit') != PINS['luci']:
        raise ValueError('source-first oracle identity differs')
    if obj.get('status') != 'source-first only; no package build or output inspected':
        raise ValueError('source oracle status changed')
    return obj


def preflight(oracle: dict, luci: Path) -> dict:
    pinned_clean('luci', luci)
    recipe_rows = oracle.get('recipes', {})
    if set(recipe_rows) != set(PACKAGE_NAMES):
        raise ValueError('oracle package recipe set differs')
    for pkg, recipe in recipe_rows.items():
        path = recipe['recipe']
        source_blob(luci, path, '100644', recipe['recipe_blob'], recipe['recipe_sha256'])
        if recipe['findrev_last_non_po_commit'] != '8125d1288b359f6df505d3328b712bf059843fc8':
            raise ValueError(f'{pkg} findrev source projection differs')
        if recipe['projected_pkg_src_version'] != '26.284.22350~8125d12':
            raise ValueError(f'{pkg} version projection differs')
    admin = source_blob(luci, ADMIN_FULL_PATH, '100644', ADMIN_FULL_BLOB, ADMIN_FULL_SHA256)
    admin_paths = git(luci, 'ls-tree', '-r', '--name-only', PINS['luci'], '--', 'modules/luci-mod-admin-full').splitlines()
    if admin_paths != [ADMIN_FULL_PATH]:
        raise ValueError('luci-mod-admin-full source tree is no longer dependency-only')
    if b'LUCI_DEPENDS:=+luci-base +luci-mod-status +luci-mod-system +luci-mod-network' not in admin:
        raise ValueError('luci-mod-admin-full dependency recipe differs')
    luci_mk = subprocess.check_output(['git', '-C', str(luci), 'show', f"{PINS['luci']}:luci.mk"])
    if digest(luci_mk) != '9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d':
        raise ValueError('pinned luci.mk digest differs')
    counts = {pkg: sum(r.get('package') == pkg for r in oracle.get('rows', [])) for pkg in PACKAGE_NAMES}
    if counts != {'luci-mod-status': 34, 'luci-mod-network': 17, 'luci-mod-system': 22}:
        raise ValueError(f'oracle source row counts differ: {counts}')
    projected_seen = set()
    for row in oracle.get('rows', []):
        if row.get('package') not in PACKAGE_NAMES:
            raise ValueError('oracle row package is outside selected batch')
        body = source_blob(luci, row['source_path'], row['git_mode'], row['git_blob'], row['source_sha256'])
        if len(body) != row['size']:
            raise ValueError(f'source size differs: {row["source_path"]}')
        if row.get('first_line') is not None and body.splitlines()[0].decode('utf-8', errors='replace') != row['first_line']:
            raise ValueError(f'source first line differs: {row["source_path"]}')
        if row['classification'] != 'build_input_not_direct_member':
            source_root, source_rel = row['source_path'].split('/', 2)[2].split('/', 1)
            expected = source_rel if source_root == 'root' else ('www/' + source_rel if source_root == 'htdocs' else 'usr/share/ucode/luci/' + source_rel if source_root == 'ucode' else None)
            projected = row.get('projected_member')
            if not projected or PurePosixPath(projected).is_absolute() or '..' in PurePosixPath(projected).parts:
                raise ValueError(f'unsafe projected member: {projected!r}')
            if projected in projected_seen:
                raise ValueError(f'duplicate projected source path: {projected}')
            projected_seen.add(projected)
            if expected is None or projected != expected:
                raise ValueError(f'projection differs for {row["source_path"]}')
    if len(projected_seen) != 71:
        raise ValueError(f'projected source member count differs: {len(projected_seen)}')
    return {'luci': pinned_clean('luci', luci), 'source_rows': len(oracle['rows']),
            'oracle_sha256': ORACLE_SHA256, 'luci_mk_sha256': digest(luci_mk),
            'admin_full_dependency_collection': {'source_path': ADMIN_FULL_PATH, 'blob': ADMIN_FULL_BLOB,
                                                  'sha256': ADMIN_FULL_SHA256, 'direct_payload': False}}


def config_facts(openwrt: Path) -> dict:
    lines = (openwrt / '.config').read_text().splitlines()
    def one(symbol):
        rows = [x for x in lines if x.startswith(symbol + '=') or x == '# ' + symbol + ' is not set']
        if len(rows) != 1:
            raise ValueError(f'config symbol missing/duplicated: {symbol}')
        return rows[0]
    required = {'CONFIG_TARGET_x86':'CONFIG_TARGET_x86=y',
                'CONFIG_TARGET_x86_64':'CONFIG_TARGET_x86_64=y',
                'CONFIG_PER_FEED_REPO':'CONFIG_PER_FEED_REPO=y'}
    for symbol, expected in required.items():
        if one(symbol) != expected:
            raise ValueError(f'build config value differs: {symbol}')
    if one('CONFIG_USE_APK') not in ('CONFIG_USE_APK=n', '# CONFIG_USE_APK is not set'):
        raise ValueError('IPK output requires CONFIG_USE_APK=n or unset')
    packages = {}
    for name in PACKAGE_NAMES:
        symbol = 'CONFIG_PACKAGE_' + name
        if one(symbol) != symbol + '=m':
            raise ValueError(f'{name} must be explicitly selected as a package')
        packages[name] = 'm'
    dependencies = {}
    for name in DEPENDENCY_NAMES:
        symbol = 'CONFIG_PACKAGE_' + name
        value = one(symbol)
        if value not in (symbol + '=m', symbol + '=y'):
            raise ValueError(f'required package dependency is not selected: {name}')
        dependencies[name] = value.split('=', 1)[1]
    if any(x.startswith('CONFIG_PACKAGE_luci-mod-admin-full=') for x in lines):
        raise ValueError('admin-full is a dependency collection only, not a selected payload package')
    def optional(symbol):
        rows = [x for x in lines if x.startswith(symbol + '=') or x == '# ' + symbol + ' is not set']
        if len(rows) > 1:
            raise ValueError(f'duplicate config symbol: {symbol}')
        if not rows:
            return 'implicit n'
        return rows[0]
    js = optional('CONFIG_LUCI_JSMIN')
    css = optional('CONFIG_LUCI_CSSTIDY')
    return {'config_sha256': digest((openwrt / '.config').read_bytes()),
            'package_selection': packages, 'resolved_dependencies': dependencies, 'js_minification': js, 'css_tidy': css,
            'apk': 'disabled', 'target': 'x86_64'}


def physical_under(path: Path, root: Path, label: str) -> Path:
    root = root.resolve(strict=True)
    absolute = Path(os.path.abspath(path))
    try:
        rel = absolute.relative_to(root)
    except ValueError as exc:
        raise ValueError(f'{label} escapes {root}') from exc
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f'{label} has symlink component: {current}')
    if absolute.resolve(strict=True) != absolute:
        raise ValueError(f'{label} path aliases another path')
    return absolute


def stage_files(stage: Path) -> dict:
    rows = {}
    for path in stage.rglob('*'):
        rel = path.relative_to(stage).as_posix()
        if path.is_symlink():
            raise ValueError(f'stage contains symlink: {rel}')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f'stage contains special file: {rel}')
        rows[rel] = (path.read_bytes(), path.stat().st_mode & 0o7777)
    return rows


def transform_expected(row: dict, config: dict) -> str:
    path = row['source_path']
    if path.endswith('.ut'):
        return 'pinned-substitution-noop-projected'
    if row['classification'].startswith('auxiliary_htdocs'):
        if path.endswith('.js') and config['js_minification'] not in ('# CONFIG_LUCI_JSMIN is not set', 'CONFIG_LUCI_JSMIN=n', 'implicit n'):
            return 'minification-enabled-output-bytes-unknown'
        if path.endswith('.css') and config['css_tidy'] not in ('# CONFIG_LUCI_CSSTIDY is not set', 'CONFIG_LUCI_CSSTIDY=n', 'implicit n'):
            return 'css-tidy-enabled-output-bytes-unknown'
    return 'direct-copy-projection'


def package_version(pkg: str, recipe: str) -> str:
    body = recipe.decode()
    m = re.search(r'^PKG_VERSION\s*:?=\s*([^\s#]+)', body, re.M)
    if m:
        release = re.search(r'^PKG_RELEASE\s*:?=\s*([^\s#]+)', body, re.M)
        suffix = release.group(1) if release else '1'
        return f'{m.group(1)}-r{suffix}' if suffix else m.group(1)
    return '26.284.22350~8125d12'


def compare_package(pkg: str, oracle: dict, luci: Path, stage: Path, ipk: Path, config: dict) -> dict:
    control_rows, members, outer_hashes = archive.read_ipk(ipk.read_bytes())
    fields = base.control_from_rows(control_rows)
    expected_arch = 'x86_64' if pkg == 'luci-mod-status' else 'all'
    rows = [r for r in oracle['rows'] if r['package'] == pkg and r['classification'] != 'build_input_not_direct_member']
    build_input_rows = [r for r in oracle['rows'] if r['package'] == pkg and r['classification'] == 'build_input_not_direct_member']
    recipe_body = source_blob(luci, oracle['recipes'][pkg]['recipe'], '100644', oracle['recipes'][pkg]['recipe_blob'], oracle['recipes'][pkg]['recipe_sha256'])
    expected_version = package_version(pkg, recipe_body)
    if fields != {'Package': pkg, 'Version': expected_version, 'Architecture': expected_arch}:
        raise ValueError(f'{pkg} control metadata differs: {fields}; expected version={expected_version} arch={expected_arch}')
    archive_files = {p: v for p, v in members.items() if v['type'] == 'file'}
    control_files = {p: v for p, v in control_rows.items() if v['type'] == 'file'}
    stage_map = stage_files(stage)
    expected_stage = set(archive_files) | {'CONTROL/' + p for p in control_files}
    if set(stage_map) != expected_stage:
        raise ValueError(f'{pkg} full stage/IPK member set differs; missing={sorted(expected_stage-set(stage_map))}, extra={sorted(set(stage_map)-expected_stage)}')
    if any(path == 'CONTROL' or path.startswith('CONTROL/') for path in members):
        raise ValueError(f'{pkg} data member aliases package control path')
    for path, item in archive_files.items():
        data, mode = stage_map[path]
        if data != item['bytes'] or mode != item['mode']:
            raise ValueError(f'{pkg} stage/IPK bytes or mode differ: {path}')
    for path, item in control_files.items():
        data, mode = stage_map['CONTROL/' + path]
        if data != item['bytes'] or mode != item['mode']:
            raise ValueError(f'{pkg} stage/IPK control bytes or mode differ: {path}')
    prepared = stage.parents[1]
    prepared_records = []
    checked = set()
    build_inputs = []
    for row in rows:
        member = row['projected_member']
        if member in checked:
            raise ValueError(f'duplicate projected member in oracle: {member}')
        checked.add(member)
        archived = archive_files.get(member)
        if archived is None:
            raise ValueError(f'{pkg} missing source-projected member: {member}')
        source = source_blob(luci, row['source_path'], row['git_mode'], row['git_blob'], row['source_sha256'])
        source_root, source_rel = row['source_path'].split('/', 2)[2].split('/', 1)
        prep_data, prep_mode = base.checked_file(prepared, f'{source_root}/{source_rel}')
        src_mode = int(row['git_mode'][-3:], 8)
        if prep_data != source or prep_mode != src_mode:
            raise ValueError(f'{pkg} prepared input differs from pinned source: {row["source_path"]}')
        output_hash = digest(archived['bytes'])
        transformed = transform_expected(row, config)
        if row['classification'] == 'selected_markup_candidate' and not row['source_path'].endswith('.ut'):
            raise ValueError('selected markup source is not an explicit .ut file')
        if row['classification'] == 'extensionless_unknown_shell':
            if not row.get('first_line', '').startswith('#!/bin/sh') or base.recognized_shebang(source.splitlines()[0]):
                raise ValueError(f'{pkg} near-miss shell control is not source-authored shell: {row["source_path"]}')
        if transformed in ('direct-copy-projection', 'pinned-substitution-noop-projected'):
            if output_hash != row['source_sha256']:
                raise ValueError(f'{pkg} direct copy/output bytes differ: {member}')
            if archived['mode'] != int(row['projected_mode'], 8):
                raise ValueError(f'{pkg} direct copy/output mode differs: {member}')
        prepared_records.append({'source_path': row['source_path'], 'projected_member': member,
                                'classification': row['classification'], 'transform': transformed,
                                'source_sha256': row['source_sha256'], 'source_mode': row['git_mode'],
                                'prepared_sha256': digest(prep_data), 'prepared_mode': format(prep_mode, '04o'),
                                'stage_sha256': output_hash, 'stage_mode': format(archived['mode'], '04o'),
                                'ipk_sha256': output_hash, 'ipk_mode': format(archived['mode'], '04o')})
    if pkg == 'luci-mod-system' and SYSTEM_ACL not in checked:
        raise ValueError('system ACL source oracle row is missing')
    if pkg == 'luci-mod-status' and STATUS_MARKUP not in checked:
        raise ValueError('status markup candidate is missing from oracle projection')
    # Required shell near-miss controls remain separate from candidate Ucode claims.
    shells = (STATUS_SHELL,) if pkg == 'luci-mod-status' else NETWORK_SHELL if pkg == 'luci-mod-network' else ()
    for path in shells:
        if path not in checked:
            raise ValueError(f'{pkg} shell route control is missing from oracle: {path}')
    for row in build_input_rows:
        source = source_blob(luci, row['source_path'], row['git_mode'], row['git_blob'], row['source_sha256'])
        source_rel = row['source_path'].split('/', 2)[2]
        prepared_data, prepared_mode = base.checked_file(prepared, source_rel)
        if prepared_data != source or prepared_mode != int(row['git_mode'][-3:], 8):
            raise ValueError(f'{pkg} prepared build input differs: {row["source_path"]}')
        build_inputs.append({'source_path': row['source_path'], 'source_sha256': digest(source),
                             'prepared_sha256': digest(prepared_data), 'prepared_mode': format(prepared_mode, '04o'),
                             'generated_member_expected': 'usr/bin/luci-bwc' if pkg == 'luci-mod-status' else None,
                             'generated_bytes_and_mode': 'unknown until build'})
    generated = []
    for path in sorted(set(archive_files) - checked):
        entry = archive_files[path]
        first_line = entry['bytes'].split(b'\n', 1)[0]
        if (path.endswith(('.uc', '.ucode', '.ut')) or
                path.startswith('usr/share/rpcd/ucode/') or
                (path.startswith(('usr/share/ucode/', 'usr/lib/ucode/')) and not PurePosixPath(path).suffix) or
                base.recognized_shebang(first_line)):
            raise ValueError(f'{pkg} unexpected Ucode-shaped IPK member: {path}')
        generated.append({'path': path, 'status': 'observed_unclassified_package_member',
                          'sha256': digest(entry['bytes']), 'mode': format(entry['mode'], '04o'),
                          'size': len(entry['bytes'])})
    if pkg == 'luci-mod-status' and 'usr/bin/luci-bwc' not in {x['path'] for x in generated}:
        raise ValueError('status generated luci-bwc member is missing or already source-classified')
    return {'package': pkg, 'control': fields, 'version_projection': oracle['recipes'][pkg]['projected_pkg_src_version'],
            'ipk_sha256': digest(ipk.read_bytes()), 'outer_archive_hashes': outer_hashes,
            'source_mappings': prepared_records, 'build_inputs': build_inputs,
            'generated_or_unclassified_members': [dict(x, status=('observed_generated_build_artifact_no_source_projection' if pkg == 'luci-mod-status' and x['path'] == 'usr/bin/luci-bwc' else 'observed_unmapped_member')) for x in generated],
            'data_archive_members': archive.receipts(members),
            'control_archive_members': archive.receipts(control_rows),
            'route_expectations': [{'source_path': row['source_path'], 'member': row['projected_member'],
                                    'source_classification': row['classification'],
                                    'route_claim': ('markup suffix candidate; semantics inconclusive' if row['classification'] == 'selected_markup_candidate' else
                                                    'shell near-miss control; no Ucode classification claim' if row['classification'] == 'extensionless_unknown_shell' else
                                                    'auxiliary package member') } for row in rows]}


def require_package_feed_links(openwrt: Path, luci: Path):
    expected = {name: luci / 'modules' / name for name in (*PACKAGE_NAMES, 'luci-mod-admin-full')}
    for name, target in expected.items():
        link = openwrt / 'package' / 'feeds' / 'luci' / name
        if not link.exists() or link.is_symlink() and link.resolve(strict=True) != target.resolve(strict=True):
            raise ValueError(f'LuCI package feed link is missing or differs: {name}')
        if link.resolve(strict=True) != target.resolve(strict=True):
            raise ValueError(f'LuCI package feed path differs: {name}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight', action='store_true')
    p.add_argument('--oracle', type=Path, default=HERE / 'source-oracle.json')
    p.add_argument('--run-root', type=Path, required=True)
    p.add_argument('--openwrt', type=Path, required=True)
    p.add_argument('--luci', type=Path, required=True)
    p.add_argument('--packages', type=Path, required=True)
    p.add_argument('--package', choices=PACKAGE_NAMES)
    p.add_argument('--stage', type=Path)
    p.add_argument('--ipk', type=Path)
    p.add_argument('--built-ipk', type=Path)
    p.add_argument('--config-sha256')
    p.add_argument('--receipt', type=Path)
    args = p.parse_args()
    start = time.monotonic()
    oracle = load_oracle(args.oracle)
    run = args.run_root.resolve(strict=True)
    if Path(os.path.abspath(args.run_root)) != run:
        raise ValueError('run root must be physical')
    for name, repo in (('openwrt', args.openwrt), ('luci', args.luci), ('packages', args.packages)):
        if repo.resolve(strict=True) != run / name:
            raise ValueError(f'{name} repo must be in run-owned path')
    pins = {name: pinned_clean(name, repo) for name, repo in (('openwrt', args.openwrt), ('luci', args.luci), ('packages', args.packages))}
    pre = preflight(oracle, args.luci)
    config = config_facts(args.openwrt) if (args.openwrt / '.config').is_file() else None
    if args.preflight:
        if any((args.package, args.stage, args.ipk, args.built_ipk, args.config_sha256, args.receipt)):
            raise ValueError('preflight may not accept build output paths')
        print(json.dumps({'status': 'PREFLIGHT_PASS', 'pins': pins, 'source_preflight': pre, 'config': config or {'status': 'not configured yet'}}, indent=2, sort_keys=True))
        return
    if not all((args.package, args.stage, args.ipk, args.built_ipk, args.config_sha256, args.receipt)):
        raise ValueError('comparison requires package, stage, retained/built IPK, frozen config digest and receipt')
    stage = physical_under(args.stage, args.openwrt / 'build_dir', 'stage')
    ipk = physical_under(args.ipk, args.run_root / 'output', 'IPK')
    receipt = args.receipt
    physical_under(receipt.parent, args.run_root / 'output', 'receipt directory')
    if not ipk.is_file() or ipk.is_symlink() or not stage.is_dir():
        raise ValueError('IPK must be regular and stage a directory')
    if stage.name != args.package or not stage.parent.name.startswith('ipkg-'):
        raise ValueError('stage path does not identify selected package')
    if ipk.name != f'{args.package}.ipk':
        raise ValueError('retained IPK filename is not package-specific')
    if config is None:
        raise ValueError('resolved build config is missing')
    if config['config_sha256'] != args.config_sha256:
        raise ValueError('resolved config digest differs from frozen batch input')
    base.require_feed_links(args.openwrt, args.luci, args.packages)
    require_package_feed_links(args.openwrt, args.luci)
    built_ipk = physical_under(args.built_ipk, args.openwrt / 'bin' / 'packages', 'built IPK')
    if not built_ipk.is_file() or built_ipk.is_symlink() or built_ipk.read_bytes() != ipk.read_bytes():
        raise ValueError('retained IPK bytes differ from exact current build output')
    parsed = compare_package(args.package, oracle, args.luci, stage, ipk, config)
    expected_arch = 'x86_64' if args.package == 'luci-mod-status' else 'all'
    expected_name = f"{args.package}_{parsed['control']['Version']}_{expected_arch}.ipk"
    if (stage.parent.name != f'ipkg-{expected_arch}' or stage.parents[1].name != args.package or
            built_ipk.name != expected_name or
            built_ipk.relative_to(args.openwrt / 'bin' / 'packages').parts != ('x86_64', 'luci', expected_name)):
        raise ValueError(f'{args.package} stage/IPK layout or filename differs')
    record = {'status': 'PASS', 'scope': 'source/prepared/stage/IPK package byte inventory; not root-image/runtime or semantic coverage',
              'pins': pins, 'config': config, 'source_preflight': pre,
              'build_output': {'path': built_ipk.relative_to(args.openwrt).as_posix(), 'sha256': digest(built_ipk.read_bytes())},
              'retained_ipk': {'path': ipk.relative_to(args.run_root).as_posix(), 'sha256': digest(ipk.read_bytes())}, **parsed}
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open('x') as fh:
        fh.write(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
