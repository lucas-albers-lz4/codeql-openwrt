#!/usr/bin/env python3
"""Compare independently pinned app/service IPKs without extracting archive entries."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'luci-base-inventory'))
import archive
spec = importlib.util.spec_from_file_location("luci_base_compare", Path(__file__).resolve().parent.parent / "luci-base-inventory" / "compare.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

PINS = {'app': 'ea71145e8da15d306d601227c4b74a710b44516823a0192ebed509d1d7e72e2d',
        'service': 'ddbe34ee43f78824045ad60e1a114fd313b380ac7eaddb238407105603cd0758'}
VERSION = '1.2.4-r4'
NAMES = {'app': 'luci-app-adblock-fast', 'service': 'adblock-fast'}

def digest(data): return hashlib.sha256(data).hexdigest()

def load_oracle(kind, path):
    data = path.read_bytes()
    if digest(data) != PINS[kind]: raise ValueError('oracle hash differs: ' + kind)
    return json.loads(data, object_pairs_hook=base.unique_object)

def git_blob(repo, revision, path, expected_oid, expected_hash):
    info = base.git(repo, 'ls-tree', revision, '--', path).split('\t', 1)
    if len(info) != 2 or info[1] != path or info[0].split() != ['100644', 'blob', expected_oid]:
        raise ValueError('source git identity differs: ' + path)
    data = subprocess.check_output(['git', '-C', str(repo), 'show', revision + ':' + path])
    if digest(data) != expected_hash: raise ValueError('source digest differs: ' + path)
    return data

def preflight(app, service, luci, packages):
    base.pinned_clean('luci', luci); base.pinned_clean('packages', packages)
    for kind, oracle, repo, rev, rows in (
        ('app', app, luci, base.PINS['luci'], app['projected_files']),
        ('service', service, packages, base.PINS['packages'], service['source_mapping'])):
        for row in rows:
            git_blob(repo, rev, row['source_path'], row['git_blob'], row['source_sha256'])
        if kind == 'app':
            recipe = app['package']; git_blob(repo, rev, recipe['recipe'], recipe['recipe_blob'], recipe['recipe_sha256'])
            mk = subprocess.check_output(['git', '-C', str(repo), 'show', rev + ':luci.mk'])
            if digest(mk) != recipe['luci_mk_sha256']: raise ValueError('luci.mk digest differs')
        else:
            recipe = service['recipe']; git_blob(repo, rev, recipe['path'], recipe['git_blob'], recipe['sha256'])

def check_config(root):
    result = base.build_inputs(root)
    lines = (root / '.config').read_text().splitlines()
    for symbol in ('CONFIG_PACKAGE_luci-app-adblock-fast', 'CONFIG_PACKAGE_adblock-fast'):
        entries = [line for line in lines if line.startswith(symbol + '=') or line == '# ' + symbol + ' is not set']
        if entries != [symbol + '=m']: raise ValueError('package configuration differs: ' + symbol)
    if 'CONFIG_PER_FEED_REPO=y' not in lines: raise ValueError('per-feed package repository must be enabled')
    js = [line for line in lines if line.startswith('CONFIG_LUCI_JSMIN=') or line == '# CONFIG_LUCI_JSMIN is not set']
    if js not in (['CONFIG_LUCI_JSMIN=y'], ['# CONFIG_LUCI_JSMIN is not set'], ['CONFIG_LUCI_JSMIN=n']):
        raise ValueError('JS minification config missing or ambiguous')
    result['js_minification'] = js[0] == 'CONFIG_LUCI_JSMIN=y'
    return result

def require_physical_under(path, root, label):
    root = root.resolve(strict=True)
    absolute = Path(os.path.abspath(path))
    try: parts = absolute.relative_to(root).parts
    except ValueError as exc: raise ValueError(label + ' outside run root') from exc
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink(): raise ValueError(label + ' contains symlink')
    if absolute.resolve(strict=True) != absolute: raise ValueError(label + ' aliases path')
    return absolute

def stage_inventory(root):
    result = set()
    for path in root.rglob('*'):
        if path.is_symlink(): raise ValueError('stage symlink: ' + str(path))
        if path.is_file(): result.add(path.relative_to(root).as_posix())
        elif not path.is_dir(): raise ValueError('stage special file: ' + str(path))
    return result

def inspect_package(kind, oracle, repo, stage, ipk, prepared=None, js_minification=False):
    control, members, outer = archive.read_ipk(ipk)
    fields = base.control_from_rows(control)
    if fields != {'Package': NAMES[kind], 'Version': VERSION, 'Architecture': 'all'}:
        raise ValueError('package control identity differs: ' + kind)
    actual = {p for p, v in members.items() if v['type'] == 'file'}
    control_files = {p for p, v in control.items() if v['type'] == 'file'}
    stage_files = stage_inventory(stage)
    if stage_files != actual | {'CONTROL/' + p for p in control_files}:
        raise ValueError('stage/IPK full file inventory differs: ' + kind)
    for path in control_files:
        data, mode = base.checked_file(stage, 'CONTROL/' + path)
        if data != control[path]['bytes'] or mode != control[path]['mode']:
            raise ValueError('stage/IPK control differs: ' + path)
    staged_files = {}
    for path in actual:
        data, mode = base.checked_file(stage, path)
        staged_files[path] = (data, mode)
        if data != members[path]['bytes'] or mode != members[path]['mode']:
            raise ValueError('stage/IPK bytes or mode differ: ' + path)
    records = oracle['projected_files'] if kind == 'app' else oracle['source_mapping']
    expected_paths = set()
    output = []
    for row in records:
        path = row['projected_member_path'] if kind == 'app' else row['projected_member']
        if path in expected_paths: raise ValueError('duplicate oracle member: ' + path)
        expected_paths.add(path)
        entry = members.get(path)
        if entry is None or entry['type'] != 'file': raise ValueError('missing projected member: ' + path)
        mode = row['projected_mode_bits'] if kind == 'app' else int(row['expected_member_mode'], 8)
        if entry['mode'] != mode: raise ValueError('member mode differs: ' + path)
        source = git_blob(repo, base.PINS['luci'] if kind == 'app' else base.PINS['packages'], row['source_path'], row['git_blob'], row['source_sha256'])
        if kind == 'app':
            if prepared is None: raise ValueError('missing app prepared root')
            before, before_mode = base.checked_file(prepared, row['source_path'].removeprefix('applications/luci-app-adblock-fast/'))
            if before != source or before_mode != int(row['git_mode'][-3:], 8): raise ValueError('app prepared source differs: ' + path)
            # JS may be transformed by configured JsMin; receipt retains both hashes.
            if (row['disposition'] != 'auxiliary_htdocs_js' or not js_minification) and digest(entry['bytes']) != row['source_sha256']:
                raise ValueError('app root copy differs: ' + path)
            disposition = row['disposition']
            provenance = 'minification_unverified' if disposition == 'auxiliary_htdocs_js' and js_minification else 'source_equal'
        else:
            if digest(entry['bytes']) != row['expected_member_sha256'] or len(entry['bytes']) != row['expected_member_size']:
                raise ValueError('service recipe bytes differ: ' + path)
            disposition = row['recipe_action']
            provenance = 'recipe_expected_hash'
        output.append({'path':path, 'disposition':disposition, 'transform_provenance':provenance,
                       'source_sha256':digest(source), 'source_git_mode':row['git_mode'],
                       'prepared_sha256':digest(before) if kind == 'app' else None,
                       'prepared_mode':format(before_mode, '04o') if kind == 'app' else None,
                       'staged_sha256':digest(staged_files[path][0]), 'staged_mode':format(staged_files[path][1], '04o'),
                       'ipk_sha256':digest(entry['bytes']), 'ipk_mode':format(entry['mode'], '04o')})
    extra = sorted(actual - expected_paths)
    if extra: raise ValueError('unexpected package files: ' + ', '.join(extra))
    return {'package':kind, 'ipk_sha256':digest(ipk), 'control':fields, 'outer_sha256':outer,
            'source_mappings':output, 'data_members':archive.receipts(members), 'control_members':archive.receipts(control)}


def main():
    p = argparse.ArgumentParser(); p.add_argument('--kind', choices=sorted(NAMES))
    p.add_argument('--preflight', action='store_true')
    for name in ('luci', 'packages', 'run-root'): p.add_argument('--'+name, type=Path, required=True)
    for name in ('stage', 'ipk', 'receipt', 'prepared'): p.add_argument('--'+name, type=Path)
    p.add_argument('--config-root', type=Path)
    p.add_argument('--config-sha256')
    args = p.parse_args()
    here = Path(__file__).resolve().parent
    app = load_oracle('app', here/'app-oracle.json'); service = load_oracle('service', here/'service-oracle.json')
    run = args.run_root.resolve(strict=True)
    if Path(os.path.abspath(args.run_root)) != run: raise ValueError('run root is not physical')
    if args.luci.resolve(strict=True) != run / 'luci' or args.packages.resolve(strict=True) != run / 'packages': raise ValueError('source roots differ from run-owned paths')
    require_physical_under(args.luci, run, 'luci'); require_physical_under(args.packages, run, 'packages')
    preflight(app, service, args.luci, args.packages)
    config = None
    if args.config_root is not None:
        if args.config_root.resolve(strict=True) != run / 'openwrt': raise ValueError('config root differs')
        base.pinned_clean('openwrt', args.config_root)
        config = check_config(args.config_root)
        if not args.config_sha256 or config['config']['sha256'] != args.config_sha256: raise ValueError('frozen config digest differs')
    if args.preflight:
        if args.kind or args.stage or args.ipk or args.receipt or args.prepared: raise ValueError('preflight cannot accept output arguments')
        return
    if not all((args.kind, args.stage, args.ipk, args.receipt, args.config_root, args.config_sha256)):
        raise ValueError('comparison requires kind, stage, IPK, config root and receipt')
    stage = require_physical_under(args.stage, args.config_root, 'stage')
    ipk = require_physical_under(args.ipk, run / 'output', 'IPK')
    if not ipk.is_file(): raise ValueError('IPK must be regular file')
    if stage.name != NAMES[args.kind] or stage.parent.name != 'ipkg-all': raise ValueError('package stage layout differs')
    expected_build_dir = 'luci-app-adblock-fast' if args.kind == 'app' else 'adblock-fast-1.2.4'
    if stage.parent.parent.name != expected_build_dir or not stage.is_relative_to(args.config_root / 'build_dir'): raise ValueError('package build directory differs')
    if ipk.name != NAMES[args.kind] + '.ipk': raise ValueError('retained IPK name differs')
    if args.kind == 'app':
        if args.prepared is None or require_physical_under(args.prepared, args.config_root, 'prepared') != stage.parent.parent: raise ValueError('app prepared root differs')
    elif args.prepared is not None: raise ValueError('service has no separate prepared root')
    output = require_physical_under(args.receipt.parent, run / 'output', 'receipt directory')
    if args.receipt.name in ('', '.', '..') or args.receipt.parent.resolve() != output: raise ValueError('receipt path differs')
    result = inspect_package(args.kind, app if args.kind == 'app' else service, args.luci if args.kind == 'app' else args.packages, stage, ipk.read_bytes(), args.prepared, config['js_minification'])
    result.update({'oracle_sha256':PINS[args.kind], 'config':config, 'source_pins':base.PINS})
    with args.receipt.open('x') as f: f.write(json.dumps(result, indent=2, sort_keys=True)+'\n')
if __name__ == '__main__': main()
