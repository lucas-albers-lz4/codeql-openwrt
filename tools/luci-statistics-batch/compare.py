#!/usr/bin/env python3
"""Compare the source-first Statistics main-package projection to an IPK."""
import hashlib
import importlib.util
import json
import stat
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('batch', HERE.parent / 'luci-app-module-batches' / 'compare.py')
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
ORACLE_SHA = 'a5ab0a2b8f0099073a040b57ec4be3324a874d2f67ec3951a62a18cfa886cf4f'
LUCI_SHA = 'cb87fe60e1e2e052af36a93647f2264577829e0a'

def load_oracle():
    raw = (HERE / 'source-oracle.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORACLE_SHA:
        raise ValueError('source oracle digest differs')
    return json.loads(raw, object_pairs_hook=batch.unique)

def expected_rows(oracle):
    rows = [r for r in oracle['entries'] if r['package'] == 'luci-app-statistics' and r['projected_member'] is not None]
    result = {r['projected_member']: r for r in rows}
    if len(rows) != 126 or len(result) != 126:
        raise ValueError('Statistics source projection differs')
    return result

def physical_directory(path, run):
    path = Path(path)
    run = Path(run)
    if not path.is_absolute() or not run.is_absolute() or run.resolve(strict=True) != run:
        raise ValueError('run or directory is not physical and absolute')
    try:
        relative = path.relative_to(run)
    except ValueError as exc:
        raise ValueError('directory outside run root') from exc
    current = run
    for component in relative.parts:
        current = current / component
        if current.is_symlink() or not current.is_dir():
            raise ValueError('directory contains alias or is missing')
    if path.resolve(strict=True) != path:
        raise ValueError('directory is not physical')

def safe_file(root, relative):
    if not relative or relative.startswith('/') or '\\' in relative or PurePosixPath(relative).as_posix() != relative:
        raise ValueError('unsafe relative path: ' + relative)
    current = root
    for component in PurePosixPath(relative).parts:
        if component in ('', '.', '..'):
            raise ValueError('unsafe relative path: ' + relative)
        current = current / component
        if current.is_symlink():
            raise ValueError('file path contains alias: ' + relative)
    info = current.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('file is not a unique regular file: ' + relative)
    return current.read_bytes(), stat.S_IMODE(info.st_mode)

def compare(luci, prepared, stage, ipk, oracle, run, config):
    for path in (luci, prepared, stage):
        physical_directory(path, run)
    lines = config.decode().splitlines()
    for name in ('CONFIG_LUCI_JSMIN', 'CONFIG_LUCI_CSSTIDY'):
        matches = [x for x in lines if x.startswith(name + '=') or x == '# ' + name + ' is not set']
        if matches not in ([name + '=n'], ['# ' + name + ' is not set']):
            raise ValueError('minifier config must be disabled: ' + name)
    expected = expected_rows(oracle)
    control, members, outer = batch.archive.read_ipk(ipk)
    fields = batch.base.control_from_rows(control)
    if fields != {'Package': 'luci-app-statistics', 'Version': '26.205.85817~58d43e5', 'Architecture': 'all'}:
        raise ValueError('package control differs')
    if any(p == 'CONTROL' or p.startswith('CONTROL/') for p in members):
        raise ValueError('data archive uses reserved CONTROL namespace')
    actual = {p for p, r in members.items() if r['type'] == 'file'}
    if actual != set(expected):
        raise ValueError('package member set differs: missing=%r extra=%r' % (sorted(set(expected) - actual), sorted(actual - set(expected))))
    controls = {p for p, r in control.items() if r['type'] == 'file'}
    if batch.stage_inventory(stage) != actual | {'CONTROL/' + p for p in controls}:
        raise ValueError('stage file set differs')
    for path in controls:
        data, mode = safe_file(stage, 'CONTROL/' + path)
        if data != control[path]['bytes'] or mode != control[path]['mode']:
            raise ValueError('stage control differs: ' + path)
    rows = []
    prefix = 'applications/luci-app-statistics/'
    for path, row in sorted(expected.items()):
        source_row = dict(row, git_blob=row['git_object'])
        source = batch.git_blob(luci, LUCI_SHA, source_row)
        prepped, pmode = safe_file(prepared, row['source_path'].removeprefix(prefix))
        staged, smode = safe_file(stage, path)
        member = members[path]
        mode = int(row['source_mode_projected'], 8)
        if pmode != int(row['git_mode'][-3:], 8) or prepped != source:
            raise ValueError('prepared source differs: ' + path)
        if smode != mode or member['mode'] != mode or staged != member['bytes'] or staged != source:
            raise ValueError('source/stage/IPK bytes or mode differ: ' + path)
        rows.append({'path': path, 'source_path': row['source_path'],
                     'source_sha256': hashlib.sha256(source).hexdigest(), 'source_git_mode': row['git_mode'],
                     'prepared_sha256': hashlib.sha256(prepped).hexdigest(), 'prepared_mode': format(pmode, '04o'),
                     'stage_sha256': hashlib.sha256(staged).hexdigest(), 'stage_mode': format(smode, '04o'),
                     'ipk_sha256': hashlib.sha256(member['bytes']).hexdigest(), 'ipk_mode': format(member['mode'], '04o')})
    return {'package': fields, 'outer_member_sha256': outer, 'members': rows,
            'archive_data_members': batch.archive.receipts(members),
            'archive_control_members': batch.archive.receipts(control)}
