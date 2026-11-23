"""Read-only admission of the one historical #136 observation, not execution trust."""
import argparse
from collections import Counter
import csv
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import stat

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_SHA256 = 'c4e0c735ec41c09c40032e489e2ffc5147bf6376a76f70bc4ef6e84459044fc2'
INVENTORY_SHA256 = '05598b6bb1dd7d63a4f8cc109367980e51f334385704c3d92453b411c737ab9c'
STAGE = '/private/tmp/openwrt68-stage'

class Rejected(ValueError):
    pass

class Incomplete(ValueError):
    pass

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read(path):
    # O_NONBLOCK prevents opening a FIFO from waiting for a writer. Inspect the
    # opened descriptor before reading, so non-regular inputs are rejected.
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise Rejected(f'not a regular file: {path}')
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENXIO):
            raise Rejected(f'invalid path: {path}') from exc
        raise Incomplete(f'unavailable {path}: {exc}') from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Rejected(f'not a regular file: {path}')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            return stream.read()
    except OSError as exc:
        raise Incomplete(f'unavailable {path}: {exc}') from exc
    finally:
        if fd is not None:
            os.close(fd)

def confined(root, name):
    p = Path(name)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise Rejected('invalid evidence path')
    try:
        resolved_root = root.resolve()
        target = (root / p).resolve()
    except RuntimeError as exc:  # pathlib symlink loops on Python 3.12
        raise Rejected('invalid evidence path') from exc
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Rejected('invalid evidence path') from exc
        raise Incomplete(f'evidence path unavailable: {exc}') from exc
    if not target.is_relative_to(resolved_root):
        raise Rejected('evidence path escapes root')
    return target

def strict_json(data):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise Rejected('duplicate JSON key')
            result[k] = v
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected(f'invalid JSON: {exc}') from exc

def table(data, columns):
    obj = strict_json(data)
    if not isinstance(obj, dict) or set(obj) != {'#select'}:
        raise Rejected('diagnostic envelope')
    t = obj['#select']
    if not isinstance(t, dict) or set(t) != {'columns', 'tuples'} or t['columns'] != columns or not isinstance(t['tuples'], list):
        raise Rejected('diagnostic schema')
    return t['tuples']

def semantics(manifest, routing, extracted, errors, ast, inventory, ref):
    if not isinstance(manifest, list) or len(manifest) != 12:
        raise Rejected('selected manifest')
    paths = {}
    for row in manifest:
        if not isinstance(row, dict) or set(row) != {'installed', 'source', 'sha256', 'blob'}:
            raise Rejected('manifest fields')
        installed = row['installed']
        if not isinstance(installed, str) or not installed.startswith('/usr/share/ucode/luci/') or installed in paths:
            raise Rejected('selected identity')
        paths[installed] = row
    selected = [r for r in inventory if r.get('classification') == 'markup']
    if len(selected) != 12 or {r.get('fs_path') for r in selected} != set(paths):
        raise Rejected('inventory identities')
    for r in selected:
        row = paths[r['fs_path']]
        if (r.get('source') != row['source'] or r.get('corpus_revision') != ref['corpus_revision'] or
            r.get('profile') != ref['profile'] or r.get('analysis_revision') != ref['inventory_revision']):
            raise Rejected('inventory binding')
    counters = {'input_count':12, 'plain_count':0, 'markup_count':12, 'markup_inconclusive_count':12, 'uncertain_count':0, 'excluded_count':0, 'duplicate_input_count':0}
    if not isinstance(routing, dict) or set(routing) != set(counters) | {'decisions'} or any(type(routing[k]) is not int or routing[k] != v for k,v in counters.items()):
        raise Rejected('routing counters')
    expected = []
    for installed in paths:
        path = STAGE + installed
        expected.append({'path':path, 'installed_path':installed.lstrip('/'), 'classification':'markup', 'reason':'markup_tag_content' if installed == '/usr/share/ucode/luci/uhttpd.uc' else 'ut_markup_extension', 'status':'inconclusive', 'inconclusive_reason':'markup_not_modeled'})
    encode = lambda x: json.dumps(x, sort_keys=True, separators=(',', ':'))
    if not isinstance(routing['decisions'], list) or Counter(map(encode, routing['decisions'])) != Counter(map(encode, expected)):
        raise Rejected('routing decisions')
    rows = table(extracted, [{'name':'f','kind':'Entity'}, {'kind':'String'}])
    wanted = [[{'label': STAGE + p, 'url': {'uri': Path(STAGE + p).as_uri(), 'startLine':0, 'startColumn':0, 'endLine':0, 'endColumn':0}}, ''] for p in paths]
    if Counter(map(encode, rows)) != Counter(map(encode, wanted)):
        raise Rejected('success tuples')
    if table(errors, [{'name':'error','kind':'Entity'}, {'kind':'String'}, {'kind':'Integer'}]):
        raise Rejected('error tuples contradict positive observation')
    try:
        records = list(csv.reader(io.StringIO(ast.decode('utf-8'), newline=''), strict=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise Rejected('invalid AST CSV') from exc
    if not records or records[0] != [f'col{i}' for i in range(7)] or any(len(r) != 7 for r in records[1:]):
        raise Rejected('AST schema')
    if ref['ast_scope'] != '/usr/share/ucode/luci/uhttpd.uc' or not records[1:] or records[1][:6] != ['ImportStatement','3','1','3','39','Markup']:
        raise Rejected('AST scope or first import')
    # The remaining tuple values and parent indices are retained artifact bytes,
    # not independently established AST identities or a completeness oracle.
    retained = [['ImportStatement','3','1','3','39','Markup','1'], ['ImportStatement','4','1','4','32','Markup','2'], ['FunctionExpression','6','25','12','1','AssignmentExpression','2'], ['AssignmentExpression','6','1','12','1','ExpressionStatement','0']]
    if records[1:] != retained:
        raise Rejected('AST retained tuples differ')
    return paths

def check_reference_version(ref):
    if not isinstance(ref, dict) or type(ref.get('version')) is not int or ref['version'] != 1:
        raise Rejected('unsupported reference version')

def validate(reference, evidence_root, source, requested_profile, lock, inventory):
    try:
        raw = read(reference)
        ref = strict_json(raw)
        check_reference_version(ref)
        if digest(raw) != REFERENCE_SHA256:
            raise Rejected('reference differs from independent authority')
        if requested_profile != ref['profile']:
            raise Rejected('requested profile differs')
        if digest(read(lock)) != ref['corpus_revision'].removeprefix('sha256:'):
            raise Rejected('lock differs')
        inv_raw = read(inventory)
        if digest(inv_raw) != INVENTORY_SHA256:
            raise Rejected('inventory differs')
        artifacts = {}
        for name, expected in ref['artifacts'].items():
            data = read(confined(evidence_root, name))
            if digest(data) != expected:
                raise Rejected(f'artifact differs: {name}')
            artifacts[name] = data
        manifest = strict_json(artifacts['manifest.json'])
        paths = semantics(manifest, strict_json(artifacts['routing.json']), artifacts['extracted.json'], artifacts['errors.json'], artifacts['uhttpd-ast.csv'], strict_json(inv_raw), ref)
        # Ignore ambient Git redirections, replace refs, configuration and lazy fetch.
        env = {k: val for k, val in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_LAZY_FETCH='1')
        def git(*args):
            try:
                return subprocess.run(['git', '--no-replace-objects', '-C', str(source), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env)
            except OSError as exc:
                raise Incomplete(f'Git unavailable: {exc}') from exc
        commit = git('cat-file', '-t', ref['source_commit'])
        if commit.returncode:
            raise Incomplete('pinned source commit unavailable')
        if commit.stdout.strip() != b'commit':
            raise Rejected('pinned source is not a commit')
        for row in paths.values():
            entry = git('ls-tree', '-z', ref['source_commit'], '--', row['source'])
            if entry.returncode:
                raise Incomplete('pinned source tree unavailable')
            expected_entry = f"100644 blob {row['blob']}\t{row['source']}".encode() + b'\0'
            if entry.stdout != expected_entry:
                raise Rejected('source tree entry differs')
            obj = git('cat-file', 'blob', row['blob'])
            if obj.returncode:
                raise Incomplete('pinned source blob unavailable')
            data = obj.stdout
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if digest(data) != row['sha256'] or blob != row['blob']:
                raise Rejected('source blob or bytes differ')
        return {'status':'admitted', 'observation_id':ref['observation_id'],
                'rows':[{'observation_id':ref['observation_id'], 'corpus_revision':ref['corpus_revision'],
                         'profile':ref['profile'], 'inventory_revision':ref['inventory_revision'],
                         'installed_path':p, 'source':paths[p]['source'], 'blob':paths[p]['blob'],
                         'source_sha256':paths[p]['sha256'], 'routing_status':'inconclusive',
                         'routing_reason':'markup_not_modeled',
                         'ast_scope':'selected' if p == ref['ast_scope'] else 'outside_scope'} for p in sorted(paths)],
                'limits':'Historical source-relative query outputs only; original stage equality is reported, not revalidated. No execution trust, complete AST, runtime, policy, or security claim.'}
    except Incomplete as exc:
        return {'status':'incomplete', 'reason':str(exc)}
    except (Rejected, KeyError, TypeError) as exc:
        return {'status':'rejected', 'reason':str(exc)}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path, help='Git repository containing pinned LuCI commit')
    p.add_argument('--profile', default='luci-ssl-25.12')
    p.add_argument('--reference', type=Path, default=Path(__file__).with_name('reference.json'))
    p.add_argument('--evidence-root', type=Path, default=ROOT / 'evidence/markup-profile-0a6612f')
    p.add_argument('--lock', type=Path, default=ROOT / 'corpus/lock.json')
    p.add_argument('--inventory', type=Path, default=ROOT / 'reports/m4-luci-ssl-files.json')
    args = p.parse_args()
    result = validate(args.reference, args.evidence_root, args.source, args.profile, args.lock, args.inventory)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'admitted' else 1

if __name__ == '__main__':
    raise SystemExit(main())
