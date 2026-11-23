#!/usr/bin/env python3
"""Run a frozen, reviewed twelve-stage typed handoff in a fresh directory.

Receipts describe an observation; they do not authenticate command execution.
"""
import hashlib
import json
import re
import shutil
import os
from pathlib import Path
import subprocess
import sys
import time

STAGES = ('init', 'index', 'finalize', 'extracted_query', 'extracted_decode',
          'errors_query', 'errors_decode', 'effects_query', 'effects_decode',
          'export', 'import', 'reimport')

def family_check(context, oracle):
    source = 'usr/share/rpcd/ucode/luci'
    if set(context['git']) != {'producer','consumer'} or not all(type(v) is str and len(v) == 40 and all(c in '0123456789abcdef' for c in v) for v in context['git'].values()): raise ValueError('git pins')
    expected = {'effects_rows':'534c56fb839086b13015a79dee7a6e6037490c8e245012ffade21e6a2d214949',
                'errors_rows':'da8d8575723b6f72f2bf8bffc2ea5b27156d34a16465409667d24dc96ffccd95',
                'neutral_typed_payload':'d95f8db3493aa677b19a3e78b875eb0a064ff74341837d2f5c1a8b586c24aec4'}
    for name, wanted in expected.items():
        data = json.dumps(oracle[name], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if hashlib.sha256(data).hexdigest() != wanted: raise ValueError('family oracle: ' + name)
    if oracle['source'] != source or oracle['source_sha256'] != '6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e' or oracle['lock_sha256'] != 'b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a': raise ValueError('family source or lock')
    if context['initial']['consumer']['corpus/lock.json']['sha256'] != oracle['lock_sha256']: raise ValueError('consumer lock')
    if sorted(oracle['expected_effects']) != ['reports/handler_effects.json','reports/m4-block-device-exec.json']: raise ValueError('family reports')
    files = context['initial']['source']
    if set(files) != {source, 'usr','usr/share','usr/share/rpcd','usr/share/rpcd/ucode'} or files[source]['sha256'] != oracle['source_sha256']: raise ValueError('source inventory')
    expected_rows = [['f','col1'], [str(Path(context['inputs']['source']) / source), '']]
    if oracle['extracted_rows'] != expected_rows: raise ValueError('extracted identity')

def log_only(before, after):
    if type(before) is not dict or type(after) is not dict: return False
    added = set(after) - set(before)
    if any(after.get(k) != v for k,v in before.items()) or len(added) != 2: return False
    return all(type(after[name]) is dict and set(after[name]) == {'sha256','size'} for name in added) and sum(bool(re.fullmatch(r'log/execute-queries-[^/]+\.log', name)) for name in added) == 1 and sum(bool(re.fullmatch(r'log/query-run-[^/]+\.log', name)) for name in added) == 1

def same(a, b):
    return json.dumps(a, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(b, sort_keys=True, separators=(',', ':'), allow_nan=False)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def load(path):
    return parse(path.read_bytes())

def inventory(path):
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError('symlink inventory root')
    if path.is_file():
        if path.stat().st_nlink != 1: raise ValueError('hardlinked file: ' + str(path))
        return {'sha256': sha(path), 'size': path.stat().st_size}
    result = {}
    def walk_error(exc): raise exc
    for directory, dirs, files in os.walk(path, followlinks=False, onerror=walk_error):
        dirs.sort(); files.sort()
        for name in dirs + files:
            p = Path(directory) / name
            if p.is_symlink():
                raise ValueError('symlink in inventory: ' + str(p))
            if p.is_dir():
                result[str(p.relative_to(path))] = {'directory': True}
            elif p.is_file():
                if p.stat().st_nlink != 1: raise ValueError('hardlinked input: ' + str(p))
                result[str(p.relative_to(path))] = {'sha256': sha(p), 'size': p.stat().st_size}
            else:
                raise ValueError('unsupported filesystem entry: ' + str(p))
    return result

def fail(message):
    raise ValueError(message)

def no_symlink_components(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: fail('path must be absolute and normalized')
    for part in (path, *path.parents):
        if part.is_symlink(): fail('symlink path component: ' + str(part))


def main(context_file, oracle_file, approval):
    no_symlink_components(context_file); no_symlink_components(oracle_file)
    context_file = Path(context_file).resolve(strict=True)
    oracle_file = Path(oracle_file).resolve(strict=True)
    context_bytes = context_file.read_bytes(); oracle_bytes = oracle_file.read_bytes()
    context = parse(context_bytes); oracle = parse(oracle_bytes)
    family_check(context, oracle)
    # Approval is an external reviewer's context digest, not an authentication mechanism.
    if approval != hashlib.sha256(context_bytes).hexdigest(): fail('reviewed context digest mismatch')
    if context['oracle_sha256'] != hashlib.sha256(oracle_bytes).hexdigest(): fail('oracle mismatch')
    if sha(Path(__file__)) != context['runner_sha256'] or sha(Path(__file__).with_name('verify.py')) != context['verifier_sha256']: fail('implementation digest mismatch')
    for command in context['commands'].values():
        exe = command['argv'][0]
        no_symlink_components(exe)
        if not Path(exe).is_file() or not os.access(exe, os.X_OK): fail('invalid executable')
        if exe not in context['executables'] or sha(Path(exe)) != context['executables'][exe]: fail('executable digest mismatch')
    if list(context['commands']) != list(STAGES): fail('stage sequence mismatch')
    if set(context) != {'oracle_sha256','commands','inputs','run','initial','git','outputs','executables','runner_sha256','verifier_sha256','git_executable','git_env','required_absent','runtime_transitions'}: fail('context fields')
    if set(context['outputs']) != {'runtime','database','extracted_bqrs','errors_bqrs','effects_bqrs','extracted','errors','effects','typed'}: fail('output roles')
    if set(context['initial']) != set(context['inputs']) or 'consumer' not in context['inputs']: fail('input roles')
    for value in context['inputs'].values(): no_symlink_components(value)
    no_symlink_components(context['run'])
    roots = {k: Path(v).resolve(strict=True) for k, v in context['inputs'].items()}
    run = Path(context['run'])
    if not run.is_absolute() or run.exists(): fail('run directory must be fresh and absolute')
    run = run.parent.resolve(strict=True) / run.name
    if any(run == p or run in p.parents or p in run.parents for p in roots.values()):
        fail('run overlaps an input')
    if any(a == b or a in b.parents or b in a.parents for i,a in enumerate(roots.values()) for b in list(roots.values())[i+1:]): fail('input roots must be distinct and disjoint')
    for name, root in roots.items():
        if inventory(root) != context['initial'][name]: fail('input inventory mismatch: ' + name)
    git_exe, git_env = context['git_executable'], context['git_env']
    no_symlink_components(git_exe)
    if not Path(git_exe).is_file() or not os.access(git_exe, os.X_OK): fail('invalid git executable')
    if git_exe not in context['executables'] or sha(Path(git_exe)) != context['executables'][git_exe]: fail('git executable digest mismatch')
    git_receipts = {}
    for role, pin in context['git'].items():
        root = roots[role]
        head_argv = [git_exe, 'rev-parse', 'HEAD']; status_argv = [git_exe, 'status', '--porcelain', '--untracked-files=all']
        head = subprocess.check_output(head_argv, cwd=root, env=git_env, text=True)
        status = subprocess.check_output(status_argv, cwd=root, env=git_env, text=True)
        if head.strip() != pin or status: fail('unclean or wrong git input: ' + role)
        git_receipts[role] = {'cwd':str(root),'env':git_env,'head_argv':head_argv,'head_stdout':head,'status_argv':status_argv,'status_stdout':status}
    paths = {**roots, **{k: run / v for k, v in context['outputs'].items()}}
    output_paths = [paths[k] for k in context['outputs']]
    if any(a == b or a in b.parents or b in a.parents for i,a in enumerate(output_paths) for b in output_paths[i+1:]): fail('overlapping output paths')
    for name, relative in context['outputs'].items():
        p = Path(relative)
        if p.is_absolute() or '..' in p.parts or not p.parts: fail('invalid output path')
        if paths[name].exists(): fail('output already exists')
    if type(context['runtime_transitions']) is not dict or list(context['runtime_transitions']) != list(STAGES): fail('runtime transition stages')
    for allowed in context['runtime_transitions'].values():
        if type(allowed) is not list or len(set(allowed)) != len(allowed) or any(type(p) is not str or not p or p == '.' or p != str(Path(p)) or Path(p).is_absolute() or '..' in Path(p).parts for p in allowed): fail('invalid runtime allowlist')
    if type(context['required_absent']) is not list or not context['required_absent'] or any(type(v) is not str or Path(v).is_absolute() or '..' in Path(v).parts or paths['runtime'] not in (run/v).parents for v in context['required_absent']) or len(set(context['required_absent'])) != len(context['required_absent']): fail('invalid required absence paths')
    reserved = [run/'context.json', run/'oracle.json', run/'git-preflight.json', run/'reports', run/'inputs', run/'implementation'] + [run/(stage+suffix) for stage in STAGES for suffix in ('.stdout','.stderr','.receipt.json','.failure.json')]
    if any(a == b or a in b.parents or b in a.parents for a in output_paths for b in reserved): fail('output collides with reserved packet path')
    run.mkdir(mode=0o700)
    (run / 'context.json').write_bytes(context_bytes)
    (run / 'oracle.json').write_bytes(oracle_bytes)
    with (run/'git-preflight.json').open('x') as f: json.dump(git_receipts, f, sort_keys=True)
    (run / 'implementation').mkdir()
    shutil.copyfile(Path(__file__), run/'implementation/runner.py')
    shutil.copyfile(Path(__file__).with_name('verify.py'), run/'implementation/verify.py')
    (run / 'inputs').mkdir()
    shutil.copyfile(roots['source']/oracle['source'], run/'inputs/source')
    shutil.copyfile(roots['consumer']/'corpus/lock.json', run/'inputs/lock.json')
    paths['runtime'].mkdir(parents=True)
    def snapshot(): return {k: inventory(v) for k, v in paths.items()}
    def exact(name, key):
        import csv
        with paths[name].open(newline='') as stream:
            if list(csv.reader(stream)) != oracle[key]: fail('oracle mismatch: ' + name)
    initial = snapshot()
    imported = None
    for stage in STAGES:
        cfg = context['commands'][stage]
        if sha(Path(cfg['argv'][0])) != context['executables'][cfg['argv'][0]]: fail('executable drift: ' + stage)
        if set(cfg) != {'argv','cwd','env'} or not isinstance(cfg['argv'], list) or not cfg['argv'] or not all(type(x) is str for x in cfg['argv']) or type(cfg['cwd']) is not str or type(cfg['env']) is not dict or not all(type(k) is str and type(v) is str for k,v in cfg['env'].items()): fail('invalid command: ' + stage)
        if stage != 'reimport':
            current = snapshot()
            for name in roots:
                if (name != 'consumer' or stage != 'import') and current[name] != initial[name]: fail('input drift: ' + name)
        if stage == 'export':
            for name in ('extracted', 'errors', 'effects'): exact(name, name + '_rows')
        if stage == 'import' and not same(load(paths['typed']), oracle['neutral_typed_payload']):
            fail('typed payload mismatch')
        if stage == 'reimport':
            for name in oracle['expected_effects']:
                before_report = parse((run/'reports'/'init'/name).read_bytes())
                after_bytes = (roots['consumer']/name).read_bytes()
                if after_bytes != (run/'reports'/'import'/name).read_bytes(): fail('first import snapshot mismatch')
                after_report = parse(after_bytes)
                target = oracle['prestate_provenance'][name]['target_index']
                if type(target) is not int or target < 0: fail('invalid target index')
                def positions(rows): return [i for i,row in enumerate(rows) if row.get('record_id') == 'm4:effect:luci-setBlockDetect-system']
                if positions(before_report) != [target] or positions(after_report) != [target]: fail('target position mismatch')
                if not same(after_report[target],oracle['expected_complete_targets'][name][0]): fail('import target mismatch')
                if not same(before_report[:target]+before_report[target+1:],after_report[:target]+after_report[target+1:]): fail('other report rows changed')

        before = snapshot()
        if not paths['runtime'].is_dir(): fail('runtime is not a directory')
        if stage == 'reimport' and before != imported: fail('pre-reimport state changed')
        created = {'init':'database', 'extracted_query':'extracted_bqrs', 'errors_query':'errors_bqrs', 'effects_query':'effects_bqrs', 'extracted_decode':'extracted', 'errors_decode':'errors', 'effects_decode':'effects', 'export':'typed'}.get(stage)
        if created and before[created] is not None: fail('output not absent: ' + created)
        start = time.time_ns()
        stdout = run / (stage + '.stdout'); stderr = run / (stage + '.stderr')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                result = subprocess.run(cfg['argv'], cwd=cfg['cwd'], env=cfg['env'], stdout=out, stderr=err, check=False)
                exit_code = result.returncode
            except OSError as exc:
                err.write(('execution error: ' + str(exc) + '\n').encode())
                exit_code = 127
        try:
            if exit_code == 0 and stage in ('extracted_decode','errors_decode','effects_decode','export'):
                name = stage.removesuffix('_decode') if stage != 'export' else 'typed'
                with paths[name].open('xb') as target: target.write(stdout.read_bytes())
            after = snapshot(); end = time.time_ns()
            if any((run/rel).exists() or (run/rel).is_symlink() for rel in context['required_absent']): fail('required path exists')
        except (OSError, ValueError) as exc:
            failure = {'stage':stage, 'context_sha256':approval, 'argv':cfg['argv'], 'cwd':cfg['cwd'],
                       'environment':cfg['env'], 'exit_code':exit_code, 'start_ns':start,
                       'end_ns':time.time_ns(), 'before':before, 'snapshot_error':str(exc),
                       'stdout_sha256':sha(stdout), 'stderr_sha256':sha(stderr)}
            with (run/(stage+'.failure.json')).open('x') as f: json.dump(failure, f, sort_keys=True)
            fail('stage artifact or snapshot failed: '+stage)
        receipt = {'stage': stage, 'context_sha256': approval, 'argv': cfg['argv'],
                   'cwd': cfg['cwd'], 'environment': cfg['env'], 'exit_code': exit_code,
                   'start_ns': start, 'end_ns': end, 'before': before, 'after': after,
                   'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
        with (run / (stage + '.receipt.json')).open('x') as f: json.dump(receipt, f, sort_keys=True)
        if exit_code: fail('stage failed: ' + stage)
        if created and after[created] is None: fail('output not created: ' + created)
        if stage == 'init' and not paths['database'].is_dir(): fail('database must be a directory')
        if not paths['runtime'].is_dir(): fail('runtime is not a directory')
        if stage.endswith('_query') and not log_only(before['database'],after['database']): fail('query log transition')
        allowed = context['runtime_transitions'][stage]
        if type(allowed) is not list or any(type(p) is not str or not p or Path(p).is_absolute() or '..' in Path(p).parts for p in allowed): fail('invalid runtime allowlist')
        changed_runtime = {k for k in set(before['runtime']) | set(after['runtime']) if before['runtime'].get(k) != after['runtime'].get(k)}
        if any(not any(k == prefix or k.startswith(prefix+'/') for prefix in allowed) for k in changed_runtime): fail('unexpected runtime transition')
        for name in context['outputs']:
            if name != created and name != 'runtime' and before[name] != after[name]:
                permitted_db = name == 'database' and (stage in ('index','finalize') or (stage.endswith('_query') and log_only(before[name], after[name])))
                if not permitted_db: fail('unexpected output transition: ' + name)
        for name in roots:
            if (name != 'consumer' or stage in ('init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode','export')) and after[name] != initial[name]: fail('input drift: ' + name)
        if stage == 'import':
            before_consumer, after_consumer = before['consumer'], after['consumer']
            changed = sorted(k for k in set(before_consumer) | set(after_consumer) if before_consumer.get(k) != after_consumer.get(k))
            if changed != sorted(oracle['expected_effects']): fail('unexpected consumer changes')
            if before['typed'] != after['typed']: fail('typed input changed')
            imported = after
        if stage == 'reimport':
            if imported is None or before != imported or after['consumer'] != imported['consumer'] or after['typed'] != imported['typed']:
                fail('replay changed consumer or typed input')
        if stage in ('init', 'import', 'reimport'):
            consumer = roots['consumer']
            for name in oracle['expected_effects']:
                target = run / 'reports' / stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as f: f.write((consumer / name).read_bytes())
    print('Stages completed; independent verification still required.')

if __name__ == '__main__':
    try:
        if len(sys.argv) != 5 or sys.argv[1] != '--synthetic-only':
            fail('prototype requires --synthetic-only; real runs are not supported')
        main(*sys.argv[2:])
    except (ValueError, KeyError, TypeError, IndexError, OSError, subprocess.SubprocessError) as exc:
        print('handoff failed:', exc, file=sys.stderr); sys.exit(1)
