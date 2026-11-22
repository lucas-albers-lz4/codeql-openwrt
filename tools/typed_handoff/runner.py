#!/usr/bin/env python3
"""Run a frozen, reviewed twelve-stage typed handoff in a fresh directory.

Receipts describe an observation; they do not authenticate command execution.
"""
import hashlib
import json
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
    expected = {'effects_rows':'534c56fb839086b13015a79dee7a6e6037490c8e245012ffade21e6a2d214949',
                'errors_rows':'da8d8575723b6f72f2bf8bffc2ea5b27156d34a16465409667d24dc96ffccd95',
                'neutral_typed_payload':'d95f8db3493aa677b19a3e78b875eb0a064ff74341837d2f5c1a8b586c24aec4'}
    for name, wanted in expected.items():
        data = json.dumps(oracle[name], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if hashlib.sha256(data).hexdigest() != wanted: raise ValueError('family oracle: ' + name)
    if oracle['source'] != source or oracle['source_sha256'] != '6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e' or oracle['lock_sha256'] != 'b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a': raise ValueError('family source or lock')
    files = context['initial']['source']
    if set(files) != {source} or files[source]['sha256'] != oracle['source_sha256']: raise ValueError('source inventory')
    expected_rows = [['f','col1'], [str(Path(context['inputs']['source']) / source), '']]
    if oracle['extracted_rows'] != expected_rows: raise ValueError('extracted identity')

def same(a, b):
    return json.dumps(a, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(b, sort_keys=True, separators=(',', ':'), allow_nan=False)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def inventory(path):
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError('symlink inventory root')
    if path.is_file():
        if path.stat().st_nlink != 1: raise ValueError('hardlinked file: ' + str(path))
        return {'sha256': sha(path), 'size': path.stat().st_size}
    result = {}
    for directory, dirs, files in os.walk(path, followlinks=False):
        dirs.sort(); files.sort()
        for name in dirs + files:
            p = Path(directory) / name
            if p.is_symlink():
                raise ValueError('symlink in inventory: ' + str(p))
            if p.is_file():
                if p.stat().st_nlink != 1: raise ValueError('hardlinked input: ' + str(p))
                result[str(p.relative_to(path))] = {'sha256': sha(p), 'size': p.stat().st_size}
    return result

def fail(message):
    raise ValueError(message)

def main(context_file, oracle_file, approval):
    context_file = Path(context_file).resolve(strict=True)
    oracle_file = Path(oracle_file).resolve(strict=True)
    context = load(context_file); oracle = load(oracle_file)
    family_check(context, oracle)
    # Approval is an external reviewer's context digest, not an authentication mechanism.
    if approval != sha(context_file): fail('reviewed context digest mismatch')
    if context['oracle_sha256'] != sha(oracle_file): fail('oracle mismatch')
    if list(context['commands']) != list(STAGES): fail('stage sequence mismatch')
    if set(context) != {'oracle_sha256','commands','inputs','run','initial','git','outputs'}: fail('context fields')
    if set(context['outputs']) != {'database','extracted_bqrs','errors_bqrs','effects_bqrs','extracted','errors','effects','typed'}: fail('output roles')
    if set(context['initial']) != set(context['inputs']) or 'consumer' not in context['inputs']: fail('input roles')
    if any(Path(v).is_symlink() for v in context['inputs'].values()): fail('symlink input root')
    roots = {k: Path(v).resolve(strict=True) for k, v in context['inputs'].items()}
    run = Path(context['run'])
    if not run.is_absolute() or run.exists(): fail('run directory must be fresh and absolute')
    run = run.parent.resolve(strict=True) / run.name
    if any(run == p or run in p.parents or p in run.parents for p in roots.values()):
        fail('run overlaps an input')
    if any(a == b or a in b.parents or b in a.parents for i,a in enumerate(roots.values()) for b in list(roots.values())[i+1:]): fail('input roots must be distinct and disjoint')
    for name, root in roots.items():
        if inventory(root) != context['initial'][name]: fail('input inventory mismatch: ' + name)
    for role, pin in context['git'].items():
        root = roots[role]
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
        status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root, text=True)
        if head != pin or status: fail('unclean or wrong git input: ' + role)
    run.mkdir(mode=0o700)
    (run / 'context.json').write_bytes(context_file.read_bytes())
    (run / 'oracle.json').write_bytes(oracle_file.read_bytes())
    paths = {**roots, **{k: run / v for k, v in context['outputs'].items()}}
    output_paths = [paths[k] for k in context['outputs']]
    if any(a == b or a in b.parents or b in a.parents for i,a in enumerate(output_paths) for b in output_paths[i+1:]): fail('overlapping output paths')
    for name, relative in context['outputs'].items():
        p = Path(relative)
        if p.is_absolute() or '..' in p.parts or not p.parts: fail('invalid output path')
        if paths[name].exists(): fail('output already exists')
    def snapshot(): return {k: inventory(v) for k, v in paths.items()}
    def exact(name, key):
        import csv
        with paths[name].open(newline='') as stream:
            if list(csv.reader(stream)) != oracle[key]: fail('oracle mismatch: ' + name)
    initial = snapshot()
    imported = None
    for stage in STAGES:
        cfg = context['commands'][stage]
        if set(cfg) != {'argv','cwd','env'} or not isinstance(cfg['argv'], list) or not cfg['argv'] or not all(type(x) is str for x in cfg['argv']) or type(cfg['cwd']) is not str or type(cfg['env']) is not dict or not all(type(k) is str and type(v) is str for k,v in cfg['env'].items()): fail('invalid command: ' + stage)
        if stage != 'reimport':
            current = snapshot()
            for name in roots:
                if (name != 'consumer' or stage != 'import') and current[name] != initial[name]: fail('input drift: ' + name)
        if stage == 'export':
            for name in ('extracted', 'errors', 'effects'): exact(name, name + '_rows')
        if stage == 'import' and not same(load(paths['typed']), oracle['neutral_typed_payload']):
            fail('typed payload mismatch')
        before = snapshot()
        created = {'init':'database', 'extracted_query':'extracted_bqrs', 'errors_query':'errors_bqrs', 'effects_query':'effects_bqrs', 'extracted_decode':'extracted', 'errors_decode':'errors', 'effects_decode':'effects', 'export':'typed'}.get(stage)
        if created and before[created] is not None: fail('output not absent: ' + created)
        start = time.time_ns()
        stdout = run / (stage + '.stdout'); stderr = run / (stage + '.stderr')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            result = subprocess.run(cfg['argv'], cwd=cfg['cwd'], env=cfg['env'], stdout=out, stderr=err, check=False)
        if stage in ('extracted_decode','errors_decode','effects_decode','export'):
            name = stage.removesuffix('_decode') if stage != 'export' else 'typed'
            with paths[name].open('xb') as target: target.write(stdout.read_bytes())
        after = snapshot(); end = time.time_ns()
        if created and after[created] is None: fail('output not created: ' + created)
        for name in context['outputs']:
            if name != created and not (name == 'database' and stage in ('index','finalize')) and before[name] != after[name]: fail('unexpected output transition: ' + name)
        for name in roots:
            if (name != 'consumer' or stage in ('init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode','export')) and after[name] != initial[name]: fail('input drift: ' + name)
        receipt = {'stage': stage, 'context_sha256': approval, 'argv': cfg['argv'],
                   'cwd': cfg['cwd'], 'environment': cfg['env'], 'exit_code': result.returncode,
                   'start_ns': start, 'end_ns': end, 'before': before, 'after': after,
                   'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
        with (run / (stage + '.receipt.json')).open('x') as f: json.dump(receipt, f, sort_keys=True)
        if result.returncode: fail('stage failed: ' + stage)
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
                target.write_bytes((consumer / name).read_bytes())
    print('Stages completed; independent verification still required.')

if __name__ == '__main__':
    try:
        if len(sys.argv) != 5 or sys.argv[1] != '--synthetic-only':
            fail('prototype requires --synthetic-only; real runs are not supported')
        main(*sys.argv[2:])
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print('handoff failed:', exc, file=sys.stderr); sys.exit(1)
