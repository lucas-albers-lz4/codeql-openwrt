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
    # Approval is an external reviewer's context digest, not an authentication mechanism.
    if approval != sha(context_file): fail('reviewed context digest mismatch')
    if context['oracle_sha256'] != sha(oracle_file): fail('oracle mismatch')
    if list(context['commands']) != list(STAGES): fail('stage sequence mismatch')
    if set(context) != {'oracle_sha256','commands','inputs','run','initial','git','outputs'}: fail('context fields')
    if set(context['outputs']) != {'extracted','errors','effects','typed'}: fail('output roles')
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
    if len(set(paths.values())) != len(paths): fail('duplicate inventory paths')
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
    for stage in STAGES:
        cfg = context['commands'][stage]
        if stage != 'reimport':
            current = snapshot()
            for name in roots:
                if (name != 'consumer' or stage != 'import') and current[name] != initial[name]: fail('input drift: ' + name)
        if stage == 'export':
            for name in ('extracted', 'errors', 'effects'): exact(name, name + '_rows')
        if stage == 'import' and load(paths['typed']) != oracle['neutral_typed_payload']:
            fail('typed payload mismatch')
        before = snapshot(); start = time.time_ns()
        stdout = run / (stage + '.stdout'); stderr = run / (stage + '.stderr')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            result = subprocess.run(cfg['argv'], cwd=cfg['cwd'], env=cfg['env'], stdout=out, stderr=err, check=False)
        after = snapshot(); end = time.time_ns()
        for name in roots:
            if (name != 'consumer' or stage in ('init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode','export')) and after[name] != initial[name]: fail('input drift: ' + name)
        receipt = {'stage': stage, 'context_sha256': approval, 'argv': cfg['argv'],
                   'cwd': cfg['cwd'], 'environment': cfg['env'], 'exit_code': result.returncode,
                   'start_ns': start, 'end_ns': end, 'before': before, 'after': after,
                   'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
        with (run / (stage + '.receipt.json')).open('x') as f: json.dump(receipt, f, sort_keys=True)
        if result.returncode: fail('stage failed: ' + stage)
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
