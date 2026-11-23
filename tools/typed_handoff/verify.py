#!/usr/bin/env python3
"""Independent offline checks for experimental handoff packets.

This checks retained evidence against external context and oracle, not execution trust.
"""
import csv
import hashlib
import json
import os
import re
from pathlib import Path
import sys

STAGES = ('init','index','finalize','extracted_query','extracted_decode',
          'errors_query','errors_decode','effects_query','effects_decode','export','import','reimport')
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
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    return all(re.fullmatch(r'log/(?:execute-queries|query-run)-[^/]+\.log', name) for name in changed)

def same(a, b):
    return json.dumps(a, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(b, sort_keys=True, separators=(',', ':'), allow_nan=False)

def digest(data): return hashlib.sha256(data).hexdigest()
def parse(data):
    def pairs(items):
        obj = {}
        for key, val in items:
            if key in obj: raise ValueError('duplicate key: ' + key)
            obj[key] = val
        return obj
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
def read_json(path): return parse(path.read_bytes())
def inventory(root):
    if root.is_symlink(): raise ValueError('symlink: '+str(root))
    if not root.exists(): raise ValueError('missing: '+str(root))
    if root.is_file():
        if root.stat().st_nlink != 1: raise ValueError('hardlink: '+str(root))
        return {'sha256': digest(root.read_bytes()), 'size': root.stat().st_size}
    result = {}
    def error(exc): raise exc
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=error):
        for name in sorted(dirs+files):
            p = Path(directory)/name; key = str(p.relative_to(root))
            if p.is_symlink(): raise ValueError('symlink: '+key)
            if p.is_dir(): result[key] = {'directory':True}
            elif p.is_file():
                if p.stat().st_nlink != 1: raise ValueError('hardlink: '+key)
                result[key] = {'sha256':digest(p.read_bytes()),'size':p.stat().st_size}
            else: raise ValueError('special entry: '+key)
    return result

def require(condition, text):
    if not condition: raise ValueError(text)
def verify(packet, context_file, oracle_file, expected_context, expected_oracle):
    packet = Path(packet); context_file = Path(context_file); oracle_file = Path(oracle_file)
    for path in (packet, context_file, oracle_file):
        require(path.is_absolute() and '..' not in path.parts, 'non-absolute or traversing path')
        require(not any(part.is_symlink() for part in (path, *path.parents)), 'symlink path')
    context_bytes, oracle_bytes = context_file.read_bytes(), oracle_file.read_bytes()
    require(digest(context_bytes) == expected_context, 'context digest')
    require(digest(oracle_bytes) == expected_oracle, 'oracle digest')
    context, oracle = parse(context_bytes), parse(oracle_bytes)
    require(set(context) == {'oracle_sha256','commands','inputs','run','initial','git','outputs','executables','runner_sha256','verifier_sha256'}, 'context fields')
    family_check(context, oracle)
    require(digest((packet/'implementation/runner.py').read_bytes()) == context['runner_sha256'], 'runner digest')
    require(digest((packet/'implementation/verify.py').read_bytes()) == context['verifier_sha256'] == digest(Path(__file__).read_bytes()), 'verifier digest')
    require(context['oracle_sha256'] == expected_oracle, 'oracle binding')
    require((packet/'context.json').read_bytes() == context_bytes, 'packet context')
    require((packet/'oracle.json').read_bytes() == oracle_bytes, 'packet oracle')
    require(list(context['commands']) == list(STAGES), 'stages')
    receipts = []
    for stage in STAGES:
        rec = read_json(packet / (stage + '.receipt.json')); cfg = context['commands'][stage]
        require(set(rec) == {'stage','context_sha256','argv','cwd','environment','exit_code','start_ns','end_ns','before','after','stdout_sha256','stderr_sha256'}, 'receipt fields: '+stage)
        require(cfg['argv'][0] in context['executables'], 'executable role: '+stage)
        require(set(cfg) == {'argv','cwd','env'} and type(cfg['argv']) is list and bool(cfg['argv']) and all(type(x) is str for x in cfg['argv']) and type(cfg['cwd']) is str and type(cfg['env']) is dict and all(type(k) is str and type(v) is str for k,v in cfg['env'].items()), 'command fields: '+stage)
        require(set(rec['before']) == set(context['inputs']) | set(context['outputs']) and set(rec['after']) == set(rec['before']), 'inventory roles: '+stage)
        require(rec['stage'] == stage and rec['context_sha256'] == expected_context, 'receipt identity: '+stage)
        require(rec['argv'] == cfg['argv'] and rec['cwd'] == cfg['cwd'] and rec['environment'] == cfg['env'], 'command: '+stage)
        require(type(rec['exit_code']) is int and rec['exit_code'] == 0, 'exit: '+stage)
        require(type(rec['start_ns']) is int and type(rec['end_ns']) is int and rec['start_ns'] <= rec['end_ns'], 'time: '+stage)
        for stream in ('stdout','stderr'):
            require(digest((packet/(stage+'.'+stream)).read_bytes()) == rec[stream+'_sha256'], 'stream: '+stage)
        if receipts:
            require(receipts[-1]['end_ns'] <= rec['start_ns'], 'stage order')
            require(receipts[-1]['after'] == rec['before'], 'state continuity')
        receipts.append(rec)
    require(digest((packet/'inputs/source').read_bytes()) == oracle['source_sha256'], 'retained source')
    require(digest((packet/'inputs/lock.json').read_bytes()) == oracle['lock_sha256'], 'retained lock')
    require((packet/context['outputs']['database']).is_dir(), 'database directory')
    require(inventory(packet/context['outputs']['database']) == receipts[-1]['after']['database'], 'database inventory')
    expected_files = {'context.json','oracle.json','inputs/source','inputs/lock.json','implementation/runner.py','implementation/verify.py'}
    expected_files.update(stage+suffix for stage in STAGES for suffix in ('.stdout','.stderr','.receipt.json'))
    for name, rel in context['outputs'].items():
        if name == 'database':
            expected_files.add(rel)
            expected_files.update(str(Path(rel)/child) for child in receipts[-1]['after'][name])
        else: expected_files.add(rel)
    expected_files.update(str(Path('reports')/phase/name) for phase in ('init','import','reimport') for name in oracle['expected_effects'])
    expected_paths = set(expected_files)
    for name in list(expected_files):
        expected_paths.update(str(parent) for parent in Path(name).parents if str(parent) != '.')
    packet_inventory = inventory(packet)
    require(set(packet_inventory) == expected_paths, 'packet inventory')
    initial = receipts[0]['before']
    for name, value in context['initial'].items():
        require(initial[name] == value, 'initial: '+name)
    for name in context['inputs']:
        if name != 'consumer':
            require(all(r[edge][name] == initial[name] for r in receipts for edge in ('before','after')), 'input drift: '+name)
    for name, rel in context['outputs'].items():
        require(initial[name] is None, 'output not absent: '+name)
        p = Path(rel)
        require(not p.is_absolute() and '..' not in p.parts, 'output path')
    require(set(context['outputs']) == {'database','extracted_bqrs','errors_bqrs','effects_bqrs','extracted','errors','effects','typed'}, 'output roles')
    creates = {'init':'database', 'extracted_query':'extracted_bqrs', 'errors_query':'errors_bqrs', 'effects_query':'effects_bqrs', 'extracted_decode':'extracted', 'errors_decode':'errors', 'effects_decode':'effects', 'export':'typed'}
    for stage, rec in zip(STAGES, receipts):
        created = creates.get(stage)
        if created:
            require(rec['before'][created] is None and rec['after'][created] is not None, 'creation: '+stage)
        for name in context['outputs']:
            if name != created and rec['before'][name] != rec['after'][name]:
                permitted_db = name == 'database' and (stage in ('index','finalize') or (stage.endswith('_query') and log_only(rec['before'][name], rec['after'][name])))
                require(permitted_db, 'output transition: '+stage+'/'+name)
    for name in ('extracted','errors','effects'):
        bqrs = name+'_bqrs'; raw = (packet/context['outputs'][bqrs]).read_bytes()
        require(receipts[STAGES.index(name+'_query')]['after'][bqrs]['sha256'] == digest(raw), 'bqrs: '+name)
        with (packet/context['outputs'][name]).open(newline='') as f: rows = list(csv.reader(f))
        require(rows == oracle[name+'_rows'], 'rows: '+name)
    require(same(read_json(packet/context['outputs']['typed']), oracle['neutral_typed_payload']), 'typed')
    imp = receipts[STAGES.index('import')]; replay = receipts[-1]
    require(all(r[edge]['consumer'] == initial['consumer'] for r in receipts[:STAGES.index('import')] for edge in ('before','after')), 'early consumer change')
    for name in ('extracted', 'errors', 'effects', 'typed'):
        stage = name + '_decode' if name != 'typed' else 'export'
        rec = receipts[STAGES.index(stage)]
        output = packet / context['outputs'][name]
        require(rec['before'][name] is None, 'output not absent at stage: '+name)
        require(rec['after'][name]['sha256'] == digest(output.read_bytes()) == rec['stdout_sha256'], 'output binding: '+name)
        require(all(r[edge][name] == rec['after'][name] for r in receipts[STAGES.index(stage)+1:] for edge in ('before','after')), 'output drift: '+name)
    before, after = imp['before']['consumer'], imp['after']['consumer']
    require(imp['after']['consumer'] == replay['before']['consumer'] == replay['after']['consumer'], 'replay inventory')
    changed = sorted(k for k in set(before)|set(after) if before.get(k) != after.get(k))
    require(changed == sorted(oracle['expected_effects']), 'consumer changed paths')
    for name in oracle['expected_effects']:
        raw = [(packet/'reports'/phase/name).read_bytes() for phase in ('init','import','reimport')]
        require(digest(raw[0]) == before[name]['sha256'], 'before report: '+name)
        require(digest(raw[1]) == after[name]['sha256'] and raw[1] == raw[2], 'replay report: '+name)
        rows = [parse(b) for b in raw]
        positions = [[i for i,x in enumerate(row) if x.get('record_id') == 'm4:effect:luci-setBlockDetect-system'] for row in rows]
        require(positions[0] == positions[1] == positions[2] == [oracle['prestate_provenance'][name]['target_index']], 'target position: '+name)
        i = positions[0][0]
        require(same(rows[1][i], oracle['expected_complete_targets'][name][0]), 'target: '+name)
        require(same(rows[0][:i]+rows[0][i+1:], rows[1][:i]+rows[1][i+1:]), 'other rows: '+name)
    print('Packet checks passed; execution is not authenticated.')
if __name__ == '__main__':
    try:
        if len(sys.argv) != 6: raise ValueError('usage: verify.py PACKET CONTEXT ORACLE CONTEXT_SHA256 ORACLE_SHA256')
        verify(*sys.argv[1:])
    except (ValueError, KeyError, OSError, TypeError, IndexError) as exc:
        print('verification failed:', exc, file=sys.stderr); sys.exit(1)
