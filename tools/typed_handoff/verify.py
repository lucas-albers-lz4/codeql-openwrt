#!/usr/bin/env python3
"""Independent offline checks for experimental handoff packets.

This checks retained evidence against external context and oracle, not execution trust.
"""
import csv
import hashlib
import json
from pathlib import Path
import sys

STAGES = ('init','index','finalize','extracted_query','extracted_decode',
          'errors_query','errors_decode','effects_query','effects_decode','export','import','reimport')
def digest(data): return hashlib.sha256(data).hexdigest()
def read_json(path):
    def pairs(items):
        obj = {}
        for key, val in items:
            if key in obj: raise ValueError('duplicate key: ' + key)
            obj[key] = val
        return obj
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
def require(condition, text):
    if not condition: raise ValueError(text)
def verify(packet, context_file, oracle_file, expected_context, expected_oracle):
    packet = Path(packet); context_file = Path(context_file); oracle_file = Path(oracle_file)
    require(digest(context_file.read_bytes()) == expected_context, 'context digest')
    require(digest(oracle_file.read_bytes()) == expected_oracle, 'oracle digest')
    context, oracle = read_json(context_file), read_json(oracle_file)
    require(context['oracle_sha256'] == expected_oracle, 'oracle binding')
    require((packet/'context.json').read_bytes() == context_file.read_bytes(), 'packet context')
    require((packet/'oracle.json').read_bytes() == oracle_file.read_bytes(), 'packet oracle')
    require(list(context['commands']) == list(STAGES), 'stages')
    receipts = []
    for stage in STAGES:
        rec = read_json(packet / (stage + '.receipt.json')); cfg = context['commands'][stage]
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
    for name in ('extracted','errors','effects'):
        with (packet/context['outputs'][name]).open(newline='') as f: rows = list(csv.reader(f))
        require(rows == oracle[name+'_rows'], 'rows: '+name)
    require(read_json(packet/context['outputs']['typed']) == oracle['neutral_typed_payload'], 'typed')
    imp = receipts[STAGES.index('import')]; replay = receipts[-1]
    before, after = imp['before']['consumer'], imp['after']['consumer']
    require(imp['after']['consumer'] == replay['before']['consumer'] == replay['after']['consumer'], 'replay inventory')
    changed = sorted(k for k in set(before)|set(after) if before.get(k) != after.get(k))
    require(changed == sorted(oracle['expected_effects']), 'consumer changed paths')
    for name in oracle['expected_effects']:
        raw = [(packet/'reports'/phase/name).read_bytes() for phase in ('init','import','reimport')]
        require(digest(raw[0]) == before[name]['sha256'], 'before report: '+name)
        require(digest(raw[1]) == after[name]['sha256'] and raw[1] == raw[2], 'replay report: '+name)
        rows = [json.loads(b) for b in raw]
        positions = [[i for i,x in enumerate(row) if x.get('record_id') == 'm4:effect:luci-setBlockDetect-system'] for row in rows]
        require(positions[0] == positions[1] == positions[2] == [oracle['prestate_provenance'][name]['target_index']], 'target position: '+name)
        i = positions[0][0]
        require(rows[1][i] == oracle['expected_complete_targets'][name][0], 'target: '+name)
        require(rows[0][:i]+rows[0][i+1:] == rows[1][:i]+rows[1][i+1:], 'other rows: '+name)
    print('Packet checks passed; execution is not authenticated.')
if __name__ == '__main__':
    try:
        if len(sys.argv) != 6: raise ValueError('usage: verify.py PACKET CONTEXT ORACLE CONTEXT_SHA256 ORACLE_SHA256')
        verify(*sys.argv[1:])
    except (ValueError, KeyError, OSError, TypeError, IndexError) as exc:
        print('verification failed:', exc, file=sys.stderr); sys.exit(1)
