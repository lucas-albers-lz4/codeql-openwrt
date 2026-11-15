#!/usr/bin/python3
"""DRAFT issue 89 orchestration; needs independent review before any real run.

The final packet must supply config.json and preapproved inventories. This module
has not been integration-tested with CodeQL and is not authorized to execute.
"""
# Direct execution is unsafe: fail before importing any packet or stdlib module.
if __name__ == '__main__':
    raise SystemExit('direct execution forbidden; use the independently reviewed isolated bootstrap')

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

import comparator as c
import recorder as r

NAMES = ('effects', 'extracted', 'errors')
REPORTS = ('reports/m4-block-device-exec.json', 'reports/handler_effects.json')

def _copy(source, destination):
    with Path(source).open('rb') as src, Path(destination).open('xb') as dst:
        shutil.copyfileobj(src, dst)

def valid_source_root(path):
    return path.parts[-3:] == ('ql','test','extractor-smoke')

def check_executable_pins(commands, roots):
    pinned = [Path(p) for p in roots]
    for name, spec in commands.items():
        argv = spec['argv']
        if not argv or not Path(argv[0]).is_absolute(): raise ValueError('absolute executable required: '+name)
        exe = Path(argv[0]).resolve(strict=True)
        if not any(exe == root or root in exe.parents for root in pinned):
            raise ValueError('executable outside frozen roots: '+name)

def run(packet, manifest, manifest_sha256, ack, ack_sha256):
    packet = Path(packet).resolve(strict=True)
    # No results directory or child process can exist before this gate.
    r.verify_approval(packet, manifest, manifest_sha256, ack, ack_sha256)
    for module in (sys.modules[__name__], c, r):
        if Path(module.__file__).resolve().parent != packet:
            raise ValueError('executing scripts must be the approved packet bytes')
    cfg = c.load(packet/'config.json')
    attempt = Path(cfg['attempt'])
    if not attempt.is_absolute() or attempt != attempt.parent.resolve(strict=True)/attempt.name:
        raise ValueError('attempt must be a normalized absolute path with an existing parent')
    for p in (packet, Path(cfg['producer']).resolve(), Path(cfg['consumer']).resolve(), Path(cfg['source_root']).resolve(), Path(cfg['codeql_root']).resolve()):
        if attempt == p or attempt in p.parents or p in attempt.parents: raise ValueError('attempt overlaps an input')
    if os.path.lexists(attempt): raise FileExistsError('attempt already exists')
    if len(cfg['commands']) != 15 or set(cfg['commands']) != {'init','index','finalize','export','import','reimport',*[x+'-query' for x in NAMES],*[x+'-decode' for x in NAMES],*[x+'-resolve' for x in NAMES]}:
        raise ValueError('unexpected command set')
    for name, spec in cfg['commands'].items():
        if type(spec) is not dict or set(spec) != {'argv','cwd','env'}:
            raise ValueError('unexpected command fields: '+name)
        argv, cwd, env = spec['argv'], spec['cwd'], spec['env']
        if type(argv) is not list or not argv or not all(type(x) is str and x for x in argv) or not os.path.isabs(argv[0]):
            raise ValueError('invalid command argv: '+name)
        if type(cwd) is not str or not os.path.isabs(cwd): raise ValueError('invalid command cwd: '+name)
        if type(env) is not dict or not all(type(k) is str and type(v) is str for k,v in env.items()):
            raise ValueError('invalid command environment: '+name)
        if any(not k or '=' in k for k in env): raise ValueError('invalid environment key: '+name)
        for value in [*argv, cwd, *env.keys(), *env.values()]:
            if '\0' in value: raise ValueError('NUL in command: '+name)
            try: os.fsencode(value)
            except UnicodeError as exc: raise ValueError('unencodable command: '+name) from exc
    if cfg['commands']['import'] != cfg['commands']['reimport']:
        raise ValueError('reimport must use identical command and environment')
    expected_inputs = c.load(packet/'input-inventories.json')
    required_roots = {cfg['producer'], cfg['consumer'], cfg['source_root'], cfg['codeql_root']}
    if not required_roots.issubset(expected_inputs):
        raise ValueError('incomplete frozen input roots')
    for root, expected in expected_inputs.items():
        p = Path(root)
        if not p.is_absolute() or p != p.resolve(strict=True): raise ValueError('input root is not absolute realpath: '+root)
        if attempt == p or attempt in p.parents or p in attempt.parents: raise ValueError('attempt overlaps input root')
        if not c.same(r.inventory(root), expected): raise ValueError('frozen input mismatch: '+root)
    check_executable_pins(cfg['commands'], expected_inputs)
    consumer = Path(cfg['consumer']); producer = Path(cfg['producer']); source = Path(cfg['source']); source_root = Path(cfg['source_root'])
    if not valid_source_root(source_root): raise ValueError('unexpected source root layout')
    if (consumer/'.git').exists() or (producer/'.git').exists(): raise ValueError('use isolated exports, not Git worktrees')
    for root in (str(consumer),str(producer)):
        if any('__pycache__' in Path(k).parts or k.endswith('.pyc') for k in expected_inputs[root]):
            raise ValueError('product bytecode present in '+root)
    oracle = c.load(packet/'oracle-csv-fixture.json'); neutral = c.load(packet/'oracle-neutral.json'); retained = c.load(packet/'oracle-retained.json')
    source_files = [k for k,v in expected_inputs[str(source_root)].items() if v['type'] == 'file']
    if source_files != [oracle['source_path']]: raise ValueError('source root must contain exactly the expected source file')
    if source != source_root/oracle['source_path'] or r.sha(source) != oracle['source_sha256']:
        raise ValueError('source does not match independently approved oracle')
    if tuple(oracle['artifacts']) != REPORTS: raise ValueError('unexpected report paths')
    env_keys = {'HOME','LANG','LC_ALL','PATH','TMPDIR','TZ','XDG_CACHE_HOME','XDG_CONFIG_HOME'}
    cmds = cfg['commands']
    for name in ('export','import','reimport'):
        if cmds[name]['argv'][1:4] != ['-E','-S','-B']: raise ValueError('Python isolation flags missing: '+name)
    env = cmds['init']['env']
    if set(env) != env_keys or any(cmds[n]['env'] != env for n in cmds): raise ValueError('environment mismatch')
    for name, dirname in (('HOME','home'),('TMPDIR','tmp'),('XDG_CACHE_HOME','cache'),('XDG_CONFIG_HOME','config')):
        if Path(env[name]) != attempt/dirname: raise ValueError('unexpected runtime path: '+name)
    attempt.mkdir(mode=0o700)  # exclusive ownership; retain any incomplete attempt
    artifacts = attempt/'artifacts'; artifacts.mkdir(); logs = attempt/'logs'; logs.mkdir()
    _copy(manifest, attempt/'approved-manifest.json')
    _copy(ack, attempt/'approval-ack.json')
    with (attempt/'approval-binding.json').open('x',encoding='utf8') as f:
        json.dump({'manifest_sha256':manifest_sha256,'ack_sha256':ack_sha256},f,sort_keys=True); f.write('\n')
    for name in ('home','tmp','cache','config','query-cache','common-cache'):
        (attempt/name).mkdir()
    db = attempt/'database'
    # The packet's commands are independently reviewed as exact, absolute vectors.
    # Product code is never generated, patched or invoked to invent expectations.
    def stage(name, inputs=(), outputs=(), mutables=(), artifact=None):
        spec = cmds[name]
        if set(spec) != {'argv','cwd','env'}: raise ValueError('unexpected command fields: '+name)
        return r.run_stage(name, dict(spec, inputs=list(map(str, inputs)), outputs=list(map(str, outputs)), mutables=list(map(str, mutables)), stdout_artifact=str(artifact) if artifact else None), logs)
    def frozen(exclude_reports=False):
        for root, expected in expected_inputs.items():
            actual = r.inventory(root)
            if exclude_reports and root == str(consumer):
                actual = {k:v for k,v in actual.items() if k not in REPORTS}
                expected = {k:v for k,v in expected.items() if k not in REPORTS}
            if not c.same(actual, expected): raise ValueError('frozen input changed: '+root)
    for n in NAMES:
        stage(n+'-resolve')
        got = c.load(logs/(n+'-resolve.stdout'))
        if not c.same(got, c.load(packet/(n+'-resolution.json'))): raise ValueError('resolution differs: '+n)
    frozen()
    for i, report in enumerate(REPORTS): _copy(consumer/report, artifacts/('before-'+str(i)+'.json'))
    c.check_prestates(c.load(artifacts/'before-0.json'),c.load(artifacts/'before-1.json'),oracle,retained)
    stage('init', inputs=[source], outputs=[db])
    stage('index', inputs=[source], mutables=[db])
    routing = db/'trap/ucode/routing.json'
    _copy(routing, artifacts/'routing.json')
    c.check_routing(artifacts/'routing.json',str(source),oracle['source_path'])
    stage('finalize', inputs=[source], mutables=[db])
    c.check_archive(db/'src.zip',source)
    _copy(db/'src.zip', artifacts/'source-archive.zip')
    with (artifacts/'finalized-db-inventory.json').open('x', encoding='utf8') as f:
        json.dump(r.inventory(db),f,sort_keys=True,indent=2); f.write('\n')
    for n in NAMES: stage(n+'-query', inputs=[source,artifacts/'source-archive.zip'], mutables=[db], outputs=[artifacts/(n+'.bqrs')])
    if r.sha(db/'src.zip') != r.sha(artifacts/'source-archive.zip'): raise ValueError('database source archive changed')
    for n in NAMES: stage(n+'-decode', inputs=[artifacts/(n+'.bqrs')], artifact=artifacts/(n+'.csv'))
    c.check_csv(artifacts,oracle,str(source))
    frozen()
    stage('export', inputs=[source, consumer/'corpus/lock.json', *[artifacts/(n+'.csv') for n in NAMES]], artifact=artifacts/'typed.json')
    c.check_typed(artifacts,neutral)
    reports = [consumer/p for p in REPORTS]
    stage('import', inputs=[source,artifacts/'typed.json'], mutables=reports)
    for i, report in enumerate(reports): _copy(report, artifacts/('after-'+str(i)+'.json'))
    frozen(exclude_reports=True)
    c.check_reports(artifacts,consumer,oracle,retained,require_reimport=False)
    stage('reimport', inputs=[source,artifacts/'typed.json'], mutables=reports)
    for i, report in enumerate(reports): _copy(report, artifacts/('reimport-'+str(i)+'.json'))
    frozen(exclude_reports=True)
    c.check_reports(artifacts,consumer,oracle,retained)
    c.check_archive(artifacts/'source-archive.zip',source)
    r.verify_approval(packet, manifest, manifest_sha256, ack, ack_sha256)
    with (attempt/'complete.json').open('x',encoding='utf8') as f:
        json.dump({'status':'consistent_observed_boundaries','coverage':'partial','attestation':False},f,sort_keys=True); f.write('\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packet',required=True); p.add_argument('--manifest',required=True)
    p.add_argument('--manifest-sha256',required=True); p.add_argument('--ack',required=True); p.add_argument('--ack-sha256',required=True)
    a=p.parse_args(); run(a.packet,a.manifest,a.manifest_sha256,a.ack,a.ack_sha256)

if __name__ == '__main__': main()
