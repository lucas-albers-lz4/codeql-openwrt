#!/usr/bin/env python3
"""Compare two actual wifi-scripts package stages and IPKs to pinned Git blobs."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tarfile
import io

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ipk', HERE.parent / 'installed-byte/compare.py')
ipk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ipk)
PIN = '4e9642517b48bae612ff10fb72fb9199e559500e'
COLLISION = 'lib/netifd/wireless/mac80211.sh'
SHELL = 'package/network/config/wifi-scripts/files/' + COLLISION
PREFIX = 'package/network/config/wifi-scripts/'

def digest(b):
    return hashlib.sha256(b).hexdigest()

def members(archive):
    parts = ipk.ipk_parts(archive)
    out = {}
    with tarfile.open(fileobj=io.BytesIO(parts['data.tar.gz']), mode='r:gz') as tf:
        for m in tf.getmembers():
            name = ipk.member_name(m.name)
            if not name:
                if not m.isdir(): raise ValueError('invalid root')
                continue
            if name in out: raise ValueError('duplicate data member: ' + name)
            if m.isfile():
                out[name] = tf.extractfile(m).read()
            elif m.isdir(): out[name] = None
            else: out[name] = 'nonregular'
    return out

def config(path, enabled):
    lines = path.read_text().splitlines()
    for sym, val in [('CONFIG_TARGET_x86','y'), ('CONFIG_TARGET_x86_64','y'), ('CONFIG_PACKAGE_wifi-scripts','m'), ('CONFIG_USE_APK','n'), ('CONFIG_WIFI_SCRIPTS_UCODE', 'y' if enabled else 'n')]:
        found = [x for x in lines if x.startswith(sym + '=') or x == '# '+sym+' is not set']
        if len(found) != 1 or found[0] not in ([sym+'='+val] if val != 'n' else [sym+'=n', '# '+sym+' is not set']):
            raise ValueError('unexpected config ' + sym + ': ' + repr(found))
    return lines

def compare_configs(configs):
    base = []
    for enabled in (True, False):
        lines = config(configs[enabled], enabled)
        base.append([x for x in lines if not (x.startswith('CONFIG_WIFI_SCRIPTS_UCODE=') or x == '# CONFIG_WIFI_SCRIPTS_UCODE is not set')])
    if base[0] != base[1]: raise ValueError('final configs differ outside WIFI_SCRIPTS_UCODE')

def compare(oracle, source, stages, archives, configs):
    selected = oracle['selected']
    if oracle['source']['commit'] != PIN or len(selected) != 17: raise ValueError('oracle pin/count')
    paths = [r['stage_path'] for r in selected]
    if len(set(paths)) != 17: raise ValueError('duplicate oracle path')
    common = {r['stage_path'] for r in selected if r['config_condition'] != 'CONFIG_WIFI_SCRIPTS_UCODE=y'}
    conditional = set(paths) - common
    if len(common) != 7 or len(conditional) != 10 or COLLISION not in conditional: raise ValueError('oracle partition')
    compare_configs(configs)
    sources = {}
    for row in selected:
        b = source(row['source_path'])
        if digest(b) != row['sha256'] or hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest() != row['git_blob']: raise ValueError('source hash/blob ' + row['source_path'])
        sources[row['stage_path']] = b
    shell = source(SHELL)
    alt = oracle['excluded_alternative']
    if digest(shell) != alt['sha256'] or hashlib.sha1(b'blob '+str(len(shell)).encode()+b'\0'+shell).hexdigest() != alt['git_blob']: raise ValueError('shell hash/blob')
    if shell == sources[COLLISION]: raise ValueError('collision sources equal')
    receipt = {}
    for enabled in (True, False):
        archive = archives[enabled]
        fields = ipk.ipk_control_fields(archive)
        if fields != {'Package':'wifi-scripts', 'Version':'1.0-r1', 'Architecture':'all'}: raise ValueError('package control mismatch: '+repr(fields))
        data = members(archive)
        expected = common | (conditional if enabled else set())
        nonregular_ucode_paths = {p for p,b in data.items() if b == 'nonregular' and p.endswith(('.uc','.ucode'))}
        if nonregular_ucode_paths: raise ValueError('nonregular Ucode-suffix member: '+repr(sorted(nonregular_ucode_paths)))
        # Discover every Ucode-looking regular member, including unexpected ones.
        detected = {p for p,b in data.items() if isinstance(b, bytes) and (p.endswith(('.uc','.ucode')) or b.startswith(b'#!/usr/bin/env ucode') or b.startswith(b'#!/usr/bin/ucode'))}
        if detected != expected: raise ValueError('Ucode member mismatch: '+repr((sorted(expected-detected), sorted(detected-expected))))
        expected_bytes = {p:sources[p] for p in expected}
        if not enabled: expected_bytes[COLLISION] = shell
        records = []
        for p, b in sorted(expected_bytes.items()):
            file = stages[enabled] / p
            staged = ipk.read_regular_under(file, stages[enabled], 'stage '+p)
            if data.get(p) != b or staged != b: raise ValueError('source/stage/IPK mismatch '+p)
            records.append({'path':p, 'sha256':digest(b)})
        # No other conditional member may appear when disabled.
        if not enabled and (conditional - {COLLISION}) & data.keys(): raise ValueError('disabled conditional member present')
        receipt['y' if enabled else 'n'] = {'ipk_sha256':digest(archive.read_bytes()), 'control':fields, 'ucode_members':sorted(detected), 'compared':records, 'config_sha256':digest(configs[enabled].read_bytes())}
    return receipt

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=pathlib.Path, required=True)
    for flag in ('stage-y','stage-n','ipk-y','ipk-n','config-y','config-n','receipt'): p.add_argument('--'+flag, type=pathlib.Path, required=True)
    a=p.parse_args()
    repo=a.source
    def git(*args): return subprocess.check_output(['git','-C',str(repo),*args])
    if git('rev-parse','HEAD').decode().strip()!=PIN or git('status','--porcelain=v1','--untracked-files=no').strip(): raise ValueError('source revision or dirty tracked files')
    oracle=json.loads((HERE/'oracle.json').read_text())
    def source(path):
        b=git('show',PIN+':'+path)
        actual=ipk.read_regular_under(repo/path,repo,'source')
        if actual != b: raise ValueError('working source differs from Git blob '+path)
        return b
    result=compare(oracle,source,{True:a.stage_y,False:a.stage_n},{True:a.ipk_y,False:a.ipk_n},{True:a.config_y,False:a.config_n})
    a.receipt.write_text(json.dumps({'schema':'wifi-ipk-byte-v1','source_commit':PIN,'source_tree':git('rev-parse','HEAD^{tree}').decode().strip(),'variants':result},indent=2)+'\n')

if __name__=='__main__':
    try: main()
    except Exception as e:
        print('FAIL:', e, file=sys.stderr)
        sys.exit(1)
