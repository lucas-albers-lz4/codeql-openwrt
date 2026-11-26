#!/usr/bin/env python3
"""Validate pinned actual app IPK and testing inputs before creating three-file stage."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import check

HEX=re.compile(r'^[0-9a-f]{64}$')
def need_hash(v,name):check.require(isinstance(v,str) and HEX.fullmatch(v) is not None and v!='0'*64,'missing reviewed '+name+' hash');return v

def tree_digest(root):
    root=Path(root);check.require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(),'pack root not physical');rows=[]
    for p in sorted(root.rglob('*')):
        check.require(not p.is_symlink(),'pack symlink')
        if p.is_dir():continue
        check.require(p.is_file() and p.stat().st_nlink==1,'pack special or aliased file')
        rows.append({'path':p.relative_to(root).as_posix(),'mode':p.stat().st_mode & 0o7777,'sha256':check.digest(p.read_bytes())})
    check.require(rows,'empty pack');return check.digest(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())

def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],text=True).strip()

def preflight(lock,ipk,receipt,producer,cli,pack,dependencies):
    check.require(lock.get('schema')=='issue175-run-lock-v1','wrong run lock schema')
    for n in ('ipk_sha256','receipt_sha256','cli_sha256','extractor_pack_tree_sha256','dependencies_tree_sha256'):need_hash(lock.get(n),n)
    check.require(lock.get('producer_commit')==check.PRODUCER and lock.get('query_sha256')==check.QUERY_SHA and lock.get('models_sha256')==check.MODELS_SHA,'producer or query lock differs')
    data=check.safe_file(receipt).read_bytes();check.require(check.digest(data)==lock['receipt_sha256'],'app receipt digest differs')
    app=check.validate_app_package(check.safe_file(ipk).read_bytes(),check.load_json(data),lock)
    producer=Path(producer);check.require(producer.is_absolute() and producer.resolve(strict=True)==producer and producer.is_dir(),'producer root not physical')
    check.require((producer/'.git').is_dir() and not (producer/'.git').is_symlink() and not (producer/'.git/objects/info/alternates').exists(),'producer must be standalone without object alternates')
    check.require(git(producer,'rev-parse','HEAD')==check.PRODUCER and not git(producer,'status','--porcelain=v1','--untracked-files=all'),'producer source differs')
    hashes={'.codeqlmanifest.json':'59a8b55940864bfabb4f276fc97eead605f063928dc5d4a7c05f435b0c989068','ql/src/qlpack.yml':'043c06ddb4f7562efc1b0ac860c7d17f453cdb38d549a8a9d5ee35c547d79280','ql/lib/qlpack.yml':'f33e8f2ddd53de4094c4f9c4ff9d04e1e2e42341eaa0e2fd75591b091852d550','ql/src/m3/BuiltinSystem.ql':check.QUERY_SHA,'ql/lib/codeql/ucode/m3/Models.qll':check.MODELS_SHA}
    for p,sha in hashes.items():check.require(check.digest(check.safe_file(producer/p).read_bytes())==sha,'producer file differs: '+p)
    manifest=check.load_json((producer/'.codeqlmanifest.json').read_bytes());check.require(manifest.get('provide')==['ql/*/qlpack.yml'],'workspace manifest differs')
    cli=check.safe_file(cli);check.require(check.digest(cli.read_bytes())==lock['cli_sha256'],'CLI digest differs')
    v=subprocess.check_output([str(cli),'version'],text=True);check.require(v.splitlines() and v.splitlines()[0]=='CodeQL command-line toolchain release 2.27.4.','CLI version differs')
    check.require(tree_digest(pack)==lock['extractor_pack_tree_sha256'] and tree_digest(dependencies)==lock['dependencies_tree_sha256'],'extractor or dependency tree differs')
    controls={}
    for path,name in ((check.POS,'positive.uc'),(check.NEG,'near-miss.uc')):
        controls[path]=(check.HERE/name).read_bytes();check.require(check.digest(controls[path])==check.CONTROL_SHA[path],'control bytes differ: '+path)
    return {check.APP:app,**controls}

def layout(lock,stage,before):
    root=Path(lock.get('run_root',''));check.require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(),'run root not physical')
    check.require(stage==root/'stage' and lock.get('database_path')==str(root/'db'),'stage/database layout differs')
    outs=lock.get('output_paths');bqrs=lock.get('bqrs_paths');res=lock.get('resolver_paths')
    check.require(outs=={n:str(root/'output'/(n+'.json')) for n in ('routing','successful','errors','query')},'output layout differs')
    check.require(bqrs=={n:str(root/'output'/(n+'.bqrs')) for n in ('successful','errors','query')},'BQRS layout differs')
    check.require(res=={n:str(root/'output'/('resolve-'+n+'.json')) for n in ('query','successful','errors')},'resolver layout differs')
    check.require(lock.get('raw_routing_path')==str(root/'db/trap/ucode/routing.json') and lock.get('commands_path')==str(root/'output/commands.json'),'routing/command layout differs')
    paths=[*outs.values(),*bqrs.values(),*res.values(),lock['commands_path']];check.require(len(paths)==len(set(paths)),'output alias')
    if before:
        for n in ('stage','db','output','cache','home','tmp'):
            p=root/n;check.require(not p.exists() and not p.is_symlink(),'run path not fresh: '+n)
    return root

def create_stage(stage,files):
    stage=Path(stage);check.require(stage.is_absolute() and not stage.exists() and not stage.is_symlink() and stage.parent.resolve(strict=True)==stage.parent,'stage path not fresh and physical')
    check.require(set(files)==set(check.PATHS),'stage inputs differ');stage.mkdir()
    for path in check.PATHS:
        dest=stage/path;dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as f:f.write(files[path])
        dest.chmod(0o644)
    check.stage_inputs(stage,{check.APP:check.APP_SHA,**check.CONTROL_SHA});check.check_source_spans(stage,check.oracle())

def main():
    parser=argparse.ArgumentParser()
    for n in ('lock','ipk','receipt','producer','cli','pack','dependencies','stage'):parser.add_argument('--'+n,type=Path,required=True)
    parser.add_argument('--lock-sha256',required=True);a=parser.parse_args();raw=check.safe_file(a.lock).read_bytes()
    check.require(check.digest(raw)==need_hash(a.lock_sha256,'lock'),'run lock digest differs');lock=check.load_json(raw);layout(lock,a.stage,True)
    files=preflight(lock,a.ipk,a.receipt,a.producer,a.cli,a.pack,a.dependencies);create_stage(a.stage,files)
    print(json.dumps({'status':'preflight_and_stage_verified','app_sha256':check.digest(files[check.APP]),'lock_sha256':a.lock_sha256,'scope':'Supplied-evidence consistency; receipt authenticity and runtime not established.'},sort_keys=True))
if __name__=='__main__':main()
