#!/usr/bin/env python3
"""Preflight actual #173 IPK and pinned testing producer before creating one-file stage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import check

HEX=re.compile(r'^[0-9a-f]{64}$')

def need_digest(value, label):
    check.require(isinstance(value,str) and HEX.fullmatch(value) is not None and value!='0'*64, 'missing '+label+' digest')
    return value

def tree_digest(root):
    root=Path(root)
    check.require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(), 'extractor pack path not physical')
    rows=[]
    for p in sorted(root.rglob('*')):
        check.require(not p.is_symlink(), 'extractor pack symlink')
        if p.is_dir(): continue
        check.require(p.is_file() and p.stat().st_nlink==1, 'extractor pack special or aliased file')
        rows.append({'path':p.relative_to(root).as_posix(), 'mode':p.stat().st_mode & 0o7777, 'sha256':check.digest(p.read_bytes())})
    check.require(rows, 'extractor pack empty')
    return check.digest(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())

def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],text=True).strip()

def preflight(lock, ipk, receipt, producer, cli, pack, dependencies):
    check.require(lock.get('schema')=='issue174-run-lock-v1', 'wrong lock schema')
    for name in ('ipk_sha256','receipt_sha256','cli_sha256','extractor_pack_tree_sha256','dependencies_tree_sha256'):
        need_digest(lock.get(name),name)
    check.require(lock.get('package_run_id')=='45741119647-1' and lock['ipk_sha256']=='41376c6774b35ff140ff3fa441643a184be252070cd3f462f645c6a98e527d6b' and lock['receipt_sha256']=='1c80809ed7c87a2a586d0df7bdebcfc35eaecf6370013b27f994a46d0324b677', '#173 audited artifact pin differs')
    check.require(lock.get('producer_commit')==check.PRODUCER and lock.get('query_sha256')==check.QUERY_SHA and lock.get('models_sha256')==check.MODEL_SHA, 'producer/query lock differs')
    ipk=check.safe_file(ipk); receipt=check.safe_file(receipt); cli=check.safe_file(cli)
    receipt_bytes=receipt.read_bytes()
    check.require(check.digest(receipt_bytes)==lock['receipt_sha256'], '#173 receipt digest differs')
    provider=check.validate_package(ipk.read_bytes(),check.json_object(receipt_bytes),lock['ipk_sha256'])
    producer=Path(producer)
    check.require(producer.is_absolute() and producer.resolve(strict=True)==producer and producer.is_dir(), 'producer path not physical')
    check.require(git(producer,'rev-parse','HEAD')==check.PRODUCER and not git(producer,'status','--porcelain=v1','--untracked-files=all'), 'producer checkout mismatch')
    for path,digest in [('ql/src/m4/RequestArgsExec.ql',check.QUERY_SHA),('ql/lib/codeql/ucode/m3/Models.qll',check.MODEL_SHA),('ql/test/models-fs-popen-controls/pinned-production-baseline.json','ace8f6ff871c3261992c9088d4065c2fdf9e5e77d391f34447fb5ebb254fa4ac')]:
        file=producer/path
        check.require(check.safe_file(file) and check.digest(file.read_bytes())==digest, 'producer source bytes differ: '+path)
    manifest=check.safe_file(producer/'.codeqlmanifest.json')
    check.require(check.digest(manifest.read_bytes())=='59a8b55940864bfabb4f276fc97eead605f063928dc5d4a7c05f435b0c989068', 'workspace manifest bytes differ')
    manifest_obj=check.json_object(manifest.read_bytes())
    check.require(manifest_obj.get('provide')==['ql/*/qlpack.yml'], 'workspace manifest package paths differ')
    for path,digest in [('ql/src/qlpack.yml','043c06ddb4f7562efc1b0ac860c7d17f453cdb38d549a8a9d5ee35c547d79280'),('ql/lib/qlpack.yml','f33e8f2ddd53de4094c4f9c4ff9d04e1e2e42341eaa0e2fd75591b091852d550')]:
        check.require(check.digest(check.safe_file(producer/path).read_bytes())==digest, 'workspace pack differs: '+path)
    check.require(check.digest(cli.read_bytes())==lock['cli_sha256'], 'CodeQL executable hash differs')
    version=subprocess.check_output([str(cli),'version'],text=True)
    check.require(version.splitlines() and version.splitlines()[0]=='CodeQL command-line toolchain release 2.27.4.', 'CodeQL version differs')
    check.require(tree_digest(pack)==lock['extractor_pack_tree_sha256'], 'extractor pack digest differs')
    check.require(tree_digest(dependencies)==lock['dependencies_tree_sha256'], 'dependency pack digest differs')
    return provider

def validate_layout(lock, stage, *, before):
    root=Path(lock.get('run_root',''))
    check.require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(), 'run root not physical')
    check.require(stage == root/'stage' and lock.get('database_path')==str(root/'db'), 'stage/database layout differs')
    outputs=lock.get('output_paths');bqrs=lock.get('bqrs_paths');resolvers=lock.get('resolver_paths')
    check.require(isinstance(outputs,dict) and outputs=={'routing':str(root/'output/routing.json'), **{n:str(root/'output'/(n+'.json')) for n in ('successful','errors','query')}}, 'output layout differs')
    check.require(isinstance(bqrs,dict) and bqrs=={n:str(root/'output'/(n+'.bqrs')) for n in ('successful','errors','query')}, 'BQRS layout differs')
    check.require(isinstance(resolvers,dict) and resolvers=={n:str(root/'output'/('resolve-'+n+'.json')) for n in ('query','successful','errors')}, 'resolver layout differs')
    check.require(lock.get('raw_routing_path')==str(root/'db/trap/ucode/routing.json'), 'raw routing layout differs')
    check.require(lock.get('commands_path')==str(root/'output/commands.json'), 'command receipt layout differs')
    all_paths=[*outputs.values(),*bqrs.values(),*resolvers.values(),lock['commands_path']]
    check.require(len(all_paths)==len(set(all_paths)), 'output path alias')
    if before:
        for name in ('stage','db','output','cache','home','tmp'):
            p=root/name;check.require(not p.exists() and not p.is_symlink(), 'run location is not fresh: '+name)
    return root


def create_stage(provider, output):
    output=Path(output)
    check.require(output.is_absolute() and not output.exists() and not output.is_symlink(), 'stage must be new absolute path')
    check.require(output.parent.resolve(strict=True)==output.parent and output.parent.is_dir(), 'stage parent not physical')
    output.mkdir(mode=0o755)
    p=output/check.IPK_SOURCE
    p.parent.mkdir(parents=True)
    with p.open('xb') as stream:stream.write(provider)
    p.chmod(0o644)
    check.require(check.digest(p.read_bytes())==check.SOURCE_SHA, 'stage byte copy differs')

def main():
    p=argparse.ArgumentParser()
    for name in ('lock','ipk','receipt','producer','cli','pack','dependencies','stage'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--lock-sha256',required=True)
    args=p.parse_args()
    lock_bytes=check.safe_file(args.lock).read_bytes()
    check.require(check.digest(lock_bytes)==need_digest(args.lock_sha256,'lock'),'run lock digest differs')
    lock=check.json_object(lock_bytes)
    validate_layout(lock,args.stage,before=True)
    provider=preflight(lock,args.ipk,args.receipt,args.producer,args.cli,args.pack,args.dependencies)
    create_stage(provider,args.stage)
    print(json.dumps({'status':'preflight_and_stage_verified','stage':str(args.stage),'provider_sha256':check.digest(provider),'lock_sha256':args.lock_sha256,'boundary':'Hash and shape checks do not authenticate the receipt or attest execution.'},sort_keys=True))
if __name__=='__main__':main()
