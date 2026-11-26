#!/usr/bin/env python3
"""Execute only the nine locked #174 phases after independently reviewed resolvers."""
import copy
import json
import pathlib
import subprocess
import sys
import time

CONTEXT=pathlib.Path('/Users/lalbers/gitroot/ucode/coverage-wave-work/issue174-retry-context-20261126')
CODE=pathlib.Path('/Users/lalbers/gitroot/ucode/.worktrees/openwrt-issue174-core-20261126/tools/issue174-core')
sys.path.insert(0,str(CODE))
import check
import prepare
import verify

CTX_SHA='7eec2dd07de96d3f25a6663d7c732e857ab9e5ad31e40c3d3d56391acfab7681'
IPK=pathlib.Path('/private/tmp/review173-hosted-DbFKwjHj/luci-base.ipk')
PACKAGE_RECEIPT=pathlib.Path('/private/tmp/review173-hosted-DbFKwjHj/byte-comparison.json')
CLI=pathlib.Path('/Users/lalbers/gitroot/ucode/.tools/codeql-2.27.4/codeql/codeql')
PRODUCER=CONTEXT/'producer'; PACK=CONTEXT/'extractor-pack'; DEPS=CONTEXT/'dependencies'

def read_locked():
    raw=(CONTEXT/'continuation-context.json').read_bytes()
    check.require(check.digest(raw)==CTX_SHA,'continuation context digest differs')
    context=check.json_object(raw)
    raw=(CONTEXT/'run-lock.json').read_bytes()
    check.require(check.digest(raw)==context['lock_sha256'],'run lock digest differs')
    lock=check.json_object(raw)
    for name,digest in context['code_sha256'].items():
        check.require(check.digest(check.safe_file(CODE/name).read_bytes())==digest,'checker code changed: '+name)
    shared=CODE.parent/'luci-base-inventory'
    for name,digest in context['shared_code_sha256'].items():
        check.require(check.digest(check.safe_file(shared/name).read_bytes())==digest,'shared checker code changed: '+name)
    return context,lock

def inventory(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        check.require(not p.is_symlink(),'run tree symlink: '+str(p))
        if p.is_dir():rows.append({'path':p.relative_to(root).as_posix(),'type':'directory','mode':p.stat().st_mode & 0o7777})
        elif p.is_file() and p.stat().st_nlink==1:rows.append({'path':p.relative_to(root).as_posix(),'type':'file','mode':p.stat().st_mode & 0o7777,'sha256':check.digest(p.read_bytes())})
        else:raise ValueError('run tree special or aliased file: '+str(p))
    return rows

def pinned_inputs(context,lock):
    provider=prepare.preflight(lock,IPK,PACKAGE_RECEIPT,PRODUCER,CLI,PACK,DEPS)
    stage=pathlib.Path(lock['run_root'])/'stage'; path=check.safe_file(stage/check.IPK_SOURCE)
    check.require(path.read_bytes()==provider and path.stat().st_mode & 0o7777==0o644,'stage bytes or mode changed')
    files=[]
    for p in stage.rglob('*'):
        check.require(not p.is_symlink(),'stage symlink')
        if p.is_file():files.append(p.relative_to(stage).as_posix())
        else:check.require(p.is_dir(),'stage special file')
    check.require(files==[check.IPK_SOURCE],'stage file inventory changed')
    resolver=pathlib.Path(lock['run_root'])/'output/resolver-only-commands.json'
    check.require(check.digest(check.safe_file(resolver).read_bytes())==context['resolver_only_sha256'],'resolver receipt changed')
    for name,digest in context['code_sha256'].items():check.require(check.digest(check.safe_file(CODE/name).read_bytes())==digest,'checker code changed: '+name)
    return stage,resolver

def resolver_rows(lock,resolver):
    prior=check.json_object(resolver.read_bytes())['commands'];check.require(len(prior)==3,'resolver receipt count differs')
    expected_names=[('resolve-query','query','m4/RequestArgsExec.ql'),('resolve-success','successful','diagnostics/SuccessfullyExtractedFiles.ql'),('resolve-errors','errors','diagnostics/ExtractionErrors.ql')]
    result=[]
    for row,(label,name,relative) in zip(prior,expected_names):
        check.require(row['label']==label and row['argv']==lock['phase_argv'][label] and row['cwd']==lock['cwd'] and row['env']==lock['env'] and row['exit']==0,'resolver command differs: '+label)
        out=check.safe_file(pathlib.Path(lock['resolver_paths'][name]));err=check.safe_file(pathlib.Path(lock['run_root'])/'output/logs'/(label+'.stderr'))
        check.require(row['stdout_path']==str(out) and row['stderr_path']==str(err) and row['stdout_sha256']==check.digest(out.read_bytes()) and row['stderr_sha256']==check.digest(err.read_bytes()) and err.read_bytes()==b'', 'resolver logs differ: '+label)
        data=check.json_object(out.read_bytes())
        check.require(data.get('libraryPath')==lock['resolved_library_paths'] and data.get('dbscheme')==str(PRODUCER/'ql/lib/ucode.dbscheme') and data.get('relativeName')=='lucas-albers-lz4/ucode-queries/'+relative and data.get('qlPackName')=='lucas-albers-lz4/ucode-queries' and data.get('compilationCache')==[str(pathlib.Path(lock['run_root'])/'cache/compile')], 'resolver output differs: '+label)
        copied=copy.deepcopy(row);copied['artifacts']={str(out):check.digest(out.read_bytes())};result.append(copied)
    return result

def phase_gate(label, lock, stage, row):
    if label=='database-index':
        raw=check.safe_file(pathlib.Path(lock['raw_routing_path'])).read_bytes()
        check.validate_route(stage,check.json_object(raw))
        retained=pathlib.Path(lock['output_paths']['routing'])
        with retained.open('xb') as f:f.write(raw)
        check.require(check.digest(check.safe_file(retained).read_bytes())==check.digest(raw),'retained route differs')
        row['raw_routing_sha256']=check.digest(raw)
    elif label=='database-finalize':
        check.validate_source_archive(stage,pathlib.Path(lock['database_path'])/'src.zip')
    elif label=='success-decode':
        check.validate_success(stage,check.json_object(pathlib.Path(lock['output_paths']['successful']).read_bytes()))
    elif label=='errors-decode':
        check.validate_success(stage,check.json_object(pathlib.Path(lock['output_paths']['successful']).read_bytes()))
        check.validate_errors(check.json_object(pathlib.Path(lock['output_paths']['errors']).read_bytes()))


def run_phase(label, lock, output, artifacts, stage):
    out=output/'logs'/(label+'.stdout');err=output/'logs'/(label+'.stderr');argv=lock['phase_argv'][label]
    start=time.monotonic();failure=None
    row={'label':label,'argv':argv,'cwd':lock['cwd'],'env':lock['env'],'exit':None,'peak_rss_bytes':None,'rss_note':'not measured on this run','stdout_path':str(out),'stderr_path':str(err)}
    try:
        with out.open('xb') as stdout,err.open('xb') as stderr:
            result=subprocess.run(argv,cwd=lock['cwd'],env=lock['env'],stdout=stdout,stderr=stderr,check=False)
        row['exit']=result.returncode
        check.require(result.returncode==0,'command failed: '+label)
        text=err.read_text(errors='replace').upper();check.require('WARNING:' not in text and 'ERROR:' not in text,'command warning/error requires review: '+label)
        phase_gate(label,lock,stage,row)
        if label in artifacts:
            artifact=check.safe_file(pathlib.Path(artifacts[label]));row['artifacts']={str(artifact):check.digest(artifact.read_bytes())}
    except Exception as exc:
        failure=repr(exc);row['phase_error']=failure
    row['elapsed_seconds']=time.monotonic()-start
    for stream,path in (('stdout',out),('stderr',err)):
        row[stream+'_sha256']=check.digest(path.read_bytes()) if path.is_file() and not path.is_symlink() else None
    with (output/'logs'/(label+'.receipt.json')).open('x') as f:json.dump(row,f,indent=2,sort_keys=True);f.write('\n')
    if failure is not None:raise RuntimeError('phase failed; retained receipt: '+label+' '+failure)
    return row


def main():
    context,lock=read_locked();run=pathlib.Path(lock['run_root']);prepare.validate_layout(lock,run/'stage',before=False)
    check.require(inventory(run)==context['initial_run_tree'],'run tree changed since resolver audit')
    stage,resolver=pinned_inputs(context,lock);records=resolver_rows(lock,resolver)
    dummy=records+[{'label':name,'argv':lock['phase_argv'][name],'cwd':lock['cwd'],'env':lock['env'],'exit':0,'elapsed_seconds':0,'peak_rss_bytes':0} for name in verify.PHASES[3:]]
    verify.validate_commands(lock,{'commands':dummy},CLI,PRODUCER,stage,PACK,DEPS)
    (run/'cache/database').mkdir(exist_ok=False)
    output=run/'output';failure=None
    artifacts={'database-index':lock['output_paths']['routing'],'database-finalize':str(pathlib.Path(lock['database_path'])/'src.zip'),
               'success-query':lock['bqrs_paths']['successful'],'success-decode':lock['output_paths']['successful'],
               'errors-query':lock['bqrs_paths']['errors'],'errors-decode':lock['output_paths']['errors'],
               'target-query':lock['bqrs_paths']['query'],'target-decode':lock['output_paths']['query']}
    try:
        for label in verify.PHASES[3:]:records.append(run_phase(label,lock,output,artifacts,stage))
        verify.validate_commands(lock,{'commands':records},CLI,PRODUCER,stage,PACK,DEPS)
        verify.validate_logs(lock,records)
    except Exception as exc:
        failure=repr(exc)
    try:
        read_locked();pinned_inputs(context,lock);resolver_rows(lock,resolver)
        initial=[row for row in context['initial_run_tree'] if row['path']=='stage' or row['path'].startswith('stage/')]
        current=[row for row in inventory(run) if row['path']=='stage' or row['path'].startswith('stage/')]
        check.require(initial==current,'stage tree changed since preflight')
        post={'status':'inputs_unchanged','failure':failure}
    except Exception as exc:
        post={'status':'postguard_failed','failure':failure,'postguard_error':repr(exc)}
    with (output/'continuation-postguard.json').open('x') as f:json.dump(post,f,indent=2,sort_keys=True);f.write('\n')
    if failure is not None or post['status']!='inputs_unchanged':
        with (output/'continuation-failure.json').open('x') as f:json.dump(post,f,indent=2,sort_keys=True);f.write('\n')
        raise SystemExit(1)
    with (output/'commands.json').open('x') as f:json.dump({'commands':records},f,indent=2,sort_keys=True);f.write('\n')
    print('nine locked phases complete; run verify.py separately')
if __name__=='__main__':main()
