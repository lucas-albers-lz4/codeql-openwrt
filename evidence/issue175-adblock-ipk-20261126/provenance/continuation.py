#!/usr/bin/env python3
"""Execute only the nine locked #175 phases after independently reviewed resolvers."""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import time

CONTEXT=pathlib.Path('/Users/lalbers/gitroot/ucode/coverage-wave-work/issue175-execution-context-20261126')
CODE=pathlib.Path('/Users/lalbers/gitroot/ucode/.worktrees/openwrt-issue175-adblock-20261126/tools/issue175-adblock')
# Verify every imported helper before import; execution must use reviewed bytes.
for path,digest in ((CODE/'check.py','ddf0c5605e1984da7c90ec70c2b4ee294fb374a99f3102473589732f7158a2ec'),(CODE/'prepare.py','0fa1e168d400dc4baba3a52e77dc3b36d101db8ddb9a14e914d96e707498c146'),(CODE/'verify.py','51f70af09f718aa2a521c1fb15ec39cabed31cf0fe41ac5066b7ef380ca15290'),(CODE.parent/'luci-base-inventory/archive.py','224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100'),(CODE.parent/'luci-base-inventory/compare.py','2cea4cc96279f75f0b1f1194639c7b6285f4e17403f8d49e587143ce2b1974ae')):
    if not path.is_file() or path.is_symlink() or path.resolve()!=path or path.stat().st_nlink!=1 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('import helper differs: '+str(path))
sys.path.insert(0,str(CODE))
import check
import prepare
import verify

CTX_SHA='c6697af4a558ba4378c1e100ae11dd368707b80d2f85cf7c6d69526da4254fc7'
IPK=pathlib.Path('/private/tmp/review173-adblock-8kyTYVz1/luci-app-adblock-fast.ipk')
PACKAGE_RECEIPT=pathlib.Path('/private/tmp/review173-adblock-8kyTYVz1/app.json')
CLI=pathlib.Path('/Users/lalbers/gitroot/ucode/.tools/codeql-2.27.4/codeql/codeql')
PRODUCER=CONTEXT/'producer'; PACK=CONTEXT/'extractor-pack'; DEPS=CONTEXT/'dependencies'

def read_locked():
    raw=(CONTEXT/'continuation-context.json').read_bytes()
    check.require(check.digest(raw)==CTX_SHA,'continuation context digest differs')
    context=check.load_json(raw)
    raw=(CONTEXT/'run-lock.json').read_bytes()
    check.require(check.digest(raw)==context['lock_sha256'],'run lock digest differs')
    lock=check.load_json(raw)
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
    files=prepare.preflight(lock,IPK,PACKAGE_RECEIPT,PRODUCER,CLI,PACK,DEPS)
    stage=pathlib.Path(lock['run_root'])/'stage'
    check.stage_inputs(stage,{check.APP:check.APP_SHA,**check.CONTROL_SHA})
    check.require(check.safe_file(stage/check.APP).read_bytes()==files[check.APP],'stage app bytes changed')
    check.check_source_spans(stage,check.oracle())
    resolver=pathlib.Path(lock['run_root'])/'output/resolver-only-commands.json'
    check.require(check.digest(check.safe_file(resolver).read_bytes())==context['resolver_only_sha256'],'resolver receipt changed')
    for name,digest in context['code_sha256'].items():check.require(check.digest(check.safe_file(CODE/name).read_bytes())==digest,'checker code changed: '+name)
    return stage,resolver

def resolver_rows(lock,resolver):
    prior=check.load_json(resolver.read_bytes())['commands'];check.require(len(prior)==3,'resolver receipt count differs')
    expected_names=[('resolve-query','query','m3/BuiltinSystem.ql'),('resolve-success','successful','diagnostics/SuccessfullyExtractedFiles.ql'),('resolve-errors','errors','diagnostics/ExtractionErrors.ql')]
    result=[]
    for row,(label,name,relative) in zip(prior,expected_names):
        check.require(row['label']==label and row['argv']==lock['phase_argv'][label] and row['cwd']==lock['cwd'] and row['env']==lock['env'] and row['exit']==0,'resolver command differs: '+label)
        out=check.safe_file(pathlib.Path(lock['resolver_paths'][name]));err=check.safe_file(pathlib.Path(lock['run_root'])/'output/logs'/(label+'.stderr'))
        check.require(row['stdout_path']==str(out) and row['stderr_path']==str(err) and row['stdout_sha256']==check.digest(out.read_bytes()) and row['stderr_sha256']==check.digest(err.read_bytes()) and err.read_bytes()==b'', 'resolver logs differ: '+label)
        data=check.load_json(out.read_bytes())
        check.require(data.get('libraryPath')==lock['resolved_library_paths'] and data.get('dbscheme')==str(PRODUCER/'ql/lib/ucode.dbscheme') and data.get('relativeName')=='lucas-albers-lz4/ucode-queries/'+relative and data.get('qlPackName')=='lucas-albers-lz4/ucode-queries' and data.get('compilationCache')==[str(pathlib.Path(lock['run_root'])/'cache/compile')], 'resolver output differs: '+label)
        copied=copy.deepcopy(row);copied['artifacts']={str(out):check.digest(out.read_bytes())};result.append(copied)
    return result

def phase_gate(label, lock, stage, row):
    if label=='database-index':
        raw=check.safe_file(pathlib.Path(lock['raw_routing_path'])).read_bytes()
        check.validate_route(stage,check.load_json(raw))
        retained=pathlib.Path(lock['output_paths']['routing'])
        with retained.open('xb') as f:f.write(raw)
        check.require(check.digest(check.safe_file(retained).read_bytes())==check.digest(raw),'retained route differs')
        row['raw_routing_sha256']=check.digest(raw)
    elif label=='database-finalize':
        check.validate_source_archive(stage,pathlib.Path(lock['database_path'])/'src.zip')
    elif label=='success-decode':
        check.validate_success(stage,check.load_json(check.safe_file(pathlib.Path(lock['output_paths']['successful'])).read_bytes()))
    elif label=='errors-decode':
        check.validate_success(stage,check.load_json(check.safe_file(pathlib.Path(lock['output_paths']['successful'])).read_bytes()))
        check.validate_errors(check.load_json(check.safe_file(pathlib.Path(lock['output_paths']['errors'])).read_bytes()))
    elif label=='target-decode':
        check.validate_query(stage,check.load_json(check.safe_file(pathlib.Path(lock['output_paths']['query'])).read_bytes()),check.oracle())


def run_phase(label, lock, output, artifacts, stage):
    out=output/'logs'/(label+'.stdout');err=output/'logs'/(label+'.stderr');argv=lock['phase_argv'][label]
    start=time.monotonic();failure=None
    row={'label':label,'argv':argv,'cwd':lock['cwd'],'env':lock['env'],'exit':None,'peak_rss_bytes':None,'rss_note':'not measured on this run','stdout_path':str(out),'stderr_path':str(err)}
    try:
        if label.endswith('-query') or label.endswith('-decode'):
            target=pathlib.Path(artifacts[label]);check.require(not target.exists() and not target.is_symlink(),'phase output not fresh: '+label)
        if label.endswith('-decode'):
            prefix={'success':'successful','errors':'errors','target':'query'}[label.removesuffix('-decode')]
            check.require(check.safe_file(pathlib.Path(lock['bqrs_paths'][prefix])).stat().st_size>0,'empty BQRS before decode: '+label)
        with out.open('xb') as stdout,err.open('xb') as stderr:
            result=subprocess.run(argv,cwd=lock['cwd'],env=lock['env'],stdout=stdout,stderr=stderr,check=False)
        row['exit']=result.returncode
        check.require(result.returncode==0,'command failed: '+label)
        for stream,path in (('stdout',out),('stderr',err)):
            text=path.read_text(errors='replace');upper=text.upper()
            check.require(not any(token in upper for token in ('ERROR:','FATAL:')),'command error requires review: '+label)
            warnings=[line for line in text.splitlines() if 'WARNING:' in line.upper()]
            check.require(not warnings or stream=='stderr' and label in verify.QUERY_PHASES and warnings==[verify.KNOWN_CACHE_WARNING], 'command warning requires review: '+label)
            if stream=='stderr':row['classified_warnings']=warnings
        phase_gate(label,lock,stage,row)
        if label in artifacts:
            artifact=check.safe_file(pathlib.Path(artifacts[label]));check.require(not label.endswith('-query') or artifact.stat().st_size>0,'empty BQRS after query: '+label);row['artifacts']={str(artifact):check.digest(artifact.read_bytes())}
        if row.get('classified_warnings'):check.require(label in artifacts and 'artifacts' in row,'warned phase missing artifact')
    except Exception as exc:
        failure=repr(exc);row['phase_error']=failure
    row['elapsed_seconds']=time.monotonic()-start
    for stream,path in (('stdout',out),('stderr',err)):
        row[stream+'_sha256']=check.digest(path.read_bytes()) if path.is_file() and not path.is_symlink() else None
    with (output/'logs'/(label+'.receipt.json')).open('x') as f:json.dump(row,f,indent=2,sort_keys=True);f.write('\n')
    if failure is not None:raise RuntimeError('phase failed; retained receipt: '+label+' '+failure)
    return row


def main():
    context,lock=read_locked();run=pathlib.Path(lock['run_root']);prepare.layout(lock,run/'stage',before=False)
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
        current_rows={r['path']:r for r in inventory(run)}
        for item in context['initial_run_tree']:
            if item['path'].startswith('output/'):
                check.require(current_rows.get(item['path'])==item,'original resolver output changed')
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
