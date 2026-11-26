#!/usr/bin/env python3
"""Resume reviewed #174 attempt after one explicitly accepted cache warning; no extraction retry."""
import copy
import importlib.util
import json
import pathlib
import subprocess
import time

BASE=pathlib.Path('/Users/lalbers/gitroot/ucode/coverage-wave-work/issue174-retry-context-20261126')
SPEC=importlib.util.spec_from_file_location('prior_continuation',BASE/'continuation.py')
prior=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(prior)
check=prior.check;prepare=prior.prepare;verify=prior.verify
CTX_SHA='cea021c8b17ece8d7e93408e32c53f4e3d5d801bba5666d85a124966658c6e3c'


def read_inputs():
    raw=check.safe_file(BASE/'resume-context-v2.json').read_bytes();check.require(check.digest(raw)==CTX_SHA,'resume context differs')
    context=check.json_object(raw);raw=check.safe_file(BASE/'run-lock.json').read_bytes();check.require(check.digest(raw)==context['run_lock_sha256'],'run lock differs');lock=check.json_object(raw)
    check.require(check.digest(check.safe_file(BASE/'continuation.py').read_bytes())==context['prior_continuation_sha256'],'prior executor differs')
    check.require(check.digest(check.safe_file(BASE/'continuation-context.json').read_bytes())==context['prior_continuation_context_sha256'],'prior context differs')
    for name,sha in context['code_sha256'].items():check.require(check.digest(check.safe_file(prior.CODE/name).read_bytes())==sha,'checker code differs: '+name)
    for name,sha in context['shared_code_sha256'].items():check.require(check.digest(check.safe_file(prior.CODE.parent/'luci-base-inventory'/name).read_bytes())==sha,'shared checker differs: '+name)
    return context,lock


def prior_records(context,lock,stage):
    run=pathlib.Path(lock['run_root']);output=run/'output';resolver=check.safe_file(output/'resolver-only-commands.json')
    check.require(check.digest(resolver.read_bytes())==context['resolver_only_sha256'],'resolver receipt differs')
    rows=prior.resolver_rows(lock,resolver)
    failure=check.json_object(check.safe_file(output/'continuation-failure.json').read_bytes())
    check.require(failure=={'status':'inputs_unchanged','failure':"RuntimeError(\"phase failed; retained receipt: success-query ValueError('command warning/error requires review: success-query')\")"},'prior failure differs')
    check.require(check.json_object(check.safe_file(output/'continuation-postguard.json').read_bytes())==failure,'prior postguard differs')
    for label in ('database-init','database-index','database-finalize','success-query'):
        path=check.safe_file(output/'logs'/(label+'.receipt.json'));row=check.json_object(path.read_bytes())
        check.require(row.get('label')==label and row.get('argv')==lock['phase_argv'][label] and row.get('cwd')==lock['cwd'] and row.get('env')==lock['env'] and row.get('exit')==0,'prior phase differs: '+label)
        for stream in ('stdout','stderr'):
            log=check.safe_file(pathlib.Path(row[stream+'_path']));check.require(check.digest(log.read_bytes())==row[stream+'_sha256'],'prior log differs: '+label)
        lines=[x for x in pathlib.Path(row['stderr_path']).read_text(errors='replace').splitlines() if 'WARNING:' in x.upper()]
        if label=='success-query':
            check.require(lines==[context['known_warning']] and row.get('phase_error')=="ValueError('command warning/error requires review: success-query')",'prior warning differs')
            bqrs=check.safe_file(pathlib.Path(lock['bqrs_paths']['successful']));check.require(check.digest(bqrs.read_bytes())==context['success_bqrs_sha256'],'prior successful BQRS differs')
            row=copy.deepcopy(row);row['classified_warnings']=lines;row['artifacts']={str(bqrs):check.digest(bqrs.read_bytes())};row['exception']={'kind':'reviewed_cache_performance_warning','original_phase_receipt_sha256':check.digest(path.read_bytes()),'prior_failure_retained':True}
        else:
            check.require(not lines and 'phase_error' not in row,'unexpected prior warning/error: '+label)
        rows.append(row)
    route=check.safe_file(pathlib.Path(lock['output_paths']['routing']));check.validate_route(stage,check.json_object(route.read_bytes()))
    index=next(r for r in rows if r['label']=='database-index');check.require(index.get('artifacts')=={str(route):check.digest(route.read_bytes())} and index.get('raw_routing_sha256')==check.digest(route.read_bytes()),'prior route binding differs')
    src=pathlib.Path(lock['database_path'])/'src.zip';source_sha=check.validate_source_archive(stage,src);finalize=next(r for r in rows if r['label']=='database-finalize');check.require(finalize.get('artifacts')=={str(src):source_sha},'prior source archive differs')
    return rows


def run_phase(label,lock,output,artifacts,stage):
    out=output/'logs'/(label+'.stdout');err=output/'logs'/(label+'.stderr');argv=lock['phase_argv'][label]
    start=time.monotonic();failure=None
    row={'label':label,'argv':argv,'cwd':lock['cwd'],'env':lock['env'],'exit':None,'peak_rss_bytes':None,'rss_note':'not measured on this run','stdout_path':str(out),'stderr_path':str(err)}
    try:
        with out.open('xb') as stdout,err.open('xb') as stderr:
            result=subprocess.run(argv,cwd=lock['cwd'],env=lock['env'],stdout=stdout,stderr=stderr,check=False)
        row['exit']=result.returncode;check.require(result.returncode==0,'command failed: '+label)
        text=err.read_text(errors='replace');stdout_text=out.read_text(errors='replace');warnings=[line for line in text.splitlines() if 'WARNING:' in line.upper()]
        check.require(not any(token in stdout_text.upper() for token in ('WARNING:', 'ERROR:', 'FATAL:')), 'unexpected stdout warning/error: '+label)
        check.require(not any(token in text.upper() for token in ('ERROR:', 'FATAL:')) and (not warnings or label in verify.QUERY_PHASES and warnings==[verify.KNOWN_CACHE_WARNING]),'unexpected command warning/error: '+label)
        if label in artifacts:
            artifact=check.safe_file(pathlib.Path(artifacts[label]));row['artifacts']={str(artifact):check.digest(artifact.read_bytes())}
        if warnings:
            check.require(label in verify.QUERY_PHASES and len(row.get('artifacts',{}))==1,'warned query lacks artifact: '+label)
            row['classified_warnings']=warnings;row['exception']={'kind':'reviewed_cache_performance_warning','prior_failure_retained':True}
        prior.phase_gate(label,lock,stage,row)
    except Exception as exc:
        failure=repr(exc);row['phase_error']=failure
    row['elapsed_seconds']=time.monotonic()-start
    for stream,path in (('stdout',out),('stderr',err)):
        row[stream+'_sha256']=check.digest(path.read_bytes()) if path.is_file() and not path.is_symlink() else None
    with (output/'logs'/(label+'.receipt.json')).open('x') as f:json.dump(row,f,indent=2,sort_keys=True);f.write('\n')
    if failure is not None:raise RuntimeError('phase failed; retained receipt: '+label+' '+failure)
    return row


def immutable_previous(context,run):
    current={r['path']:r for r in prior.inventory(run)}
    def immutable(path):
        return path=='stage' or path.startswith('stage/') or path=='db' or path.startswith('db/') or path.startswith('output/')
    for row in context['initial_run_tree']:
        if immutable(row['path']):check.require(current.get(row['path'])==row,'prior input or artifact changed: '+row['path'])
    before={r['path'] for r in context['initial_run_tree'] if r['path']=='db/db-ucode' or r['path'].startswith('db/db-ucode/')}
    after={p for p in current if p=='db/db-ucode' or p.startswith('db/db-ucode/')}
    check.require(before==after,'semantic database inventory changed')
    before_stage={r['path'] for r in context['initial_run_tree'] if r['path']=='stage' or r['path'].startswith('stage/')}
    after_stage={p for p in current if p=='stage' or p.startswith('stage/')}
    check.require(before_stage==after_stage,'stage inventory changed')


def main():
    context,lock=read_inputs();run=pathlib.Path(lock['run_root']);stage=run/'stage'
    check.require(prior.inventory(run)==context['initial_run_tree'],'stopped attempt tree changed')
    provider=prepare.preflight(lock,prior.IPK,prior.PACKAGE_RECEIPT,prior.PRODUCER,prior.CLI,prior.PACK,prior.DEPS)
    check.require(check.safe_file(stage/check.IPK_SOURCE).read_bytes()==provider,'stage differs from actual package')
    rows=prior_records(context,lock,stage);verify.validate_logs(lock,rows)
    pending=verify.PHASES[len(rows):];check.require(pending==('success-decode','errors-query','errors-decode','target-query','target-decode'),'resume phase list differs')
    dummy=rows+[{'label':n,'argv':lock['phase_argv'][n],'cwd':lock['cwd'],'env':lock['env'],'exit':0,'elapsed_seconds':0,'peak_rss_bytes':0} for n in pending]
    verify.validate_commands(lock,{'commands':dummy},prior.CLI,prior.PRODUCER,stage,prior.PACK,prior.DEPS)
    output=run/'output';failure=None
    artifacts={'success-decode':lock['output_paths']['successful'],'errors-query':lock['bqrs_paths']['errors'],'errors-decode':lock['output_paths']['errors'],'target-query':lock['bqrs_paths']['query'],'target-decode':lock['output_paths']['query']}
    try:
        for label in pending:rows.append(run_phase(label,lock,output,artifacts,stage))
        verify.validate_commands(lock,{'commands':rows},prior.CLI,prior.PRODUCER,stage,prior.PACK,prior.DEPS);verify.validate_logs(lock,rows)
    except Exception as exc:failure=repr(exc)
    try:
        read_inputs();prepare.preflight(lock,prior.IPK,prior.PACKAGE_RECEIPT,prior.PRODUCER,prior.CLI,prior.PACK,prior.DEPS);immutable_previous(context,run);prior_records(context,lock,stage)
        post={'status':'inputs_unchanged','failure':failure}
    except Exception as exc:post={'status':'postguard_failed','failure':failure,'postguard_error':repr(exc)}
    with (output/'resume-postguard.json').open('x') as f:json.dump(post,f,indent=2,sort_keys=True);f.write('\n')
    if failure is not None or post['status']!='inputs_unchanged':
        with (output/'resume-failure.json').open('x') as f:json.dump(post,f,indent=2,sort_keys=True);f.write('\n')
        raise SystemExit(1)
    with (output/'commands.json').open('x') as f:json.dump({'commands':rows},f,indent=2,sort_keys=True);f.write('\n')
    print('five remaining phases complete; run verifier separately')
if __name__=='__main__':main()
