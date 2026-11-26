#!/usr/bin/env python3
"""Decode one reviewed existing mutant BQRS; do not rerun extraction/query."""
import hashlib,importlib.util,json,pathlib,subprocess,time
BASE=pathlib.Path('/Users/lalbers/gitroot/ucode/coverage-wave-work/issue175-execution-context-20261126')
EXEC_SHA='44306b16aa0484ed8f8ebb930a40c09803e95cfc7ccdb4b4c73084f58b6bce6a'
CONTEXT_SHA='9954c6529714f6ab6436ebeac8eaed7b558a30e1a0c1e9970e2d6bfedd297da4'
def data(p):
 if not p.is_absolute() or p.resolve(strict=True)!=p or not p.is_file() or p.is_symlink() or p.stat().st_nlink!=1:raise ValueError('unsafe file: '+str(p))
 return p.read_bytes()
def sha(p):return hashlib.sha256(data(p)).hexdigest()
if sha(BASE/'controls-executor.py')!=EXEC_SHA:raise ValueError('control executor differs')
spec=importlib.util.spec_from_file_location('previous_controls',BASE/'controls-executor.py');prev=importlib.util.module_from_spec(spec);spec.loader.exec_module(prev)
check=prev.check;prior=prev.prior
WARNING1='WARNING: Not caching stages during query-loading, since max heap size is only 1816 MB.'
WARNING2="WARNING: unused predicate 'systemFormalInBody' ("+str(BASE/'mutation-producer/ql/lib/codeql/ucode/m3/Models.qll')+':149,19-37)'

def guard(context,lock,stage):
 prev.read_inputs();prev.source_guards();run=pathlib.Path(lock['run_root'])
 current={x['path']:x for x in prior.inventory(run)}
 for row in context['initial_run_tree']:check.require(current.get(row['path'])==row,'stopped evidence changed: '+row['path'])
 extra=set(current)-{x['path'] for x in context['initial_run_tree']};check.require(not extra or extra=={'mutation/output/mutant.json'},'unexpected run additions')
 for name,d in context['retained_files_sha256'].items():check.require(sha(BASE/name)==d,'retained receipt differs: '+name)
 bqrs=run/'mutation/output/mutant.bqrs';check.require(sha(bqrs)==context['mutant_bqrs_sha256'] and bqrs.stat().st_size>0,'mutant BQRS differs')
 receipt=check.load_json(data(run/'mutation/output/logs/query.receipt.json'));plan=check.load_json(data(BASE/'mutation-plan.json'))
 check.require(receipt['argv']==plan['commands']['query'] and receipt['cwd']==plan['cwd'] and receipt['env']==plan['env'] and receipt['exit']==0 and receipt.get('phase_error')=="ValueError('unexpected control stderr warning')",'stopped query identity differs')
 stderr=data(pathlib.Path(receipt['stderr_path'])).decode();stdout=data(pathlib.Path(receipt['stdout_path'])).decode();warnings=[line for line in stderr.splitlines() if 'WARNING:' in line.upper()]
 check.require(warnings==[WARNING1,WARNING2] and not any(t in stderr.upper() for t in ('ERROR:','FATAL:')) and not any(t in stdout.upper() for t in ('WARNING:','ERROR:','FATAL:')),'stopped warning set differs')
 check.require(any(line.endswith('Evaluation done; writing results to '+str(bqrs)+'.') for line in stderr.splitlines()),'query evaluation output destination differs')
 check.require(receipt['stdout_sha256']==hashlib.sha256(stdout.encode()).hexdigest() and receipt['stderr_sha256']==hashlib.sha256(stderr.encode()).hexdigest(),'stopped output digests differ')
 return plan

def main():
 context_data=data(BASE/'mutation-decode-context.json');check.require(hashlib.sha256(context_data).hexdigest()==CONTEXT_SHA,'decode context differs');context=check.load_json(context_data)
 _,lock,stage=prev.read_inputs();plan=guard(context,lock,stage);run=pathlib.Path(lock['run_root']);target=run/'mutation/output/mutant.json';check.require(not target.exists() and not target.is_symlink(),'decode output not fresh')
 stdout=BASE/'mutation-decode.stdout';stderr=BASE/'mutation-decode.stderr';record=BASE/'mutation-decode-receipt.json'
 for p in (stdout,stderr,record):check.require(not p.exists() and not p.is_symlink(),'decode receipt/log path not fresh')
 failure=None;exitcode=None;start=time.monotonic()
 try:
  with stdout.open('xb') as out,stderr.open('xb') as err:exitcode=subprocess.run(plan['commands']['decode'],cwd=plan['cwd'],env=plan['env'],stdout=out,stderr=err,check=False).returncode
  check.require(exitcode==0,'decode command failed');check.require(not data(stderr),'decode stderr nonempty');text=data(stdout).decode(errors='replace').upper();check.require(not any(x in text for x in ('WARNING:','ERROR:','FATAL:')),'decode stdout warning/error')
  output=data(target);check.require(bool(output),'empty decoded output')
  result=prev.controls.validate(stage,check.oracle(),check.load_json(data(run/'output/query.json')),check.load_json(data(run/'witness/output/witness.json')),check.load_json(output))
 except Exception as e:failure=repr(e);result=None
 try:guard(context,lock,stage);post='inputs_unchanged'
 except Exception as e:post='postguard_failed';failure=(failure or '')+' postguard '+repr(e)
 row={'argv':plan['commands']['decode'],'cwd':plan['cwd'],'env':plan['env'],'exit':exitcode,'elapsed_seconds':time.monotonic()-start,'peak_rss_bytes':None,'rss_note':'not measured','prior_warning_exception':{'warnings':[WARNING1,WARNING2],'query_receipt_sha256':context['query_receipt_sha256'],'bqrs_sha256':context['mutant_bqrs_sha256']},'postguard':post,'failure':failure,'result':result}
 for n,p in (('stdout',stdout),('stderr',stderr),('decoded',target)):
  try:row[n+'_sha256']=sha(p)
  except Exception as e:
   row[n+'_sha256']=None;row[n+'_capture_error']=repr(e)
   if failure is None:failure=repr(e);row['failure']=failure
 with record.open('x') as f:json.dump(row,f,indent=2,sort_keys=True);f.write('\n')
 if failure or post!='inputs_unchanged':raise SystemExit('decode failed; receipt retained')
 print('mutant decode and exact control observations passed; independent audit required')
if __name__=='__main__':main()
