#!/usr/bin/env python3
"""Proposed two-control continuation; no extraction or mutation of producer."""
import hashlib,importlib.util,json,pathlib,subprocess,time
BASE=pathlib.Path('/Users/lalbers/gitroot/ucode/coverage-wave-work/issue175-execution-context-20261126')
CONTINUATION_SHA='1d61f4b27e65fb6617fcde1a70bb55a77711732b5ae531c1ccde7b663b820201'
CONTROL_SHA='0c4c53928683975514cce8b7715034923ece3a4487e11e52300b7724db4707e0'
CONTEXT_SHA='6038246476c80885931c7f3152e9d8fbd1f70da25380c468344d7e879e95076e'
def rawfile(p):
 if not p.is_absolute() or p.resolve(strict=True)!=p or not p.is_file() or p.is_symlink() or p.stat().st_nlink!=1:raise ValueError('unsafe file: '+str(p))
 return p.read_bytes()
def digest(data):return hashlib.sha256(data).hexdigest()
if digest(rawfile(BASE/'continuation.py'))!=CONTINUATION_SHA:raise ValueError('continuation changed')
spec=importlib.util.spec_from_file_location('prior_continuation175',BASE/'continuation.py');prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
check=prior.check;prepare=prior.prepare;verify=prior.verify
controlfile=prior.CODE/'controls.py'
if digest(rawfile(controlfile))!=CONTROL_SHA:raise ValueError('control checker differs')
spec=importlib.util.spec_from_file_location('controls175',controlfile);controls=importlib.util.module_from_spec(spec);spec.loader.exec_module(controls)

def source_guards():
 for name,expected_status in (('witness','?? ql/src/m3/Issue175CoordinateWitness.ql'),('mutation',' M ql/lib/codeql/ucode/m3/Models.qll')):
  root=BASE/(name+'-producer')
  check.require(root.resolve(strict=True)==root and (root/'.git').is_dir() and not (root/'.git').is_symlink() and not (root/'.git/objects/info/alternates').exists(),'control producer is not standalone')
  def git(*args):return subprocess.check_output(['git','-C',str(root),*args],text=True).rstrip('\n')
  check.require(git('rev-parse','HEAD')==check.PRODUCER and git('status','--porcelain=v1','--ignored','--untracked-files=all')==expected_status,'control source status differs')
  if name=='mutation':
   check.require(digest(subprocess.check_output(['git','-C',str(root),'diff','--binary']))=='13bdb71af2e5c4c2ca68daae1b7882fcad570f24a07dba3c6270bc5c88e5f738','mutation diff differs')
   check.require(digest(rawfile(root/'ql/lib/codeql/ucode/m3/Models.qll'))=='7ed06cb413f421ee094e2d392fd8698fc9d652931929f5a6b67364df52464aef','mutant source differs')
  else:check.require(digest(rawfile(root/'ql/src/m3/Issue175CoordinateWitness.ql'))=='f921d9f1efb08b507199c0fc6b197a1ca19d73e0eecd7f781acc2c535d78f6ea','witness source differs')

def read_inputs():
 source_guards()
 context_data=rawfile(BASE/'controls-context.json');check.require(digest(context_data)==CONTEXT_SHA,'controls context differs');context=check.load_json(context_data)
 for name,sha in context['retained_files_sha256'].items():check.require(digest(rawfile(BASE/name))==sha,'retained evidence differs: '+name)
 prior_context,lock=prior.read_locked();run=pathlib.Path(lock['run_root'])
 for name,sha in context['plans_sha256'].items():check.require(digest(rawfile(BASE/name))==sha,'plan differs: '+name)
 check.require(digest(rawfile(controlfile))==CONTROL_SHA and digest(rawfile(BASE/'continuation.py'))==CONTINUATION_SHA,'executor input differs')
 stage,resolver=prior.pinned_inputs(prior_context,lock);prior.resolver_rows(lock,resolver)
 verify.validate_commands(lock,check.load_json(rawfile(run/'output/commands.json')),prior.CLI,prior.PRODUCER,stage,prior.PACK,prior.DEPS)
 check.validate_route(stage,check.load_json(rawfile(run/'output/routing.json')));check.validate_source_archive(stage,run/'db/src.zip')
 check.validate_success(stage,check.load_json(rawfile(run/'output/successful.json')));check.validate_errors(check.load_json(rawfile(run/'output/errors.json')))
 check.validate_query(stage,check.load_json(rawfile(run/'output/query.json')),check.oracle())
 return context,lock,stage

def immutable(context,run):
 current={r['path']:r for r in prior.inventory(run)}
 for row in context['initial_run_tree']:
  check.require(current.get(row['path'])==row,'prior evidence changed: '+row['path'])
 for prefix in ('stage','db/db-ucode'):
  before={r['path'] for r in context['initial_run_tree'] if r['path']==prefix or r['path'].startswith(prefix+'/')}
  after={n for n in current if n==prefix or n.startswith(prefix+'/')}
  check.require(before==after,'immutable path set changed: '+prefix)
 old={r['path'] for r in context['initial_run_tree']}
 for path in current.keys()-old:
  check.require(path in ('witness','mutation') or path.startswith(('witness/','mutation/','db/log/','db/diagnostic/')),'unexpected run addition: '+path)

def witness_unchanged(snapshot,root):
 check.require(prior.inventory(root)==snapshot,'witness output changed during mutation')

def run_control(kind,plan,lock,stage):
 root=pathlib.Path(plan['private_root']);check.require(not root.exists() and not root.is_symlink(),'control root not fresh')
 root.mkdir();out=root/'output';out.mkdir();(out/'logs').mkdir()
 for x in ('home','tmp','cache/queries','cache/compile'):(root/x).mkdir(parents=True,exist_ok=False)
 records=[]
 for phase in ('resolve','query','decode'):
  argv=plan['commands'][phase];stdout=out/('resolver.json' if phase=='resolve' else 'logs/'+phase+'.stdout');stderr=out/'logs'/(phase+'.stderr');start=time.monotonic();row={'phase':phase,'argv':argv,'cwd':plan['cwd'],'env':plan['env'],'exit':None,'stdout_path':str(stdout),'stderr_path':str(stderr),'peak_rss_bytes':None,'rss_note':'not measured'};failure=None
  try:
   if phase=='query':target=out/('witness.bqrs' if kind=='witness' else 'mutant.bqrs')
   elif phase=='decode':
    bqrs=check.safe_file(out/('witness.bqrs' if kind=='witness' else 'mutant.bqrs'));check.require(bqrs.stat().st_size>0,'empty input BQRS');check.require(records and records[-1].get('phase')=='query' and digest(rawfile(bqrs))==records[-1].get('artifact_sha256'),'query BQRS changed before decode');target=out/('witness.json' if kind=='witness' else 'mutant.json')
   else:target=None
   if target is not None:check.require(not target.exists() and not target.is_symlink(),'control target not fresh')
   with stdout.open('xb') as so,stderr.open('xb') as se:row['exit']=subprocess.run(argv,cwd=plan['cwd'],env=plan['env'],stdout=so,stderr=se,check=False).returncode
   check.require(row['exit']==0,'control command failed');out_text=rawfile(stdout).decode(errors='replace');err_text=rawfile(stderr).decode(errors='replace');warnings=[x for x in err_text.splitlines() if 'WARNING:' in x.upper()]
   check.require(not any(x in out_text.upper() for x in ('WARNING:','ERROR:','FATAL:')) and not any(x in err_text.upper() for x in ('ERROR:','FATAL:')),'control warning/error')
   check.require(not warnings or phase=='query' and warnings==[verify.KNOWN_CACHE_WARNING],'unexpected control stderr warning');row['classified_warnings']=warnings
   if phase=='resolve':
    check.require(not err_text,'resolver stderr nonempty');data=check.load_json(rawfile(stdout));producer=pathlib.Path(plan['cwd']);expected=[x.replace(str(prior.PRODUCER),str(producer)) for x in lock['resolved_library_paths']]
    check.require(data.get('libraryPath')==expected and data.get('dbscheme')==str(producer/'ql/lib/ucode.dbscheme') and data.get('relativeName')==plan['resolved_relative_name'] and data.get('qlPackName')=='lucas-albers-lz4/ucode-queries' and data.get('compilationCache')==[str(root/'cache/compile')],'control resolver differs')
    row['artifact_sha256']=digest(rawfile(stdout))
   else:
    payload=rawfile(target);check.require(bool(payload),'control artifact empty');row['artifact_sha256']=digest(payload)
    if phase=='decode':
     expected=check.oracle();expected['rows']=[dict(x,expected_rows=1) if x['path']==check.NEG else x for x in expected['rows']]
     check.validate_query(stage,check.load_json(payload),expected)
  except Exception as e:failure=repr(e);row['phase_error']=failure
  row['elapsed_seconds']=time.monotonic()-start
  for n,p in (('stdout',stdout),('stderr',stderr)):
   try:row[n+'_sha256']=digest(rawfile(p))
   except Exception as e:
    row[n+'_sha256']=None
    if failure is None:failure=repr(e);row['phase_error']=failure
    else:row[n+'_capture_error']=repr(e)
  with (out/'logs'/(phase+'.receipt.json')).open('x') as f:json.dump(row,f,indent=2,sort_keys=True);f.write('\n')
  records.append(row)
  if failure:raise RuntimeError('control stopped with retained phase receipt: '+kind+' '+phase+' '+failure)
 return records

def postguard(context,run,witness_snapshot):
 read_inputs();immutable(context,run)
 if witness_snapshot is not None:witness_unchanged(witness_snapshot,run/'witness')

def main():
 context,lock,stage=read_inputs();run=pathlib.Path(lock['run_root']);check.require(prior.inventory(run)==context['initial_run_tree'],'baseline run tree differs')
 plans={n:check.load_json(rawfile(BASE/(n+'-plan.json'))) for n in ('witness','mutation')}
 # Separate pack source identities checked before and after by the context inventory below.
 failure=None;witness_snapshot=None
 try:
  run_control('witness',plans['witness'],lock,stage);immutable(context,run)
  witness_snapshot=prior.inventory(run/'witness')
  source_guards();run_control('mutation',plans['mutation'],lock,stage);immutable(context,run)
  witness_unchanged(witness_snapshot,run/'witness')
  result=controls.validate(stage,check.oracle(),check.load_json(rawfile(run/'output/query.json')),check.load_json(rawfile(run/'witness/output/witness.json')),check.load_json(rawfile(run/'mutation/output/mutant.json')))
 except Exception as e:failure=repr(e);result=None
 try:
  postguard(context,run,witness_snapshot)
  post={'status':'baseline_unchanged','failure':failure,'result':result}
 except Exception as e:post={'status':'postguard_failed','failure':failure,'postguard_error':repr(e)}
 with (BASE/'controls-postguard.json').open('x') as f:json.dump(post,f,indent=2,sort_keys=True);f.write('\n')
 if failure or post['status']!='baseline_unchanged':raise SystemExit('control failure preserved')
 print('both control queries matched source-first oracle; independent audit required')
if __name__=='__main__':main()
