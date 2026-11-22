#!/usr/bin/env python3
"""Execute one reviewed stage, with exclusive log/receipt creation and snapshots."""
import hashlib,json,os,pathlib,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parent
ctxpath=root/'context-frozen.json'; context=json.loads(ctxpath.read_text()); run=root/'run'; stage=sys.argv[1]; cfg=context['commands'][stage]
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  while b:=f.read(1048576): h.update(b)
 return h.hexdigest()
def inventory(base):
 if not base.exists(): return None
 if base.is_file(): return {'sha256':digest(base)}
 result={}
 for d,dirs,files in os.walk(base,followlinks=False):
  dirs[:]=sorted(x for x in dirs if x != '.git'); files.sort()
  for n in dirs+files:
   p=pathlib.Path(d)/n; name=str(p.relative_to(base))
   if p.is_symlink(): result[name]={'symlink':os.readlink(p)}
   elif p.is_file(): result[name]={'sha256':digest(p),'size':p.stat().st_size}
 return result
paths={'source':run/'src','consumer':root/'consumer','ql_src':root/'producer/ql/src','ql_lib':root/'producer/ql/lib','extractor':root/'producer/extractor-pack','packs':run/'home/.codeql/packages','database':run/'db','effects_bqrs':run/'effects.bqrs','extracted_bqrs':run/'extracted.bqrs','errors_bqrs':run/'errors.bqrs','effects_csv':run/'effects.csv','extracted_csv':run/'extracted.csv','errors_csv':run/'errors.csv','typed':run/'typed.json'}
# Lock establishes a single runner in this run; no earlier output may be replaced.
lock=run/'stage-runner.lock'; fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
try:
 expected_output=run/'db' if stage=='init' else run/(stage.removesuffix('_query')+'.bqrs') if stage.endswith('_query') else None
 if expected_output is not None and expected_output.exists(): raise RuntimeError('stage output already exists: '+str(expected_output))
 before={k:inventory(v) for k,v in paths.items()}; start=time.time()
 with open(cfg['stdout'],'xb') as stdout,open(cfg['stderr'],'xb') as stderr:
  proc=subprocess.run(cfg['argv'],cwd=cfg['cwd'],env=cfg['env'],stdout=stdout,stderr=stderr,check=False)
 after={k:inventory(v) for k,v in paths.items()}; receipt={'stage':stage,'context_sha256':digest(ctxpath),'argv':cfg['argv'],'cwd':cfg['cwd'],'environment':cfg['env'],'start_epoch':start,'end_epoch':time.time(),'exit_code':proc.returncode,'stdout':{'path':cfg['stdout'],'sha256':digest(pathlib.Path(cfg['stdout']))},'stderr':{'path':cfg['stderr'],'sha256':digest(pathlib.Path(cfg['stderr']))},'before':before,'after':after}
 with open(cfg['receipt'],'x') as f: json.dump(receipt,f,sort_keys=True,indent=2); f.write('\n')
 if proc.returncode != cfg['expected_exit']: sys.exit(proc.returncode or 1)
finally: lock.unlink()
