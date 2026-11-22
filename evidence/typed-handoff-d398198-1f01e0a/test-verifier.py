#!/usr/bin/env python3
"""Regression checks: mutate and reseal the outer checksum list in disposable copies."""
import hashlib,json,pathlib,shutil,subprocess,sys,tempfile
source=pathlib.Path(__file__).resolve().parent
def mutate_json(path,fn):
 data=json.loads(path.read_text()); fn(data); path.write_text(json.dumps(data,indent=2)+'\n')
def run(case):
 with tempfile.TemporaryDirectory() as temp:
  p=pathlib.Path(temp)/'packet'; shutil.copytree(source,p); r=p/'run'
  if case=='bqrs': (r/'effects.bqrs').write_bytes(b'replaced')
  if case=='timing': mutate_json(r/'index.receipt.json',lambda x:x.update(start_epoch=0))
  if case=='stream': mutate_json(r/'import.receipt.json',lambda x:x['stderr'].update(path=x['stderr']['path'].replace('import.stderr','export.stderr')))
  if case=='typed': mutate_json(r/'reimport.receipt.json',lambda x:x['before']['typed'].update(sha256='0'*64))
  if case=='summary': mutate_json(r/'verification.json',lambda x:x['stages']['init'].update(receipt_sha256='0'*64))
  if case=='source':
   for f in r.glob('*.receipt.json'):
    x=json.loads(f.read_text())
    for edge in ['before','after']:
     x[edge]['source']['usr/share/rpcd/ucode/luci']['sha256']='0'*64
    f.write_text(json.dumps(x,indent=2)+'\n')
  summary=json.loads((r/'verification.json').read_text())
  for stage,record in summary['stages'].items(): record['receipt_sha256']=hashlib.sha256((r/(stage+'.receipt.json')).read_bytes()).hexdigest()
  if case!='summary': (r/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
  (p/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(p))+'\n' for f in sorted(p.rglob('*')) if f.is_file() and f.name!='SHA256SUMS'))
  result=subprocess.run([sys.executable,'-B',str(p/'verify.py')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  assert result.returncode!=0,case
for case in ['bqrs','timing','stream','typed','summary','source']:
 run(case); print(case,'rejected')
