import pathlib,json,subprocess,sys,csv,hashlib
r=pathlib.Path('/Users/lalbers/gitroot/ucode/wave-experiments/typed-handoff-20261122'); c=json.loads((r/'context-frozen.json').read_text()); o=json.loads((r/'oracle-expanded.json').read_text()); run=r/'run'; py=c['preparation']['python']; prefix=f'pycache_prefix={run}/empty-pycache'; env=c['environment']; base=[py,'-S','-B','-X',prefix,str(r/'stage-runner.py')]
def invoke(stage):
 print('starting',stage,flush=True); p=subprocess.run(base+[stage],cwd=r,env=env); print('finished',stage,p.returncode,flush=True); assert p.returncode==0,stage
for s in ['init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode']: invoke(s)
for name,key in [('extracted','extracted_rows'),('errors','errors_rows'),('effects','effects_rows')]:
 with (run/(name+'.csv')).open(newline='') as f: actual=list(csv.reader(f))
 assert actual==o[key],(name,actual,o[key])
print('independent exact CSV and diagnostics gate passed',flush=True)
invoke('export')
assert json.loads((run/'typed.json').read_text())==o['neutral_typed_payload']; print('complete neutral payload gate passed',flush=True)
for s in ['import','reimport']: invoke(s)
print('all stages finished',flush=True)
