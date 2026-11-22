import pathlib,json,hashlib,os,subprocess,sys
r=pathlib.Path('/Users/lalbers/gitroot/ucode/wave-experiments/typed-handoff-20261122'); ctx=json.loads((r/'context-frozen.json').read_text()); prep=r/'preparation'; h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert h(r/'context-frozen.json')=='56e0a7fdf6f23ff5a38ad61942e687d8c720e4d5772fd72c35b53b93c9f2a995'; assert h(r/'oracle-expanded.json')=='cc978a8068a5a2cc0d8ae9f9a2460b6e95f03b4742a550eee4af05961abe311b'; assert h(r/'stage-runner.py')=='296d7b28def67b7bb80d27912b285ebdf9eefa42294eb6115fe21f4ea7ec161f'; assert h(pathlib.Path(ctx['preparation']['python_framework']['path']))==ctx['preparation']['python_framework']['sha256']; assert h(pathlib.Path(ctx['preparation']['python']))==ctx['preparation']['python_binary_sha256']
for name,digest in ctx['preparation']['inventories'].items():
 f=prep/name; assert h(f)==digest; inv=json.loads(f.read_text()); root=pathlib.Path(inv['root']); actual={}
 for d,dirs,files in os.walk(root,followlinks=False):
  dirs.sort(); files.sort()
  for n in dirs+files:
   p=pathlib.Path(d)/n; rel=str(p.relative_to(root))
   if p.is_symlink(): actual[rel]={'symlink':os.readlink(p)}
   elif p.is_file(): actual[rel]={'sha256':h(p),'size':p.stat().st_size}
 assert actual==inv['files'],name
for side in ['producer','consumer']:
 root=r/side; assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==ctx[side+'_commit']; assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True); expected=ctx[side+'_tracked_sha256']; assert all(h(root/p)==v for p,v in expected.items()),side
assert not (r/'run/db').exists(); assert not (r/'run/empty-pycache').exists(); result={'frozen_context':h(r/'context-frozen.json'),'oracle':h(r/'oracle-expanded.json'),'runner':h(r/'stage-runner.py'),'exporter':h(r/'producer/tools/export_setblock_detect.py'),'python':h(pathlib.Path(ctx['preparation']['python'])),'framework':h(pathlib.Path(ctx['preparation']['python_framework']['path'])),'roots_clean':True,'inventories_match':True,'database_absent':True}; (prep/'preflight.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result))
