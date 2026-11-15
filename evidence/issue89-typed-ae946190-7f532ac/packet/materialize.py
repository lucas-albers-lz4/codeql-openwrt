#!/usr/bin/python3
"""Prepare unapproved issue89 exact-pin candidate; no DB or product execution."""
import ast, copy, hashlib, io, json, os, pathlib, re, shutil, stat, subprocess, sys, tarfile
BASE=pathlib.Path('/root/workspace/workflow-design')
T=BASE/'live-handoff/issue89-typed-ae946190-7f532ac-a3/trusted'
E=BASE/'evidence/issue89-typed-ae946190-7f532ac-a3'
A=E/'attempt'
OLD=BASE/'evidence/issue89-typed-ae946190-7f532ac-a1'
OLDT=BASE/'live-handoff/issue89-typed-ae946190-7f532ac-a1/trusted'
DRAFT=BASE/'live-handoff/typed89-runner-draft'
Q=pathlib.Path('/root/.local/share/gh/extensions/gh-codeql/dist/release/v2.27.4')
PY=pathlib.Path('/usr/bin/python3.13')
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest()
def save(p,o): p.write_text(json.dumps(o,sort_keys=True,indent=2,ensure_ascii=True)+'\n',encoding='utf8')
if T.parent.exists() or E.exists(): raise SystemExit('candidate path already exists; preserving it')
T.mkdir(parents=True); E.mkdir(parents=True)
P=E/'producer'; C=E/'consumer'; S=E/'sealed/ql/test/extractor-smoke'; source=S/'usr/share/rpcd/ucode/luci'
prov={'status':'UNAPPROVED; no DB/query/export/import execution','git_exports':{}}
for name,repo,commit in [('producer','/root/workspace/codeql-ucode','ae946190661eb221bc1f562fdba02088ef83de2d'),('consumer','/root/workspace/wt-openwrt-typed-89','7f532ac6ab527ee1bf07711fd7942dc4be381b48')]:
 out=E/name; out.mkdir(); archive=subprocess.check_output(['git','-C',repo,'archive','--format=tar',commit])
 with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(out,filter='data')
 entries=subprocess.check_output(['git','-C',repo,'ls-tree','-rz','--full-tree',commit]).split(b'\0'); tracked={}
 for entry in filter(None,entries):
  meta,path=entry.split(b'\t',1); mode,kind,blob=meta.decode().split(); path=os.fsdecode(path); p=out/path
  if kind!='blob' or not p.is_file() or p.is_symlink(): raise RuntimeError('unsupported git entry '+path)
  data=p.read_bytes(); actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
  if actual!=blob or bool(p.stat().st_mode&0o111)!=(mode=='100755'): raise RuntimeError('archive mismatch '+path)
  tracked[path]={'git_mode':mode,'git_blob':blob,'mode':stat.S_IMODE(p.stat().st_mode),'sha256':hashlib.sha256(data).hexdigest()}
 if any(p.name=='__pycache__' or p.suffix=='.pyc' for p in out.rglob('*')):raise RuntimeError('product bytecode present')
 save(T/(name+'-commit-inventory.json'),tracked)
 tree=subprocess.check_output(['git','-C',repo,'rev-parse',commit+'^{tree}'],text=True).strip()
 prov['git_exports'][name]={'commit':commit,'tree':tree,'archive_sha256':hashlib.sha256(archive).hexdigest(),'tracked_count':len(tracked),'repository':repo,'destination':str(out)}
for name in ('bootstrap.py','orchestrator.py','recorder.py','comparator.py','test_draft.py','README.md','unit-tests-normal-2026.log','unit-tests-optimized-2026.log','red-duplicate-mutant-normal-2026.log','red-duplicate-mutant-optimized-2026.log'):
 shutil.copy2(DRAFT/name,T/name)
# This materialization-only correction binds tests to packaged independent oracles
# and the exact staged consumer; it does not change the runner trust anchors.
test=T/'test_draft.py'
text=test.read_text(encoding='utf8')
old="OLD = HERE.parent / 'issue89-typed-ae946190-280cb62-a1' / 'trusted'\nCONSUMER = HERE.parent.parent / 'evidence/issue89-typed-ae946190-280cb62-a1/consumer'"
new="OLD = HERE\nCONSUMER = Path('/root/workspace/workflow-design/evidence/issue89-typed-ae946190-7f532ac-a3/consumer')"
if text.count(old)!=1: raise RuntimeError('unexpected test layout')
test.write_text(text.replace(old,new),encoding='utf8')
readme=T/'README.md'; text=readme.read_text(encoding='utf8')
text=text.replace('Tests use data from the **old** draft as fixture inputs', 'Tests use this packet’s oracles and the explicitly pinned a3 staged consumer as fixture inputs')
text=text.replace('These tests read the earlier staged consumer and old oracle files to construct explicitly synthetic fixtures; the final packet must not depend on those mutable paths.', 'These tests read the a3 staged consumer and this packet’s oracle files to construct explicitly synthetic fixtures; they are not live evidence. The staged consumer is inventoried but must remain unchanged.')
text=text.replace("### This revision's synthetic evidence",'### Historical draft synthetic evidence (not this packet’s test run)')
readme.write_text(text,encoding='utf8')
sys.path.insert(0,str(T)); import recorder as r, comparator as c
for name in ('extractor-pack','resolved-packs'):
 src=OLD/'producer'/name; dest=P/name; shutil.copytree(src,dest,symlinks=True)
 if not c.same(r.inventory(src),r.inventory(dest)): raise RuntimeError('generated copy differs '+name)
 save(T/(name+'-inventory.json'),r.inventory(dest))
source.parent.mkdir(parents=True);shutil.copy2(OLD/'sealed/ql/test/extractor-smoke/usr/share/rpcd/ucode/luci',source)
if sha(source)!='6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e':raise RuntimeError('source digest')
prov['source']={'origin':str(OLD/'sealed/ql/test/extractor-smoke/usr/share/rpcd/ucode/luci'),'url':'https://raw.githubusercontent.com/openwrt/luci/b2e0be4b46ec0fd43394c081fa7c50657af14011/modules/luci-base/root/usr/share/rpcd/ucode/luci','sha256':sha(source),'path':str(source),'mode':stat.S_IMODE(source.stat().st_mode),'note':'copied from previous evidence; not freshly fetched'}
prov['generated']={'origin':str(OLD/'producer'),'items':['extractor-pack','resolved-packs'],'copy_verified_path_mode_and_sha256':True,'note':'historical generated bytes, not proven built from merged producer commit; prior build provenance retained; independent review required'}
shutil.copytree(OLDT/'prior-preparation',T/'prior-preparation');shutil.copy2(OLDT/'old-producer-vs-pin.json',T/'old-producer-vs-pin.json');shutil.copy2(OLDT/'prior-independent-design-review.txt',T/'prior-independent-design-review.txt')
# Restricted literal AST extraction from committed consumer source; no product imports.
tree=ast.parse((C/'policy/tests/test_setblock_typed.py').read_text());nodes={}
for n in tree.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('RID','NEUTRAL'):nodes[n.targets[0].id]=n.value
rid=ast.literal_eval(nodes['RID'])
class Replace(ast.NodeTransformer):
 def visit_Name(self,n):
  if n.id!='RID':raise ValueError(n.id)
  return ast.copy_location(ast.Constant(rid),n)
neutral=ast.literal_eval(Replace().visit(nodes['NEUTRAL'])); retained=copy.deepcopy(neutral)
retained['analysis_revision']='step3:setblock-typed-import-v1';retained['assessment']='intended_access';retained['expectation_id']='luci-mod-system-mounts'
retained['assumptions'].append('Assessment uses the independent synthetic mounts expectation, not the source table')
retained['evidence_refs']=['policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect','policy:grant:root:ubus_http:luci.setBlockDetect']+retained['evidence_refs']
save(T/'oracle-neutral.json',[neutral]);save(T/'oracle-retained.json',retained);shutil.copy2(C/'policy/fixtures/setblock-handoff-v1.json',T/'oracle-csv-fixture.json')
if sha(T/'oracle-neutral.json')!='5c619d5aa3566c5296080b0a9be7072b38d6eb7a98eae647d68c5dcf09b2b59b' or sha(T/'oracle-retained.json')!='c6ba7438debd5d65250448fb60346eb051dfad1d438f38513c7fd732c5a0ae59':raise RuntimeError('oracle mismatch')
prov['oracle']={'test':str(C/'policy/tests/test_setblock_typed.py'),'test_sha256':sha(C/'policy/tests/test_setblock_typed.py'),'derivation':'restricted literal NEUTRAL with RID substitution; RETAINED edits transcribed from committed test lines 47-54; fixture copied from pinned consumer; never exporter output','neutral_sha256':sha(T/'oracle-neutral.json'),'retained_sha256':sha(T/'oracle-retained.json'),'fixture_sha256':sha(T/'oracle-csv-fixture.json')}
QEX=Q/'codeql';D=A/'database';B=A/'artifacts';sp=':'.join(str(P/x) for x in ('extractor-pack','ql/lib','ql/src','resolved-packs'))
env={'HOME':str(A/'home'),'TMPDIR':str(A/'tmp'),'XDG_CACHE_HOME':str(A/'cache'),'XDG_CONFIG_HOME':str(A/'config'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','PATH':'/usr/bin:/bin'}
common=['--no-default-compilation-cache','--compilation-cache='+str(A/'query-cache'),'--common-caches='+str(A/'common-cache')]
commands={}
def add(n,argv,cwd=P):commands[n]={'argv':list(map(str,argv)),'cwd':str(cwd),'env':env.copy()}
add('init',[QEX,'database','init',D,'--language=ucode','--search-path='+str(P/'extractor-pack'),'--source-root='+str(S),'--common-caches='+str(A/'common-cache')])
add('index',[QEX,'database','index-files',D,'--language=ucode','--include=**/rpcd/ucode/luci','--working-dir='+str(S),'--common-caches='+str(A/'common-cache')])
add('finalize',[QEX,'database','finalize',D,'--common-caches='+str(A/'common-cache')])
for n,q in [('effects','m4/SetBlockDetectEffectTable.ql'),('extracted','diagnostics/SuccessfullyExtractedFiles.ql'),('errors','diagnostics/ExtractionErrors.ql')]:
 add(n+'-resolve',[QEX,'resolve','library-path','--query='+str(P/'ql/src'/q),'--format=json','--search-path='+sp,'--additional-packs='+str(P/'resolved-packs')]+common)
 add(n+'-query',[QEX,'query','run',P/'ql/src'/q,'--database='+str(D),'--search-path='+sp,'--additional-packs='+str(P/'resolved-packs'),'--output='+str(B/(n+'.bqrs'))]+common)
 add(n+'-decode',[QEX,'bqrs','decode','--format=csv',B/(n+'.bqrs')])
add('export',[PY,'-E','-S','-B',P/'tools/export_setblock_detect.py','--csv',B/'effects.csv','--extracted',B/'extracted.csv','--errors',B/'errors.csv','--source-root',S,'--lock',C/'corpus/lock.json'])
for n in ('import','reimport'):add(n,[PY,'-E','-S','-B','-m','policy.setblock_table','--typed-json',B/'typed.json','--source-root',S],C)
cfg={'attempt':str(A),'producer':str(P),'consumer':str(C),'source_root':str(S),'source':str(source),'codeql_root':str(Q),'commands':commands};save(T/'config.json',cfg)
# Only dependency resolution: same argv, cwd, complete environment and paths as eventual run.
# Temporarily create the future writable directories; remove ALL of them after checks,
# before any approval, so an actual attempt gets newly empty caches and an absent root.
A.mkdir(mode=0o700)
try:
 for name in ('home','tmp','cache','config','query-cache','common-cache'):(A/name).mkdir()
 for n in ('effects','extracted','errors'):
  spec=commands[n+'-resolve']; proc=subprocess.run(spec['argv'],cwd=spec['cwd'],env=spec['env'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
  if proc.returncode: raise RuntimeError('resolution failed '+n+': '+proc.stderr.decode(errors='replace'))
  result=json.loads(proc.stdout)
  for p in result['libraryPath']+[result['dbscheme']]:
   if not pathlib.Path(p).is_relative_to(P):raise RuntimeError('resolution escaped producer '+p)
  if result['compilationCache']!=[str(A/'query-cache')]:raise RuntimeError('unexpected compilation cache')
  (T/(n+'-resolution.json')).write_bytes(proc.stdout)
  (T/(n+'-resolution.stderr')).write_bytes(proc.stderr)
 if (A/'database').exists() or (A/'artifacts').exists() or (A/'logs').exists():raise RuntimeError('unexpected attempt content')
finally:
 shutil.rmtree(A)
prov['resolution']='Three resolve library-path calls only, with byte-identical argv/cwd/env to configured eventual resolution; temporary future attempt directories and caches removed afterward; absent attempt will be exclusively recreated with empty caches. Actual raw stdout retained as expectations; no receipts emitted.'
roots=[P,C,S,Q,PY]; inventories={str(p):r.inventory(p) for p in roots};save(T/'input-inventories.json',inventories)
save(T/'consumer-policy-profile-inventory.json',{k:v for k,v in inventories[str(C)].items() if k=='policy' or k.startswith('policy/') or k=='corpus' or k.startswith('corpus/') or k=='reports' or k.startswith('reports/')})
selected=['/usr/bin/dash','/usr/bin/uname','/usr/bin/gcc','/usr/bin/cc','/usr/bin/as','/usr/bin/ld','/usr/bin/env','/usr/bin/python3.13']
tools={}
for raw in selected:
 p=pathlib.Path(raw)
 if p.exists():
  real=p.resolve(); tools[raw]={'realpath':str(real),'mode':stat.S_IMODE(real.stat().st_mode),'size':real.stat().st_size,'sha256':sha(real)}
save(T/'system-tool-inventory.json',tools)
stdlib=pathlib.Path('/usr/lib/python3.13'); st={}
for p in [stdlib,*sorted(stdlib.rglob('*'))]:
 rel='.' if p==stdlib else str(p.relative_to(stdlib)); s=p.lstat();mode=stat.S_IMODE(s.st_mode)
 if stat.S_ISLNK(s.st_mode):st[rel]={'type':'symlink','mode':mode,'target':os.readlink(p)}
 elif stat.S_ISREG(s.st_mode):st[rel]={'type':'file','mode':mode,'size':s.st_size,'sha256':sha(p)}
 elif stat.S_ISDIR(s.st_mode):st[rel]={'type':'directory','mode':mode}
 else:raise RuntimeError('special stdlib '+str(p))
save(T/'python-stdlib-inventory.json',{'root':str(stdlib),'entries':st,'note':'static supplemental snapshot, not runner enforced'})
ldd={}
for binary in [str(PY),str(P/'extractor-pack/tools/linux64/extractor'),str(Q/'tools/linux64/java/bin/java')]:
 proc=subprocess.run(['/usr/bin/ldd',binary],env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 paths=set(re.findall(r'(/[^\s()]+)',proc.stdout));files={}
 for name in sorted(paths):
  p=pathlib.Path(name)
  if p.is_file():
   real=p.resolve();files[name]={'realpath':str(real),'mode':stat.S_IMODE(real.stat().st_mode),'size':real.stat().st_size,'sha256':sha(real)}
 ldd[binary]={'argv':['/usr/bin/ldd',binary],'returncode':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr,'files':files,'note':'direct dynamic links only; not runner enforced'}
save(T/'dynamic-link-inventory.json',ldd)
prov['runtime_limit']='Runner enforces distribution, products, source and Python executable inventory; stdlib/system tools/direct links are static supplemental snapshots, not enforced; no full OS, native library, nested process or runtime closure; hostile concurrent writers and interruption/descendant cleanup are outside guarantee.'
prov['test_materialization']='Only test fixture paths and clarifying draft documentation changed: packet-local independent oracles and exact a3 staged consumer; runner and bootstrap bytes unchanged. Historical copied draft logs are not a3 test results.'
prov['scope']='No DB initialization/index/finalization, query, decode, exporter, importer, receipt, independent approval, GitHub or product-repository write.'
save(T/'provenance.json',prov)
shutil.copy2(__file__,T/'materialize.py')
status='''# UNAPPROVED exact-pin candidate: STOP before execution

The external manifest identifies this candidate, not authorization. Independent review must approve exact packet, oracle, vectors, inputs, separate bootstrap/interpreter/flags, runtime boundary and fresh attempt **before** DB creation. No acknowledgment has been created. The required independent acknowledgment is outside packet and attempt, with exactly {"approved_manifest_sha256":"<manifest digest>","decision":"approve"}; its raw digest must be conveyed independently. Never self-approve.

Only three CodeQL resolve library-path operations were run during preparation. They used the **identical** argv, cwd, clean environment and absolute cache paths as the future runner; raw output is retained. Temporary attempt directories were removed in full after resolution and must remain absent until authorized execution; fresh empty caches will be recreated. No DB, query, decode, export, import, or execution receipt was produced. Resolutions will be repeated and compared before DB init by the runner.

The separate bootstrap is a separately reviewed trust anchor, not authenticated by its own manifest. Use exactly env -i and /usr/bin/python3.13 -I -S -B with no -X, and separately pin bootstrap bytes and interpreter. Child Python uses -E -S -B, product trees contain no bytecode at freeze. OS/stdlib/native/dynamic and descendant-tool closure is not comprehensively bound; only static supplemental inventories, not runner enforcement. No hostile-writer or interruption/process-group guarantee, no attestation. Generated extractor is reused historical bytes, not proven built from merged commit. No actual CodeQL integration or output has been checked. Full consumer/producer gates and controlled mutations are still pending in separate clean exports. Historical synthetic draft test logs are not a3 test results or live evidence. Exact a3 suite output is retained separately outside the frozen packet. Independent reviewer must validate command semantics, source/archive/routing behavior and all these limitations before any authorization. Failed attempts must remain separately retained and never reused.
'''
(T/'PACKET-STATUS.md').write_text(status,encoding='utf8')
# Validate static requirements before sealing, without mutating or invoking runner.
if A.exists(): raise RuntimeError('attempt still exists')
if set(commands)!={'init','index','finalize','export','import','reimport'}|{n+'-'+s for n in ('effects','extracted','errors') for s in ('resolve','query','decode')}:raise RuntimeError('command shape')
if commands['import']!=commands['reimport'] or any(x['env']!=env for x in commands.values()):raise RuntimeError('command environment')
for n in ('effects','extracted','errors'):
 for flag in common+['--additional-packs='+str(P/'resolved-packs')]:
  if flag not in commands[n+'-resolve']['argv'] or flag not in commands[n+'-query']['argv']:raise RuntimeError('flags '+n)
for root,expected in inventories.items():
 if not c.same(r.inventory(root),expected):raise RuntimeError('input changed '+root)
oracle=c.load(T/'oracle-csv-fixture.json');expected=c.load(T/'oracle-retained.json')
c.check_prestates(c.load(C/oracle['artifacts'][0]),c.load(C/oracle['artifacts'][1]),oracle,expected)
# Read-only modes in packet only; compute manifest after all writes and chmod.
for p in sorted(T.rglob('*'),reverse=True):
 if p.is_file():p.chmod(0o444)
 elif p.is_dir():p.chmod(0o555)
T.chmod(0o555)
manifest=r.inventory(T);manifest.pop('.')
save(T.parent/'packet-manifest.json',manifest);(T.parent/'packet-manifest.json').chmod(0o444)
print(json.dumps({'packet':str(T),'manifest':str(T.parent/'packet-manifest.json'),'manifest_sha256':sha(T.parent/'packet-manifest.json'),'bootstrap_sha256':sha(T/'bootstrap.py'),'python_sha256':sha(PY),'attempt_absent':not A.exists(),'roots':{k:len(v) for k,v in inventories.items()},'tracked':{k:v['tracked_count'] for k,v in prov['git_exports'].items()}},indent=2))
