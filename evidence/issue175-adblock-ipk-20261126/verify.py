#!/usr/bin/env python3
"""Check retained #175 observations on any platform; does not run CodeQL."""
from collections import Counter
import hashlib,json,math,stat,zipfile
from pathlib import Path,PurePosixPath
from urllib.parse import quote
ROOT=Path(__file__).resolve().parent
APP='usr/share/rpcd/ucode/luci.adblock-fast'; POS='usr/share/ucode/issue175/positive.uc'; NEG='usr/share/ucode/issue175/near-miss.uc'; PATHS=(APP,POS,NEG)
SHA={APP:'3cb9d07b33a0aec36743326a5cb1e18885d245a132ef92174eb4c8b70aaebdd8',POS:'b6284410ba2f2fc28ba43a8584506eb0afbaf0e864ef25c9ac5877a3a97a4e81',NEG:'d7da956a8afbc3162a83f014c33cf82ebf923d9624011b09f3cb283365cde942'}
ANCHORS={'source-first-oracle.json':'378771758beee24fc1f32c91ffcfd573c0ff655a5287f8663c370c8834795297','provenance/run-lock.json':'80babfb3ac3dec5ce79d52f0201ecac914ec765ecdabd8017fe60110cfe677d2','provenance/app-comparison.json':'b00b66f746faf84ed761d142d9d54213eade3f5b78f24f564439e070acf9d658','provenance/controls-postguard.json':'2008a8689812f8966b3c693beca115acbdb9701492264e17c49fbbe6d84f9a11','provenance/mutation-decode-receipt.json':'e7af2c820e254e885298a6d7d35aae2d40ff4976c9ba199a660ec90966484aac','provenance/verification-absolute.stdout':'c529ce2d9cd5e9d54a62ea85e144f52e5ac5d02bbc87e04cd2c34afad0a86204','raw/output/commands.json':'84b3b3cce739a02340db7ba98ae91e705c16d84437c0e9c6bc25f132c8f07516','raw/output/query.json':'a6815baa77b6a330dfdec9d2eee3af2c560ee580be73ae48d6c750bac458827f','raw/output/routing.json':'be7e2811c2d7fd6bb01f793eef20ea1abc5dd3ffd7ca0d9251a5d41f9014ea73','raw/output/successful.json':'be5e89738497e3c523720c92cd98a33ed2304087e4b863738dca969929730add','raw/output/errors.json':'2c38be0a7d1935f63300ceccb92fd50f5bb76b829bcd0bac782393521a7665fc','raw/witness/output/witness.json':'63c4d11bcc35973820142a5a03358a6db97d2ea920b01ef7cdc7956e30f1d3ea','raw/mutation/output/mutant.json':'63c4d11bcc35973820142a5a03358a6db97d2ea920b01ef7cdc7956e30f1d3ea','raw/mutation/output/mutant.bqrs':'dd526c3940f1201c6b82a48f24a202ebd927ddd6fc0546b14b7bc123b29a4b65','raw/mutation/output/logs/query.receipt.json':'1c2581484c268c225ef1a5f3cbe11de64b0ae6d373943e6f4062de5a4b851421','raw/mutation/output/logs/query.stderr':'fce1fc863f747bb90e31a22a63c15db67444dbd1d2db7dfdf9cb8bcb555a5977','package-context/luci-app-adblock-fast-acl.json':'af249e0610e568be8e7bac542c0ce9f402e1a95cd34d3c5eb9a9724aff46502d'}
ANCHORS.update({'raw/src.zip':'c228b6e9615b9d796e3fb086f7a794fdcfd0c68036bb2d176f2f979f57e83a9d','provenance/mutation-plan.json':'d441e7f1629907d3e3032106fbaa9dd36b4a5e213f7e7ad532ceb93b0c7b7129','provenance/witness-plan.json':'119e7de0d9fd6e5fa0119cc0ec3ec9142a776fbae1f5e0dc643ed0e22b5c7991','provenance/Issue175CoordinateWitness.ql':'f921d9f1efb08b507199c0fc6b197a1ca19d73e0eecd7f781acc2c535d78f6ea','raw/witness/output/logs/query.receipt.json':'733429a2b9a363251c229f4b2f1817c0564042e2611134b4e9f1b626cb8491ec','raw/witness/output/logs/query.stderr':'aa2b4de7bcfa7315c43df225187e56f57a7121de0f7483d0b50e2451f35a4951','raw/mutation/output/logs/resolve.receipt.json':'ad89e4eb5b4cf71b2bcee0c8209b9a07379d35f5787ee11db19c3aca3412a55b','raw/witness/output/logs/resolve.receipt.json':'55e6ee5a11ff7e68456d7f95675644763b5f5628fbb30e23a04b5d4c9b02158a','raw/witness/output/logs/decode.receipt.json':'0101195f4d83cbe26eed5ad144ab4a2eae9f69f3089f14a8d2df368f60f90c9a'})

def need(v,msg):
 if not v:raise ValueError(msg)
def digest(v):return hashlib.sha256(v).hexdigest()
def obj(path):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 def bad(v):raise ValueError('invalid JSON constant')
 return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=bad)
def inventory(root):
 manifest=root/'SHA256SUMS';need(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir() and not root.is_symlink() and manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_nlink==1,'packet root or manifest unsafe')
 expected={}
 for line in (root/'SHA256SUMS').read_text().splitlines():
  h,sep,name=line.partition('  ');p=PurePosixPath(name);need(sep and len(h)==64 and all(c in '0123456789abcdef' for c in h) and name and not p.is_absolute() and str(p)==name and '..' not in p.parts and name not in expected,'invalid checksum line');expected[name]=h
 actual=set()
 for p in root.rglob('*'):
  need(not p.is_symlink(),'packet symlink')
  if p.is_file():
   need(p.stat().st_nlink==1,'packet hardlink alias')
   if p.relative_to(root).as_posix()!='SHA256SUMS':actual.add(p.relative_to(root).as_posix())
  else:need(p.is_dir(),'packet special file')
 need(actual==set(expected),'packet inventory differs')
 for name,h in expected.items():need(digest((root/name).read_bytes())==h,'packet digest differs: '+name)
 for name,h in ANCHORS.items():need(expected.get(name)==h,'anchor differs: '+name)
def query(value,oracle,original_stage,include_shadow):
 expected=[]
 for r in oracle['rows']:
  if r['expected_rows'] or include_shadow and r['path']==NEG:
   expected.append((r['path'],*r['start'],*r['end_inclusive'],f"builtin system() in {Path(r['path']).name} at line {r['source_line']}"))
 actual=[];ids={};spans={}
 for row in value['#select']['tuples']:
  need(isinstance(row,list) and len(row)==2 and isinstance(row[0],dict) and isinstance(row[1],str),'query tuple shape');e=row[0];u=e.get('url',{});uri=u.get('uri');matching=[p for p in PATHS if uri=='file://'+quote(original_stage+'/'+p,safe='/')];need(len(matching)==1 and type(e.get('id')) is int and e.get('label')=='CallExpression','query entity differs');path=matching[0];coords=[u.get(k) for k in ('startLine','startColumn','endLine','endColumn')];need(all(type(x) is int and x>0 for x in coords),'query coordinates differ');key=(path,*coords);ident=e['id'];need(key not in spans or spans[key]==ident,'span ID differs');need(ident not in ids or ids[ident]==key,'AST ID reused');spans[key]=ident;ids[ident]=key;actual.append((*key,row[1]))
 need(Counter(actual)==Counter(expected),'query row multiset differs');return spans

def control_log_path(row,phase,stream,plan,directory):
 relative='resolver.json' if phase=='resolve' and stream=='stdout' else 'logs/'+phase+'.'+stream
 need(row[stream+'_path']==plan['private_root']+'/output/'+relative,'control log path differs')
 return directory/relative

def control_resolver(data,plan,lock):
 expected=[x.replace(lock['cwd'],plan['cwd']) for x in lock['resolved_library_paths']]
 need(data.get('libraryPath')==expected and data.get('dbscheme')==plan['cwd']+'/ql/lib/ucode.dbscheme' and data.get('relativeName')==plan['resolved_relative_name'] and data.get('qlPackName')=='lucas-albers-lz4/ucode-queries' and data.get('compilationCache')==[plan['private_root']+'/cache/compile'],'control resolver identity differs')

def verify(root):
 inventory(root);lock=obj(root/'provenance/run-lock.json');oracle=obj(root/'source-first-oracle.json');stage=lock['env']['CODEQL_UCODE_STAGED_ROOT'];need(oracle['expected_rows']==14 and len(oracle['rows'])==15,'oracle count differs')
 stage_root=root/'stage';need({p.relative_to(stage_root).as_posix() for p in stage_root.rglob('*') if p.is_file()}==set(PATHS),'stage file inventory differs')
 for path,h in SHA.items():
  f=root/'stage'/path;need(f.is_file() and not f.is_symlink() and stat.S_IMODE(f.stat().st_mode)==0o644 and digest(f.read_bytes())==h,'stage identity differs: '+path)
 for r in oracle['rows']:
  data=(root/'stage'/r['path']).read_bytes();a=r['byte_start_0'];b=r['byte_end_exclusive_0'];need(0<=a<b<=len(data) and digest(data[a:b])==r['expression_sha256'],'source span differs')
  def point(n):q=data[:n];return [q.count(b'\n')+1,n-(q.rfind(b'\n')+1)+1]
  need(point(a)==r['start'] and point(b-1)==r['end_inclusive'],'source coordinates differ')
 receipt=obj(root/'provenance/app-comparison.json');need(receipt['ipk_sha256']=='b3d18c736a970f0ba17919e1249c837dae393b04f5ec541950a6cce737110e0f' and receipt['package']=='app' and receipt['control']=={'Package':'luci-app-adblock-fast','Version':'1.2.4-r4','Architecture':'all'},'package receipt differs');rows=[x for x in receipt['source_mappings'] if x['path']==APP];need(len(rows)==1 and rows[0]['disposition']=='selected_ucode_rpcd' and rows[0]['source_git_mode']=='100644' and all(rows[0][k]==SHA[APP] for k in ('source_sha256','prepared_sha256','staged_sha256','ipk_sha256')) and all(rows[0][k]=='0644' for k in ('prepared_mode','staged_mode','ipk_mode')),'source mapping differs')
 acl=[x for x in receipt['source_mappings'] if x['path']=='usr/share/rpcd/acl.d/luci-app-adblock-fast.json'];acl_hash=ANCHORS['package-context/luci-app-adblock-fast-acl.json'];need(len(acl)==1 and acl[0]['disposition']=='auxiliary_acl_evidence' and acl[0]['source_git_mode']=='100644' and all(acl[0][k]==acl_hash for k in ('source_sha256','prepared_sha256','staged_sha256','ipk_sha256')) and all(acl[0][k]=='0644' for k in ('prepared_mode','staged_mode','ipk_mode')),'ACL source mapping differs')
 route=obj(root/'raw/output/routing.json');need(all(type(route[k]) is int and route[k]==v for k,v in [('input_count',3),('plain_count',3),('duplicate_input_count',0),('markup_count',0),('markup_inconclusive_count',0),('uncertain_count',0),('excluded_count',0)]),'route counts differ');need(Counter(x['installed_path'] for x in route['decisions'])==Counter(PATHS),'route members differ')
 for d in route['decisions']:
  p=d['installed_path'];need(d['path']==stage+'/'+p and d['classification']=='plain' and d['status']=='plain_route_selected' and d['reason']==('rpcd_raw_mode_full_path' if p==APP else 'ucode_extension') and d.get('inconclusive_reason') is None,'route decision differs')
 success=obj(root/'raw/output/successful.json')['#select']['tuples'];need(Counter(r[0]['url']['uri'] for r in success)==Counter('file://'+quote(stage+'/'+p,safe='/') for p in PATHS) and all(len(r)==2 and r[1]=='' for r in success),'success rows differ');need(obj(root/'raw/output/errors.json')['#select']['tuples']==[],'extraction errors present')
 with zipfile.ZipFile(root/'raw/src.zip') as z:
  items=z.infolist();need(len(items)==3,'source archive count differs');want={(stage+'/'+p).lstrip('/'):h for p,h in SHA.items()};need(Counter(i.filename for i in items)==Counter(want.keys()),'source archive paths differ')
  for i in items:need(i.create_system==3 and stat.S_ISREG(i.external_attr>>16) and (i.external_attr>>16)&0o7777==0o644 and digest(z.read(i))==want[i.filename],'source archive member differs')
 baseline=query(obj(root/'raw/output/query.json'),oracle,stage,False);witness=query(obj(root/'raw/witness/output/witness.json'),oracle,stage,True);mutant=query(obj(root/'raw/mutation/output/mutant.json'),oracle,stage,True);need(witness==mutant and all(witness.get(k)==v for k,v in baseline.items()),'cross-query AST identity differs')
 phases=('resolve-query','resolve-success','resolve-errors','database-init','database-index','database-finalize','success-query','success-decode','errors-query','errors-decode','target-query','target-decode')
 commands=obj(root/'raw/output/commands.json')['commands'];need([r['label'] for r in commands]==list(phases),'command order differs')
 warning='WARNING: Not caching stages during query-loading, since max heap size is only 1816 MB.';run=lock['run_root']
 for row in commands:
  label=row['label'];need(row['argv']==lock['phase_argv'][label] and row['cwd']==lock['cwd'] and row['env']==lock['env'] and row['exit']==0,'command identity differs: '+label)
  elapsed=row['elapsed_seconds'];need(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0 and row.get('peak_rss_bytes') is None and row.get('rss_note'),'command cost differs')
  for stream in ('stdout','stderr'):
   original=row[stream+'_path'];need(original.startswith(run+'/output/'),'command log path differs');f=root/'raw/output'/original.removeprefix(run+'/output/');need(digest(f.read_bytes())==row[stream+'_sha256'],'command log hash differs: '+label)
   lines=[x for x in f.read_text(errors='replace').splitlines() if 'WARNING:' in x.upper()];need(not any(x in f.read_text(errors='replace').upper() for x in ('ERROR:','FATAL:')),'command log error')
   need(not lines if stream=='stdout' else lines==([warning] if label in ('success-query','errors-query','target-query') else []),'command warning differs: '+label)
  for original,h in row.get('artifacts',{}).items():
   if original==run+'/db/src.zip':f=root/'raw/src.zip'
   else:need(original.startswith(run+'/output/'),'artifact path differs');f=root/'raw/output'/original.removeprefix(run+'/output/')
   need(digest(f.read_bytes())==h,'phase artifact differs: '+label)
 for variant in ('witness','mutation'):
  plan=obj(root/'provenance'/(variant+'-plan.json'));original=plan['private_root']+'/output/';directory=root/'raw'/variant/'output'
  for phase in (('resolve','query','decode') if variant=='witness' else ('resolve','query')):
   r=obj(directory/'logs'/(phase+'.receipt.json'));need(r['phase']==phase and r['argv']==plan['commands'][phase] and r['cwd']==plan['cwd'] and r['env']==plan['env'] and r['exit']==0,'control command differs: '+variant+' '+phase)
   need(type(r['elapsed_seconds']) in (int,float) and math.isfinite(r['elapsed_seconds']) and r['elapsed_seconds']>=0 and r.get('peak_rss_bytes') is None and r.get('rss_note'),'control cost differs')
   for stream in ('stdout','stderr'):
    log=control_log_path(r,phase,stream,plan,directory);need(digest(log.read_bytes())==r[stream+'_sha256'],'control log differs')
   if phase=='resolve':
    artifact=directory/'resolver.json';control_resolver(obj(artifact),plan,lock);need((directory/'logs/resolve.stderr').read_bytes()==b'','control resolver stderr differs')
   elif phase=='query':artifact=directory/('witness.bqrs' if variant=='witness' else 'mutant.bqrs')
   else:artifact=directory/'witness.json'
   if variant=='mutation' and phase=='query':need(digest(artifact.read_bytes())==ANCHORS['raw/mutation/output/mutant.bqrs'],'stopped BQRS differs')
   else:need(digest(artifact.read_bytes())==r['artifact_sha256'],'control artifact differs')
 decoded=obj(root/'provenance/mutation-decode-receipt.json');need(decoded['exit']==0 and decoded['postguard']=='inputs_unchanged' and decoded['failure'] is None and decoded['result']['near_miss_added']==1,'mutation continuation differs');stopped=obj(root/'raw/mutation/output/logs/query.receipt.json');need(stopped['exit']==0 and stopped['phase_error']=="ValueError('unexpected control stderr warning')",'stopped mutation receipt differs')
 stderr=(root/'raw/mutation/output/logs/query.stderr').read_text();warnings=[x for x in stderr.splitlines() if 'WARNING:' in x.upper()];expected_warning="WARNING: unused predicate 'systemFormalInBody' ("+run.removesuffix('/run')+'/mutation-producer/ql/lib/codeql/ucode/m3/Models.qll:149,19-37)';need(warnings==[warning,expected_warning] and decoded['prior_warning_exception']['warnings']==warnings and decoded['prior_warning_exception']['query_receipt_sha256']==ANCHORS['raw/mutation/output/logs/query.receipt.json'] and decoded['prior_warning_exception']['bqrs_sha256']==ANCHORS['raw/mutation/output/mutant.bqrs'],'mutation warning exception differs')
 plan=obj(root/'provenance/mutation-plan.json');need(decoded['argv']==plan['commands']['decode'] and decoded['cwd']==plan['cwd'] and decoded['env']==plan['env'] and decoded['decoded_sha256']==ANCHORS['raw/mutation/output/mutant.json'],'decode command differs')
 need((root/'provenance/mutation-decode.stdout').read_bytes()==b'' and (root/'provenance/mutation-decode.stderr').read_bytes()==b'' and decoded['stdout_sha256']==digest(b'') and decoded['stderr_sha256']==digest(b''),'decode logs differ')
 need((root/'provenance/verification.json').read_bytes()==b'','failed verifier output differs')
 return {'status':'retained_evidence_consistent','baseline_calls':14,'witness_calls':15,'mutant_calls':15,'near_miss_added':1}
if __name__=='__main__':print(json.dumps(verify(ROOT),sort_keys=True))
