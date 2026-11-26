#!/usr/bin/env python3
"""Source-first Git inventory only: no package bytes or build actions."""
import argparse,hashlib,json,subprocess
from collections import Counter
from pathlib import Path
COMMIT='cb87fe60e1e2e052af36a93647f2264577829e0a'
BASELINE='91fcf7f84e2934a1df21c7438f898fb5cd097eb9f6cfde3bc80239369c0d7cbc'
PACKAGES=('luci-app-dockerman','luci-app-statistics')
def sha(data):return hashlib.sha256(data).hexdigest()
def run(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args])
def main():
 p=argparse.ArgumentParser();p.add_argument('--luci',type=Path,required=True);p.add_argument('--inventory172',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();repo=a.luci.resolve(strict=True)
 if run(repo,'rev-parse','HEAD').decode().strip()!=COMMIT or run(repo,'status','--porcelain=v1','--untracked-files=all'):raise ValueError('source must be clean at exact LuCI pin')
 baseline=a.inventory172.read_bytes()
 if sha(baseline)!=BASELINE:raise ValueError('#172 inventory digest differs')
 data=json.loads(baseline);selected={x['source_path']:x for x in data['candidates'] if x['package_owner'] in PACKAGES}
 roots=['applications/'+n for n in PACKAGES];lines=run(repo,'ls-tree','-r','-z','--full-tree',COMMIT,'--',*roots).split(b'\0');rows=[]
 for line in lines:
  if not line:continue
  meta,path=line.split(b'\t',1);mode,kind,oid=meta.decode().split();path=path.decode();blob=run(repo,'cat-file','blob',oid);parts=path.split('/');pkg=parts[1];rel='/'.join(parts[2:]);top=parts[2];tail='/'.join(parts[3:]);candidate=selected.get(path)
  if top=='root':installed=tail;category='root direct-copy projection'
  elif top=='ucode':installed='usr/share/ucode/luci/'+tail;category='ucode direct-copy projection; .ut version substitution if applicable'
  elif top=='htdocs':installed='www/'+tail;category='htdocs projection; JS/CSS transformation conditional on config'
  elif top=='po':
   installed=None;category=('translation template; not direct member' if path.endswith('.pot') else 'translation source; generated language package, not direct member')
  else:installed=None;category='recipe or documentation; not direct installed member'
  row={'source_path':path,'package':pkg,'git_mode':mode,'git_object':oid,'object_type':kind,'bytes':len(blob),'sha256':sha(blob),'first_line':blob.split(b'\n',1)[0][:200].decode('utf-8','backslashreplace'),'projected_member':installed,'projection':category,'source_mode_projected':('0'+mode[-3:]) if installed is not None and mode in ('100644','100755') else None,'baseline172_disposition':candidate.get('disposition') if candidate else None,'baseline172_route':candidate.get('expected_route') if candidate else None}
  if candidate and (candidate['git_object']!=oid or candidate['sha256']!=row['sha256'] or candidate['git_mode']!=mode):raise ValueError('candidate mismatch: '+path)
  rows.append(row)
 if set(selected)-{r['source_path'] for r in rows}:raise ValueError('missing #172 candidates')
 mk=run(repo,'show',COMMIT+':luci.mk');result={'schema':'issue173-dockerman-statistics-source-oracle-v1','source_commit':COMMIT,'source_tree':run(repo,'rev-parse',COMMIT+'^{tree}').decode().strip(),'source_dirty':False,'inventory172_sha256':sha(baseline),'luci_mk_sha256':sha(mk),'policy':'all tracked package paths; po/ contains translation sources and templates; root/, ucode/, htdocs/ mappings are recipe projections, not observations; preserve generated/conditional outcomes as unknown','counts':{'total':len(rows),'by_package':dict(Counter(r['package'] for r in rows)),'by_projection':dict(Counter(r['projection'] for r in rows)),'git_modes':dict(Counter(r['git_mode'] for r in rows)),'baseline172':dict(Counter(r['baseline172_disposition'] or 'not #172 candidate' for r in rows))},'entries':rows}
 if run(repo,'status','--porcelain=v1','--untracked-files=all'):raise ValueError('source changed during inventory')
 a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
if __name__=='__main__':main()
