import subprocess,json,hashlib,re,collections,os,sys
from pathlib import Path
if len(sys.argv) != 3: raise SystemExit("usage: inventory.py LUCICHECKOUT OUTPUT_JSON")
source=Path(sys.argv[1]).resolve(); output=Path(sys.argv[2]).resolve(); os.chdir(source)
packet=Path(__file__).resolve().parent
from pathlib import PurePosixPath
run=lambda *a:subprocess.check_output(a)
rev=run('git','rev-parse','HEAD').decode().strip(); old='b2e0be4b46ec0fd43394c081fa7c50657af14011'
if rev != 'cb87fe60e1e2e052af36a93647f2264577829e0a': raise SystemExit('unexpected source revision')
if run('git','status','--porcelain=v1','--untracked-files=normal'): raise SystemExit('source checkout is dirty')
prior=json.load(open(packet/'claim085-inventory.json'))
oldpaths={x['source_path']:x for x in prior['candidates']}
tree=run('git','ls-tree','-rz','--full-tree',rev).split(b'\0'); rows=[]
for ent in tree:
 if not ent:continue
 meta,path=ent.split(b'\t',1); mode,typ,obj=meta.decode().split(); path=path.decode(); p=PurePosixPath(path); parts=p.parts
 raw='/root/usr/share/rpcd/ucode/' in path
 installed=(('/root/' in path and (len(p.suffix)==0)) or ('/ucode/' in path and len(p.suffix)==0))
 suffix=path.endswith(('.uc','.ucode','.ut','.uc.in','.ucode.in'))
 # Read every tracked blob for shebang and exact bytes; git reads symlinks as link text.
 data=run('git','cat-file','blob',obj)
 line=data.split(b'\n',1)[0].decode('utf-8',errors='replace'); words=line[2:].split() if line.startswith('#!') else []
 def is_command(command):
  command=command.strip("'\""); command=command.removeprefix('-S'); return command.split()[0].strip("'\"").split('/')[-1]=='ucode' if command.split() else False
 shebang=bool(words and (words[0].split('/')[-1]=='ucode' or (words[0] in ('/usr/bin/env','/bin/env') and len(words)>1 and (is_command(words[2]) if words[1]=='-S' and len(words)>2 else is_command(words[1])))))
 if not (path in oldpaths or raw or installed or suffix or shebang):continue
 owner=parts[1] if len(parts)>2 and parts[0] in ('applications','modules','protocols','themes','libs','collections') else None
 if path in oldpaths:
  x=oldpaths[path].copy(); disposition='excluded symlink' if mode=='120000' else ('excluded test/fixture' if x['candidate_group']=='tests_or_fixtures' else 'selected source candidate')
 else:
  x={}; disposition='generator input' if path.endswith(('.uc.in','.ucode.in')) else ('new source candidate: review' if suffix or raw or shebang else 'extensionless installed-root candidate: unsupported/unknown')
 x.update(source_path=path,package_owner=owner,git_mode=mode,git_object=obj,git_blob=obj,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),symlink=mode=='120000',symlink_target=data.decode(errors='replace') if mode=='120000' else None,ucode_shebang_scan=shebang,disposition=disposition)
 rows.append(x)
assert len({x['source_path'] for x in rows})==len(rows)
oldnew={x['source_path']:x for x in rows}; delta={'removed':sorted(oldpaths.keys()-oldnew.keys()),'added':sorted(oldnew.keys()-oldpaths.keys()),'changed_prior_candidates':sorted(p for p in oldpaths.keys() & oldnew.keys() if (oldpaths[p]['git_mode'], oldpaths[p]['git_blob']) != (oldnew[p]['git_mode'], oldnew[p]['git_blob']))}
result={'schema':'issue172-source-inventory-draft-v1','source':{'repository':'https://github.com/openwrt/luci.git','branch':'openwrt-25.12','commit':rev,'tree':run('git','rev-parse',rev+'^{tree}').decode().strip(),'dirty':run('git','status','--porcelain=v1','--untracked-files=normal').decode().splitlines()},'baseline':old,'tracked_entries':len([x for x in tree if x]),'policy':'Prior claim 085 candidates plus every tracked .uc/.ucode/.ut and generator suffix, recognized shebang, rpcd tree, and extensionless package root/ or ucode/ path. Extensionless broad candidates have not been assumed to be Ucode. Blob bytes, including symlink text, are never followed. Package owner is directory inference only.','delta':delta,'counts':dict(collections.Counter(x['disposition'] for x in rows)),'candidates':rows}
open(output,'w').write(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({k:result[k] for k in ('source','tracked_entries','delta','counts')},indent=2))
