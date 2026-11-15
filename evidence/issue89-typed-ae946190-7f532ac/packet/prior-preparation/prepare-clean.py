#!/usr/bin/python3
"""Fresh producer preparation after a recorded failed build, without reused outputs."""
import datetime,json,pathlib,subprocess,time
E=pathlib.Path(__file__).resolve().parent; P=E/'producer'; L=E/'logs'
env=json.loads((E/'environment.json').read_text()); env['CARGO_TARGET_DIR']=str(E/'target-clean')
(E/'environment-clean.json').write_text(json.dumps(env,indent=2)+'\n')
def run(name,argv,cwd):
    start=datetime.datetime.now(datetime.timezone.utc).isoformat(); t=time.monotonic()
    with (L/(name+'.stdout')).open('xb') as out,(L/(name+'.stderr')).open('xb') as err:
        p=subprocess.run(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,check=False)
    record={'stage':name,'argv':argv,'cwd':str(cwd),'started':start,'finished':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_s':time.monotonic()-t,'exit_code':p.returncode}
    with (E/'preparation-ledger.jsonl').open('a') as f: f.write(json.dumps(record)+'\n')
    print(name,p.returncode,flush=True)
    if p.returncode: raise SystemExit('STOP: '+name)
if P.exists() or (E/'target-clean').exists(): raise SystemExit('fresh paths already exist')
run('clean-clone-producer',['git','clone','--no-checkout','https://github.com/lucas-albers-lz4/codeql-ucode.git',str(P)],E)
run('clean-checkout-producer',['git','checkout','--detach','fbcad5ff8840d83042a4ea2992fbd31c5f94a681'],P)
run('clean-head-producer',['git','rev-parse','HEAD'],P)
run('clean-status-producer',['git','status','--porcelain=v1','--untracked-files=all'],P)
if (L/'clean-status-producer.stdout').read_bytes(): raise SystemExit('clean checkout is dirty')
(E/'target-clean').mkdir(); (P/'target').symlink_to(E/'target-clean',target_is_directory=True)
run('clean-clone-grammar',['bash','scripts/clone-grammar.sh'],P)
run('clean-grammar-head',['git','rev-parse','HEAD'],P/'extractor/tree-sitter')
run('clean-grammar-status',['git','status','--porcelain=v1','--untracked-files=all'],P/'extractor/tree-sitter')
run('clean-grammar-diff',['git','diff','--binary'],P/'extractor/tree-sitter')
run('clean-create-extractor-pack',['bash','scripts/create-extractor-pack.sh'],P)
run('clean-producer-tracked-diff',['git','diff','--exit-code'],P)
run('clean-pack-install-lib',['codeql','pack','install',str(P/'ql/lib'),'--common-caches='+str(E/'common-cache')],P)
run('clean-pack-install-src',['codeql','pack','install',str(P/'ql/src'),'--common-caches='+str(E/'common-cache')],P)
run('clean-producer-tracked-diff-postpack',['git','diff','--exit-code'],P)
