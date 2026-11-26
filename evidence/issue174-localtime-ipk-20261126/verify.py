#!/usr/bin/env python3
"""Verify the portable #174 evidence packet; this does not rerun CodeQL."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import stat
from urllib.parse import quote
import zipfile

ROOT=Path(__file__).resolve().parent
MEMBER='usr/share/rpcd/ucode/luci'
SOURCE_SHA='04c9cc966f9cbdd9bea942f55ab139ba11bff78e751ed3ee2e99f52be9c73dbf'
WARNING='WARNING: Not caching stages during query-loading, since max heap size is only 1816 MB.'
PHASES=('resolve-query','resolve-success','resolve-errors','database-init','database-index','database-finalize','success-query','success-decode','errors-query','errors-decode','target-query','target-decode')
ANCHORS={
 'source-first-oracle.json':'95fde6067e9cd3b602fb73b3d72937003f80a7e96574e30ce0139337cf07769f',
 'provenance/first-run-lock.json':'0e6471a32620f6e178e022377bd2b268b28d96d3f937ebce8fb33ec4b4ca6d2d',
 'raw/first-output/resolver-only-commands.json':'74a912b67500008e1dac0de8828a98bb2a4fadafc63fc353c1403eba67cc846b',
 'raw/first-output/logs/success-query.receipt.json':'fa17c996b3df9e56a229a60691ab6a31eca334b59e99ab2a27c6b640ee030b90',
 'raw/first-output/logs/success-query.stderr':'fe5d45349fff3581cc6a32a68ce807ae360fd8404a308a054899567453738273',
 'raw/first-src.zip':'48dee5f39d0cbc1214e155a382e9b39e9f9f84ce4fcc5ab16d563432ecebb0bf',
 'provenance/run-lock.json':'f4a5abd675c5bec3fdfdb6bc1b2901d4037a01b666c46fddb8dfe92cd9121ae0',
 'provenance/ipk-comparison.json':'1c80809ed7c87a2a586d0df7bdebcfc35eaecf6370013b27f994a46d0324b677',
 'provenance/extractor-build.json':'61ed94ace73b839ce506fd676c385ac4c32e1e7d60a8e0c8b05e1d7860ebc680',
 'stage/usr/share/rpcd/ucode/luci':SOURCE_SHA,
 'raw/retry-output/commands.json':'9f193c187c6ab229a4d4c7a01817b4fc066ca5b353330a144b751fc54f7c527c',
 'raw/retry-output/query.json':'b52963d1dddfc71938aaf96c1d4af7b1e1b1fd5382702e1a3adbcd0a9c56a5c7',
 'raw/retry-output/query.bqrs':'e4436fa8a1279fe546eb4548700ee1aa6cf7195ebeb0ac270477604b4e216363',
 'raw/retry-src.zip':'32e0906dd919f6774d11b32f9f159683ee48976f2e9fd95e9540601097013520',
 'raw/verification.json':'1c7e897d73f204fdce18f936f338626169fcfb7a2d6d4188de36d4cc59d25a59',
 'raw/retry-output/continuation-failure.json':'cf405156954cb247b3c2c063a5dd824e90e70e9adebb5a09e3ad789126988fb3',
}

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def obj(path):
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,'duplicate JSON key: '+k);d[k]=v
        return d
    def bad(x):raise ValueError('invalid JSON constant: '+x)
    return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=bad)

def verify_inventory(root):
    lines=(root/'SHA256SUMS').read_text().splitlines(); expected={}
    for line in lines:
        digest,sep,name=line.partition('  ');p=PurePosixPath(name)
        need(sep and len(digest)==64 and all(x in '0123456789abcdef' for x in digest) and name and not p.is_absolute() and str(p)==name and '..' not in p.parts,'invalid checksum line')
        need(name not in expected,'duplicate checksum path');expected[name]=digest
    actual=set()
    for p in root.rglob('*'):
        need(not p.is_symlink(),'symlink in evidence packet')
        if p.is_file():
            rel=p.relative_to(root).as_posix()
            if rel!='SHA256SUMS':actual.add(rel)
        else:need(p.is_dir(),'special file in evidence packet')
    need(set(expected)==actual,'evidence inventory differs')
    for name,digest in expected.items():need(sha(root/name)==digest,'evidence digest differs: '+name)
    for name,digest in ANCHORS.items():need(expected.get(name)==digest,'anchor differs: '+name)

def tuples(spec):
    pos=spec['positive'];src={'entity':[MEMBER,*pos['source']['start'],*pos['source']['end_inclusive']],'label':pos['source']['kind']};sink={'entity':[MEMBER,*pos['sink']['start'],*pos['sink']['end_inclusive']],'label':pos['sink']['kind']}
    return [[src,pos['expected_message'],sink,pos['sink']['name']]]+spec['ambient_historical_expectations']

def validate_query(data,spec,uri):
    actual=[];by_span={};by_id={}
    for row in data['#select']['tuples']:
        need(isinstance(row,list) and len(row)==4 and isinstance(row[1],str) and isinstance(row[3],str),'query tuple shape differs')
        normalized=[]
        for value in (row[0],row[2]):
            need(isinstance(value,dict) and type(value.get('id')) is int and isinstance(value.get('label'),str),'node identity missing')
            u=value.get('url',{});need(u.get('uri')==uri,'query file URI differs')
            coords=[u.get(k) for k in ('startLine','startColumn','endLine','endColumn')]
            need(all(type(x) is int and x>0 for x in coords) and tuple(coords[2:])>=tuple(coords[:2]),'query node range invalid')
            node={'entity':[MEMBER,*coords],'label':value['label']};key=json.dumps(node,sort_keys=True);ident=value['id']
            need(by_span.setdefault(key,ident)==ident and by_id.setdefault(ident,key)==key,'AST identity inconsistency')
            normalized.append(node)
        actual.append([normalized[0],row[1],normalized[1],row[3]])
    canon=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))
    need(Counter(map(canon,actual))==Counter(map(canon,tuples(spec))),'query tuple multiset differs')
    return len(actual)

def run_relative(root, original, path):
    prefix=original+'/output/'
    if path.startswith(prefix):
        rel=path[len(prefix):];p=PurePosixPath(rel);need(rel and not p.is_absolute() and '..' not in p.parts and str(p)==rel,'unsafe output path');return root/'raw/retry-output'/rel
    need(path==original+'/db/src.zip','unexpected phase artifact path')
    return root/'raw/retry-src.zip'

def validate(root):
    verify_inventory(root)
    lock=obj(root/'provenance/run-lock.json');spec=obj(root/'source-first-oracle.json');receipt=obj(root/'provenance/ipk-comparison.json')
    need(receipt.get('status')=='PASS' and receipt['ipk']['sha256']=='41376c6774b35ff140ff3fa441643a184be252070cd3f462f645c6a98e527d6b','IPK receipt differs')
    member_rows=[x for x in receipt['files'] if x.get('installed_path')==MEMBER]
    need(len(member_rows)==1,'IPK member receipt count differs')
    row=member_rows[0]
    need(row.get('source')=='modules/luci-base/root/usr/share/rpcd/ucode/luci' and row.get('status')=='selected present' and row.get('mode')=='0644' and all(row.get(k)==SOURCE_SHA for k in ('source_sha256','prepared_sha256','staged_sha256','ipk_sha256')),'IPK member mapping differs')
    raw_members=[r for r in receipt.get('archive_data_members',[]) if r.get('path')==MEMBER]
    need(len(raw_members)==1 and raw_members[0]=={'mode':'0644','path':MEMBER,'sha256':SOURCE_SHA,'size':16240,'type':'file'},'IPK member size/mode differs')
    selected=root/'stage'/MEMBER;info=selected.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_mode & 0o7777==0o644 and info.st_size==16240,'retained stage mode/size differs')
    original=lock['run_root'];stage=original+'/stage';source=stage+'/'+MEMBER;uri='file://'+quote(source,safe='/')
    route=obj(root/'raw/retry-output/routing.json');d=route.get('decisions',[])
    need(len(d)==1 and route.get('input_count')==1 and route.get('plain_count')==1 and route.get('duplicate_input_count')==0 and all(route.get(x)==0 for x in ('markup_count','markup_inconclusive_count','uncertain_count','excluded_count')),'route count differs')
    need(d[0].get('path')==source and d[0].get('installed_path')==MEMBER and d[0].get('classification')=='plain' and d[0].get('reason')=='rpcd_raw_mode_full_path' and d[0].get('status')=='plain_route_selected' and d[0].get('inconclusive_reason') is None,'route identity differs')
    success=obj(root/'raw/retry-output/successful.json')['#select']['tuples'];errors=obj(root/'raw/retry-output/errors.json')['#select']['tuples']
    need(len(success)==1 and len(success[0])==2 and success[0][0].get('url',{}).get('uri')==uri and success[0][1]=='','successful file differs');need(errors==[],'extraction errors present')
    count=validate_query(obj(root/'raw/retry-output/query.json'),spec,uri)
    with zipfile.ZipFile(root/'raw/retry-src.zip') as z:
        entries=z.infolist();need(len(entries)==1,'source ZIP inventory differs');item=entries[0];mode=item.external_attr>>16
        need(item.filename==source.lstrip('/') and item.create_system==3 and stat.S_ISREG(mode) and mode & 0o7777==0o644,'source ZIP identity differs')
        need(hashlib.sha256(z.read(item)).hexdigest()==SOURCE_SHA,'source ZIP bytes differ')
    rows=obj(root/'raw/retry-output/commands.json')['commands'];need([r.get('label') for r in rows]==list(PHASES),'phase ordering differs')
    warnings={}
    for row in rows:
        label=row['label'];need(row.get('exit')==0 and row.get('argv')==lock['phase_argv'][label] and row.get('cwd')==lock['cwd'] and row.get('env')==lock['env'],'phase command differs: '+label)
        elapsed=row.get('elapsed_seconds');need(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0,'phase timing differs')
        for stream in ('stdout','stderr'):
            log=run_relative(root,original,row[stream+'_path']);need(sha(log)==row[stream+'_sha256'],'phase log differs: '+label)
            text=log.read_text(errors='replace');lines=[line for line in text.splitlines() if 'WARNING:' in line.upper()]
            need(not any(x in text.upper() for x in ('ERROR:','FATAL:')),'phase error marker: '+label)
            if stream=='stdout':need(not lines,'stdout warning: '+label)
            else:
                need(not lines or label in ('success-query','errors-query','target-query') and lines==[WARNING],'unexpected warning: '+label)
                need(row.get('classified_warnings',[])==lines,'warning classification differs: '+label)
                if lines:warnings[label]=lines
        for path,digest in row.get('artifacts',{}).items():need(sha(run_relative(root,original,path))==digest,'phase artifact differs: '+label)
    index=next(x for x in rows if x['label']=='database-index');need(index.get('raw_routing_sha256')==sha(root/'raw/retry-output/routing.json'),'raw/retained route mismatch')
    need(set(warnings)=={'success-query','errors-query','target-query'},'warning inventory differs')
    for row in rows:
        if row['label'] in warnings:
            exception=row.get('exception',{})
            need(exception.get('kind')=='reviewed_cache_performance_warning' and exception.get('prior_failure_retained') is True,'warning exception metadata differs')
    original_phase=root/'raw/retry-output/logs/success-query.receipt.json'
    prior=obj(original_phase);derived=next(row for row in rows if row['label']=='success-query')
    need(derived.get('exception',{}).get('original_phase_receipt_sha256')==sha(original_phase),'original stopped phase hash differs')
    prior_copy=dict(derived)
    for key in ('classified_warnings','artifacts','exception'):prior_copy.pop(key,None)
    need(prior_copy==prior,'original stopped phase was not preserved')
    first=root/'raw/first-output';first_lock=obj(root/'provenance/first-run-lock.json')
    first_phase=obj(first/'logs/success-query.receipt.json');first_err=(first/'logs/success-query.stderr').read_text(errors='replace')
    expected_first=['WARNING: Failed to retrieve qlpack commit hash from Git repository','WARNING: Not caching stages during query-loading, since max heap size is only 1256 MB.']
    need(first_phase.get('exit')==0 and first_phase.get('label')=='success-query' and first_phase.get('argv')==first_lock['phase_argv']['success-query'] and first_phase.get('stderr_sha256')==sha(first/'logs/success-query.stderr') and [line for line in first_err.splitlines() if 'WARNING:' in line]==expected_first,'first stopped phase differs')
    need(not (first/'routing.json').exists() and not (first/'successful.json').exists() and not (first/'errors.json').exists() and not (first/'query.json').exists(),'first attempt scope differs')
    with zipfile.ZipFile(root/'raw/first-src.zip') as z:
        entries=z.infolist();need(len(entries)==1,'first source ZIP inventory differs');item=entries[0];mode=item.external_attr>>16
        need(item.filename==(first_lock['run_root']+'/stage/'+MEMBER).lstrip('/') and item.create_system==3 and stat.S_ISREG(mode) and mode & 0o7777==0o644 and hashlib.sha256(z.read(item)).hexdigest()==SOURCE_SHA,'first source ZIP differs')
    failed=obj(root/'raw/retry-output/continuation-failure.json');need(failed.get('status')=='inputs_unchanged' and 'success-query' in failed.get('failure',''),'stopped attempt receipt differs')
    post=obj(root/'raw/retry-output/resume-postguard.json');need(post=={'failure':None,'status':'inputs_unchanged'},'resume postguard differs')
    need(obj(root/'raw/verification.json').get('status')=='observations_match_source_first','original verification differs')
    return {'status':'portable_evidence_consistent','selected_files':1,'query_rows':count,'extraction_errors':0,'warnings':warnings,'boundary':'Consistency of retained evidence; execution trust, runtime, authorization and security are not established.'}

if __name__=='__main__':print(json.dumps(validate(ROOT),indent=2,sort_keys=True))
