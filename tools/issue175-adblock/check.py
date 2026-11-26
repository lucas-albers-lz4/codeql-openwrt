#!/usr/bin/env python3
"""Check #175 frozen call inventory; supplied evidence is not an execution attestation."""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import io
import stat
import zipfile
from urllib.parse import urlsplit,unquote

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'luci-base-inventory'))
import archive
spec=importlib.util.spec_from_file_location('luci_base_175',HERE.parent/'luci-base-inventory/compare.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
APP='usr/share/rpcd/ucode/luci.adblock-fast'
POS='usr/share/ucode/issue175/positive.uc'
NEG='usr/share/ucode/issue175/near-miss.uc'
PATHS=(APP,POS,NEG)
APP_SHA='3cb9d07b33a0aec36743326a5cb1e18885d245a132ef92174eb4c8b70aaebdd8'
ORACLE_SHA='378771758beee24fc1f32c91ffcfd573c0ff655a5287f8663c370c8834795297'
CONTROL_SHA={POS:'b6284410ba2f2fc28ba43a8584506eb0afbaf0e864ef25c9ac5877a3a97a4e81', NEG:'d7da956a8afbc3162a83f014c33cf82ebf923d9624011b09f3cb283365cde942'}
APP_ORACLE_SHA='ea71145e8da15d306d601227c4b74a710b44516823a0192ebed509d1d7e72e2d'
PRODUCER='a7bf614e2fb59200e303f04b6255af7e6d4007e2'
QUERY_SHA='69cd39c500b6ac6cf697ed5dfd180d1cf6ae8664939cc96a763dc5234648d37f'
MODELS_SHA='fac64bc3b9fc232225c351c44a7985458a2fe90d87e462f1af2803b26185fd1e'

def require(value,message):
    if not value:raise ValueError(message)
def digest(data):return hashlib.sha256(data).hexdigest()
def load_json(data):
    def pairs(items):
        d={}
        for k,v in items:require(k not in d,'duplicate JSON key: '+k);d[k]=v
        return d
    def reject(v):raise ValueError('invalid JSON constant: '+v)
    d=json.loads(data,object_pairs_hook=pairs,parse_constant=reject);require(isinstance(d,dict),'expected JSON object');return d

def oracle():
    data=(HERE/'expected-call-spans.json').read_bytes();require(digest(data)==ORACLE_SHA,'source-first oracle digest differs');return load_json(data)

def safe_file(path):
    p=Path(path);require(p.is_absolute() and p.resolve(strict=True)==p and p.is_file() and not p.is_symlink() and p.stat().st_nlink==1,'file must be physical and non-aliased');return p

def validate_app_package(ipk_bytes,receipt,lock):
    for key in ('package_run_id','artifact_url'):
        require(isinstance(lock.get(key),str) and lock[key], 'missing independently reviewed '+key)
    require(re.fullmatch(r'[0-9]+-[0-9]+',lock['package_run_id']) is not None,'invalid package run identity')
    expected=lock.get('ipk_sha256');require(isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected) is not None and expected!='0'*64,'missing reviewed IPK digest')
    require(digest(ipk_bytes)==expected and receipt.get('ipk_sha256')==expected,'IPK digest differs from reviewed receipt')
    require(receipt.get('package')=='app' and receipt.get('oracle_sha256')==APP_ORACLE_SHA,'app package receipt differs')
    require(receipt.get('source_pins')==base.PINS,'app source pins differ')
    require(isinstance(lock.get('config'),dict) and receipt.get('config')==lock['config'] and isinstance(lock['config'].get('config'),dict) and re.fullmatch('[0-9a-f]{64}',str(lock['config']['config'].get('sha256',''))) is not None,'reviewed resolved config differs')
    control,members,outer=archive.read_ipk(ipk_bytes)
    require(receipt.get('outer_sha256')==outer and receipt.get('control_members')==archive.receipts(control) and receipt.get('data_members')==archive.receipts(members),'IPK archive inventory differs from receipt')
    require(base.control_from_rows(control)==receipt.get('control')=={'Package':'luci-app-adblock-fast','Version':'1.2.4-r4','Architecture':'all'},'app IPK control differs')
    acl=members.get('usr/share/rpcd/acl.d/luci-app-adblock-fast.json')
    require(acl is not None and acl['type']=='file' and acl['mode']==0o644 and digest(acl['bytes'])=='af249e0610e568be8e7bac542c0ce9f402e1a95cd34d3c5eb9a9724aff46502d','app ACL package context differs')
    entry=members.get(APP);require(entry is not None and entry['type']=='file' and entry['mode']==0o644 and digest(entry['bytes'])==APP_SHA,'app RPC member differs')
    selected=[r for r in receipt.get('source_mappings',[]) if r.get('path')==APP]
    require(len(selected)==1 and selected[0].get('disposition')=='selected_ucode_rpcd' and selected[0].get('source_git_mode')=='100644' and all(selected[0].get(k)==APP_SHA for k in ('source_sha256','prepared_sha256','staged_sha256','ipk_sha256')) and all(selected[0].get(k)=='0644' for k in ('prepared_mode','staged_mode','ipk_mode')),'app source-to-member mapping differs')
    return entry['bytes']

def stage_inputs(stage, files):
    require(set(files)==set(PATHS),'stage expected-hash keys differ')
    stage=Path(stage);require(stage.is_absolute() and stage.resolve(strict=True)==stage and stage.is_dir(),'stage not physical')
    actual=[];dirs=[]
    for p in stage.rglob('*'):
        require(not p.is_symlink(),'stage symlink')
        if p.is_file():require(p.stat().st_nlink==1 and p.stat().st_mode & 0o7777==0o644,'stage mode or link differs');actual.append(p.relative_to(stage).as_posix())
        else:
            require(p.is_dir(),'stage special file');dirs.append(p.relative_to(stage).as_posix())
    expected_dirs=set()
    for name in PATHS:
        parent=Path(name).parent
        while str(parent)!='.':expected_dirs.add(parent.as_posix());parent=parent.parent
    require(set(actual)==set(PATHS) and len(actual)==3 and set(dirs)==expected_dirs,'stage inventory differs')
    for path,expected in files.items():require(digest(safe_file(stage/path).read_bytes())==expected,'stage bytes differ: '+path)

def file_uri(uri,stage):
    require(isinstance(uri,str),'missing URI');u=urlsplit(uri);require(u.scheme=='file' and u.netloc=='' and not u.query and not u.fragment,'entity URI not local file')
    p=Path(unquote(u.path));require(p.is_absolute() and p.resolve(strict=True)==p and uri==p.as_uri(),'entity URI not canonical')
    try:rel=p.relative_to(stage).as_posix()
    except ValueError as e:raise ValueError('entity URI outside stage') from e
    require(rel in PATHS,'unexpected entity path');return rel

def tuples(value):
    result=value.get('#select');require(isinstance(result,dict) and isinstance(result.get('tuples'),list),'invalid decoded #select');return result['tuples']

def check_source_spans(stage,expected):
    require(expected.get('schema')=='issue175-source-first-call-spans-v1' and expected.get('expected_rows')==14,'oracle schema/count differs')
    rows=expected.get('rows');require(isinstance(rows,list) and len(rows)==15,'source span count differs')
    for row in rows:
        path=row['path'];require(path in PATHS,'oracle source path differs');data=safe_file(stage/path).read_bytes();start=row['byte_start_0'];end=row['byte_end_exclusive_0']
        require(type(start) is int and type(end) is int and 0<=start<end<=len(data),'invalid span offsets')
        piece=data[start:end];require(digest(piece)==row['expression_sha256'] and piece.startswith(b'system(') and piece.endswith(b')'),'source expression differs')
        def position(n):
            prefix=data[:n];return [prefix.count(b'\n')+1,n-(prefix.rfind(b'\n')+1)+1]
        require(position(start)==row['start'] and position(end-1)==row['end_inclusive'],'source coordinates differ')
    require(Counter((r['path'],r['expected_rows']) for r in rows)==Counter({(APP,1):13,(POS,1):1,(NEG,0):1}),'oracle positive/near-miss count differs')

def validate_route(stage,route):
    require(all(type(route.get(k)) is int and route[k]==v for k,v in (('input_count',3),('duplicate_input_count',0),('plain_count',3),('markup_count',0),('markup_inconclusive_count',0),('uncertain_count',0),('excluded_count',0))),'route counts differ')
    decisions=route.get('decisions');require(isinstance(decisions,list) and len(decisions)==3,'route decision count differs');seen=[]
    for d in decisions:
        path=d.get('installed_path');require(path in PATHS and d.get('path')==str(stage/path),'route path differs')
        reason='rpcd_raw_mode_full_path' if path==APP else 'ucode_extension'
        require(d.get('classification')=='plain' and d.get('reason')==reason and d.get('status')=='plain_route_selected' and d.get('inconclusive_reason') is None,'route identity differs');seen.append(path)
    require(Counter(seen)==Counter(PATHS),'route multiset differs')

def validate_success(stage,value):
    observed=[]
    for row in tuples(value):
        require(isinstance(row,list) and len(row)==2 and row[1]=='' and isinstance(row[0],dict),'success row shape differs')
        observed.append(file_uri(row[0].get('url',{}).get('uri'),stage))
    require(Counter(observed)==Counter(PATHS),'successful-file multiset differs')

def validate_errors(value):require(tuples(value)==[],'extraction errors present')

def validate_query(stage,value,expected):
    actual=[];ids={};spans={}
    for row in tuples(value):
        require(isinstance(row,list) and len(row)==2 and isinstance(row[0],dict) and isinstance(row[1],str),'query tuple shape differs')
        entity=row[0];require(type(entity.get('id')) is int and entity.get('label')=='CallExpression','query node identity differs')
        u=entity.get('url',{});path=file_uri(u.get('uri'),stage);coords=[u.get(k) for k in ('startLine','startColumn','endLine','endColumn')]
        require(all(type(x) is int and x>0 for x in coords) and tuple(coords[2:])>=tuple(coords[:2]),'invalid query range')
        key=(path,*coords);ident=entity['id'];require(key not in spans or spans[key]==ident,'equal span entity ID differs');require(ident not in ids or ids[ident]==key,'entity ID reused for different call');spans[key]=ident;ids[ident]=key
        actual.append((path,*coords,row[1]))
    want=[]
    for r in expected['rows']:
        if r['expected_rows']:
            path=r['path'];want.extend([(path,*r['start'],*r['end_inclusive'],f"builtin system() in {Path(path).name} at line {r['source_line']}")]*r['expected_rows'])
    require(Counter(actual)==Counter(want),'query call identity/multiplicity differs')
    return {'status':'observations_match_source_first','app_calls':13,'synthetic_positive':1,'formal_shadow_near_miss':0,'total_rows':len(actual),'boundary':'Supplied-output consistency only; no runtime, authorization, taint or security claim.'}


def validate_source_archive(stage, zip_path):
    data=safe_file(zip_path).read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        entries=z.infolist()
        require(len(entries)==len(PATHS),'source archive member count differs')
        expected={str(stage/path).lstrip('/'):sha for path,sha in {APP:APP_SHA,**CONTROL_SHA}.items()}
        seen=[]
        for item in entries:
            mode=item.external_attr >> 16
            require(item.filename in expected and not item.is_dir() and item.create_system==3 and stat.S_ISREG(mode) and mode & 0o7777==0o644,'source archive member identity or mode differs')
            require(digest(z.read(item))==expected[item.filename],'source archive bytes differ');seen.append(item.filename)
        require(Counter(seen)==Counter(expected.keys()),'source archive member multiset differs')
    return digest(data)
