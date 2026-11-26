#!/usr/bin/env python3
"""Bounded #174 evidence checker. Does not run CodeQL or authenticate a receipt."""
import hashlib
import json
import stat
import zipfile
from collections import Counter
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'luci-base-inventory'))
import archive
import compare as base

HERE = Path(__file__).resolve().parent
ORACLE_SHA = '95fde6067e9cd3b602fb73b3d72937003f80a7e96574e30ce0139337cf07769f'
IPK_SOURCE = 'usr/share/rpcd/ucode/luci'
SOURCE_SHA = '04c9cc966f9cbdd9bea942f55ab139ba11bff78e751ed3ee2e99f52be9c73dbf'
PRODUCER = 'a7bf614e2fb59200e303f04b6255af7e6d4007e2'
QUERY_SHA = '0bf41049d4841a6c989425b14d7f26ba12587a94c4e2c41f4da1b053f01bbb35'
MODEL_SHA = 'fac64bc3b9fc232225c351c44a7985458a2fe90d87e462f1af2803b26185fd1e'

def require(ok, why):
    if not ok: raise ValueError(why)

def digest(data): return hashlib.sha256(data).hexdigest()

def json_object(data):
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result, 'duplicate JSON key: '+k); result[k]=v
        return result
    def reject_constant(value): raise ValueError('invalid JSON constant: '+value)
    value=json.loads(data, object_pairs_hook=pairs, parse_constant=reject_constant)
    require(isinstance(value,dict),'expected JSON object')
    return value

def oracle():
    data=(HERE/'expected-tuples.json').read_bytes()
    require(digest(data)==ORACLE_SHA,'source oracle digest differs')
    return json_object(data)

def expected_rows(spec):
    pos=spec['positive']
    source={'entity':[IPK_SOURCE,*pos['source']['start'],*pos['source']['end_inclusive']], 'label':pos['source']['kind']}
    sink={'entity':[IPK_SOURCE,*pos['sink']['start'],*pos['sink']['end_inclusive']], 'label':pos['sink']['kind']}
    return [[source,pos['expected_message'],sink,pos['sink']['name']]]+spec['ambient_historical_expectations']

def safe_file(path):
    path=Path(path)
    require(path.is_absolute() and path.resolve(strict=True)==path, 'path must be absolute and physical')
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1, 'expected non-aliased regular file')
    return path

def validate_package(ipk_bytes, receipt, expected_ipk_sha):
    require(len(expected_ipk_sha)==64 and all(c in '0123456789abcdef' for c in expected_ipk_sha) and expected_ipk_sha != '0'*64, 'missing or invalid independently pinned IPK hash')
    require(digest(ipk_bytes)==expected_ipk_sha, 'IPK digest differs')
    require(receipt.get('status')=='PASS' and receipt.get('ipk',{}).get('sha256')==expected_ipk_sha, '#173 receipt/IPK mismatch')
    expected_pins={'luci':'cb87fe60e1e2e052af36a93647f2264577829e0a',
                   'openwrt':'4e9642517b48bae612ff10fb72fb9199e559500e',
                   'packages':'07e0d16305d2b5903b37ad7913e33e18795f81a4'}
    pins=receipt.get('pins',{})
    require(isinstance(pins,dict) and all(isinstance(pins.get(k),dict) and pins[k].get('sha')==v and pins[k].get('dirty') is False for k,v in expected_pins.items()), '#173 source pins differ')
    require(receipt.get('oracle_sha256')=='5fe8593458900f5eca20e20de5e68e1d7cba079fd985e93ec53bff5551b5f999', '#173 oracle digest differs')
    control,members,_=archive.read_ipk(ipk_bytes)
    fields=base.control_from_rows(control)
    require(fields.get('Package')=='luci-base' and fields.get('Version')==receipt.get('package_version')=='26.317.52279~1c75ea4' and fields.get('Architecture')=='x86_64', 'IPK control identity differs')
    member=members.get(IPK_SOURCE)
    require(member is not None and member['type']=='file' and member['mode']==0o644 and digest(member['bytes'])==SOURCE_SHA, 'provider member identity differs')
    matches=[r for r in receipt.get('files',[]) if r.get('installed_path')==IPK_SOURCE]
    require(len(matches)==1 and matches[0].get('status')=='selected present' and matches[0].get('ipk_sha256')==SOURCE_SHA and matches[0].get('source_sha256')==SOURCE_SHA, '#173 provider mapping differs')
    return member['bytes']

def relative_file(uri, stage):
    require(isinstance(uri,str),'missing entity URI')
    u=urlsplit(uri)
    require(u.scheme=='file' and u.netloc=='' and not u.query and not u.fragment,'entity URI must be local file')
    path=Path(unquote(u.path))
    require(path.is_absolute() and path.resolve(strict=True)==path and uri==path.as_uri(),'entity URI is nonphysical or noncanonical')
    require(path==stage/IPK_SOURCE,'entity URI does not identify selected provider')
    return IPK_SOURCE

def entity(value, stage):
    require(isinstance(value,dict) and type(value.get('id')) is int,'entity id missing')
    require(isinstance(value.get('label'),str),'entity label missing')
    url=value.get('url');require(isinstance(url,dict),'entity location missing')
    uri=relative_file(url.get('uri'),stage)
    positions=[url.get(k) for k in ('startLine','startColumn','endLine','endColumn')]
    require(all(type(x) is int and x>0 for x in positions),'invalid entity coordinates')
    require(tuple(positions[2:])>=tuple(positions[:2]),'reversed entity range')
    return ({'entity':[uri,*positions], 'label':value['label']},value['id'])

def rows_from_bqrs(value):
    result=value.get('#select');require(isinstance(result,dict) and isinstance(result.get('tuples'),list),'invalid decoded #select')
    return result['tuples']

def validate_route(stage, route):
    file=stage/IPK_SOURCE
    require(all(type(route.get(k)) is int and route[k]==v for k,v in (('input_count',1),('duplicate_input_count',0),('plain_count',1))), 'route counts differ')
    for key in ('markup_count','markup_inconclusive_count','uncertain_count','excluded_count'):
        require(type(route.get(key)) is int and route[key]==0,'unexpected route count: '+key)
    decisions=route.get('decisions');require(isinstance(decisions,list) and len(decisions)==1,'route decision count differs')
    d=decisions[0]
    require(d.get('path')==str(file) and d.get('installed_path')==IPK_SOURCE and d.get('classification')=='plain' and d.get('reason')=='rpcd_raw_mode_full_path' and d.get('status')=='plain_route_selected' and d.get('inconclusive_reason') is None,'route identity differs')

def validate_success(stage, success):
    s=rows_from_bqrs(success);require(len(s)==1 and len(s[0])==2,'successful-file multiset differs')
    require(s[0][1]=='','successful-file diagnostic value differs')
    require(isinstance(s[0][0],dict) and relative_file(s[0][0].get('url',{}).get('uri'),stage)==IPK_SOURCE,'successful-file identity differs')

def validate_errors(errors):
    require(rows_from_bqrs(errors)==[],'extraction errors present')

def validate_source_archive(stage, zip_path):
    data=safe_file(zip_path).read_bytes()
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        entries=z.infolist()
        require(len(entries)==1,'source archive member count differs')
        item=entries[0]
        expected=str(stage/IPK_SOURCE).lstrip('/')
        mode=item.external_attr >> 16
        require(item.filename==expected and not item.is_dir() and item.create_system==3 and stat.S_ISREG(mode) and mode & 0o7777==0o644,'source archive member identity or mode differs')
        require(digest(z.read(item))==SOURCE_SHA,'source archive bytes differ')
    return digest(data)

def check_observations(stage, route, success, errors, query, spec):
    stage=Path(stage)
    require(stage.is_absolute() and stage.resolve(strict=True)==stage, 'stage must be physical absolute')
    file=stage/IPK_SOURCE
    require(safe_file(file) and file.stat().st_mode & 0o7777 == 0o644 and digest(file.read_bytes())==SOURCE_SHA,'stage provider differs')
    files=[]
    for item in stage.rglob('*'):
        require(not item.is_symlink(),'stage symlink')
        if item.is_file(): files.append(item.relative_to(stage).as_posix())
        else: require(item.is_dir(),'stage special file')
    require(files==[IPK_SOURCE],'stage inventory differs')
    validate_route(stage,route)
    validate_success(stage,success)
    validate_errors(errors)
    actual=[]; ids={}; locations_by_id={}
    for row in rows_from_bqrs(query):
        require(isinstance(row,list) and len(row)==4 and isinstance(row[1],str) and isinstance(row[3],str),'query tuple shape differs')
        src,sid=entity(row[0],stage); sink,kid=entity(row[2],stage)
        for norm,ident in ((src,sid),(sink,kid)):
            key=json.dumps(norm,sort_keys=True)
            if key in ids: require(ids[key]==ident,'equal expected span has distinct entity IDs')
            else: ids[key]=ident
            if ident in locations_by_id: require(locations_by_id[ident]==key, 'entity ID reused for different nodes')
            else: locations_by_id[ident]=key
        actual.append([src,row[1],sink,row[3]])
    canon=lambda row:json.dumps(row,sort_keys=True,separators=(',',':'))
    require(Counter(map(canon,actual))==Counter(map(canon,expected_rows(spec))),'query tuple multiset differs')
    return {'status':'observations_match_source_first', 'query_rows':len(actual), 'successful_files':[IPK_SOURCE], 'extraction_errors':0,
            'scope':'Consistency of supplied outputs only; execution origin, runtime and security not established.'}
