#!/usr/bin/python3
"""Issue 89 offline consistency checks; not execution or freshness attestation."""
import csv
import io
import json
from pathlib import Path

RID = 'm4:effect:luci-setBlockDetect-system'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'duplicate JSON key: ' + key)
        out[key] = value
    return out

def load(path):
    def bad(value):
        raise ValueError('non-JSON number: ' + value)
    return json.loads(Path(path).read_bytes().decode('utf-8'), object_pairs_hook=pairs, parse_constant=bad)

def same(a, b):
    if type(a) is not type(b): return False
    if type(a) is dict: return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if type(a) is list: return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b

def readcsv(path):
    try:
        return list(csv.reader(io.StringIO(Path(path).read_bytes().decode('utf-8'), newline=''), strict=True))
    except (csv.Error, UnicodeError) as e:
        raise ValueError('invalid CSV: ' + str(path)) from e

def check_csv(artifacts, oracle, source):
    require(readcsv(artifacts/'effects.csv') == [oracle['header']] + oracle['rows'], 'effects CSV mismatch')
    require(readcsv(artifacts/'extracted.csv') == [['f', 'col1'], [source, '']], 'extracted CSV mismatch')
    require(readcsv(artifacts/'errors.csv') == [['error', 'col1', 'col2']], 'extraction errors CSV mismatch')

def check_routing(path, source, installed):
    expected = {'input_count':1, 'plain_count':1, 'markup_count':0,
                'markup_inconclusive_count':0, 'uncertain_count':0,
                'excluded_count':0, 'duplicate_input_count':0,
                'decisions':[{'path':source, 'installed_path':installed,
                              'classification':'plain', 'reason':'rpcd_raw_mode_full_path',
                              'status':'plain_route_selected'}]}
    require(same(load(path), expected), 'unexpected routing')

def check_archive(archive, source):
    import zipfile
    source = Path(source)
    require(source.is_absolute(), 'source must be absolute')
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        require(names == [str(source).lstrip('/')], 'source archive path set mismatch')
        require(z.read(names[0]) == source.read_bytes(), 'source archive bytes mismatch')

def check_typed(artifacts, oracle):
    require(same(load(artifacts/'typed.json'), oracle), 'neutral typed oracle mismatch')

def target(rows):
    require(type(rows) is list and all(type(r) is dict for r in rows), 'report must be array of objects')
    found = [r for r in rows if r.get('record_id') == RID]
    require(len(found) == 1, 'expected exactly one target')
    return found[0]

def check_prestates(before0, before1, oracle, expected):
    legacy = dict(oracle['effect'], corpus_revision=expected['corpus_revision'])
    require(same(target(before0), legacy) and same(target(before1), legacy), 'CSV prestates differ from independent oracle')

def check_reports(artifacts, consumer, oracle, expected, require_reimport=True):
    grants = load(consumer/'policy/grants.json')
    decisions = load(consumer/'policy/policy_decisions.json')['decisions']
    require(type(grants) is list and type(decisions) is list, 'invalid policy inputs')
    for i in range(2):
        before = load(artifacts/('before-'+str(i)+'.json'))
        after = load(artifacts/('after-'+str(i)+'.json'))
        old, new = target(before), target(after)
        legacy = dict(oracle['effect'], corpus_revision=expected['corpus_revision'])
        require(same(old, legacy), 'CSV prestate mismatch')
        require(same(new, expected), 'retained target mismatch')
        require(not same(old, new), 'no-op transition')
        require(same([r for r in before if r.get('record_id') != RID], [r for r in after if r.get('record_id') != RID]), 'unrelated rows changed')
        if require_reimport:
            require((artifacts/('after-'+str(i)+'.json')).read_bytes() == (artifacts/('reimport-'+str(i)+'.json')).read_bytes(), 'reimport is not byte-idempotent')
        refs = [r for r in new['evidence_refs'] if r.startswith('policy:grant:')]
        require(refs == [g['record_id'] for g in oracle['grants']], 'grant references mismatch')
        matching = []
        for g in oracle['grants']:
            rows = [r for r in grants if r.get('record_id') == g['record_id']]
            require(len(rows) == 1 and all(k in rows[0] and same(rows[0][k], v) for k,v in g.items()), 'grant mismatch')
            matching.append(rows[0])
        primary = [g['record_id'] for g in matching if g['expectation_id'] == new['expectation_id']]
        supplementary = [g['record_id'] for g in matching if g['expectation_id'] != new['expectation_id']]
        require(primary == [oracle['grants'][0]['record_id']] and supplementary == [oracle['grants'][1]['record_id']], 'grant partition mismatch')
    deny = [d for d in decisions if d.get('record_id') == oracle['deny_id']]
    require(len(deny) == 1 and deny[0].get('outcome') == 'deny' and deny[0].get('session_class') == 'unauthenticated' and deny[0].get('grant_emitted') is False, 'unauthenticated deny mismatch')
    require(not any(g.get('session_class') == 'unauthenticated' and g.get('entrypoint_id') == 'ubus_http:luci.setBlockDetect' for g in grants), 'unauthenticated grant')
