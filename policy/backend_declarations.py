"""Pinned, non-writing source-declaration / grant-catalog comparison.

This module validates supplied bytes, not their execution history. It does not
run CodeQL, evaluate policy, import findings, or infer runtime registration.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
REL_SOURCE = 'usr/share/rpcd/ucode/luci'
SOURCE_HASH = '6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e'
PROFILE = 'luci-ssl-25.12'
CORPUS = 'b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a'
PINS = {
    'policy/tests/fixtures/luci-backend-source-v1.json': 'f8b5a575002a1b7937a563f96e3e2c914b64a1dc2fc0c39def09a761dca8dc0d',
    'policy/tests/fixtures/luci-backend-grants-v1.json': 'a8749b7e302f1d7ee10154e6ca80492c758d6f3667f0946321d4a0921e1c9a62',
    'policy/grants.json': 'b34cdc9b9403c0ca21761ca340d6840e2b23f522486c4d6f7e139a4fa77b12bc',
    'corpus/lock.json': CORPUS,
    'corpus/profiles/luci-ssl-25.12/profile.json': '16a5468601be4b23f45795a43deedd6fda6726ff7503abb9d80e493d16808ac5',
}
HEADER = ['observation_kind','ubus_object','method','source_path','start_line','start_column','end_line','end_column']


class ValidationError(ValueError):
    """Unsupported or invalid comparison input."""


def _csv(data, header):
    try:
        text = data.decode('utf-8')
        if text.startswith('\ufeff'):
            raise ValidationError('CSV BOM not supported')
        result = list(csv.reader(io.StringIO(text, newline=''), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise ValidationError('invalid UTF-8 CSV') from exc
    if not result or result[0] != header or any(len(r) != len(header) for r in result[1:]):
        raise ValidationError('CSV header or row width mismatch')
    return result[1:]


def parse_table(data):
    parsed = _csv(data, HEADER)
    if not parsed:
        raise ValidationError('empty table is unknown')
    for row in parsed:
        if row[0:2] != ['source_declared_callback','luci'] or row[3] != REL_SOURCE or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*',row[2]):
            raise ValidationError('unsupported observation identity')
        if any(not re.fullmatch(r'[1-9][0-9]*', x) for x in row[4:]):
            raise ValidationError('noncanonical coordinate')
        if (int(row[4]), int(row[5])) > (int(row[6]), int(row[7])):
            raise ValidationError('reversed span')
    return parsed


def validate_observations(rows, oracle):
    expected = []
    for o in oracle['observations']:
        expected.append(('source_declared_callback','luci',o['method'],REL_SOURCE, *(str(o[k]) for k in ('start_line','start_column','end_line','end_column'))))
    actual = [tuple(row) for row in rows]
    if len(set(actual)) != len(actual) or Counter(actual) != Counter(expected):
        raise ValidationError('source identity/span multiset mismatch')
    return sorted(({'method':r[2], 'start_line':int(r[4]), 'start_column':int(r[5]), 'end_line':int(r[6]), 'end_column':int(r[7])} for r in actual), key=lambda r:(r['start_line'],r['start_column'],r['method']))


def validate_diagnostics(extracted, errors, root):
    if not root.startswith('/') or Path(root).as_posix() != root or '..' in Path(root).parts:
        raise ValidationError('source root must be an absolute canonical path')
    if _csv(extracted,['f','col1']) != [[root.rstrip('/')+'/'+REL_SOURCE,'']]:
        raise ValidationError('successful extraction diagnostic mismatch')
    if _csv(errors,['error','col1','col2']):
        raise ValidationError('extraction errors reported')


def validate_grants(grants, expected):
    if not isinstance(grants,list) or any(not isinstance(g,dict) for g in grants):
        raise ValidationError('grant catalog must be a list of objects')
    ids = [g.get('record_id') for g in grants]
    if any(not isinstance(x,str) or not x.strip() for x in ids) or len(ids) != len(set(ids)):
        raise ValidationError('invalid or duplicate grant ID')
    # Scan all identity-bearing fields: changing a single filter field cannot
    # hide a former luci grant. The independently frozen catalog map binds each.
    def related(g):
        return (g.get('ubus_object') == 'luci' or any('luci.' in str(g.get(k,'')) for k in ('record_id','entrypoint_id','target_id')))
    selected = [g for g in grants if related(g)]
    keys = tuple(expected[0])
    actual = sorted(({k:g.get(k) for k in keys} for g in selected), key=lambda g:g['record_id'])
    if actual != sorted(expected, key=lambda g:g['record_id']):
        raise ValidationError('grant identity/context mismatch')
    return actual


def make_report(observations, grants):
    groups = {}
    for g in grants:
        groups.setdefault(g['method'], []).append(g['record_id'])
    declarations = []
    for o in observations:
        ids = sorted(groups.get(o['method'], []))
        declarations.append({**o, 'grant_ids':ids, 'relation':'current_grant_rows' if ids else 'no_current_grant_row'})
    source_names = {o['method'] for o in observations}
    source_only = sorted(o['method'] for o in observations if o['method'] not in groups)
    grant_only = sorted(set(groups)-source_names)
    return {
        'artifact_format':'luci_backend_declaration_grant_comparison_report', 'format_version':1,
        'source':{'repository':'https://github.com/openwrt/luci','revision':'b2e0be4b46ec0fd43394c081fa7c50657af14011','path':REL_SOURCE,'sha256':SOURCE_HASH},
        'context':{'profile':PROFILE,'corpus_revision':'sha256:'+CORPUS,'producer_revision_reference':'d54c17a8cefc43ef9cde36d65558c986348aa7b2','query_sha256':'58d11ee8bf4f27db2dec4e34292d5155874f035bac8b98121c9ee8d85225a298','consumer_baseline_reference':'fc084f564660c8366022787aaf09e38f8ee32139'},
        'scope':['Syntactic source declarations only; no runtime registration, reachability or execution is established.', 'Unmatched means no current materialized grant row, not denial or an ACL defect.', 'Offline validation does not attest fresh extraction or execution.'],
        'declarations':declarations, 'source_only':source_only, 'grant_only':grant_only,
        'summary':{'declarations':len(declarations),'represented_methods':sum(bool(d['grant_ids']) for d in declarations),'grant_rows':sum(len(d['grant_ids']) for d in declarations),'source_only':len(source_only),'grant_only':len(grant_only)},
    }


def _json(data):
    def unique(pairs):
        d = {}
        for k,v in pairs:
            if k in d:
                raise ValidationError('duplicate JSON key')
            d[k] = v
        return d
    def invalid(value):
        raise ValidationError('non-finite JSON value: '+value)
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError('invalid JSON') from exc


def _pinned(path):
    data = (ROOT/path).read_bytes()
    if hashlib.sha256(data).hexdigest() != PINS[path]:
        raise ValidationError('context digest mismatch: '+path)
    return data


def compare(table, extracted, errors, source_root):
    root = Path(source_root)
    if not root.is_absolute() or str(root) != source_root or str(root.resolve()) != source_root:
        raise ValidationError('source root must be canonical and not an alias')
    source = root/REL_SOURCE
    if source.resolve() != source:
        raise ValidationError('source path is an alias')
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_HASH:
        raise ValidationError('source digest mismatch')
    validate_diagnostics(extracted,errors,source_root)
    oracle = _json(_pinned('policy/tests/fixtures/luci-backend-source-v1.json'))
    expected = _json(_pinned('policy/tests/fixtures/luci-backend-grants-v1.json'))
    grants = _json(_pinned('policy/grants.json'))
    _pinned('corpus/lock.json')
    _pinned('corpus/profiles/luci-ssl-25.12/profile.json')
    return make_report(validate_observations(parse_table(table),oracle), validate_grants(grants,expected))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('table','extracted','errors','source-root'):
        parser.add_argument('--'+name,required=True)
    args = parser.parse_args(argv)
    try:
        report = compare(Path(args.table).read_bytes(),Path(args.extracted).read_bytes(),Path(args.errors).read_bytes(),args.source_root)
        sys.stdout.buffer.write((json.dumps(report,indent=2,ensure_ascii=True)+'\n').encode('utf-8'))
    except (ValidationError, OSError) as exc:
        print('comparison failed: '+str(exc),file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
