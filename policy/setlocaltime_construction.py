"""Provisional non-writing checker for one pinned source construction.

CSV agreement is not proof of producer execution, runtime behavior, or policy.
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

from policy.interchange_contract import ContractError, join_policy_grants

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'usr/share/rpcd/ucode/luci'
SOURCE_HASH = '6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e'
CORPUS = 'b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a'
PROFILE = 'luci-ssl-25.12'
ORACLE_PATH = 'policy/tests/fixtures/setlocaltime-construction-source-v1.json'
PINS = {
    ORACLE_PATH: 'a7e0a95e0c77f5e1e87cf20d32144f791df980ac4dd1ed2ddf16c7663d7c8218',
    'corpus/lock.json': CORPUS,
    'corpus/profiles/luci-ssl-25.12/profile.json': '16a5468601be4b23f45795a43deedd6fda6726ff7503abb9d80e493d16808ac5',
    'policy/grants.json': 'b34cdc9b9403c0ca21761ca340d6840e2b23f522486c4d6f7e139a4fa77b12bc',
    'policy/policy_decisions.json': 'abc44873c15a0a682e8527d20547a8cc9335e263696dee5749dfada6e2239f31',
    'reports/handler_effects.json': '2644d1187afaaf126afa71572cc980afbecd3f22592057809951491f90a436a0',
    'reports/m4-findings.json': '70873734806b6fbd359715634795acb4639a4517fde3f4e7d175822b2f36dd60',
}
COMMON = ['observation_kind', 'ubus_object', 'method', 'source_path', 'local_name', 'format_value']
SPANS = ['callback', 'initializer', 'input', 'guard', 'formatter', 'format', 'sink']
COORDS = ['start_line', 'start_column', 'end_line', 'end_column']
HEADER = COMMON + [f'{span}_{coord}' for span in SPANS for coord in COORDS] + ['slot_index', 'conversion', 'field_name'] + [f'field_{coord}' for coord in COORDS]
PRIMARY = 'policy:grant:luci-mod-system-config:ubus_http:luci.setLocaltime'
SUPPLEMENTARY = 'policy:grant:root:ubus_http:luci.setLocaltime'
EFFECT = 'm4:effect:luci-setLocaltime-system'
TAINT = 'm4:luci-setLocaltime-request-args-system'
UNKNOWN = [
    'live uhttpd/rpcd not executed',
    'int/sprintf conversion is not modeled as a barrier',
    'builtin runtime targets and dynamic global mutation are not resolved',
    'target firmware, libc, timezone and helper execution are not established',
    'source construction does not establish registration, reachability, execution or authorization',
]


class ValidationError(ValueError):
    """Input is invalid or unassessed, never a negative security finding."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError('duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValidationError('non-finite JSON value: ' + value)
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError('invalid JSON') from exc


def _check_csv_quotes(text):
    # csv.reader(strict=True) still accepts bare quotes in unquoted fields.
    state = 'start'
    i = 0
    while i < len(text):
        ch = text[i]
        if state == 'quoted':
            if ch == '"':
                if i + 1 < len(text) and text[i+1] == '"':
                    i += 1
                else:
                    state = 'closed'
        elif ch in ',\r\n':
            state = 'start'
        elif state == 'start':
            state = 'quoted' if ch == '"' else 'bare'
        elif state == 'closed' or ch == '"':
            raise ValidationError('invalid CSV quote')
        i += 1
    if state == 'quoted':
        raise ValidationError('unterminated CSV quote')


def _csv(data, header):
    try:
        text = data.decode('utf-8')
        if text.startswith('\ufeff'):
            raise ValidationError('CSV BOM not supported')
        _check_csv_quotes(text)
        rows = list(csv.reader(io.StringIO(text, newline=''), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise ValidationError('invalid UTF-8 CSV') from exc
    if not rows or rows[0] != header or any(len(row) != len(header) for row in rows[1:]):
        raise ValidationError('CSV header or width mismatch')
    return rows[1:]


def parse_table(data):
    rows = _csv(data, HEADER)
    if len(rows) != 6:
        raise ValidationError('six rows required; missing or unsupported output is unassessed')
    ints = [i for i, name in enumerate(HEADER) if name.endswith(tuple('_' + c for c in COORDS)) or name == 'slot_index']
    for row in rows:
        if any(not re.fullmatch(r'[1-9][0-9]*', row[i]) for i in ints):
            raise ValidationError('noncanonical positive integer')
    return rows


def _expected_rows(oracle):
    o = oracle['observation']
    common = [o[k] if k != 'source_path' else oracle['source_path'] for k in COMMON]
    common += [str(n) for span in SPANS for n in o[span]]
    return [tuple(common + [str(s['slot_index']), s['conversion'], s['field_name']] + [str(n) for n in s['field']]) for s in o['slots']]


def validate_rows(rows, oracle):
    if Counter(map(tuple, rows)) != Counter(_expected_rows(oracle)):
        raise ValidationError('source construction identity/slot multiset mismatch')
    observations = []
    for row in sorted(rows, key=lambda r: int(r[34])):
        d = dict(zip(HEADER, row))
        observations.append({'slot_index': int(d['slot_index']), 'conversion': d['conversion'], 'field_name': d['field_name'], 'field': [int(d['field_'+c]) for c in COORDS]})
    first = dict(zip(HEADER, rows[0]))
    result = {key: first[key] for key in COMMON if key != 'source_path'}
    result.update({span: [int(first[span+'_'+c]) for c in COORDS] for span in SPANS})
    result['slots'] = observations
    return result


def _pinned_inputs():
    result = {}
    for path, expected in PINS.items():
        data = (ROOT/path).read_bytes()
        if digest(data) != expected:
            raise ValidationError('context digest mismatch: ' + path)
        result[path] = data
    return result


def _record(rows, record_id):
    selected = [r for r in rows if isinstance(r, dict) and r.get('record_id') == record_id]
    if len(selected) != 1:
        raise ValidationError('existing record identity mismatch: ' + record_id)
    return selected[0]


def _validate_links(inputs):
    grants = _json(inputs['policy/grants.json'])
    if not isinstance(grants, list) or any(not isinstance(g, dict) or not isinstance(g.get('record_id'), str) for g in grants):
        raise ValidationError('invalid grant catalog')
    ids = [g['record_id'] for g in grants]
    if len(set(ids)) != len(ids):
        raise ValidationError('duplicate grant')
    effects = _json(inputs['reports/handler_effects.json'])
    findings = _json(inputs['reports/m4-findings.json'])
    effect, finding = _record(effects, EFFECT), _record(findings, TAINT)
    # Join is not source/sink validation. Bind that identity separately.
    for key, value in {'record_type':'handler_effect', 'effect_id':'setLocaltime.date.system', 'target_id':'command:date', 'sink_kind':'system', 'method':'setLocaltime', 'ingress':'ubus_http', 'profile':PROFILE, 'corpus_revision':'sha256:'+CORPUS}.items():
        if effect.get(key) != value:
            raise ValidationError('effect identity mismatch: '+key)
    for key, value in {'record_type':'taint_path', 'evidence_status':'path_found', 'target_id':'command:date', 'sink_kind':'system', 'method':'setLocaltime', 'session_class':'luci-mod-system-config', 'synthetic_session':True, 'ingress':'ubus_http', 'profile':PROFILE, 'corpus_revision':'sha256:'+CORPUS}.items():
        if type(finding.get(key)) is not type(value) or finding.get(key) != value:
            raise ValidationError('taint identity mismatch: '+key)
    if any(u not in effect.get('unknowns', []) or u not in finding.get('unknowns', []) for u in UNKNOWN[:2]):
        raise ValidationError('historical unknowns missing')
    indexed = {g['record_id']: g for g in grants}
    try:
        primary, supplementary = join_policy_grants(effect, indexed, scope='aggregate')
        caller, other = join_policy_grants(finding, indexed, scope='caller', requested_caller='luci-mod-system-config')
    except ContractError as exc:
        raise ValidationError('existing grant join failed') from exc
    if [g['record_id'] for g in primary] != [PRIMARY] or [g['record_id'] for g in supplementary] != [SUPPLEMENTARY] or [g['record_id'] for g in caller] != [PRIMARY] or other:
        raise ValidationError('existing grant partition mismatch')
    return {'existing_effect_record_id': EFFECT, 'existing_taint_record_id': TAINT, 'primary_grant_ids':[PRIMARY], 'supplementary_grant_ids':[SUPPLEMENTARY], 'unauthenticated_decision_id':'policy:decision:unauthenticated-setLocaltime-deny'}


def compare(table, extracted, errors, source_root):
    root = Path(source_root)
    if not root.is_absolute() or str(root) != source_root or str(root.resolve()) != source_root:
        raise ValidationError('source root must be canonical and not an alias')
    source = root/SOURCE_PATH
    if source.resolve() != source or digest(source.read_bytes()) != SOURCE_HASH:
        raise ValidationError('source path or digest mismatch')
    if _csv(extracted, ['f','col1']) != [[str(source), '']]:
        raise ValidationError('successful extraction diagnostic mismatch')
    if _csv(errors, ['error','col1','col2']):
        raise ValidationError('extraction errors: unassessed')
    inputs = _pinned_inputs()
    oracle = _json(inputs[ORACLE_PATH])
    observation = validate_rows(parse_table(table), oracle)
    links = _validate_links(inputs)
    return {
        'artifact_format':'setlocaltime_source_construction_annotation', 'format_version':1,
        'source':{'repository':oracle['source_repository'], 'revision':oracle['source_revision'], 'path':SOURCE_PATH, 'sha256':SOURCE_HASH},
        'context':{'profile':PROFILE, 'corpus_revision':'sha256:'+CORPUS, 'consumed_input_sha256':{p:digest(b) for p,b in inputs.items()}},
        'observation':observation, 'links':links,
        'evidence':{'table_sha256':digest(table), 'extracted_csv_sha256':digest(extracted), 'errors_csv_sha256':digest(errors), 'source_oracle_sha256':digest(inputs[ORACLE_PATH])},
        'assumptions':['Source observation only; genuine unmodified builtins are not established.', 'Historical caller is synthetic; supplementary root grant does not inherit its assessment.', 'CSV and diagnostics are not authenticated producer execution.'],
        'unknowns':list(UNKNOWN), 'validation_scope':'exact_pinned_source_construction_only', 'execution_verified':False,
    }


def render_markdown(report):
    o = report['observation']
    lines = ['# Provisional setLocaltime source construction', '', 'Source-only observation; not a sanitizer, security result, authorization or execution claim.', '', f"Existing date effect: `{report['links']['existing_effect_record_id']}`; historical taint: `{report['links']['existing_taint_record_id']}`.", '', f"Format: `{o['format_value']}`", '', 'Anchors (1-based inclusive byte columns):', '']
    for span in SPANS:
        a,b,c,d = o[span]
        lines.append(f'- {span}: `{a}:{b}–{c}:{d}`')
    lines += ['', '| Slot | Conversion | Field | Span |', '|---|---|---|---|']
    for s in o['slots']:
        a,b,c,d = s['field']
        lines.append(f"| {s['slot_index']} | `{s['conversion']}` | `t.{s['field_name']}` | `{a}:{b}–{c}:{d}` |")
    lines += ['', 'Assumptions:', ''] + ['- '+s for s in report['assumptions']] + ['', 'Unknowns:', ''] + ['- '+s for s in report['unknowns']]
    return '\n'.join(lines)+'\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('table', 'extracted', 'errors', 'source-root'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--format', choices=('json','markdown'), default='json')
    args = parser.parse_args(argv)
    try:
        report = compare(Path(args.table).read_bytes(), Path(args.extracted).read_bytes(), Path(args.errors).read_bytes(), args.source_root)
        output = json.dumps(report, indent=2, ensure_ascii=True)+'\n' if args.format == 'json' else render_markdown(report)
        sys.stdout.buffer.write(output.encode('utf-8'))
    except (ValidationError, OSError) as exc:
        print('unassessed: '+str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
