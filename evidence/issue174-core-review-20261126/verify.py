#!/usr/bin/env python3
"""Check the frozen source map against retained query observations."""
import hashlib
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PINS = {
    HERE / 'operation-map.json': '6e443f538598e8944a48f24de7d0bf815ce913483410a676efb0ddaf7f546450',
    HERE / 'setlocaltime-and-request-args-expected.json': '95fde6067e9cd3b602fb73b3d72937003f80a7e96574e30ce0139337cf07769f',
    ROOT / 'issue173-core-packages-20261126/source-oracle.json': 'afa112d09dce539a3e51845cd0786938194cb8c8af7d4c67d9713361b83693a5',
    ROOT / 'issue174-localtime-ipk-20261126/raw/retry-output/query.json': 'b52963d1dddfc71938aaf96c1d4af7b1e1b1fd5382702e1a3adbcd0a9c56a5c7',
}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def compare(mapping, query, spec):
    expected = []
    for row in mapping['provider']['operation_rows']:
        expected.append((tuple(row['source']['span_inclusive']), row['message'], tuple(row['sink']['span_inclusive']), row['sink']['name']))
    observed = []
    for src, message, sink, name in query['#select']['tuples']:
        def loc(node):
            u = node['url']
            need(u['uri'] == 'file:///Users/lalbers/gitroot/ucode/coverage-wave-work/issue174-retry-context-20261126/run/stage/usr/share/rpcd/ucode/luci', 'unexpected query URI')
            return tuple(u[k] for k in ('startLine', 'startColumn', 'endLine', 'endColumn'))
        need(src['label'] == 'MemberExpression' and sink['label'] == 'CallExpression', 'unexpected entity label')
        observed.append((loc(src), message, loc(sink), name))
    need(len(expected) == len(observed) == 7 and Counter(expected) == Counter(observed), 'query tuples differ')
    need(all(row[2] != (112, 5, 112, 55) for row in observed), 'literal near miss appeared')
    positive = spec['positive']
    def span(entity):
        return tuple(entity['start'] + entity['end_inclusive'])
    frozen = [(span(positive['source']), positive['expected_message'], span(positive['sink']), positive['sink']['name'])]
    for src, message, sink, name in spec['ambient_historical_expectations']:
        frozen.append((tuple(src['entity'][1:]), message, tuple(sink['entity'][1:]), name))
    need(Counter(frozen) == Counter(expected), 'source-first oracle tuples differ')

def compare_sources(mapping, oracle, source):
    rows = oracle['rows']
    for key, acl in mapping['companion_acls'].items():
        matches = [r for r in rows if r['source_path'] == acl['path']]
        need(len(matches) == 1 and matches[0]['package'] == 'luci-mod-' + key and matches[0]['source_sha256'] == acl['sha256'], 'ACL oracle differs')
        data = (source / acl['path']).read_bytes()
        need(hashlib.sha256(data).hexdigest() == acl['sha256'], 'ACL source differs')
        lines = data.decode().splitlines()
        for grant in acl['grant_lines']:
            need(lines[grant['line'] - 1].strip() == grant['text'], 'ACL grant differs')
    path = 'modules/luci-mod-status/ucode/template/admin_status/index.ut'
    matches = [r for r in rows if r['source_path'] == path]
    digest = '652842b1e54f8a2904458ae1f5693ddfc68b97f106d8b8ff48a4d8747d673019'
    need(len(matches) == 1 and matches[0]['package'] == 'luci-mod-status' and matches[0]['source_sha256'] == digest and matches[0]['projected_member'] == 'usr/share/ucode/luci/template/admin_status/index.ut', 'markup oracle differs')
    need(hashlib.sha256((source / path).read_bytes()).hexdigest() == digest, 'markup source differs')

def main():
    for path, expected in PINS.items():
        need(hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'evidence hash differs: ' + str(path))
    mapping = json.loads((HERE / 'operation-map.json').read_text())
    query = json.loads((ROOT / 'issue174-localtime-ipk-20261126/raw/retry-output/query.json').read_text())
    spec = json.loads((HERE / 'setlocaltime-and-request-args-expected.json').read_text())
    core = ROOT / 'issue173-core-packages-20261126'
    compare(mapping, query, spec)
    compare_sources(mapping, json.loads((core / 'source-oracle.json').read_text()), core / 'source')
    print('source map and seven retained query tuples agree')

if __name__ == '__main__':
    main()
