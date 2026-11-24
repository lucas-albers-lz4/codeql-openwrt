"""Restricted conversion of the retained source multiset, not CodeQL evidence."""
import json
import hashlib
from pathlib import Path
from uci_normalize import source_paths
from collections import Counter

FIELDS = ['source_index', 'span', 'receiver_form', 'kind', 'property', 'source_expression', 'multiplicity']


def load_json(stream):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('duplicate JSON key: ' + key)
            out[key] = value
        return out
    return json.load(stream, object_pairs_hook=unique)


MULTISET_SHA256 = '341e1e41a21edc9114c5ec3eee9f76bc022ea4b89f6856d8b80854cf5b8c2a98'

def convert(raw, manifest, source):
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != MULTISET_SHA256:
        raise ValueError('source multiset digest mismatch')
    import io
    document = load_json(io.BytesIO(raw))
    if not isinstance(document, dict) or set(document) != {'planning_only', 'claim_scope', 'inputs', 'parser_provenance', 'interpretation', 'verification', 'limits', 'sources', 'candidate_tuple_field_order', 'candidates'}:
        raise ValueError('unexpected document schema')
    paths = source_paths(source, manifest)
    if document.get('candidate_tuple_field_order') != FIELDS:
        raise ValueError('unexpected source tuple schema')
    sources, candidates = document.get('sources'), document.get('candidates')
    if not isinstance(sources, list) or not isinstance(candidates, list):
        raise ValueError('invalid source multiset')
    expected = {row['source']: row['sha256'] for row in manifest}
    if len(expected) != len(manifest) or len(sources) != len(expected):
        raise ValueError('invalid manifest or source count')
    seen = set()
    for row in sources:
        if (not isinstance(row, list) or len(row) != 2 or
                not all(isinstance(v, str) for v in row) or
                row[0] in seen or expected.get(row[0]) != row[1]):
            raise ValueError('source identities differ from manifest')
        seen.add(row[0])
    contents = []
    for name, digest in sources:
        data = paths[name].read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('source bytes differ from manifest')
        contents.append(data.decode('utf-8').splitlines())
    result = Counter()
    for row in candidates:
        if not isinstance(row, list) or len(row) != 7:
            raise ValueError('invalid source tuple')
        index, span, receiver, kind, prop, expression, count = row
        if type(index) is not int or not 0 <= index < len(sources):
            raise ValueError('invalid source index')
        if (not isinstance(span, list) or len(span) != 4 or
                any(type(n) is not int or n < 1 for n in span) or tuple(span[:2]) > tuple(span[2:])):
            raise ValueError('invalid source span')
        if (receiver not in ('bare', 'L.uci') or kind != 'dot' or
                not isinstance(prop, str) or not isinstance(expression, str) or
                type(count) is not int or count < 1):
            raise ValueError('unsupported source tuple')
        lines = contents[index]
        sl, sc, el, ec = span
        if sl > len(lines) or el > len(lines) or sc > len(lines[sl-1]) + 1 or ec > len(lines[el-1]):
            raise ValueError('source span outside file')
        selected = (lines[sl-1][sc-1:ec] if sl == el else
                    '\n'.join([lines[sl-1][sc-1:], *lines[sl:el-1], lines[el-1][:ec]]))
        if selected != expression or not prop:
            raise ValueError('source expression does not match span')
        key = (sources[index][0], *span, receiver, kind, True, prop)
        if key in result:
            raise ValueError('duplicate source tuple key')
        result[key] = count
    return result
