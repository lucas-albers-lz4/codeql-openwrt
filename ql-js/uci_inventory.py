#!/usr/bin/env python3
"""Offline projection for a UCI query result; query execution is not yet authorized here.

The tentative query and literal contract require independent review and fixture
observation before an execution runner can be enabled.
"""
from collections import Counter
import json
import math
from uci_normalize import normalize, source_paths


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('nonfinite JSON number')


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('nonfinite JSON number')
    return number


def _parse(raw):
    if not isinstance(raw, bytes):
        raise ValueError('input must be JSON bytes')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_object,
                          parse_constant=_constant, parse_float=_float)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('invalid UTF-8 JSON') from exc


def project_details(raw, source, manifest):
    """Validate raw UTF-8 JSON decoded with CodeQL's planned --entities=id.

    Preserve public tuple multiplicity while requiring unique database-local IDs.
    This function does not execute CodeQL or authenticate the input.
    """
    document = _parse(raw)
    if not isinstance(document, dict) or set(document) != {'#select'}:
        raise ValueError('invalid result document')
    table = document['#select']
    if not isinstance(table, dict) or set(table) != {'columns', 'tuples'}:
        raise ValueError('invalid result table')
    columns = table['columns']
    if (not isinstance(columns, list) or len(columns) != 11 or
            any(not isinstance(col, dict) or col.get('kind') != ('Entity' if i == 0 else 'String')
                or set(col) - {'name', 'kind'} or ('name' in col and not isinstance(col['name'], str))
                for i, col in enumerate(columns))):
        raise ValueError('invalid result columns')
    rows = table['tuples']
    if not isinstance(rows, list):
        raise ValueError('invalid result rows')
    decoded = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 11:
            raise ValueError('invalid result row')
        entity = row[0]
        if not isinstance(entity, dict) or set(entity) != {'id'} or type(entity['id']) is not int:
            raise ValueError('invalid entity identity')
        decoded.append([str(entity['id']), *row[1:]])
    result = normalize(decoded, source, manifest)
    # normalize has validated every row and unique ID; build the mapping once.
    by_path = {str(path): name for name, path in source_paths(source, manifest).items()}
    identities = {}
    for identity, path, sl, sc, el, ec, receiver, kind, known, prop, _ in decoded:
        key = (by_path[path], int(sl), int(sc), int(el), int(ec), receiver, kind,
               known == 'true', prop)
        identities.setdefault(key, []).append(int(identity))
    return result, identities


def project(raw, source, manifest):
    return project_details(raw, source, manifest)[0]


def expected_rows(raw, source, manifest):
    """Parse explicit expected rows with a positive multiplicity per unique key."""
    document = _parse(raw)
    if not isinstance(document, dict) or set(document) != {'rows'} or not isinstance(document['rows'], list):
        raise ValueError('invalid expected document')
    paths = source_paths(source, manifest)
    decoded, counts = [], {}
    for row in document['rows']:
        if (not isinstance(row, list) or len(row) != 10 or
                not isinstance(row[0], str) or row[0] not in paths or
                any(type(n) is not int or n < 1 for n in row[1:5]) or
                type(row[7]) is not bool or type(row[9]) is not int or row[9] < 1):
            raise ValueError('invalid expected row')
        path, sl, sc, el, ec, receiver, kind, known, prop, count = row
        key = tuple(row[:9])
        try:
            if key in counts:
                raise ValueError('duplicate expected row')
            counts[key] = count
        except TypeError as exc:
            raise ValueError('invalid expected row') from exc
        decoded.append([str(len(decoded)), str(paths[path]), str(sl), str(sc), str(el), str(ec),
                        receiver, kind, 'true' if known else 'false', prop, 'candidate'])
    # Enforce the same classification, position and path checks as database rows.
    normalize(decoded, source, manifest)
    result = Counter(counts)
    return result


def compare(actual, expected):
    if not isinstance(actual, Counter) or not isinstance(expected, Counter):
        raise ValueError('expected multisets')
    if any(type(count) is not int or count <= 0
           for multiset in (actual, expected) for count in multiset.values()):
        raise ValueError('invalid multiset count')
    if actual != expected:
        raise ValueError('source and database candidate multisets differ')


def main(argv=None):
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description='Compare offline UCI candidate multisets')
    parser.add_argument('--result', required=True, type=Path)
    parser.add_argument('--expected', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = _parse(args.manifest.read_bytes())
        actual, identities = project_details(args.result.read_bytes(), args.source, manifest)
        expected = expected_rows(args.expected.read_bytes(), args.source, manifest)
        missing, extra = expected - actual, actual - expected
        def describe(counts):
            return [{'row': list(key), 'count': count,
                     'actual_ids': sorted(identities.get(key, []))}
                    for key, count in sorted(counts.items())]
        output = {'match': not missing and not extra,
                  'missing': describe(missing), 'extra': describe(extra)}
        print(json.dumps(output, ensure_ascii=True, sort_keys=True))
        return 0 if output['match'] else 1
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
