#!/usr/bin/env python3
"""Inventory syntactic fs property accesses in an accepted JS database."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

import extraction_gate as gate
import rpc_inventory

HERE = Path(__file__).resolve().parent


def normalize_sites(document, source, manifest):
    by_path = {str(source / row['source']): row for row in manifest}
    columns = [{'kind': 'String'}] * 5 + [{'name': 'kind', 'kind': 'String'},
                                              {'name': 'property', 'kind': 'String'},
                                              {'kind': 'String'}]
    if not isinstance(document, dict) or set(document) != {'#select'}:
        raise ValueError('invalid site result')
    table = document['#select']
    if not isinstance(table, dict) or set(table) != {'columns', 'tuples'} or table['columns'] != columns:
        raise ValueError('invalid site result columns')
    raw = table['tuples']
    if not isinstance(raw, list) or any(not isinstance(row, list) or len(row) != 8 or
                                       any(not isinstance(value, str) for value in row) for row in raw):
        raise ValueError('invalid site result rows')
    sites, seen = [], set()
    for path, sl, sc, el, ec, kind, prop, assessment in raw:
        if path not in by_path:
            if Path(path).is_relative_to(source):
                raise ValueError('unexpected selected-root path: ' + path)
            continue
        if (kind not in ('dot', 'literal-index', 'computed-index') or assessment != 'candidate' or
                (kind == 'computed-index' and prop != '<unknown>')):
            raise ValueError('invalid site classification')
        if any(not v.isascii() or not v.isdecimal() or int(v) < 1 or str(int(v)) != v for v in (sl, sc, el, ec)):
            raise ValueError('invalid site location')
        coords = tuple(map(int, (sl, sc, el, ec)))
        if coords[:2] > coords[2:]:
            raise ValueError('reversed site location')
        entry = by_path[path]
        key = (entry['source'], *coords)
        if key in seen:
            raise ValueError('duplicate site')
        seen.add(key)
        sites.append({'source': entry['source'], 'installed': entry['installed'],
                      'start_line': coords[0], 'start_column': coords[1],
                      'end_line': coords[2], 'end_column': coords[3], 'kind': kind,
                      'property': prop, 'type': 'rpc_surface', 'assessment': assessment})
    return sorted(sites, key=lambda x: (x['source'], x['start_line'], x['start_column'],
                                        x['end_line'], x['end_column'], x['kind']))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--luci-git', type=Path, required=True)
    p.add_argument('--codeql', type=Path, required=True)
    p.add_argument('--packs', type=Path, required=True)
    p.add_argument('--gate-output', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    codeql = str(a.codeql.resolve(strict=True))
    packs = a.packs.resolve(strict=True)
    accepted = a.gate_output.resolve(strict=True)
    source = accepted / 'source'
    rpc_inventory.check_receipt(json.loads((accepted / 'ACCEPTED.json').read_text()))
    rows = gate.build_manifest(a.luci_git.resolve(strict=True))
    gate.check_manifest(json.loads((HERE / 'manifest.json').read_text()), rows)
    if len(rows) != 88:
        raise ValueError('unexpected selected file count')
    version = gate.run([codeql, 'version']).decode()
    if f'toolchain release {gate.CLI_VERSION}.' not in version:
        raise ValueError('wrong CodeQL CLI version')
    resolution = json.loads(gate.run([codeql, 'resolve', 'packs', '--format=json', '--additional-packs=' + str(packs)]))
    if resolution['steps'][0]['scans'][0]['found']['codeql/javascript-all']['version'] != '3.0.0':
        raise ValueError('wrong JavaScript pack version')
    gate.check_staged(source, rows)
    out = a.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    with (out / 'commands.log').open('w', encoding='utf-8') as log:
        for name in ('files', 'errors', 'fs_surface'):
            bqrs, decoded = out / (name + '.bqrs'), out / (name + '.json')
            commands = [[codeql, 'query', 'run', str(HERE / (name + '.ql')), '--database', str(accepted / 'db'),
                         '--additional-packs=' + str(packs), '--output', str(bqrs), '--threads=2', '--ram=3072'],
                        [codeql, 'bqrs', 'decode', str(bqrs), '--format=json', '--entities=url,string', '--output', str(decoded)]]
            for cmd in commands:
                log.write(json.dumps(cmd) + '\n')
                log.flush()
                subprocess.run(cmd, check=True, stdout=log, stderr=subprocess.STDOUT)
    gate.check_staged(source, rows)
    gate.check_results([str(source / row['source']) for row in rows],
                       json.loads((out / 'files.json').read_text()), json.loads((out / 'errors.json').read_text()))
    sites = normalize_sites(json.loads((out / 'fs_surface.json').read_text()), source, rows)
    report = {'luci_pin': gate.PIN, 'family': 'fs syntactic property access', 'file_count': len(rows), 'sites': sites}
    (out / 'inventory.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Inventoried {len(sites)} candidate sites in {len(rows)} accepted files: {out}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f'REJECTED: {exc}', file=sys.stderr)
        sys.exit(1)
