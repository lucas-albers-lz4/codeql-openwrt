#!/usr/bin/env python3
"""Inventory bounded CGI URL-construction syntax in an accepted JS database."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import extraction_gate as gate
from rpc_inventory import check_receipt

HERE = Path(__file__).resolve().parent


def normalize_sites(document, source, manifest):
    by_path = {str(source / row['source']): row for row in manifest}
    columns = [{'kind': 'String'}] * 5 + [{'name': 'kind', 'kind': 'String'}, {'name': 'endpoint', 'kind': 'String'}, {'kind': 'String'}]
    if not isinstance(document, dict) or set(document) != {'#select'}:
        raise ValueError('invalid site result')
    table = document['#select']
    if not isinstance(table, dict) or set(table) != {'columns', 'tuples'} or table['columns'] != columns or not isinstance(table['tuples'], list):
        raise ValueError('invalid site result table')
    sites, seen = [], set()
    for row in table['tuples']:
        if not isinstance(row, list) or len(row) != 8 or any(not isinstance(v, str) for v in row):
            raise ValueError('invalid site result row')
        path, sl, sc, el, ec, kind, endpoint, assessment = row
        if path not in by_path:
            if Path(path).is_relative_to(source):
                raise ValueError('unexpected selected-root path: ' + path)
            continue
        if kind not in ('base-plus-string', 'template-base-and-suffix') or not re.fullmatch(r'/cgi-[A-Za-z0-9_-]+', endpoint) or assessment != 'candidate':
            raise ValueError('invalid site classification')
        if any(not v.isascii() or not v.isdecimal() or int(v) < 1 or str(int(v)) != v for v in (sl, sc, el, ec)):
            raise ValueError('invalid site location')
        coords = tuple(map(int, (sl, sc, el, ec)))
        if coords[:2] > coords[2:]:
            raise ValueError('reversed site location')
        entry = by_path[path]
        key = (entry['source'], *coords, kind, endpoint)
        if key in seen:
            raise ValueError('duplicate site')
        seen.add(key)
        sites.append({'source': entry['source'], 'installed': entry['installed'], 'start_line': coords[0], 'start_column': coords[1], 'end_line': coords[2], 'end_column': coords[3], 'kind': kind, 'endpoint': endpoint, 'type': 'rpc_surface', 'assessment': assessment})
    return sorted(sites, key=lambda x: (x['source'], x['start_line'], x['start_column'], x['end_line'], x['end_column'], x['kind'], x['endpoint']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('luci-git', 'codeql', 'packs', 'gate-output', 'output', 'common-caches'):
        parser.add_argument('--' + name, type=Path, required=True)
    a = parser.parse_args()
    codeql, packs = str(a.codeql.resolve(strict=True)), a.packs.resolve(strict=True)
    accepted = a.gate_output.resolve(strict=True)
    source = (accepted / 'source').resolve(strict=True)
    check_receipt(json.loads((accepted / 'ACCEPTED.json').read_text()))
    rows = gate.build_manifest(a.luci_git.resolve(strict=True))
    gate.check_manifest(json.loads((HERE / 'manifest.json').read_text()), rows)
    if len(rows) != 88:
        raise ValueError('unexpected selected file count')
    if f'toolchain release {gate.CLI_VERSION}.' not in gate.run([codeql, 'version']).decode():
        raise ValueError('wrong CodeQL CLI version')
    resolution = json.loads(gate.run([codeql, 'resolve', 'packs', '--format=json', '--additional-packs=' + str(packs), '--common-caches=' + str(a.common_caches)]))
    if resolution['steps'][0]['scans'][0]['found']['codeql/javascript-all']['version'] != '3.0.0':
        raise ValueError('wrong JavaScript pack version')
    gate.check_staged(source, rows)
    out = a.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    with (out / 'commands.log').open('w') as log:
        for name in ('files', 'errors', 'cgi_surface'):
            bqrs, decoded = out / (name + '.bqrs'), out / (name + '.json')
            commands = [[codeql, 'query', 'run', str(HERE / (name + '.ql')), '--database', str(accepted / 'db'), '--additional-packs=' + str(packs), '--output', str(bqrs), '--threads=1', '--ram=2048', '--no-default-compilation-cache', '--compilation-cache=' + str(out / 'compile-cache'), '--common-caches=' + str(a.common_caches)], [codeql, 'bqrs', 'decode', str(bqrs), '--format=json', '--entities=url,string', '--output', str(decoded), '--common-caches=' + str(a.common_caches)]]
            for cmd in commands:
                log.write(json.dumps(cmd) + '\n')
                log.flush()
                subprocess.run(cmd, check=True, stdout=log, stderr=subprocess.STDOUT)
    gate.check_staged(source, rows)
    gate.check_results([str(source / row['source']) for row in rows], json.loads((out / 'files.json').read_text()), json.loads((out / 'errors.json').read_text()))
    sites = normalize_sites(json.loads((out / 'cgi_surface.json').read_text()), source, rows)
    report = {'luci_pin': gate.PIN, 'family': 'CGI URL construction syntax', 'file_count': len(rows), 'sites': sites}
    (out / 'inventory.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(f'Inventoried {len(sites)} candidate sites in {len(rows)} accepted files: {out}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f'REJECTED: {exc}', file=sys.stderr)
        sys.exit(1)
