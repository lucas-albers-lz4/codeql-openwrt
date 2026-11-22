"""Validate this assessment's exact selected bytes and diagnostic identities."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def validate(manifest, stage, source, receipt, extracted, errors):
    if len(manifest) != 12:
        raise ValueError('expected 12 selected files')
    expected = {}
    for row in manifest:
        installed = row['installed']
        if not installed.startswith('/usr/share/ucode/luci/') or installed in expected:
            raise ValueError('invalid or duplicate installed identity')
        relative = Path(installed.lstrip('/'))
        if '..' in relative.parts or '..' in Path(row['source']).parts:
            raise ValueError('invalid source path')
        lexical = stage / relative
        target = lexical.resolve(strict=True)
        if not target.is_relative_to(stage.resolve()):
            raise ValueError('stage escape')
        src = (source / row['source']).resolve(strict=True)
        if not src.is_relative_to(source.resolve()):
            raise ValueError('source escape')
        src_bytes, dst_bytes = src.read_bytes(), target.read_bytes()
        if src_bytes != dst_bytes or hashlib.sha256(src_bytes).hexdigest() != row['sha256']:
            raise ValueError('source or staged bytes differ from manifest')
        expected[str(target)] = installed.lstrip('/')
    entries = list(stage.rglob('*'))
    if stage.is_symlink() or any(p.is_symlink() for p in entries):
        raise ValueError('symlink in stage')
    staged_files = {p.relative_to(stage).as_posix() for p in entries if p.is_file()}
    if staged_files != set(expected.values()):
        raise ValueError('stage has missing or unexpected files')
    if any(receipt.get(k) != v for k, v in {'input_count':12, 'plain_count':0,
           'markup_count':12, 'markup_inconclusive_count':12, 'uncertain_count':0,
           'excluded_count':0, 'duplicate_input_count':0}.items()):
        raise ValueError('routing counters differ')
    decisions = receipt['decisions']
    if len(decisions) != 12 or {d['path'] for d in decisions} != set(expected):
        raise ValueError('routing identities differ')
    for d in decisions:
        if (d['installed_path'] != expected[d['path']] or d['classification'] != 'markup'
            or d['status'] != 'inconclusive' or d['inconclusive_reason'] != 'markup_not_modeled'
            or d['reason'] != ('markup_tag_content' if d['installed_path'].endswith('/uhttpd.uc')
                               else 'ut_markup_extension')):
            raise ValueError('routing decision differs')
    def diagnostic_rows(data, columns):
        if not isinstance(data, dict) or set(data) != {'#select'}:
            raise ValueError('invalid diagnostic envelope')
        table = data['#select']
        if (not isinstance(table, dict) or set(table) != {'columns', 'tuples'}
                or table['columns'] != columns or not isinstance(table['tuples'], list)):
            raise ValueError('invalid diagnostic schema')
        return table['tuples']

    rows = diagnostic_rows(extracted, [{'name': 'f', 'kind': 'Entity'}, {'kind': 'String'}])
    error_rows = diagnostic_rows(errors, [{'name': 'error', 'kind': 'Entity'},
                                          {'kind': 'String'}, {'kind': 'Integer'}])
    wanted = [[{'label': path, 'url': {'uri': Path(path).as_uri(), 'startLine': 0,
                 'startColumn': 0, 'endLine': 0, 'endColumn': 0}}, ''] for path in expected]
    encode = lambda row: json.dumps(row, sort_keys=True, separators=(',', ':'))
    if Counter(map(encode, rows)) != Counter(map(encode, wanted)):
        raise ValueError('extracted tuples differ')
    if error_rows:
        raise ValueError('extraction errors present')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--receipt', type=Path, default=HERE / 'routing.json')
    p.add_argument('--extracted', type=Path, default=HERE / 'extracted.json')
    p.add_argument('--errors', type=Path, default=HERE / 'errors.json')
    args = p.parse_args()
    load = lambda path: json.loads(path.read_text())
    validate(load(HERE / 'manifest.json'), args.stage, args.source,
             load(args.receipt), load(args.extracted), load(args.errors))
    print('12 selected source and staged identities, receipt and diagnostics verified')


if __name__ == '__main__':
    main()
