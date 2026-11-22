"""Validate this assessment's exact selected bytes and diagnostic identities."""
import argparse
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
        target = (stage / relative).resolve(strict=True)
        if not target.is_relative_to(stage.resolve()):
            raise ValueError('stage escape')
        src = (source / row['source']).resolve(strict=True)
        if not src.is_relative_to(source.resolve()):
            raise ValueError('source escape')
        src_bytes, dst_bytes = src.read_bytes(), target.read_bytes()
        if src_bytes != dst_bytes or hashlib.sha256(src_bytes).hexdigest() != row['sha256']:
            raise ValueError('source or staged bytes differ from manifest')
        expected[str(target)] = installed.lstrip('/')
    staged_files = {str(p.resolve()) for p in stage.rglob('*') if p.is_file()}
    if staged_files != set(expected):
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
            or d['status'] != 'inconclusive' or d['inconclusive_reason'] != 'markup_not_modeled'):
            raise ValueError('routing decision differs')
    rows = extracted['#select']['tuples']
    if len(rows) != 12 or {r[0]['label'] for r in rows} != set(expected):
        raise ValueError('extracted identities differ')
    for row in rows:
        if row[0]['url']['uri'] != Path(row[0]['label']).as_uri():
            raise ValueError('extracted URL differs')
    if errors['#select']['tuples'] != []:
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
