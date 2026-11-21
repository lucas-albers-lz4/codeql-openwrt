#!/usr/bin/env python3
"""Run real CodeQL negative controls against a successful gate's staged source."""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil

import extraction_gate as gate


def must_reject(expected, files, errors):
    try:
        gate.check_results(expected, files, errors)
    except ValueError as exc:
        return str(exc)
    raise RuntimeError('negative control unexpectedly accepted')


def check_default_minified_omission(expected, actual, minified):
    """Require the default extractor result to be exactly the manifest minus one file."""
    expected_paths = Counter(expected)
    if expected_paths[minified] != 1:
        raise ValueError('known minified path is not unique in expected selection')
    expected_paths.subtract([minified])
    expected_paths += Counter()  # Remove zero-count entries after the subtraction.
    if Counter(actual) != expected_paths:
        raise ValueError('default extraction paths differ beyond the known minified omission')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codeql', type=Path, required=True)
    parser.add_argument('--packs', type=Path, required=True)
    parser.add_argument('--gate-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    codeql, packs = str(args.codeql.resolve(strict=True)), args.packs.resolve(strict=True)
    original = args.gate_output.resolve(strict=True) / 'source'
    rows = json.loads((gate.HERE / 'manifest.json').read_text(encoding='utf-8'))
    gate.check_staged(original, rows)
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    default = out / 'default-minified'
    default.mkdir()
    files, errors = gate.codeql_results(codeql, packs, original, default, allow_minified=False)
    expected = [str(original / row['source']) for row in rows]
    reason = must_reject(expected, files, errors)
    minified = str(original / 'libs/luci-lib-uqr/htdocs/luci-static/resources/uqr.js')
    actual = [row[0] for row in gate.tuples(files, 1)]
    try:
        check_default_minified_omission(expected, actual, minified)
    except ValueError as exc:
        raise RuntimeError('default extraction did not demonstrate the expected minified omission') from exc
    print('default minified omission rejected:', reason)

    malformed = out / 'malformed'
    malformed.mkdir()
    source = malformed / 'source'
    source.mkdir()
    (source / 'good.js').write_text('const good = 1;\n', encoding='utf-8')
    (source / 'broken.js').write_text('const broken = ;\n', encoding='utf-8')
    files, errors = gate.codeql_results(codeql, packs, source, malformed)
    error_rows = gate.tuples(errors, 3)
    if not any(row[0] == 'broken.js' for row in error_rows):
        raise RuntimeError('real malformed source produced no broken.js parse error')
    print('malformed source rejected:', must_reject([str(source / 'broken.js'), str(source / 'good.js')], files, errors))

    identity = out / 'identity-source'
    shutil.copytree(original, identity)
    target = identity / rows[0]['source']
    target.write_bytes(target.read_bytes() + b'\n')
    try:
        gate.check_staged(identity, rows)
    except ValueError as exc:
        print('changed source bytes rejected:', exc)
    else:
        raise RuntimeError('modified bytes unexpectedly accepted')
    gate.check_staged(original, rows)
    print('All real negative controls rejected as intended.')


if __name__ == '__main__':
    main()
