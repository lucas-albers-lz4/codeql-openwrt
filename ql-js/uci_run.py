#!/usr/bin/env python3
"""Run a separately reviewed UCI corpus experiment in a fresh output directory.

Requires an explicit compatible cache-isolating CodeQL wrapper; no download or
wrapper selection occurs here. Verify and review the wrapper and commands first.
"""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import subprocess
import sys

import extraction_gate as gate
import uci_inventory
import uci_source_conversion

HERE = Path(__file__).resolve().parent
MANIFEST = '3161274241e086d121fd5122e0dfe0c5fb5d97872710d79c87f86244be2b2627'
LOCK = 'eb487627c92c867a5760b9c24405db13d028eff5582378a9c4ff252debe13925'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('evidence must be a regular non-symlink file')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_evidence(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('evidence must be a regular non-symlink file')
    return path.read_bytes()


def commands(wrapper, packs, source, out):
    """Exact vector proposal; wrapper must support each forwarded operation."""
    db = out / 'db'
    result = [[str(wrapper), 'database', 'create', str(db), '--language=javascript',
               f'--source-root={source}', '--threads=1', '--ram=2048']]
    for name, label in (('files', 'accept-files'), ('errors', 'accept-errors'),
                        ('files', 'check-files'), ('errors', 'check-errors'),
                        ('uci_surface', 'uci_surface')):
        result.append([str(wrapper), 'query', 'run', str(HERE / (name + '.ql')),
                       '--database', str(db), '--additional-packs=' + str(packs),
                       '--output', str(out / (label + '.bqrs')), '--threads=1', '--ram=2048'])
        result.append([str(wrapper), 'bqrs', 'decode', str(out / (label + '.bqrs')),
                       '--format=json', '--entities=' + ('id' if name == 'uci_surface' else 'url,string'),
                       '--output', str(out / (label + '.json'))])
    return result


def inputs(wrapper):
    paths = [wrapper, Path(__file__), HERE / 'manifest.json', HERE / 'codeql-pack.lock.yml',
             HERE / 'qlpack.yml', HERE / 'extraction_gate.py', HERE / 'uci_inventory.py',
             HERE / 'uci_normalize.py', HERE / 'uci_source_conversion.py',
             HERE / 'files.ql', HERE / 'errors.ql', HERE / 'uci_surface.ql',
             gate.ROOT / 'corpus/lock.json', gate.ROOT / 'corpus/luci_ssl_files.py']
    return {str(path): file_digest(path) for path in paths}


def check_gate(out, rows, prefix):
    source = out / 'source'
    gate.check_staged(source, rows)
    gate.check_results([str(source / row['source']) for row in rows],
                       uci_inventory._parse(read_evidence(out / (prefix + '-files.json'))),
                       uci_inventory._parse(read_evidence(out / (prefix + '-errors.json'))))
    gate.check_staged(source, rows)


def validate(out, rows, oracle_raw, expected):
    source = out / 'source'
    gate.check_staged(source, rows)
    raw = read_evidence(out / 'uci_surface.json')
    actual, ids = uci_inventory.project_details(raw, source, rows)
    fields = ('path', 'start_line', 'start_column', 'end_line', 'end_column',
              'receiver', 'kind', 'property_known', 'property')
    candidates = [dict(zip(fields, key), count=count, ids=sorted(ids[key]),
                       family='rpc_surface', assessment='candidate')
                  for key, count in sorted(actual.items())]
    (out / 'candidates.json').write_text(json.dumps(candidates, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    missing, extra = expected - actual, actual - expected
    if missing or extra:
        def describe(delta):
            return [{'row': list(key), 'count': count, 'actual_ids': sorted(ids.get(key, []))}
                    for key, count in sorted(delta.items())]
        (out / 'mismatch.json').write_text(json.dumps({'missing': describe(missing), 'extra': describe(extra)},
                                                      sort_keys=True, indent=2) + '\n', encoding='utf-8')
        raise ValueError('source and database candidate multisets differ; see mismatch.json')
    gate.check_staged(source, rows)
    return {'files': len(rows), 'candidate_entities': sum(actual.values()),
            'candidate_tuples': len(actual), 'identities': sum(map(len, ids.values())),
            'surface_sha256': digest(raw),
            'source_multiset_sha256': digest(oracle_raw),
            'scope': 'selected path set and JSParseError only; candidates are source sites'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('wrapper', 'wrapper-log', 'packs', 'luci-git', 'oracle', 'output', 'pins'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--pins-sha256', required=True)
    args = parser.parse_args(argv)
    wrapper, packs, git, oracle, pins = (getattr(args, name).resolve(strict=True)
                                         for name in ('wrapper', 'packs', 'luci_git', 'oracle', 'pins'))
    pins_raw = pins.read_bytes()
    if digest(pins_raw) != args.pins_sha256:
        raise ValueError('pin file digest mismatch')
    selected = uci_inventory._parse(pins_raw)
    if (not isinstance(selected, dict) or set(selected) != {'inputs', 'packs', 'resolutions'}
            or not all(isinstance(selected[k], dict) for k in selected)
            or set(selected['resolutions']) != {'files', 'errors', 'uci_surface'}):
        raise ValueError('invalid reviewed pins')
    out = args.output
    if out.name != 'output':
        raise ValueError('output must be the attempt output directory')
    if not out.is_absolute() or out.parent.resolve(strict=True) != out.parent:
        raise ValueError('output parent must be a physical absolute path')
    wrapper_log = args.wrapper_log
    if (wrapper_log != out.parent / 'wrapper.log' or wrapper_log.is_symlink()
            or not wrapper_log.is_file() or stat.S_IMODE(wrapper_log.stat().st_mode) != 0o600
            or wrapper_log.stat().st_size != 0):
        raise ValueError('wrapper log must be the initialized empty private attempt wrapper.log')
    log_stat = wrapper_log.stat()
    manifest_raw = (HERE / 'manifest.json').read_bytes()
    if digest(manifest_raw) != MANIFEST or digest((HERE / 'codeql-pack.lock.yml').read_bytes()) != LOCK:
        raise ValueError('manifest or pack lock mismatch')
    rows = gate.build_manifest(git)
    gate.check_manifest(uci_inventory._parse(manifest_raw), rows)
    if len(rows) != 88:
        raise ValueError('expected 88 files')
    oracle_raw = oracle.read_bytes()
    if digest(oracle_raw) != uci_source_conversion.MULTISET_SHA256:
        raise ValueError('source multiset mismatch')
    initial_inputs = inputs(wrapper)
    def verify_pins():
        if pins.read_bytes() != pins_raw or oracle.read_bytes() != oracle_raw or inputs(wrapper) != selected['inputs']:
            raise ValueError('reviewed input mismatch')
        pack_files = {}
        for path in sorted(packs.rglob('*')):
            if path.is_symlink():
                raise ValueError('symlink in pack inventory')
            if path.is_file():
                pack_files[str(path.relative_to(packs))] = file_digest(path)
        if not pack_files or pack_files != selected['packs']:
            raise ValueError('reviewed pack inventory mismatch')
    verify_pins()
    out.mkdir(exist_ok=False)
    source = out / 'source'
    source.mkdir()
    for row in rows:
        target = source / row['source']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(gate.run(['git', '-C', str(git), 'cat-file', 'blob', row['blob']]))
    gate.check_staged(source, rows)
    expected = uci_source_conversion.convert(oracle_raw, rows, source)
    gate.check_staged(source, rows)
    vectors = commands(wrapper, packs, source, out)
    env = dict(os.environ, CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES='true',
               CODEQL_ISOLATION_ATTEMPT=str(out.parent))
    with (out / 'commands.log').open('w', encoding='utf-8') as log:
        log.write('CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES=true\n')
        log.write('CODEQL_ISOLATION_ATTEMPT=' + str(out.parent) + '\n')
        preflight = [[str(wrapper), 'version']]
        preflight += [[str(wrapper), 'resolve', 'library-path', '--additional-packs=' + str(packs),
                       '--query=' + str(HERE / (name + '.ql'))] for name in ('files', 'errors', 'uci_surface')]
        for index, vector in enumerate(preflight):
            verify_pins()
            log.write(json.dumps(vector) + '\n')
            log.flush()
            response = subprocess.run(vector, env=env, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log.write('stdout:\n' + response.stdout.decode('utf-8', errors='backslashreplace'))
            log.write('\nstderr:\n' + response.stderr.decode('utf-8', errors='backslashreplace') + '\n')
            log.flush()
            if response.returncode:
                raise subprocess.CalledProcessError(response.returncode, vector)
            if index == 0 and f'toolchain release {gate.CLI_VERSION}.' not in response.stdout.decode('utf-8'):
                raise ValueError('wrong CodeQL version')
            if index and digest(response.stdout) != selected['resolutions'][('files', 'errors', 'uci_surface')[index - 1]]:
                raise ValueError('reviewed library resolution mismatch')
        for index, vector in enumerate(vectors):
            verify_pins()
            log.write(json.dumps(vector) + '\n')
            log.flush()
            subprocess.run(vector, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
            if index == 0:
                gate.check_staged(source, rows)
            if index == 4:
                check_gate(out, rows, 'accept')
            if index == 8:
                check_gate(out, rows, 'check')
    verify_pins()
    evidence = validate(out, rows, oracle_raw, expected)
    evidence['input_sha256'] = initial_inputs
    final_log_stat = wrapper_log.stat()
    if (wrapper_log.is_symlink() or not wrapper_log.is_file() or not final_log_stat.st_size
            or stat.S_IMODE(final_log_stat.st_mode) != 0o600
            or (log_stat.st_dev, log_stat.st_ino) != (final_log_stat.st_dev, final_log_stat.st_ino)):
        raise ValueError('wrapper log missing or not a regular file')
    (out / 'wrapper.log').write_bytes(read_evidence(wrapper_log))
    (out / 'reviewed-pins.json').write_bytes(pins_raw)
    names = ['commands.log', 'wrapper.log', 'reviewed-pins.json', 'candidates.json']
    names += [label + suffix for label in ('accept-files', 'accept-errors', 'check-files', 'check-errors', 'uci_surface')
              for suffix in ('.bqrs', '.json')]
    inventory = {name: file_digest(out / name) for name in sorted(names)}
    evidence['output_sha256'] = inventory
    evidence['reviewed_pins_sha256'] = digest(pins_raw)
    verify_pins()
    temporary = out / 'ACCEPTED.json.tmp'
    temporary.write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, out / 'ACCEPTED.json')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print('REJECTED: ' + str(exc), file=sys.stderr)
        sys.exit(1)
