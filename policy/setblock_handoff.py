"""Bounded offline checks; they cannot establish execution or freshness."""
import csv
import io
import hashlib
import json
import re
from collections import Counter


class HandoffError(ValueError):
    """A named handoff contract failure."""
    def __init__(self, code, detail=''):
        self.code = code
        super().__init__(f'{code}: {detail}')


CONSUMER_REQUIRED = frozenset({
    'policy/setblock_table.py', 'policy/setblock_handoff.py', 'policy/oracle.py',
    'policy/interchange_contract.py', 'policy/__init__.py', 'corpus/lock.json',
    'policy/grants.json', 'policy/policy_decisions.json', 'schemas/finding.schema.json',
    'corpus/profiles/luci-ssl-25.12/profile.json',
    'corpus/profiles/luci-ssl-25.12/expected-capabilities.json',
})
PRODUCER_REQUIRED = frozenset({
    'ql/src/m4/SetBlockDetectEffectTable.ql', 'ql/src/diagnostics/ExtractionErrors.ql',
    'ql/src/diagnostics/SuccessfullyExtractedFiles.ql', 'ql/src/qlpack.yml',
    'ql/src/codeql-pack.lock.yml', 'ql/lib/qlpack.yml', 'ql/lib/codeql-pack.lock.yml',
    '.codeqlmanifest.json', 'Cargo.lock', 'scripts/create-extractor-pack.sh',
    'extractor-pack/tools/linux64/extractor',
})


def validate_context(expected, actual, consumer_files, producer_files, oracle_bytes):
    """Compare independently reviewed context to claimed context and actual bytes.

    Caller must independently obtain complete file maps and trusted commit/status
    observations. A claimed clean flag or digest is not execution attestation.
    """
    if (not isinstance(expected, dict) or not isinstance(actual, dict)
            or not _json_equal(expected, actual)):
        raise HandoffError('expected_context_mismatch', 'context differs')
    if (expected.get('version') != 'setblock-handoff-context-v1'
            or expected.get('clean') is not True
            or any(not isinstance(expected.get(k), str)
                   or not re.fullmatch('[0-9a-f]{40}', expected[k])
                   for k in ('producer_commit', 'consumer_commit'))):
        raise HandoffError('expected_context_mismatch', 'unsupported or unclean context')
    if hashlib.sha256(oracle_bytes).hexdigest() != expected.get('oracle_sha256'):
        raise HandoffError('expected_context_mismatch', 'oracle bytes')
    for key, files in (('consumer_files', consumer_files), ('producer_files', producer_files)):
        pinned = expected.get(key)
        if not isinstance(pinned, dict) or not pinned or not isinstance(files, dict):
            raise HandoffError('expected_context_mismatch', key)
        if key == 'consumer_files' and not CONSUMER_REQUIRED <= pinned.keys():
            raise HandoffError('expected_context_mismatch', 'missing consumer input')
        if key == 'producer_files' and (not PRODUCER_REQUIRED <= pinned.keys()
                                        or not any(p.startswith('ql/lib/') and p.endswith('.qll') for p in pinned)
                                        or not any(p.startswith('resolved-packs/') for p in pinned)):
            raise HandoffError('expected_context_mismatch', 'missing producer inputs')
        if set(files) != set(pinned):
            raise HandoffError('expected_context_mismatch', key + ' path set')
        for path, content in files.items():
            if not isinstance(path, str) or not isinstance(content, bytes):
                raise HandoffError('expected_context_mismatch', key + ' types')
            if hashlib.sha256(content).hexdigest() != pinned[path]:
                raise HandoffError('policy_context_mismatch' if path.startswith(('policy/', 'corpus/'))
                                   else 'execution_code_mismatch', path)


def validate_csv_scope(csv_bytes, oracle, advertised):
    if oracle.get('version') != 'setblock-handoff-oracle-v1':
        raise HandoffError('expected_context_mismatch', 'unknown oracle')
    try:
        rows = list(csv.reader(io.StringIO(csv_bytes.decode('utf-8'), newline=''), strict=True))
        if not rows or rows[0] != oracle['header']:
            raise HandoffError('scoped_observation_mismatch', 'header')
        actual = rows[1:]
        a = Counter(map(tuple, actual))
        b = Counter(map(tuple, advertised))
        expected = Counter(map(tuple, oracle['rows']))
    except (UnicodeError, csv.Error, TypeError, KeyError) as exc:
        raise HandoffError('scoped_observation_mismatch', str(exc)) from exc
    if a != b:
        raise HandoffError('delivery_mismatch')
    if any(count > 1 for count in a.values()):
        raise HandoffError('duplicate_observation')
    if not actual:
        raise HandoffError('scoped_observation_missing')
    if a != expected:
        raise HandoffError('scoped_observation_mismatch')
    return actual


def _json_bytes(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise HandoffError('invalid_artifact', 'duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, TypeError) as exc:
        raise HandoffError('invalid_artifact', str(exc)) from exc


def _json_equal(left, right):
    """Compare decoded JSON recursively without Python's numeric type coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    return left == right


def validate_inputs(at_handoff, after_reimport, oracle, advertised):
    """Check caller-captured immutable input bytes and bounded source table."""
    if (not isinstance(at_handoff, dict) or not isinstance(after_reimport, dict)
            or not {'source', 'csv'} <= at_handoff.keys()
            or set(at_handoff) != set(after_reimport)
            or any(not isinstance(value, bytes) for value in at_handoff.values())
            or at_handoff != after_reimport):
        raise HandoffError('handoff_input_mismatch', 'input bytes or path set changed')
    if hashlib.sha256(at_handoff['source']).hexdigest() != oracle['source_sha256']:
        raise HandoffError('handoff_input_mismatch', 'source pin')
    return validate_csv_scope(at_handoff['csv'], oracle, advertised)


def validate_retained(before, after, reimport, repo_root, oracle):
    """Validate paired artifacts and policy; caller must seal repo_root inputs.

    This is only the retained-state part of the check. Validate the fresh CSV
    and trusted context separately, before treating this result as meaningful.
    """
    from . import interchange_contract as schema_check
    from . import setblock_table as adapter

    paths = oracle['artifacts']
    if len(paths) != 2 or any(set(state) != set(paths) for state in (before, after, reimport)):
        raise HandoffError('missing_artifact', 'expected both retained paths in all states')
    lock_bytes = (repo_root / 'corpus/lock.json').read_bytes()
    lock = _json_bytes(lock_bytes)
    if lock.get('repos', {}).get('luci', {}).get('sha') != oracle['source_revision']:
        raise HandoffError('policy_context_mismatch', 'source revision')
    revision = 'sha256:' + hashlib.sha256(lock_bytes).hexdigest()
    schema = _json_bytes((repo_root / 'schemas/finding.schema.json').read_bytes())
    schema_check._check_schema_keywords(schema)
    grants = _json_bytes((repo_root / 'policy/grants.json').read_bytes())
    decisions = _json_bytes((repo_root / 'policy/policy_decisions.json').read_bytes())
    for expected_grant in oracle['grants']:
        matching = [g for g in grants if g.get('record_id') == expected_grant['record_id']]
        if len(matching) != 1 or any(matching[0].get(k) != v for k, v in expected_grant.items()):
            raise HandoffError('assessment_binding_mismatch', 'oracle grant')
    if sum(d.get('record_id') == oracle['deny_id'] for d in decisions['decisions']) != 1:
        raise HandoffError('assessment_binding_mismatch', 'oracle deny')
    old_states = []
    ident = oracle['effect']['record_id']
    for path in paths:
        old = _json_bytes(before[path])
        if not isinstance(old, list) or not all(isinstance(r, dict) for r in old):
            raise HandoffError('invalid_artifact', path)

        old_matches = [r for r in old if r.get('record_id') == ident]
        if len(old_matches) != 1:
            raise HandoffError('retained_target_missing', path)
        old_states.append(old)
    try:
        row = dict(zip(oracle['header'], oracle['rows'][0]))
        expected_states = adapter.prepare_updates(old_states[0], old_states[1], row, repo_root)
    except adapter.PrestateMismatch as exc:
        raise HandoffError('retained_prestate_mismatch', str(exc)) from exc
    except adapter.EffectIdentityCollision as exc:
        raise HandoffError('effect_identity_collision', str(exc)) from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise HandoffError('assessment_binding_mismatch', str(exc)) from exc
    targets = []
    for path, old, expected_state in zip(paths, old_states, expected_states):
        if after[path] != reimport[path]:
            raise HandoffError('unexpected_mutation', 'reimport is not byte-idempotent')
        new = _json_bytes(after[path])
        if not isinstance(new, list) or not all(isinstance(r, dict) for r in new):
            raise HandoffError('invalid_artifact', path)
        matches = [r for r in new if r.get('record_id') == ident]
        if len(matches) != 1:
            raise HandoffError('retained_target_missing', path)
        if not _json_equal([r for r in old if r.get('record_id') != ident],
                           [r for r in new if r.get('record_id') != ident]):
            raise HandoffError('unexpected_mutation', path)
        effect = matches[0]
        expected_effect = dict(oracle['effect'], corpus_revision=revision)
        if not _json_equal(effect, expected_effect):
            raise HandoffError('assessment_binding_mismatch', path)
        errors = schema_check._validate(effect, schema, path)
        if errors:
            raise HandoffError('invalid_artifact', '; '.join(errors))
        if not _json_equal(new, expected_state):
            raise HandoffError('unexpected_mutation', 'adapter transition: ' + path)
        targets.append(effect)
    if not _json_equal(targets[0], targets[1]):
        raise HandoffError('retained_target_mismatch')
    return targets[0]


# Offline receipt graph. Receipt declarations are consistency checks, not attestation.
STAGES = {
    'init': (('source',), ()),
    'index': (('source',), ()),
    'finalize': ((), ()),
    'effects_query': ((), ('effects_bqrs',)),
    'extracted_query': ((), ('extracted_bqrs',)),
    'errors_query': ((), ('errors_bqrs',)),
    'effects_decode': (('effects_bqrs',), ('csv',)),
    'extracted_decode': (('extracted_bqrs',), ('extracted_csv',)),
    'errors_decode': (('errors_bqrs',), ('errors_csv',)),
    'adapter': (('csv', 'source', 'before_0', 'before_1', 'consumer_at_handoff'),
                ('after_0', 'after_1', 'consumer_after_import')),
    'reimport': (('csv_after', 'source_after', 'after_0', 'after_1', 'consumer_after_import'),
                 ('reimport_0', 'reimport_1', 'consumer_after_reimport')),
}


def _safe_bytes(root, name):
    from pathlib import Path
    p = Path(name) if isinstance(name, str) else Path('/')
    if p.is_absolute() or not p.parts or any(x in ('.', '..') for x in p.parts):
        raise HandoffError('invalid_artifact', 'unsafe path')
    current = root
    try:
        for part in p.parts:
            current = current / part
            if current.is_symlink():
                raise HandoffError('invalid_artifact', 'symlink: ' + name)
        return current.read_bytes()
    except OSError as exc:
        raise HandoffError('missing_artifact', name) from exc


def _inventory(root, pinned, kind):
    from pathlib import Path
    if not isinstance(pinned, dict):
        raise HandoffError('expected_context_mismatch', kind)
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise HandoffError('expected_context_mismatch', kind + ' root')
    if kind == 'consumer':
        discovered = {p.relative_to(root).as_posix() for p in (root / 'policy').glob('*.py')}
        expected_discovered = {p for p in pinned if p.startswith('policy/')
                               and p.count('/') == 1 and p.endswith('.py')}
    else:
        prefixes = ('ql/lib/', 'ql/src/', 'extractor-pack/', 'resolved-packs/')
        discovered = {p.relative_to(root).as_posix() for prefix in prefixes
                      for p in (root / prefix).rglob('*') if not p.is_dir() or p.is_symlink()}
        expected_discovered = {p for p in pinned if p.startswith(prefixes)}
    if discovered != expected_discovered:
        raise HandoffError('expected_context_mismatch', kind + ' discovered path set')
    return {name: _safe_bytes(root, name) for name in pinned}


def _diagnostics(extracted, errors, source_root, source_path):
    from pathlib import PurePosixPath
    try:
        extracted_rows = list(csv.reader(io.StringIO(extracted.decode('utf-8'), newline=''), strict=True))
        error_rows = list(csv.reader(io.StringIO(errors.decode('utf-8'), newline=''), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise HandoffError('execution_inconclusive', 'malformed diagnostics') from exc
    if (not isinstance(source_root, str) or not source_root.startswith('/')
            or not isinstance(source_path, str) or source_path.startswith('/')
            or str(PurePosixPath(source_root)) != (source_root.rstrip('/') or '/')
            or str(PurePosixPath(source_path)) != source_path
            or '..' in PurePosixPath(source_root).parts
            or '..' in PurePosixPath(source_path).parts):
        raise HandoffError('execution_inconclusive', 'invalid diagnostic source path')
    expected_file = source_root.rstrip('/') + '/' + source_path
    if (extracted_rows != [['f', 'col1'], [expected_file, '']]
            or error_rows != [['error', 'col1', 'col2']]):
        raise HandoffError('execution_inconclusive', 'extraction diagnostics')


def _check_commands(context, oracle):
    from pathlib import PurePosixPath
    codeql = context.get('codeql')
    database = context.get('database')
    run_root = context.get('producer_run_root')
    paths = context.get('bqrs_paths')
    source = context.get('handoff_source_root')
    if (not all(isinstance(p, str) and p.startswith('/') for p in (codeql, database, run_root, source))
            or not isinstance(paths, dict) or set(paths) != {'effects', 'extracted', 'errors'}
            or any(not isinstance(p, str) or not p.startswith('/') for p in paths.values())
            or len(set(paths.values())) != 3):
        raise HandoffError('expected_context_mismatch', 'CodeQL paths')
    commands = context['commands']
    for stage, subcommand in (('init', 'init'), ('index', 'index-files'), ('finalize', 'finalize')):
        args = commands[stage]['argv']
        if args[:3] != [codeql, 'database', subcommand] or database not in args:
            raise HandoffError('execution_inconclusive', stage + ' command')
    if ('--source-root=' + source not in commands['init']['argv']
            or '--working-dir=' + source not in commands['index']['argv']
            or any('--language=ucode' not in commands[stage]['argv'] for stage in ('init', 'index'))):
        raise HandoffError('handoff_input_mismatch', 'database source root or language')
    queries = {'effects': oracle['query_path'],
               'extracted': 'ql/src/diagnostics/SuccessfullyExtractedFiles.ql',
               'errors': 'ql/src/diagnostics/ExtractionErrors.ql'}
    for name, query in queries.items():
        argv = commands[name + '_query']['argv']
        if (argv[:3] != [codeql, 'query', 'run']
                or str(PurePosixPath(run_root) / query) not in argv
                or '--database=' + database not in argv
                or '--output=' + paths[name] not in argv):
            raise HandoffError('execution_inconclusive', name + ' query command')
        argv = commands[name + '_decode']['argv']
        if (argv[:3] != [codeql, 'bqrs', 'decode'] or '--format=csv' not in argv
                or paths[name] not in argv):
            raise HandoffError('execution_inconclusive', name + ' decode command')


def validate_bundle(bundle_dir, *, expected_context, oracle_bytes, consumer_root, producer_root):
    """Check retained offline consistency only; this does not prove a live run.

    Expected context and oracle are independently supplied by the caller.
    Receipts and hashes are declarations; an observed trusted runner is required
    to establish execution, isolation, input read boundaries and freshness.
    """
    from pathlib import Path
    bundle_dir, consumer_root, producer_root = map(Path, (bundle_dir, consumer_root, producer_root))
    if bundle_dir.is_symlink() or not bundle_dir.is_dir():
        raise HandoffError('missing_artifact', 'bundle directory')
    manifest = _json_bytes(_safe_bytes(bundle_dir, 'manifest.json'))
    if not isinstance(manifest, dict) or manifest.get('version') != 'setblock-handoff-bundle-v1':
        raise HandoffError('expected_context_mismatch', 'bundle version')
    if manifest.get('run_kind') not in ('offline_fixture', 'historical', 'live'):
        raise HandoffError('execution_inconclusive', 'run kind')
    if manifest.get('coverage') != 'partial' or set(manifest) != {
        'version', 'run_kind', 'context', 'coverage', 'advertised', 'receipts'
    }:
        raise HandoffError('claim_strengthening', 'unsupported claim or coverage')
    if not isinstance(expected_context, dict):
        raise HandoffError('expected_context_mismatch', 'context')
    consumer = _inventory(consumer_root, expected_context.get('consumer_files'), 'consumer')
    producer = _inventory(producer_root, expected_context.get('producer_files'), 'producer')
    validate_context(expected_context, manifest.get('context'), consumer, producer, oracle_bytes)
    # Pin the modules doing the checks, not merely unrelated files in the root.
    import sys
    from . import interchange_contract, oracle as policy_oracle, setblock_table
    for name, module_file in (('policy/setblock_handoff.py', __file__),
                              ('policy/__init__.py', getattr(sys.modules.get(__package__ or ''), '__file__', None)),
                              ('policy/interchange_contract.py', interchange_contract.__file__),
                              ('policy/oracle.py', policy_oracle.__file__),
                              ('policy/setblock_table.py', setblock_table.__file__)):
        try:
            if not isinstance(module_file, str):
                raise HandoffError('execution_code_mismatch', name)
            executed = Path(module_file).read_bytes()
        except (OSError, TypeError) as exc:
            raise HandoffError('execution_code_mismatch', name) from exc
        if executed != consumer[name]:
            raise HandoffError('execution_code_mismatch', name)
    oracle = _json_bytes(oracle_bytes)
    if not isinstance(oracle, dict):
        raise HandoffError('expected_context_mismatch', 'oracle')
    roles = {r for ins, outs in STAGES.values() for r in ins + outs}
    roles.update(stage + suffix for stage in STAGES for suffix in ('_stdout', '_stderr'))
    data = {role: _safe_bytes(bundle_dir, role) for role in roles}
    receipts = manifest.get('receipts')
    commands = expected_context.get('commands')
    if not isinstance(receipts, dict) or set(receipts) != set(STAGES) or not isinstance(commands, dict) or set(commands) != set(STAGES):
        raise HandoffError('execution_inconclusive', 'required receipts')
    for stage, (ins, outs) in STAGES.items():
        receipt, command = receipts[stage], commands[stage]
        if not isinstance(receipt, dict) or not isinstance(command, dict):
            raise HandoffError('execution_inconclusive', stage)
        if (not isinstance(command.get('argv'), list) or not command['argv']
                or any(not isinstance(a, str) or not a for a in command['argv'])
                or not isinstance(command.get('cwd'), str) or not command['cwd']):
            raise HandoffError('expected_context_mismatch', stage + ' command')
        if receipt.get('argv') != command['argv'] or receipt.get('cwd') != command['cwd']:
            raise HandoffError('handoff_input_mismatch', stage + ' command')
        if type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0:
            raise HandoffError('execution_inconclusive', stage + ' exit')
        for field, names in (('inputs', ins), ('outputs', outs)):
            if receipt.get(field) != {r: hashlib.sha256(data[r]).hexdigest() for r in names}:
                raise HandoffError('artifact_digest_mismatch', stage + ' ' + field)
        for field in ('stdout', 'stderr'):
            if receipt.get(field) != hashlib.sha256(data[stage + '_' + field]).hexdigest():
                raise HandoffError('artifact_digest_mismatch', stage + ' ' + field)
    _check_commands(expected_context, oracle)
    for stage, role in (('effects_decode', 'csv'), ('extracted_decode', 'extracted_csv'),
                        ('errors_decode', 'errors_csv')):
        if data[stage + '_stdout'] != data[role]:
            raise HandoffError('handoff_input_mismatch', stage + ' stdout')
    for stage in ('adapter', 'reimport'):
        argv = commands[stage]['argv']
        csv_path, source_root = expected_context.get('handoff_csv'), expected_context.get('handoff_source_root')
        python = expected_context.get('python')
        if (not isinstance(csv_path, str) or not csv_path.startswith('/') or not isinstance(source_root, str)
                or not source_root.startswith('/') or not isinstance(python, str) or not python.startswith('/')
                or argv[:4] != [python, '-B', '-m', 'policy.setblock_table']
                or len(argv) != 8 or argv.count('--csv') != 1 or argv.count('--source-root') != 1
                or argv.index('--csv') + 1 >= len(argv) or argv[argv.index('--csv') + 1] != csv_path
                or argv.index('--source-root') + 1 >= len(argv) or argv[argv.index('--source-root') + 1] != source_root
                or argv.count('policy.setblock_table') != 1 or '-m' not in argv):
            raise HandoffError('handoff_input_mismatch', stage + ' sealed paths')
    for role in ('consumer_at_handoff', 'consumer_after_import', 'consumer_after_reimport'):
        if _json_bytes(data[role]) != expected_context['consumer_files']:
            raise HandoffError('policy_context_mismatch', role)
    _diagnostics(data['extracted_csv'], data['errors_csv'],
                 expected_context['handoff_source_root'], oracle['source_path'])
    validate_inputs({'source': data['source'], 'csv': data['csv']},
                    {'source': data['source_after'], 'csv': data['csv_after']},
                    oracle, manifest.get('advertised'))
    states = [{p: data[f'{phase}_{i}'] for i, p in enumerate(oracle['artifacts'])}
              for phase in ('before', 'after', 'reimport')]
    target = validate_retained(*states, consumer_root, oracle)
    if consumer != _inventory(consumer_root, expected_context['consumer_files'], 'consumer') or producer != _inventory(producer_root, expected_context['producer_files'], 'producer'):
        raise HandoffError('unexpected_mutation', 'context inputs changed during validation')
    return {'status': 'consistent_offline', 'coverage': 'partial', 'run_kind': manifest['run_kind'],
            'observation_count': len(oracle['rows']), 'retained_id': target['record_id'],
            'execution_verified': False, 'freshness_verified': False}


def main(argv=None):
    import argparse
    import sys
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--expected-context', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--consumer-root', type=Path, required=True)
    parser.add_argument('--producer-root', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle_path = args.bundle.resolve()
        if any(p.resolve().is_relative_to(bundle_path) for p in (args.expected_context, args.oracle)):
            raise HandoffError('expected_context_mismatch', 'trusted files inside bundle')
        result = validate_bundle(args.bundle, expected_context=_json_bytes(args.expected_context.read_bytes()),
                                 oracle_bytes=args.oracle.read_bytes(), consumer_root=args.consumer_root,
                                 producer_root=args.producer_root)
    except (HandoffError, OSError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
