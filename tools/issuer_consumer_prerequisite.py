#!/usr/bin/env python3
"""Offline consumer-graph check only. This module cannot issue a queue outcome.

The caller must independently replay the event manifest using
current_corpus_linux.validate_event_manifest before calling check_scan. These
checks do not authenticate execution or establish a trusted job boundary.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

from tools.r3_linux_handoff import ROOT, need, file_rows
from tools.sarif_accept import triage


def _unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _file(root, relative):
    path = root / relative
    need(not root.is_symlink() and root.is_dir(), 'unsafe scan root')
    cursor = root
    for part in Path(relative).parts:
        need(part not in ('', '.', '..'), 'unsafe path')
        cursor = cursor / part
        need(not cursor.is_symlink(), 'symlink in artifact path')
    need(path.is_file() and path.resolve().is_relative_to(root.resolve()), 'missing or escaping artifact')
    return path


def _load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=_unique)


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_scan(root: Path, manifest_path: Path, manifest: dict, lock: dict, run_id: str, consumer_sha: str) -> dict:
    """Check a single event/control scan's consumer edge; return no attestation.

    manifest must be the output of the real source-first oracle replay; lock
    must be independently pinned and verified. No caller-supplied digest is
    used as a substitute for reading the corresponding file.
    """
    root = Path(root)
    need(root.is_absolute() and not root.is_symlink(), 'unsafe scan root')
    manifest_path = Path(manifest_path)
    need(not manifest_path.is_symlink() and _load(manifest_path) == manifest, 'manifest bytes differ from replayed oracle')
    need(not (root / 'failure.json').exists(), 'failure marker present')
    names = ['receipt.json', 'commands.json', 'out/producer-receipt.json',
             'out/event-triage-input.json', 'out/default-suite.sarif',
             'out/triage.json', 'out/routing.json', 'out/successful.json', 'out/errors.json', 'out/coverage-event.json', 'preflight.json']
    paths = {name: _file(root, name) for name in names}
    # Strictly parse even files later read by the existing consumer, whose
    # JSON loader otherwise accepts duplicate keys.
    objects = {name: _load(path) for name, path in paths.items()}
    corpus, commands = objects['receipt.json'], objects['commands.json']
    producer = objects['out/producer-receipt.json']
    release = lock['release']
    identity = {'sha': release['commit'], 'pack_sha256': release['asset_sha256'],
                'codeql_version': lock['codeql']['version'], 'suite_sha256': release['suite_sha256']}
    rows = manifest['selected']
    expected = {'schema': 'ucode-sarif-event-triage-v1', 'producer': identity,
                'sources': [{'uri': row['proposed_installed_path'], 'sha256': row['source_sha256']} for row in rows],
                'expected_extracted': [row['proposed_installed_path'] for row in rows],
                'expected_rules': release['expected_rules'],
                'expected_sarif_descriptors': ['ucode/m4/direct-rpc-shell-word']}
    need(objects['out/event-triage-input.json'] == expected, 'consumer input differs from oracle and release')
    need(isinstance(commands, list) and commands and all(isinstance(c, dict) and type(c.get('exit')) is int and c['exit'] == 0 and isinstance(c.get('argv'), list) and c['argv'] for c in commands), 'missing or failed command')
    labels = [c.get('label') for c in commands]
    required = {'db-init', 'db-index', 'db-finalize', 'resolve-suite', 'analyze', 'triage',
                'errors-query', 'errors-decode', 'successful-query', 'successful-decode'}
    need(len(labels) == len(set(labels)) and required <= set(labels), 'missing or duplicate command labels')
    by_label = {c['label']: c for c in commands}
    codeql = str(root.parent / 'cli/codeql/codeql')
    db = str(root / 'db/current')
    for label, prefix in {'db-init': ['database', 'init', db], 'db-index': ['database', 'index-files'], 'db-finalize': ['database', 'finalize', db], 'resolve-suite': ['resolve', 'queries'], 'analyze': ['database', 'analyze', db], 'errors-query': ['query', 'run'], 'successful-query': ['query', 'run'], 'errors-decode': ['bqrs', 'decode'], 'successful-decode': ['bqrs', 'decode']}.items():
        argv = by_label[label]['argv']
        need(argv[:len(prefix)+1] == [codeql] + prefix, 'command executable or operation mismatch: ' + label)
    need('--source-root=' + str(root / 'stage') in by_label['db-init']['argv'] and '--working-dir=' + str(root / 'stage') in by_label['db-index']['argv'] and db in by_label['db-index']['argv'], 'database path mismatch')
    suite = str(root / 'bundle/ql/src/codeql-suites/code-scanning.qls')
    need(suite in by_label['resolve-suite']['argv'] and suite in by_label['analyze']['argv'], 'suite path mismatch')
    need('--output=' + str(paths['out/default-suite.sarif']) in by_label['analyze']['argv'], 'SARIF output path mismatch')
    for label, query in [('errors', 'ExtractionErrors.ql'), ('successful', 'SuccessfullyExtractedFiles.ql')]:
        argv = by_label[label + '-query']['argv']
        need(str(root / 'bundle/ql/src/diagnostics' / query) in argv and '--database=' + db in argv and '--output=' + str(root / 'out' / (label + '.bqrs')) in argv, 'diagnostic query path mismatch')
        need(str(root / 'out' / (label + '.bqrs')) in by_label[label + '-decode']['argv'], 'diagnostic decode path mismatch')
        need(by_label[label + '-decode'].get('stdout') == 'commands/' + label + '-decode.stdout', 'diagnostic stdout path mismatch')
        need(_file(root, 'commands/' + label + '-decode.stdout').read_bytes() == paths['out/' + label + '.json'].read_bytes(), 'diagnostic stdout mismatch')
    argv = by_label['triage']['argv']
    need(len(argv) == 12 and argv[1:] == ['-B', str(ROOT / 'tools/sarif_accept.py'), '--sarif', str(paths['out/default-suite.sarif']), '--manifest', str(paths['out/event-triage-input.json']), '--receipt', str(paths['out/producer-receipt.json']), '--source-root', str(root / 'stage'), '--event-triage'], 'consumer argv mismatch')
    need(by_label['triage'].get('stdout') == 'commands/triage.stdout', 'consumer stdout path mismatch')
    need(_file(root, 'commands/triage.stdout').read_bytes() == paths['out/triage.json'].read_bytes(), 'consumer stdout mismatch')
    need(producer.get('commands') == commands[:-1] and commands[-1].get('label') == 'triage', 'producer/consumer command sequence mismatch')
    need(corpus.get('schema') == 'ucode-event-corpus-linux-v1' and corpus.get('run_id') == run_id and producer.get('run_id') == run_id, 'scan run identity mismatch')
    need(corpus.get('producer_commit') == release['commit'] and corpus.get('release_tag') == release['tag'] and producer.get('producer') == identity, 'release mismatch')
    need(corpus.get('manifest_sha256') == _hash(manifest_path) and corpus.get('source_pins') == manifest['pins'] and corpus.get('event') == manifest['event'], 'manifest identity mismatch')
    need(corpus.get('consumer_sha') == consumer_sha == producer.get('consumer_sha') and producer.get('release_tag') == release['tag'] and producer.get('codeql_binary_sha256') == release['codeql_binary_sha256'], 'consumer or binary identity mismatch')
    preflight = objects['preflight.json']
    need(preflight.get('run_id') == run_id and preflight.get('consumer_sha') == consumer_sha and preflight.get('manifest_sha256') == _hash(manifest_path) and preflight.get('source_pins') == manifest['pins'] and preflight.get('event') == manifest['event'] and preflight.get('release_tag') == release['tag'] and preflight.get('release_commit') == release['commit'] and preflight.get('selected_count') == len(rows) and preflight.get('excluded_count') == len(manifest['excluded']), 'preflight identity mismatch')
    need(corpus.get('resolved_rules') == producer.get('resolved_rules') and Counter(corpus['resolved_rules']) == Counter(release['expected_rules']), 'resolved rules mismatch')
    for field, name in [('coverage_sha256', 'out/coverage-event.json'), ('sarif_sha256', 'out/default-suite.sarif'), ('accepted_sha256', 'out/triage.json'), ('commands_sha256', 'commands.json')]:
        need(corpus.get(field) == _hash(paths[name]), 'corpus artifact digest mismatch: ' + field)
    need(producer.get('route_sha256') == _hash(paths['out/routing.json']), 'routing digest mismatch')
    routing = objects['out/routing.json']
    got = Counter((d['installed_path'], d['classification'], d['reason'], d['status']) for d in routing['decisions'])
    wanted = Counter((r['proposed_installed_path'], r['expected_route']['classification'], r['expected_route']['reason'], 'plain_route_selected' if r['expected_route']['classification'] == 'plain' else 'inconclusive') for r in rows)
    counts = Counter(r['expected_route']['classification'] for r in rows)
    need(got == wanted and routing.get('input_count') == len(rows) and routing.get('plain_count') == counts['plain'] and routing.get('markup_count') == counts['markup'] and routing.get('markup_inconclusive_count') == counts['markup'] and all(routing.get(k) == 0 for k in ('excluded_count', 'uncertain_count', 'duplicate_input_count')), 'routing differs from oracle')
    need(corpus.get('route_counts') == {k: routing.get(k) for k in ('input_count', 'plain_count', 'markup_count', 'markup_inconclusive_count', 'uncertain_count', 'excluded_count', 'duplicate_input_count')} and corpus.get('selected_count') == len(rows) and corpus.get('successful_count') == len(rows) and corpus.get('extraction_error_count') == 0, 'corpus counts mismatch')
    coverage = objects['out/coverage-event.json']
    decisions = {d['installed_path']: d for d in routing['decisions']}
    selected = [{'repo': r['repo'], 'source_commit': r['source_commit'], 'source_path': r['source_path'], 'source_sha256': r['source_sha256'], 'git_blob': r['git_blob'], 'staged_path': r['proposed_installed_path'], 'route_classification': decisions[r['proposed_installed_path']]['classification'], 'route_reason': decisions[r['proposed_installed_path']]['reason'], 'route_status': decisions[r['proposed_installed_path']]['status'], 'extracted_count': 1, 'extraction_error_count': 0} for r in rows]
    need(coverage == {'schema': 'ucode-event-corpus-coverage-v1', 'source_manifest_sha256': _hash(manifest_path), 'event': manifest['event'], 'release_tag': release['tag'], 'producer_commit': release['commit'], 'source_pins': manifest['pins'], 'actual_package_installed_bytes_verified': False, 'counts': {'selected': len(rows), 'extracted_once': len(rows), 'errored': 0, 'modeled_markup_inconclusive': counts['markup'], 'excluded': len(manifest['excluded'])}, 'selected': selected, 'excluded': manifest['excluded']}, 'coverage differs from oracle')
    successful = file_rows(objects['out/successful.json']['#select']['tuples'], root / 'stage')
    errors = objects['out/errors.json']['#select']['tuples']
    need(Counter(successful) == Counter(expected['expected_extracted']) and Counter(successful) == Counter(producer['successful_files']) and errors == [] and producer['extraction_errors'] == errors, 'raw diagnostics differ from oracle or producer')
    # Reject symlinks along every staged source before the consumer opens it.
    for row in rows:
        _file(root, 'stage/' + row['proposed_installed_path'])
    actual = triage(paths['out/default-suite.sarif'], paths['out/event-triage-input.json'],
                    paths['out/producer-receipt.json'], root / 'stage')
    need(objects['out/triage.json'] == actual and corpus.get('status') == actual['status'], 'actual consumer triage differs')
    return actual
