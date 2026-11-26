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


def check_event_and_control(run_root: Path, event_manifest_path: Path, event_manifest: dict,
                            control_inputs: Path, control_manifest: dict,
                            incoming_receipt_path: Path, lock_path: Path, lock: dict,
                            run_id: str, consumer_sha: str) -> tuple[dict, dict]:
    """Check two independently replayed scans and their retained control assertion.

    Both oracle manifests and the lock must have been independently verified by
    the caller. This is an offline graph check, not an issuer or proof of execution.
    """
    from tools.event_control_scan import assert_clean
    from tools.event_corpus_manifest import POLICY_SHA256

    root, inputs = Path(run_root), Path(control_inputs)
    need(root.is_absolute() and not root.is_symlink() and inputs.is_absolute() and
         not inputs.is_symlink(), 'unsafe run or control input root')
    need(not (inputs / 'failure.json').exists() and not (inputs / 'control-failure.json').exists(), 'control failure marker')
    lock_path, incoming_receipt_path = Path(lock_path), Path(incoming_receipt_path)
    need(not lock_path.is_symlink() and _load(lock_path) == lock, 'lock bytes mismatch')
    need(not incoming_receipt_path.is_symlink(), 'unsafe incoming receipt')
    incoming = _load(incoming_receipt_path)
    need(incoming.get('schema') == 'incoming-event-receipt-v1' and incoming.get('status') == 'identities_resolved_only', 'invalid incoming receipt')
    source, control = incoming['source'], incoming['control']
    need(source['commit'] != control['commit'] and source['tree'] != control['tree'],
         'event and control commits and trees must differ')
    event_root, control_root = root / 'event-corpus', root / 'control-corpus'
    need(event_root != control_root and event_root.resolve() != control_root.resolve(), 'scan roots must differ')
    files = {name: _file(inputs, name) for name in ('control-derived-receipt.json', 'control-inventory.json', 'control-manifest.json', 'control-binding.json')}
    derived, inventory, binding = (_load(files[name]) for name in ('control-derived-receipt.json', 'control-inventory.json', 'control-binding.json'))
    need(_load(files['control-manifest.json']) == control_manifest, 'control manifest bytes differ')
    expected_derived = dict(incoming, source=control, base={'commit': inventory['base_commit'], 'tree': inventory['base_tree']})
    need(derived == expected_derived and inventory['head_commit'] == control['commit'] and inventory['head_tree'] == control['tree'], 'control derived identity mismatch')
    need(binding == {'schema': 'incoming-control-binding-v1', 'incoming_receipt_sha256': _hash(incoming_receipt_path),
                     'repository': incoming['repository'], 'control': control, 'policy_sha256': POLICY_SHA256,
                     'derived_receipt_sha256': _hash(files['control-derived-receipt.json']),
                     'inventory_sha256': _hash(files['control-inventory.json']),
                     'manifest_sha256': _hash(files['control-manifest.json']),
                     'limitations': ['Derived receipt is an oracle adapter, not a PR membership claim.',
                                     'A clean scan means zero results for this bounded source-staged corpus, not proof of safety.']}, 'control binding mismatch')
    for manifest, identity, role, receipt_hash in ((event_manifest, source, None, _hash(incoming_receipt_path)),
                                                   (control_manifest, control, 'clean_control', _hash(files['control-derived-receipt.json']))):
        event = manifest['event']
        base = incoming['base'] if role is None else derived['base']
        need(event.get('repository') == incoming['repository'] and event.get('pr_number') == incoming['pr_number'] and
             event.get('base_commit') == base['commit'] and event.get('base_tree') == base['tree'] and
             event.get('head_commit') == identity['commit'] and event.get('head_tree') == identity['tree'] and
             event.get('identity_receipt_sha256') == receipt_hash and event.get('source_role') == role and
             event.get('policy_sha256') == POLICY_SHA256, 'manifest event identity mismatch')
    need(control_manifest['event'].get('candidate_inventory_sha256') == _hash(files['control-inventory.json']), 'control inventory link mismatch')
    # Both scans must point to the same retained R3 receipt, whose preflight
    # records the actual lock bytes and job/run identity.
    r3_path = _file(root, 'receipt.json')
    r3 = _load(r3_path)
    preflight = r3.get('preflight', {})
    release = lock['release']
    need(r3.get('status') == 'accepted' and preflight.get('run_id') == run_id and
         preflight.get('consumer_sha') == consumer_sha and preflight.get('lock_sha256') == _hash(lock_path) and
         r3.get('release', {}).get('tag') == release['tag'] and
         r3['release'].get('producer_commit') == release['commit'] and
         r3['release'].get('asset_sha256') == release['asset_sha256'] and
         r3['release'].get('isImmutable') is True and
         r3.get('codeql', {}).get('binary_sha256') == release['codeql_binary_sha256'], 'R3 run or lock identity mismatch')
    for scan in (event_root, control_root):
        scan_preflight = _load(_file(scan, 'preflight.json'))
        need(scan_preflight.get('r3_receipt_sha256') == _hash(r3_path), 'scan R3 receipt mismatch')
    event_result = check_scan(event_root, event_manifest_path, event_manifest, lock, run_id, consumer_sha)
    control_result = check_scan(control_root, files['control-manifest.json'], control_manifest, lock, run_id, consumer_sha)
    assert_clean(control_result)
    assertion = _load(_file(control_root, 'control-assertion.json'))
    need(assertion == {'schema': 'incoming-clean-control-assertion-v1', 'status': 'clean_scan',
                       'binding_sha256': _hash(files['control-binding.json']),
                       'scan_receipt_sha256': _hash(_file(control_root, 'receipt.json')),
                       'triage_sha256': _hash(_file(control_root, 'out/triage.json')), 'result_count': 0}, 'control assertion mismatch')
    return event_result, control_result
