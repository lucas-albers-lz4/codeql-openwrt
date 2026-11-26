#!/usr/bin/env python3
"""Prepare and scan a canonical control independently of the incoming head."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

from tools.current_corpus_linux import run_current
from tools.event_corpus_manifest import build, POLICY_SHA256
from tools.full_tree_candidates import compare, git
from tools.r3_linux_handoff import ROOT, digest, need, write_json


def prepare(receipt_path: Path, checkout: Path, output: Path) -> None:
    receipt = json.loads(receipt_path.read_text())
    need(receipt.get('schema') == 'incoming-event-receipt-v1' and
         receipt.get('status') == 'identities_resolved_only', 'invalid incoming receipt')
    repo = receipt['repository']
    control = receipt['control']
    need(git(checkout, 'rev-parse', 'HEAD') == control['commit'] and
         git(checkout, 'rev-parse', 'HEAD^{tree}') == control['tree'] and
         not git(checkout, 'status', '--porcelain=v1'), 'control checkout identity mismatch')
    policy_path = ROOT / 'docs/current-corpus-source-v0.6.json'
    raw = policy_path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'policy digest drift')
    policy = json.loads(raw)
    # This derived input is solely an adapter for the existing source oracle;
    # its head is the control, not the captured GitHub PR head.
    inventory = compare(checkout, policy['pins'][repo], control['commit'], policy, raw, repo)
    derived = dict(receipt, source=control,
                   base={'commit': policy['pins'][repo], 'tree': inventory['base_tree']})
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / 'control-derived-receipt.json', derived)
    write_json(output / 'control-inventory.json', inventory)
    manifest = build(policy, derived, inventory, checkout)
    manifest['event'].update(identity_receipt_sha256=digest(output / 'control-derived-receipt.json'),
                             candidate_inventory_sha256=digest(output / 'control-inventory.json'),
                             route_oracle_script_sha256=digest(ROOT / 'tools/event_corpus_manifest.py'),
                             source_role='clean_control')
    write_json(output / 'control-manifest.json', manifest)
    write_json(output / 'control-binding.json', {
        'schema': 'incoming-control-binding-v1', 'incoming_receipt_sha256': digest(receipt_path),
        'repository': repo, 'control': control, 'policy_sha256': POLICY_SHA256,
        'derived_receipt_sha256': digest(output / 'control-derived-receipt.json'),
        'inventory_sha256': digest(output / 'control-inventory.json'),
        'manifest_sha256': digest(output / 'control-manifest.json'),
        'limitations': ['Derived receipt is an oracle adapter, not a PR membership claim.',
                        'A clean scan means zero results for this bounded source-staged corpus, not proof of safety.']})


def prepare_with_report(receipt_path: Path, checkout: Path, output: Path) -> None:
    try:
        prepare(receipt_path, checkout, output)
    except Exception as exc:
        output.mkdir(parents=True, exist_ok=True)
        write_json(output / 'failure.json', {'schema': 'incoming-control-failure-v1',
                   'stage': 'control_oracle', 'status': 'failed, not a clean control',
                   'error': repr(exc)})
        raise


def assert_clean(triage: dict) -> None:
    need(triage.get('status') == 'clean_scan' and triage.get('result_count') == 0 and
         triage.get('results_for_triage') == [], 'control produced findings; clean-control expectation failed')


def main() -> None:
    need(len(sys.argv) == 7, 'usage: event_control_scan RELEASE_LOCK EVENT_RECEIPT CONTROL_CHECKOUT INPUT_DIR R3_RUN_ROOT RUN_ID')
    lock, receipt, checkout, inputs, root = map(Path, sys.argv[1:6])
    run_id = sys.argv[6]
    replay = inputs.with_name(inputs.name + '-replay')
    need(inputs.is_dir() and not replay.exists(), 'control oracle missing or replay already exists')
    stage = 'replay'
    try:
        prepare(receipt, checkout, replay)
        for name in ('control-derived-receipt.json', 'control-inventory.json', 'control-manifest.json', 'control-binding.json'):
            need((inputs / name).read_bytes() == (replay / name).read_bytes(), 'control oracle replay mismatch: ' + name)
        stage = 'released_scan'
        run_current(lock, inputs / 'control-manifest.json', root, run_id,
                    event_context=(inputs / 'control-derived-receipt.json', inputs / 'control-inventory.json', checkout),
                    run_label='control-corpus')
        stage = 'clean_assertion'
        triage = json.loads((root / 'control-corpus/out/triage.json').read_text())
        assert_clean(triage)
        write_json(root / 'control-corpus/control-assertion.json', {
            'schema': 'incoming-clean-control-assertion-v1', 'status': 'clean_scan',
            'binding_sha256': digest(inputs / 'control-binding.json'),
            'scan_receipt_sha256': digest(root / 'control-corpus/receipt.json'),
            'triage_sha256': digest(root / 'control-corpus/out/triage.json'), 'result_count': 0})
    except Exception as exc:
        write_json(inputs / 'control-failure.json', {'schema': 'incoming-control-failure-v1',
                   'stage': stage, 'status': 'failed, not a clean control',
                   'error': repr(exc), 'binding_sha256': digest(inputs / 'control-binding.json')
                   if (inputs / 'control-binding.json').is_file() else None})
        raise


if __name__ == '__main__':
    main()
