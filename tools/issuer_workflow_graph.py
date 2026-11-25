#!/usr/bin/env python3
"""Same-job graph prerequisite; never issues a queue completion."""
import json
import os
from pathlib import Path
import subprocess

from tools.current_corpus_linux import validate_event_manifest
from tools.issuer_consumer_prerequisite import check_event_and_control
from tools.r3_linux_handoff import ROOT, need, pinned, write_json


def run(temp: Path, run_id: str, event_outcome: str, control_outcome: str) -> None:
    need(temp.is_absolute() and run_id and all(c.isdigit() or c == '-' for c in run_id), 'invalid run paths')
    inputs = temp / ('event-input-' + run_id)
    source = temp / ('event-source-' + run_id)
    control = temp / ('event-control-' + run_id)
    root = temp / ('r3-event-' + run_id)
    output = inputs / 'consumer-graph.json'
    try:
        need(event_outcome == 'success' and control_outcome == 'success', 'event or control step did not succeed')
        lock_path = ROOT / 'docs/r3-release-lock.json'
        lock = json.loads(lock_path.read_text())
        pinned(lock)
        consumer_sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        event_path = inputs / 'replayed-manifest.json'
        receipt = inputs / 'replayed-receipt.json'
        event = validate_event_manifest(event_path, receipt, inputs / 'replayed-inventory.json', source)
        control_inputs = inputs / 'control-oracle'
        control_manifest = validate_event_manifest(control_inputs / 'control-manifest.json',
            control_inputs / 'control-derived-receipt.json', control_inputs / 'control-inventory.json',
            control, source_role='clean_control')
        event_result, control_result = check_event_and_control(root, event_path, event,
            control_inputs, control_manifest, receipt, lock_path, lock, run_id, consumer_sha)
        write_json(output, {'schema': 'incoming-consumer-graph-workflow-v1', 'status': 'checked',
                            'run_id': run_id, 'consumer_sha': consumer_sha,
                            'event_status': event_result['status'], 'control_status': control_result['status'],
                            'limitations': ['Non-issuing graph check; not an authenticated completion or Gate 8 pass.']})
    except Exception as exc:
        inputs.mkdir(parents=True, exist_ok=True)
        write_json(output, {'schema': 'incoming-consumer-graph-workflow-v1', 'status': 'failed', 'error': repr(exc)})
        raise


if __name__ == '__main__':
    run(Path(os.environ['RUNNER_TEMP']), os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'],
        os.environ['EVENT_OUTCOME'], os.environ['CONTROL_OUTCOME'])
