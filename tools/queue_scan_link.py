#!/usr/bin/env python3
"""Compare one reserved PR with a downloaded released-scan freeze.

Read-only, offline comparison. It does not authenticate artifact custody,
attest a queue start or completion, or change queue state.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incoming_queue import _store_path
from incoming_poll import PollError, unique_object
from tools.issuer_artifact_freeze import INPUT_FILES, R3_OUT, SCAN_OUT


class LinkError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise LinkError(message)


def safe_bytes(path):
    mode = path.lstat()
    need(stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1,
         'artifact is aliased or not regular: ' + str(path))
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(descriptor)
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
             (opened.st_dev, opened.st_ino) == (mode.st_dev, mode.st_ino) and
             opened.st_size <= 64 * 1024 * 1024, 'artifact changed before read')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(64 * 1024 * 1024 + 1)
        need(len(raw) <= 64 * 1024 * 1024, 'artifact exceeds byte limit')
        return raw
    finally:
        os.close(descriptor)


def read_json(path):
    return json.loads(safe_bytes(path), object_pairs_hook=unique_object)


def verify_file(path, metadata):
    mode = path.lstat()
    need(stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1,
         'snapshot file is aliased or not regular: ' + str(path))
    need(set(metadata) == {'bytes', 'sha256'} and type(metadata['bytes']) is int and
         metadata['bytes'] >= 0 and re.fullmatch(r'[0-9a-f]{64}', metadata['sha256']),
         'invalid freeze metadata')
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(descriptor)
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
             (opened.st_dev, opened.st_ino) == (mode.st_dev, mode.st_ino),
             'snapshot file changed before read')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    finally:
        os.close(descriptor)
    need(size == metadata['bytes'] and digest.hexdigest() == metadata['sha256'],
         'snapshot hash mismatch: ' + str(path))


def verify_snapshot(snapshot, inventory, require_claim=False):
    need(snapshot.is_dir() and not snapshot.is_symlink(), 'unsafe snapshot root')
    actual = set()
    for path in snapshot.rglob('*'):
        need(not path.is_symlink(), 'snapshot contains symlink')
        if path.is_file():
            actual.add(path.relative_to(snapshot).as_posix())
        else:
            need(path.is_dir(), 'snapshot contains special file')
    records = inventory['artifacts']
    need(set(records) == {'inputs', 'event', 'control', 'r3'}, 'incomplete freeze groups')
    input_names = set(records['inputs'])
    if require_claim:
        need(input_names == INPUT_FILES, 'incomplete input inventory')
    else:
        need(input_names in (INPUT_FILES,
                             INPUT_FILES - {'reservation-claim.json'},
                             INPUT_FILES - {'dispatch-inputs.json'},
                             INPUT_FILES - {'reservation-claim.json', 'dispatch-inputs.json'}),
             'incomplete input inventory')
    for role in ('event', 'control'):
        sections = records[role]
        need(set(sections) == {'root', 'out', 'commands', 'stage'},
             'incomplete scan sections')
        need(set(sections['out']) == SCAN_OUT, 'incomplete scan output inventory')
        required_root = {'preflight.json', 'receipt.json', 'commands.json'}
        if role == 'control':
            required_root.add('control-assertion.json')
        need(set(sections['root']) == required_root, 'incomplete scan root inventory')
        need(set(sections['stage']) == set(inventory['source_identities'][role]['stage_files']),
             'scan stage identities differ from freeze source identities')
        need(bool(sections['commands']), 'missing scan command records')
    need(set(records['r3']) == {'root', 'commands', 'openvpn-parent', 'openvpn-fixed'} and
         set(records['r3']['root']) == {'preflight.json', 'receipt.json', 'commands.json'} and
         bool(records['r3']['commands']) and
         all(set(records['r3'][case]) == R3_OUT for case in ('openvpn-parent', 'openvpn-fixed')),
         'incomplete R3 inventory')
    expected = set()
    for group, sections in inventory['artifacts'].items():
        need(group in ('inputs', 'event', 'control', 'r3'), 'unexpected freeze group')
        if group == 'inputs':
            sections = {'': sections}
        for section, files in sections.items():
            need(section in ('', 'root', 'out', 'commands', 'stage', 'openvpn-parent', 'openvpn-fixed'),
                 'unexpected freeze section')
            prefix = '' if section in ('', 'root') else (
                'out/' + section if group == 'r3' and section.startswith('openvpn-') else section)
            for name, metadata in files.items():
                rel = Path(group) / prefix / name
                need(not rel.is_absolute() and all(part not in ('', '.', '..') for part in rel.parts),
                     'unsafe inventory path')
                need(rel.as_posix() not in expected, 'duplicate inventory path')
                expected.add(rel.as_posix())
                verify_file(snapshot / rel, metadata)
    verify_file(snapshot / 'release-lock.json', inventory['release_lock'])
    expected.add('release-lock.json')
    need(actual == expected, 'snapshot has missing or unexpected files')
    return len(expected) - 1


def open_readonly_queue(path):
    path, file_identity = _store_path(path, create=False)
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)
    try:
        current = path.lstat()
        need((current.st_dev, current.st_ino) == file_identity and current.st_nlink == 1,
             'queue store changed before read-only open')
        db.execute('PRAGMA query_only=ON')
        need(db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete',
             'unsupported queue journal mode')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        need(tables == {'metadata', 'history', 'events'} and
             db.execute("SELECT value FROM metadata WHERE key='schema'").fetchone() ==
             ('incoming-queue-store-v2',), 'unsupported queue schema')
        return db
    except BaseException:
        db.close()
        raise


def verify(database, artifact, run_api_path, run_id, attempt, consumer_commit,
           require_claim=False):
    need(re.fullmatch(r'[1-9][0-9]*', str(run_id)) and type(attempt) is int and attempt > 0,
         'invalid run identity')
    need(re.fullmatch(r'[0-9a-f]{40}', consumer_commit), 'invalid consumer commit')
    identity = str(run_id) + '-' + str(attempt)
    run_api = read_json(run_api_path)
    need(run_api.get('id') == int(run_id) and run_api.get('run_attempt') == attempt and
         run_api.get('event') == 'workflow_dispatch' and
         run_api.get('status') == 'completed' and run_api.get('conclusion') == 'success' and
         run_api.get('head_sha') == consumer_commit and
         run_api.get('path') == '.github/workflows/incoming-event-preflight.yml' and
         run_api.get('repository', {}).get('full_name') == 'lucas-albers-lz4/codeql-openwrt',
         'GitHub run metadata does not match completed released workflow')
    db = open_readonly_queue(str(database))
    try:
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        need(head is not None, 'queue has no history')
        sequence, digest, raw = head
        need(hashlib.sha256(raw).hexdigest() == digest, 'queue history digest mismatch')
        reservation = json.loads(raw, object_pairs_hook=unique_object)
        need(reservation.get('schema') == 'incoming-queue-manual-reservation-v1' and
             reservation.get('status') == 'reserved_only' and reservation.get('sequence') == sequence,
             'queue head is not an exact PR reservation')
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        need(reservation['queue_id'] == queue_id, 'queue ID mismatch')
        row = db.execute('SELECT event,status,reservation,reservation_digest FROM events WHERE id=?',
                         (reservation['event_id'],)).fetchone()
        need(row is not None and row[1:] == ('reserved', sequence, digest),
             'queue event is not held by this reservation')
        queued_event = json.loads(row[0], object_pairs_hook=unique_object)
    finally:
        db.close()
    need(datetime.fromisoformat(run_api['created_at'].replace('Z', '+00:00')) >=
         datetime.fromisoformat(reservation['observed_at'].replace('Z', '+00:00')),
         'workflow run predates reservation')
    need(artifact.is_dir() and not artifact.is_symlink(), 'unsafe artifact root')
    freeze = artifact / ('issuer-freeze-' + identity)
    need(freeze.is_dir() and not freeze.is_symlink(), 'unsafe freeze root')
    inventory = read_json(freeze / 'inventory.json')
    need(inventory.get('schema') == 'incoming-artifact-freeze-v1' and
         inventory.get('status') == 'frozen' and inventory.get('run_id') == identity and
         inventory.get('consumer_commit') == consumer_commit, 'freeze run or consumer mismatch')
    snapshot = freeze / 'snapshot'
    count = verify_snapshot(snapshot, inventory, require_claim)
    verify_file(freeze / 'graph-recheck.json', inventory['graph_recheck'])
    receipt = read_json(snapshot / 'inputs/incoming-event-receipt.json')
    claim_bound = False
    if 'reservation-claim.json' in inventory['artifacts']['inputs']:
        claim = read_json(snapshot / 'inputs/reservation-claim.json')
        if claim.get('status') == 'claimed_unverified':
            need(set(claim) == {'schema', 'status', 'run_id', 'queue_id',
                                'reservation_sequence', 'reservation_sha256',
                                'event_id', 'source_sha', 'control_sha'} and
                 claim.get('schema') == 'incoming-reservation-claim-v1' and
                 claim.get('run_id') == identity and
                 claim.get('queue_id') == queue_id and
                 claim.get('reservation_sequence') == sequence and
                 claim.get('reservation_sha256') == digest and
                 claim.get('event_id') == reservation['event_id'] and
                 claim.get('source_sha') == reservation['source']['commit'] and
                 claim.get('control_sha') == reservation['control_sha'],
                 'same-job reservation claim mismatch')
            claim_bound = True
    need(not require_claim or claim_bound, 'same-job reservation claim missing')
    if require_claim:
        dispatch = read_json(snapshot / 'inputs/dispatch-inputs.json')
        need(set(dispatch) == {'schema', 'status', 'run_id', 'upstream',
                               'pr_number', 'source_sha', 'control_sha',
                               'queue_id', 'reservation_sequence', 'reservation_sha256'} and
             dispatch.get('schema') == 'incoming-dispatch-inputs-v1' and
             dispatch.get('status') == 'claimed_unverified' and
             dispatch.get('run_id') == identity and
             dispatch.get('upstream') == receipt['repository'] and
             type(dispatch.get('pr_number')) is int and
             dispatch.get('pr_number') == receipt['pr_number'] and
             dispatch.get('source_sha') == receipt['source']['commit'] and
             dispatch.get('control_sha') == receipt['control']['commit'] and
             dispatch.get('queue_id') == queue_id and
             type(dispatch.get('reservation_sequence')) is int and
             dispatch.get('reservation_sequence') == sequence and
             dispatch.get('reservation_sha256') == digest,
             'pre-resolution dispatch inputs differ from reservation')
    need(safe_bytes(snapshot / 'inputs/incoming-event-receipt.json') ==
         safe_bytes(snapshot / 'inputs/replayed-receipt.json'),
         'original and replayed PR receipts differ')
    api = read_json(snapshot / 'inputs/scan-pull-api-response.json')
    event_id = json.loads(reservation['event_id'], object_pairs_hook=unique_object)
    need(type(event_id) is list and len(event_id) == 4 and event_id[1] == 'pull_request' and
         event_id[0] in ('openwrt/openwrt', 'openwrt/luci'), 'invalid reserved PR identity')
    repo, _, number, head = event_id
    need(receipt.get('repository') == repo.split('/')[1] and receipt.get('pr_number') == number and
         receipt.get('source') == inventory['source_identities']['event']['checkout'] and
         receipt['source']['commit'] == head == reservation['source']['commit'] ==
         queued_event['source']['commit'] == api['head']['sha'], 'PR source identity mismatch')
    need(receipt['base']['commit'] == receipt['control']['commit'] ==
         reservation['control_sha'] == queued_event['base_commit'] == api['base']['sha'],
         'PR base or control identity mismatch')
    graph = read_json(snapshot / 'inputs/consumer-graph.json')
    graph_recheck = read_json(freeze / 'graph-recheck.json')
    scan = read_json(snapshot / 'event/receipt.json')
    triage = read_json(snapshot / 'event/out/triage.json')
    control = read_json(snapshot / 'control/control-assertion.json')
    need(graph.get('schema') == 'incoming-consumer-graph-workflow-v1' and
         graph.get('status') == 'checked' and graph.get('run_id') == identity and
         graph.get('consumer_sha') == consumer_commit and
         graph.get('event_status') == scan.get('status') and
         graph.get('control_status') == control.get('status') and
         graph_recheck == graph and
         scan.get('run_id') == identity and scan.get('consumer_sha') == consumer_commit and
         triage.get('run_id') == identity,
         'same-run graph or scan mismatch')
    manifest_path = snapshot / 'inputs/event-corpus-manifest.json'
    manifest = read_json(manifest_path)
    release = read_json(snapshot / 'release-lock.json')['release']
    r3 = read_json(snapshot / 'r3/receipt.json')
    need(r3.get('schema') == 'ucode-r3-linux-handoff-v1' and
         r3.get('status') == 'accepted' and
         r3.get('release', {}).get('tag') == release.get('tag') and
         r3.get('release', {}).get('producer_commit') == release.get('commit') and
         r3.get('preflight', {}).get('run_id') == identity and
         r3.get('preflight', {}).get('consumer_sha') == consumer_commit and
         r3.get('preflight', {}).get('lock_sha256') == inventory['release_lock']['sha256'],
         'released R3 prerequisite mismatch')
    need(scan.get('schema') == 'ucode-event-corpus-linux-v1' and
         scan.get('event') == manifest.get('event') and
         scan.get('manifest_sha256') == hashlib.sha256(safe_bytes(manifest_path)).hexdigest() and
         scan.get('event', {}).get('head_commit') == head and
         scan.get('event', {}).get('head_tree') == receipt['source']['tree'] and
         scan.get('event', {}).get('base_commit') == reservation['control_sha'] and
         scan.get('event', {}).get('base_tree') == receipt['base']['tree'] and
         scan.get('event', {}).get('repository') == receipt['repository'] and
         scan.get('event', {}).get('pr_number') == number and
         scan.get('source_pins') == manifest.get('pins') and
         scan.get('release_tag') == release.get('tag') and
         scan.get('producer_commit') == release.get('commit') and
         scan.get('selected_count') == manifest.get('counts', {}).get('selected') and
         scan.get('coverage_sha256') == hashlib.sha256(safe_bytes(
             snapshot / 'event/out/coverage-event.json')).hexdigest() and
         scan.get('accepted_sha256') == hashlib.sha256(safe_bytes(
             snapshot / 'event/out/triage.json')).hexdigest() and
         scan.get('sarif_sha256') == triage.get('sarif_sha256') and
         scan.get('sarif_sha256') == hashlib.sha256(
             safe_bytes(snapshot / 'event/out/default-suite.sarif')).hexdigest(),
         'released scan source, manifest or SARIF binding mismatch')
    control_receipt_path = snapshot / 'control/receipt.json'
    control_receipt = read_json(control_receipt_path)
    control_manifest_path = snapshot / 'inputs/control-oracle/control-manifest.json'
    control_manifest = read_json(control_manifest_path)
    control_derived = read_json(snapshot / 'inputs/control-oracle/control-derived-receipt.json')
    control_triage_path = snapshot / 'control/out/triage.json'
    control_triage = read_json(control_triage_path)
    need(control_receipt.get('schema') == 'ucode-event-corpus-linux-v1' and
         control_receipt.get('status') == 'clean_scan' and
         control_receipt.get('run_id') == identity and
         control_receipt.get('consumer_sha') == consumer_commit and
         control_receipt.get('event') == control_manifest.get('event') and
         control_receipt.get('manifest_sha256') == hashlib.sha256(
             safe_bytes(control_manifest_path)).hexdigest() and
         control_receipt.get('source_pins') == control_manifest.get('pins') and
         control_receipt.get('selected_count') == control_receipt.get('successful_count') ==
             control_manifest.get('counts', {}).get('selected') and
         control_receipt.get('extraction_error_count') == 0 and
         control_receipt.get('release_tag') == release.get('tag') and
         control_receipt.get('producer_commit') == release.get('commit') and
         control_receipt.get('event', {}).get('head_commit') == reservation['control_sha'] and
         control_receipt.get('event', {}).get('head_tree') == receipt['control']['tree'] and
         control_receipt.get('event', {}).get('repository') == receipt['repository'] and
         control_receipt.get('event', {}).get('pr_number') == number and
         control_derived.get('source') == receipt['control'] and
         control_receipt.get('sarif_sha256') == control_triage.get('sarif_sha256') ==
             hashlib.sha256(safe_bytes(snapshot / 'control/out/default-suite.sarif')).hexdigest() and
         control_triage.get('run_id') == identity and
         control_triage.get('status') == 'clean_scan' and
         control_triage.get('result_count') == 0 and
         control.get('schema') == 'incoming-clean-control-assertion-v1' and
         control.get('scan_receipt_sha256') == hashlib.sha256(
             safe_bytes(control_receipt_path)).hexdigest() and
         control.get('triage_sha256') == hashlib.sha256(
             safe_bytes(control_triage_path)).hexdigest() and
         control.get('binding_sha256') == hashlib.sha256(safe_bytes(
             snapshot / 'inputs/control-oracle/control-binding.json')).hexdigest(),
         'clean-control identity or assertion mismatch')
    need(scan.get('status') in ('clean_scan', 'triage_required') and
         scan.get('selected_count') == scan.get('successful_count') and
         scan.get('extraction_error_count') == 0 and
         triage.get('status') == scan['status'] and
         type(triage.get('result_count')) is int and
         len(triage.get('results_for_triage', [])) == triage['result_count'] and
         control.get('status') == 'clean_scan' and control.get('result_count') == 0,
         'event or clean-control disposition mismatch')
    return {'schema': 'incoming-queue-scan-link-v1', 'status': 'linked_only',
            'queue_id': queue_id, 'reservation_sequence': sequence,
            'reservation_sha256': digest, 'run_id': identity,
            'consumer_commit': consumer_commit, 'source': receipt['source'],
            'snapshot_files_verified': count, 'scan_status': scan['status'],
            'claim_bound': claim_bound,
            'selected_count': scan['selected_count'], 'result_count': triage['result_count'],
            'limitations': ['Offline comparison; no artifact custody or queue attestation.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('--run-api', required=True, type=Path,
                        help='retained exact GitHub Actions run API response')
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt', required=True, type=int)
    parser.add_argument('--consumer-commit', required=True)
    parser.add_argument('--require-claim', action='store_true',
                        help='require a matching reservation claim frozen by the scan job')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.database, args.artifact, args.run_api, args.run_id,
                                args.attempt, args.consumer_commit,
                                args.require_claim), sort_keys=True))
        return 0
    except (LinkError, PollError, ValueError, KeyError, IndexError, TypeError, OSError,
            sqlite3.Error, json.JSONDecodeError) as exc:
        print('scan link rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
