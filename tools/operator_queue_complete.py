#!/usr/bin/env python3
"""Local operator completion from authenticated final artifact and issued start.

The private key is read only after GitHub fetches and byte comparisons. A
failed or incomplete run cannot be completed through this command.
"""
import hashlib
import hmac
import io
import json
import os
import subprocess
from pathlib import Path
import stat
import sys
from datetime import datetime, timezone
from zipfile import ZipFile, BadZipFile

from incoming_poll import PollError, check, unique_object
from incoming_queue import encoded, open_queue
from incoming_queue_issued import issue_complete
import operator_artifact_custody as custody
import operator_queue_start as starter
import operator_start_observation as observation
import queue_scan_link

EARLY = ('dispatch-inputs.json', 'replayed-receipt.json',
         'reservation-claim.json', 'scan-pull-api-response.json')


def issued_start(database, run_id, attempt):
    db = queue_scan_link.open_readonly_queue(database)
    try:
        db.execute('BEGIN')
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and hashlib.sha256(head[2]).hexdigest() == head[1],
              'missing or corrupt issued start head')
        action = json.loads(head[2], object_pairs_hook=unique_object)
        att = action.get('attestation', {})
        check(action.get('schema') == 'incoming-queue-issued-action-v1' and
              action.get('sequence') == head[0] and
              type(att) is dict and att.get('schema') == 'incoming-issued-start-v1' and
              att.get('kind') == 'start' and
              att.get('run_id') == f'{run_id}-{attempt}' and
              att.get('job', {}).get('run_id') == run_id and
              att['job'].get('attempt') == attempt and
              action.get('previous_sha256') == att.get('reservation_digest'),
              'queue head is not this run issued start')
        row = db.execute('SELECT status,reason,reservation,reservation_digest,started_job '
                         'FROM events WHERE id=?', (att['event_id'],)).fetchone()
        check(row == ('started', att['run_id'], att['reservation'],
                      att['reservation_digest'], encoded(att['job']).decode()),
              'issued start row changed')
        return action, head[1]
    finally:
        db.close()


def early_final(start, observation_path, private_root, final_root):
    check(observation_path.is_absolute() and observation_path.name ==
          'verified-observation.json' and
          observation_path.parent.parent == private_root and
          not observation_path.parent.is_symlink() and
          observation_path.parent.is_dir() and
          stat.S_IMODE(observation_path.parent.stat().st_mode) == 0o700,
          'unsafe retained start observation path')
    raw = queue_scan_link.safe_bytes(observation_path)
    att = start['attestation']
    check(hashlib.sha256(raw).hexdigest() == att['observation_sha256'],
          'retained start observation digest differs')
    observed = json.loads(raw, object_pairs_hook=unique_object)
    check(observed.get('status') == 'verified_read_only' and
          observed.get('run_id') == att['job']['run_id'] and
          observed.get('attempt') == att['job']['attempt'] and
          observed.get('job_id') == att['job']['id'] and
          observed.get('consumer_commit') == att['job']['consumer_commit'] and
          observed.get('artifact_id') == att['early_artifact']['id'] and
          observed.get('artifact_sha256') == att['early_artifact']['sha256'] and
          observed.get('reservation_sequence') == att['reservation'] and
          observed.get('reservation_sha256') == att['reservation_digest'] and
          observed.get('policy_sha256') == att['policy_sha256'],
          'start observation differs from issued record')
    archive = queue_scan_link.safe_bytes(observation_path.parent / 'download.zip')
    check(hashlib.sha256(archive).hexdigest() == att['early_artifact']['sha256'],
          'retained early ZIP differs from issued start')
    result = {}
    with ZipFile(io.BytesIO(archive)) as z:
        check(set(z.namelist()) == set(EARLY) | {'receipt.json'} and
              len(z.infolist()) == 5, 'retained early ZIP member set changed')
        for name in EARLY:
            early = z.read(name)
            check(hashlib.sha256(early).hexdigest() ==
                  observed['early_files'][name], 'retained early member differs')
            final = queue_scan_link.safe_bytes(final_root / 'inputs' / name)
            check(early == final, 'early and final frozen inputs differ: ' + name)
            result[name] = hashlib.sha256(final).hexdigest()
    return result


def complete(database, private_root, policy_path, key_path,
             observation_path, run_id, attempt):
    custody.private_root(private_root)
    start, start_digest = issued_start(database, run_id, attempt)
    att = start['attestation']
    policy, policy_digest = observation.read_policy(policy_path, private_root)
    check(policy_digest == att['policy_sha256'] and
          policy['consumer_commit'] == att['job']['consumer_commit'] and
          policy['queue_id'] == att['queue_id'],
          'approved policy differs from issued start')
    final = custody.check(database, private_root, run_id, attempt,
                          policy['consumer_commit'])
    link = final['link']
    check(final['status'] == 'verified_read_only' and
          final['job_id'] == att['job']['id'] and
          link['queue_state'] == 'started' and
          link['started_job_id'] == att['job']['id'] and
          link['reservation_sequence'] == att['reservation'] and
          link['reservation_sha256'] == att['reservation_digest'] and
          link['scan_status'] in ('clean_scan', 'triage_required'),
          'final custody does not match issued start')
    final_root = Path(final['operator_workspace']) / 'extracted' / f'issuer-freeze-{run_id}-{attempt}' / 'snapshot'
    early_map = early_final(start, observation_path, private_root,
                            final_root)
    issuer_commit = starter.clean_checkout(policy['consumer_commit'])
    final['issuer_verifier_commit'] = issuer_commit
    final['issuer_script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    final_receipt = encoded(final)
    receipt_path = Path(final['operator_workspace']) / 'verified-custody.json'
    descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(final_receipt)
    def digest(relative):
        return hashlib.sha256(queue_scan_link.safe_bytes(final_root / relative)).hexdigest()
    extraction = {'successful': digest('event/out/successful.json'),
                  'errors': digest('event/out/errors.json')}
    payload = {'schema': 'incoming-issued-completion-v1', 'kind': 'complete',
               'queue_id': att['queue_id'], 'event_id': att['event_id'],
               'reservation': att['reservation'],
               'reservation_digest': att['reservation_digest'],
               'run_id': att['run_id'], 'job': att['job'],
               'start_sequence': start['sequence'], 'start_sha256': start_digest,
               'final_artifact': {'id': final['artifact_id'],
                                  'sha256': final['artifact_sha256']},
               'custody_sha256': hashlib.sha256(final_receipt).hexdigest(),
               'early_final_sha256': hashlib.sha256(encoded(early_map)).hexdigest(),
               'source': link['source'],
               'control_commit': att['control_sha'],
               'release_lock_sha256': digest('release-lock.json'),
               'manifest_sha256': digest('inputs/event-corpus-manifest.json'),
               'extraction_sha256': hashlib.sha256(encoded(extraction)).hexdigest(),
               'sarif_sha256': digest('event/out/default-suite.sarif'),
               'control_sha256': digest('control/control-assertion.json'),
               'freeze_inventory_sha256': hashlib.sha256(queue_scan_link.safe_bytes(
                   final_root.parent / 'inventory.json')).hexdigest(),
               'consumer_disposition': 'clean' if link['scan_status'] == 'clean_scan'
                                       else 'alert_triage',
               'result_count': link['result_count']}
    key = starter.read_key(key_path, private_root)
    db = open_queue(database)
    try:
        action, action_digest = issue_complete(
            db, (start['sequence'], start_digest), payload, key,
            datetime.now(timezone.utc).isoformat())
    finally:
        db.close()
    return {'schema': 'incoming-operator-issued-completion-v1',
            'status': 'completed', 'sequence': action['sequence'],
            'sha256': action_digest, 'run_id': att['run_id'],
            'job_id': att['job']['id'], 'result_count': link['result_count'],
            'custody_sha256': payload['custody_sha256'],
            'operator_workspace': final['operator_workspace']}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--private-root', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--start-observation', required=True, type=Path)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(complete(args.database, args.private_root, args.policy,
                                  args.key, args.start_observation,
                                  args.run_id, args.attempt), sort_keys=True))
        return 0
    except (PollError, custody.CustodyError, observation.StartError,
            queue_scan_link.LinkError, OSError, ValueError, TypeError, KeyError,
            IndexError, AttributeError, RecursionError, BadZipFile,
            subprocess.SubprocessError) as exc:
        print('operator completion rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
