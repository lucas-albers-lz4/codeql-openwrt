#!/usr/bin/env python3
"""Read-only local check of one early artifact while its scan job is live.

The operator owns the private policy, queue and authenticated gh session.
This command never signs or applies a queue transition.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from zipfile import BadZipFile

import operator_artifact_custody as custody
import queue_scan_link


class StartError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise StartError(message)


def timestamp(value):
    need(isinstance(value, str), 'missing timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(result.tzinfo is not None, 'timestamp lacks timezone')
    return result


def verify_order(run, reservation):
    need(timestamp(run['created_at']) >= timestamp(reservation['observed_at']),
         'run predates queue reservation')


def read_policy(path, private_root):
    need(path.parent == private_root, 'policy must be directly in private root')
    custody.private_root(private_root)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
         before.st_size <= 4096, 'policy must be private regular mode 0600')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
             'policy changed before read')
        raw = os.read(fd, 4097)
        need(len(raw) == before.st_size, 'policy changed while reading')
        after = os.fstat(fd)
        need((after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns),
             'policy changed while reading')
    finally:
        os.close(fd)
    policy = custody.parse(raw)
    need(type(policy) is dict and set(policy) == {'schema', 'consumer_commit',
         'workflow', 'queue_id'} and policy['schema'] == 'incoming-operator-policy-v1' and
         policy['workflow'] == custody.WORKFLOW and
         isinstance(policy['consumer_commit'], str) and
         re.fullmatch(r'[0-9a-f]{40}', policy['consumer_commit']) and
         isinstance(policy['queue_id'], str) and
         re.fullmatch(r'[0-9a-f]{32}', policy['queue_id']),
         'invalid operator policy')
    return policy, hashlib.sha256(raw).hexdigest()


def reserved_queue(database, policy):
    db = queue_scan_link.open_readonly_queue(database)
    try:
        db.execute('BEGIN')
        row = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        need(row is not None, 'queue has no head')
        sequence, digest, raw = row
        need(hashlib.sha256(raw).hexdigest() == digest, 'queue head digest mismatch')
        reservation = custody.parse(raw)
        need(type(reservation) is dict and
             reservation.get('schema') == 'incoming-queue-manual-reservation-v1' and
             reservation.get('status') == 'reserved_only' and
             reservation.get('sequence') == sequence and
             reservation.get('queue_id') == policy['queue_id'],
             'queue head is not approved exact reservation')
        actual_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()
        need(actual_id == (policy['queue_id'],), 'queue ID differs from policy')
        event = db.execute('SELECT event,status,attempts,reservation,reservation_digest,started_job '
                           'FROM events WHERE id=?', (reservation['event_id'],)).fetchone()
        attempts_before = reservation.get('attempts_before', 0)
        need(type(attempts_before) is int and attempts_before >= 0 and
             event is not None and
             event[1:] == ('reserved', attempts_before, sequence, digest, None),
             'queue event is not exact reserved attempt')
        queued = custody.parse(event[0])
        need(queued['source']['commit'] == reservation['source']['commit'] and
             queued['base_commit'] == reservation['control_sha'],
             'queue event source differs from reservation')
        return reservation, digest
    finally:
        db.close()


def verify_live_api(run, jobs, artifacts, run_id, attempt, policy):
    commit = policy['consumer_commit']
    need(type(run) is dict and type(run.get('repository')) is dict and
         type(jobs) is dict and type(jobs.get('jobs')) is list and
         all(type(item) is dict for item in jobs['jobs']) and
         type(artifacts) is dict and type(artifacts.get('artifacts')) is list and
         all(type(item) is dict and type(item.get('workflow_run')) is dict
             for item in artifacts['artifacts']), 'invalid GitHub API object shape')
    need(type(run.get('id')) is int and run['id'] == run_id and
         type(run.get('run_attempt')) is int and run['run_attempt'] == attempt and
         run.get('repository', {}).get('full_name') == custody.REPO and
         run.get('path') == policy['workflow'] and
         run.get('event') == 'workflow_dispatch' and
         run.get('head_sha') == commit and run.get('status') == 'in_progress' and
         run.get('conclusion') is None, 'run is not the approved live workflow')
    need(type(jobs.get('total_count')) is int and
         jobs['total_count'] == len(jobs.get('jobs', [])), 'incomplete jobs API page')
    scans = [job for job in jobs['jobs'] if job.get('name') == 'released-event-scan'
             and job.get('run_id') == run_id and job.get('run_attempt') == attempt]
    need(len(scans) == 1, 'missing or duplicate scan job')
    job = scans[0]
    need(type(job.get('id')) is int and job['id'] > 0 and
         job.get('head_sha') == commit and job.get('status') == 'in_progress' and
         job.get('conclusion') is None and
         timestamp(job.get('started_at')) >= timestamp(run.get('created_at')),
         'scan job is not live at approved revision')
    need(type(artifacts.get('total_count')) is int and
         artifacts['total_count'] == len(artifacts.get('artifacts', [])),
         'incomplete artifacts API page')
    name = f'incoming-start-{run_id}-{attempt}'
    matches = [item for item in artifacts['artifacts'] if item.get('name') == name]
    need(len(matches) == 1, 'missing or duplicate early artifact')
    artifact = matches[0]
    need(type(artifact.get('id')) is int and artifact['id'] > 0 and
         artifact.get('workflow_run', {}).get('id') == run_id and
         artifact.get('expired') is False and
         type(artifact.get('size_in_bytes')) is int and
         0 < artifact['size_in_bytes'] <= custody.MAX_ZIP and
         isinstance(artifact.get('digest'), str) and
         re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest']) and
         timestamp(artifact.get('created_at')) >= timestamp(job['started_at']),
         'early artifact identity or digest invalid')
    return job, artifact


def verify_early_files(extracted, reservation, digest, run_id, attempt, policy):
    expected = {'receipt.json', 'dispatch-inputs.json', 'replayed-receipt.json',
                'reservation-claim.json', 'scan-pull-api-response.json'}
    actual = {path.relative_to(extracted).as_posix() for path in extracted.rglob('*')
              if path.is_file()}
    need(actual == expected, 'early artifact file set mismatch')
    values = {name: (extracted / name).read_bytes() for name in expected}
    receipt = custody.parse(values['receipt.json'])
    identity = f'{run_id}-{attempt}'
    need(type(receipt) is dict and set(receipt) == {'schema', 'status', 'run_id',
         'consumer_commit', 'files'} and
         receipt['schema'] == 'incoming-early-start-observation-v1' and
         receipt['status'] == 'retained_non_issuing' and
         receipt['run_id'] == identity and
         receipt['consumer_commit'] == policy['consumer_commit'] and
         type(receipt['files']) is dict and
         set(receipt['files']) == expected - {'receipt.json'} and
         all(receipt['files'][name] == hashlib.sha256(values[name]).hexdigest()
             for name in receipt['files']), 'early receipt or hashes differ')
    claim = custody.parse(values['reservation-claim.json'])
    dispatch = custody.parse(values['dispatch-inputs.json'])
    resolved = custody.parse(values['replayed-receipt.json'])
    pull = custody.parse(values['scan-pull-api-response.json'])
    need(all(type(value) is dict for value in (claim, dispatch, resolved, pull)),
         'invalid early JSON object')
    need(all(type(resolved.get(name)) is dict for name in ('source', 'base', 'control')) and
         type(pull.get('head')) is dict and type(pull.get('base')) is dict and
         type(pull['base'].get('repo')) is dict,
         'invalid nested PR identity object')
    event_id = custody.parse(reservation['event_id'].encode())
    need(type(event_id) is list and len(event_id) == 4 and
         event_id[1] == 'pull_request' and type(event_id[2]) is int and
         event_id[0] in ('openwrt/openwrt', 'openwrt/luci'),
         'invalid reserved event identity')
    source = reservation['source']['commit']
    control = reservation['control_sha']
    need(event_id[3] == source and
         type(claim) is dict and
         set(claim) == {'schema', 'status', 'run_id', 'queue_id',
                        'reservation_sequence', 'reservation_sha256',
                        'event_id', 'source_sha', 'control_sha'} and
         claim.get('schema') == 'incoming-reservation-claim-v1' and
         claim.get('status') == 'claimed_unverified' and claim.get('run_id') == identity and
         claim.get('queue_id') == policy['queue_id'] and
         type(claim.get('reservation_sequence')) is int and
         claim['reservation_sequence'] == reservation['sequence'] and
         claim.get('reservation_sha256') == digest and
         claim.get('event_id') == reservation['event_id'] and
         claim.get('source_sha') == source and claim.get('control_sha') == control,
         'early reservation claim differs from queue')
    need(type(dispatch) is dict and
         set(dispatch) == {'schema', 'status', 'run_id', 'upstream', 'pr_number',
                           'source_sha', 'control_sha', 'queue_id',
                           'reservation_sequence', 'reservation_sha256'} and
         dispatch.get('schema') == 'incoming-dispatch-inputs-v1' and
         dispatch.get('status') == 'claimed_unverified' and
         dispatch.get('run_id') == identity and
         dispatch.get('upstream') == event_id[0].split('/')[1] and
         type(dispatch.get('pr_number')) is int and
         dispatch['pr_number'] == event_id[2] and
         dispatch.get('source_sha') == source and
         dispatch.get('control_sha') == control and
         dispatch.get('queue_id') == policy['queue_id'] and
         type(dispatch.get('reservation_sequence')) is int and
         dispatch['reservation_sequence'] == reservation['sequence'] and
         dispatch.get('reservation_sha256') == digest,
         'early dispatch differs from queue')
    need(resolved.get('schema') == 'incoming-event-receipt-v1' and
         resolved.get('status') == 'identities_resolved_only' and
         resolved.get('repository') == dispatch['upstream'] and
         resolved.get('pr_number') == dispatch['pr_number'] and
         resolved.get('base_repository') == event_id[0] and
         resolved.get('repository_url') ==
             'https://github.com/' + event_id[0] + '.git' and
         resolved.get('event_type') == 'manual_sha_drill' and
         resolved.get('base', {}).get('commit') == control and
         resolved.get('source', {}).get('commit') == source and
         resolved.get('control', {}).get('commit') == control and
         type(pull.get('number')) is int and
         pull['number'] == event_id[2] and
         pull.get('base', {}).get('repo', {}).get('full_name') == event_id[0] and
         pull.get('head', {}).get('sha') == source and
         pull.get('base', {}).get('sha') == control and
         pull.get('state') == 'open', 'early canonical PR identity mismatch')
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in values.items()}


def check(database, private_root, policy_path, run_id, attempt):
    policy, policy_digest = read_policy(policy_path, private_root)
    reservation, reservation_digest = reserved_queue(database, policy)
    owner = Path(tempfile.mkdtemp(prefix=f'start-{run_id}-{attempt}-', dir=private_root))
    os.chmod(owner, 0o700)
    endpoint = f'repos/{custody.REPO}/actions/runs/{run_id}'
    run_raw = custody.fetch(endpoint, owner, 'run-api.json')
    jobs_raw = custody.fetch(endpoint + '/jobs?per_page=100', owner, 'jobs-api.json')
    artifacts_raw = custody.fetch(endpoint + '/artifacts?per_page=100', owner,
                                  'artifacts-api.json')
    run, jobs, artifacts = map(custody.parse, (run_raw, jobs_raw, artifacts_raw))
    job, artifact = verify_live_api(run, jobs, artifacts, run_id, attempt, policy)
    verify_order(run, reservation)
    zip_raw = custody.fetch(f'repos/{custody.REPO}/actions/artifacts/{artifact["id"]}/zip',
                            owner, 'download.zip', custody.MAX_ZIP)
    zip_digest = hashlib.sha256(zip_raw).hexdigest()
    need(artifact['digest'] == 'sha256:' + zip_digest,
         'downloaded early artifact digest mismatch')
    extracted = custody.unpack_checked(zip_raw, owner)
    file_digests = verify_early_files(extracted, reservation, reservation_digest,
                                      run_id, attempt, policy)
    # Observe the same job live again close to the eventual queue CAS boundary.
    latest_run_raw = custody.fetch(endpoint, owner, 'run-api-recheck.json')
    latest_jobs_raw = custody.fetch(endpoint + '/jobs?per_page=100', owner,
                                    'jobs-api-recheck.json')
    latest_run, latest_jobs = map(custody.parse, (latest_run_raw, latest_jobs_raw))
    latest_job, _ = verify_live_api(latest_run, latest_jobs, artifacts,
                                    run_id, attempt, policy)
    need(latest_job['id'] == job['id'], 'scan job changed during observation')
    latest_reservation, latest_digest = reserved_queue(database, policy)
    need(latest_digest == reservation_digest and
         latest_reservation == reservation, 'queue changed during observation')
    latest_policy, latest_policy_digest = read_policy(policy_path, private_root)
    need(latest_policy == policy and latest_policy_digest == policy_digest,
         'operator policy changed during observation')
    source_root = Path(__file__).resolve().parents[1]
    source_commit = os.environ.get('OPERATOR_LAUNCH_COMMIT', '')
    need(os.environ.get('OPERATOR_LAUNCH_SOURCE') == str(source_root) and
         source_commit == policy['consumer_commit'] and
         (source_root / '.operator-approved-commit').read_text() == source_commit + '\n',
         'observer was not launched from approved private source')
    source_dirty = False
    return {'schema': 'incoming-operator-start-observation-v1',
            'status': 'verified_read_only', 'run_id': run_id, 'attempt': attempt,
            'consumer_commit': policy['consumer_commit'],
            'policy_sha256': policy_digest, 'queue_id': policy['queue_id'],
            'reservation_sequence': reservation['sequence'],
            'reservation_sha256': reservation_digest, 'job_id': job['id'],
            'artifact_id': artifact['id'], 'artifact_sha256': zip_digest,
            'run_api_sha256': hashlib.sha256(run_raw).hexdigest(),
            'jobs_api_sha256': hashlib.sha256(jobs_raw).hexdigest(),
            'artifacts_api_sha256': hashlib.sha256(artifacts_raw).hexdigest(),
            'recheck_run_api_sha256': hashlib.sha256(latest_run_raw).hexdigest(),
            'recheck_jobs_api_sha256': hashlib.sha256(latest_jobs_raw).hexdigest(),
            'early_files': file_digests, 'operator_workspace': str(owner),
            'verifier_commit': source_commit,
            'verifier_dirty': source_dirty,
            'verifier_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'limitations': ['Read-only observation; no queue start or completion.']}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--private-root', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.database, args.private_root, args.policy,
                               args.run_id, args.attempt), sort_keys=True))
        return 0
    except (StartError, custody.CustodyError, queue_scan_link.LinkError,
            OSError, BadZipFile, ValueError, TypeError, KeyError, IndexError,
            AttributeError, RecursionError, UnicodeError,
            subprocess.SubprocessError) as exc:
        print('operator start observation rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
