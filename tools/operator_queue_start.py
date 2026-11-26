#!/usr/bin/env python3
"""Local operator start: verify a live hosted job, then sign one queue CAS.

Run only from an approved clean checkout. The private key is read after all
GitHub API/subprocess work and is never passed to a hosted job or subprocess.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from datetime import datetime, timezone

from incoming_poll import PollError, check
from incoming_queue import encoded, open_queue
from incoming_queue_issued import issue_start, WORKFLOW, JOB
import operator_start_observation as observation


def read_key(path, private_root):
    check(path.parent == private_root, 'issuer key must be directly in private root')
    observation.custody.private_root(private_root)
    before = path.lstat()
    check(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
          before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
          before.st_size == 32, 'issuer key must be private 32-byte regular file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        check((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
              (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
              'issuer key changed before read')
        key = os.read(descriptor, 33)
        check(len(key) == 32, 'issuer key changed while reading')
        after = os.fstat(descriptor)
        check((after.st_size, after.st_mtime_ns) ==
              (opened.st_size, opened.st_mtime_ns), 'issuer key changed while reading')
        return key
    finally:
        os.close(descriptor)


def clean_checkout(expected_commit):
    root = Path(__file__).resolve().parents[1]
    commit = os.environ.get('OPERATOR_LAUNCH_COMMIT', '')
    check(os.environ.get('OPERATOR_LAUNCH_SOURCE') == str(root) and
          commit == expected_commit and
          (root / '.operator-approved-commit').read_text() == commit + '\n',
          'issuer source was not prepared by approved launcher')
    return commit


def start(database, private_root, policy_path, key_path, run_id, attempt):
    observed = observation.check(database, private_root, policy_path, run_id, attempt)
    check(observed['status'] == 'verified_read_only' and
          observed['verifier_dirty'] is False and
          observed['verifier_commit'] == observed['consumer_commit'],
          'start observer did not run from approved clean revision')
    policy, policy_digest = observation.read_policy(policy_path, private_root)
    check(policy_digest == observed['policy_sha256'] and
          policy['consumer_commit'] == observed['consumer_commit'],
          'approved policy changed after live observation')
    reservation, digest = observation.reserved_queue(database, policy)
    check(reservation['sequence'] == observed['reservation_sequence'] and
          digest == observed['reservation_sha256'],
          'reservation changed after live observation')
    workspace = Path(observed['operator_workspace'])
    receipt = encoded(observed)
    receipt_path = workspace / 'verified-observation.json'
    fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(receipt)
    job = {'workflow': WORKFLOW, 'job': JOB, 'run_id': run_id,
           'attempt': attempt, 'id': observed['job_id'],
           'consumer_commit': observed['consumer_commit']}
    payload = {'schema': 'incoming-issued-start-v1', 'kind': 'start',
               'queue_id': observed['queue_id'], 'event_id': reservation['event_id'],
               'reservation': reservation['sequence'],
               'reservation_digest': digest, 'run_id': f'{run_id}-{attempt}',
               'job': job, 'source_sha': reservation['source']['commit'],
               'control_sha': reservation['control_sha'],
               'policy_sha256': policy_digest,
               'early_artifact': {'id': observed['artifact_id'],
                                  'sha256': observed['artifact_sha256']},
               'observation_sha256': hashlib.sha256(receipt).hexdigest(),
               'run_api_sha256': observed['run_api_sha256'],
               'jobs_api_sha256': observed['jobs_api_sha256'],
               'artifacts_api_sha256': observed['artifacts_api_sha256'],
               'recheck_run_api_sha256': observed['recheck_run_api_sha256'],
               'recheck_jobs_api_sha256': observed['recheck_jobs_api_sha256']}
    clean_checkout(policy['consumer_commit'])
    key = read_key(key_path, private_root)
    db = open_queue(database)
    try:
        document, action_digest = issue_start(
            db, (reservation['sequence'], digest), payload, key,
            datetime.now(timezone.utc).isoformat())
    finally:
        db.close()
    return {'schema': 'incoming-operator-issued-start-v1',
            'status': 'started', 'sequence': document['sequence'],
            'sha256': action_digest, 'run_id': f'{run_id}-{attempt}',
            'job_id': observed['job_id'], 'observation_sha256': payload['observation_sha256'],
            'operator_workspace': str(workspace),
            'limitations': ['Start records verified live evidence, not a completed scan.']}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--private-root', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(start(args.database, args.private_root, args.policy,
                               args.key, args.run_id, args.attempt), sort_keys=True))
        return 0
    except (PollError, observation.StartError, observation.custody.CustodyError,
            OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            RecursionError, subprocess.SubprocessError) as exc:
        print('operator start rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
