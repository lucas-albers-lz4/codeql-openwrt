#!/usr/bin/env python3
"""Return a terminal failed/cancelled issued scan to the local retry queue.

An in-progress timeout must first be cancelled and observed terminal. This
command does not infer failure from a polling timeout or missing artifact.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from incoming_poll import PollError, check
from incoming_queue import open_queue
from incoming_queue_issued import issue_failure, WORKFLOW, JOB
import operator_artifact_custody as custody
import operator_queue_complete as completion
import operator_queue_start as starter
import operator_start_observation as observation


def fail(database, private_root, policy_path, key_path, run_id, attempt):
    custody.private_root(private_root)
    start, digest = completion.issued_start(database, run_id, attempt)
    att = start['attestation']
    policy, policy_digest = observation.read_policy(policy_path, private_root)
    check(policy_digest == att['policy_sha256'] and
          policy['consumer_commit'] == att['job']['consumer_commit'] and
          policy['queue_id'] == att['queue_id'],
          'operator policy differs from issued start')
    owner = Path(tempfile.mkdtemp(prefix=f'failed-{run_id}-{attempt}-',
                                   dir=private_root))
    endpoint = f'repos/{custody.REPO}/actions/runs/{run_id}'
    run_raw = custody.fetch(endpoint, owner, 'run-api.json')
    jobs_raw = custody.fetch(endpoint + '/jobs?per_page=100', owner,
                             'jobs-api.json')
    run, jobs = map(custody.parse, (run_raw, jobs_raw))
    check(type(run) is dict and type(run.get('repository')) is dict and
          run.get('id') == run_id and run.get('run_attempt') == attempt and
          run['repository'].get('full_name') == custody.REPO and
          run.get('path') == WORKFLOW and run.get('event') == 'workflow_dispatch' and
          run.get('head_sha') == policy['consumer_commit'] and
          run.get('status') == 'completed' and
          run.get('conclusion') in ('failure', 'cancelled', 'timed_out'),
          'run is not terminal failure at approved revision')
    check(type(jobs) is dict and type(jobs.get('jobs')) is list and
          jobs.get('total_count') == len(jobs['jobs']) and
          all(type(job) is dict for job in jobs['jobs']),
          'incomplete or malformed jobs API')
    matches = [job for job in jobs['jobs'] if job.get('id') == att['job']['id']]
    check(len(matches) == 1, 'missing exact issued job')
    job = matches[0]
    check(job.get('name') == JOB and job.get('run_id') == run_id and
          job.get('run_attempt') == attempt and
          job.get('head_sha') == policy['consumer_commit'] and
          job.get('status') == 'completed' and
          job.get('conclusion') in ('failure', 'cancelled', 'timed_out'),
          'issued job is not terminal failure')
    payload = {'schema': 'incoming-issued-failure-v1', 'kind': 'failure',
               'queue_id': att['queue_id'], 'event_id': att['event_id'],
               'reservation': att['reservation'],
               'reservation_digest': att['reservation_digest'],
               'run_id': att['run_id'], 'job': att['job'],
               'start_sequence': start['sequence'], 'start_sha256': digest,
               'run_api_sha256': hashlib.sha256(run_raw).hexdigest(),
               'jobs_api_sha256': hashlib.sha256(jobs_raw).hexdigest(),
               'run_conclusion': run['conclusion'],
               'job_conclusion': job['conclusion']}
    starter.clean_checkout(policy['consumer_commit'])
    key = starter.read_key(key_path, private_root)
    db = open_queue(database)
    try:
        action, final_digest = issue_failure(db, (start['sequence'], digest),
                                              payload, key,
                                              datetime.now(timezone.utc).isoformat())
    finally:
        db.close()
    return {'schema': 'incoming-operator-issued-failure-v1',
            'status': 'pending_retry', 'sequence': action['sequence'],
            'sha256': final_digest, 'run_id': att['run_id'],
            'job_id': att['job']['id'], 'run_conclusion': run['conclusion'],
            'job_conclusion': job['conclusion'], 'operator_workspace': str(owner)}


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
        print(json.dumps(fail(args.database, args.private_root, args.policy,
                              args.key, args.run_id, args.attempt), sort_keys=True))
        return 0
    except (PollError, custody.CustodyError, observation.StartError,
            OSError, ValueError, TypeError, KeyError, IndexError,
            AttributeError, RecursionError, subprocess.SubprocessError) as exc:
        print('operator failure rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
