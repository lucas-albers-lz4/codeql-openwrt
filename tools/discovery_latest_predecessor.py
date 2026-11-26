#!/usr/bin/env python3
"""Require a discovery genesis or successor to extend the latest main chain."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import stat
import sys

from tools import incoming_poll as poll

MAX_API_BYTES = 8_000_000
MAX_RUNS_PER_EVENT = 100
MAX_RUNS = MAX_RUNS_PER_EVENT * 2
WORKFLOW = '.github/workflows/incoming-discovery-manual.yml'
CHAIN_EVENTS = ('workflow_dispatch', 'schedule')


def verify(doc: dict, repository: str, genesis: bool,
           prior_run: str, prior_attempt: str, current_run: str = '',
           current_event: str = 'workflow_dispatch',
           resolve_latest: bool = False) -> dict:
    poll.check(isinstance(doc, dict), 'latest discovery API response is not an object')
    count, runs = doc.get('total_count'), doc.get('workflow_runs')
    poll.check(type(count) is int and 0 <= count <= MAX_RUNS and
               isinstance(runs, list) and len(runs) == count,
               'invalid latest discovery run API response')
    poll.check(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)),
               'invalid repository')
    poll.check(not current_run or bool(re.fullmatch(r'[1-9][0-9]*', current_run)),
               'invalid current discovery run ID')
    poll.check(current_event in CHAIN_EVENTS, 'unsupported current discovery event')
    poll.check(not resolve_latest or (current_event == 'schedule' and not genesis and
                                      not prior_run and not prior_attempt and current_run),
               'automatic predecessor resolution requires a scheduled successor with current run ID and no explicit predecessor')
    completed = []
    seen = set()
    for run in runs:
        poll.check(isinstance(run, dict) and isinstance(run.get('repository'), dict),
                   'invalid completed discovery run')
        run_id, attempt = run.get('id'), run.get('run_attempt')
        poll.check(type(run_id) is int and run_id > 0 and run_id not in seen and
                   type(attempt) is int and attempt > 0 and
                   run['repository'].get('full_name') == repository and
                   run.get('path') == WORKFLOW,
                   'invalid or rerun discovery history requires reconciliation')
        seen.add(run_id)
        if run.get('event') not in CHAIN_EVENTS:
            poll.check(not current_run or str(run_id) != current_run,
                       'current discovery run event differs')
            continue
        poll.check(attempt == 1 and run.get('head_branch') == 'main' and
                   isinstance(run.get('created_at'), str),
                   'invalid or rerun discovery history requires reconciliation')
        try:
            created = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
        except ValueError as exc:
            raise poll.PollError('invalid completed discovery timestamp') from exc
        poll.check(created.tzinfo is not None, 'missing discovery timestamp timezone')
        if current_run and str(run_id) == current_run:
            poll.check(run.get('event') == current_event and
                       run.get('status') == 'in_progress' and
                       run.get('conclusion') is None,
                       'current discovery run API state differs')
            continue
        poll.check(run.get('status') == 'completed' and
                   isinstance(run.get('conclusion'), str) and run['conclusion'],
                   'other discovery run is not terminal')
        if run['conclusion'] == 'success':
            completed.append((created, run_id, run))
    poll.check(not current_run or int(current_run) in seen,
               'current discovery run missing from API response')
    latest = max(completed, default=None)
    if genesis:
        poll.check(current_event == 'workflow_dispatch' and not resolve_latest and
                   latest is None and not prior_run and not prior_attempt,
                   'genesis requires no successful prior run')
        return {'status': 'genesis_allowed', 'latest_run_id': None}
    poll.check(latest is not None,
               'successor requires a successful prior run')
    run_id, attempt = latest[2]['id'], latest[2]['run_attempt']
    if resolve_latest:
        return {'status': 'latest_predecessor_resolved', 'latest_run_id': run_id,
                'latest_run_attempt': attempt, 'latest_run_event': latest[2]['event']}
    poll.check(bool(re.fullmatch(r'[1-9][0-9]*', prior_run)) and
               bool(re.fullmatch(r'[1-9][0-9]*', prior_attempt)),
               'successor requires a successful prior run')
    poll.check(str(run_id) == prior_run and str(attempt) == prior_attempt,
               'predecessor is not the latest successful main discovery run')
    return {'status': 'latest_predecessor_verified', 'latest_run_id': run_id,
            'latest_run_attempt': attempt, 'latest_run_event': latest[2]['event']}


def read_api(path: Path) -> dict:
    info = path.lstat()
    poll.check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
               info.st_size <= MAX_API_BYTES, 'unsafe latest discovery API file')
    raw = path.read_bytes()
    poll.check(len(raw) <= MAX_API_BYTES, 'latest discovery API file exceeds byte limit')
    doc = json.loads(raw, object_pairs_hook=poll.unique_object)
    if isinstance(doc, dict) and doc.get('schema') == 'incoming-discovery-history-api-v1':
        poll.check(set(doc) == {'schema', 'workflow_dispatch', 'schedule'},
                   'invalid combined discovery history fields')
        runs = []
        seen = set()
        for event in CHAIN_EVENTS:
            response = doc[event]
            poll.check(isinstance(response, dict), 'invalid event-filtered Actions API response')
            count, event_runs = response.get('total_count'), response.get('workflow_runs')
            poll.check(type(count) is int and 0 <= count <= MAX_RUNS_PER_EVENT and
                       isinstance(event_runs, list) and len(event_runs) == count,
                       'event-filtered Actions API history exceeds its bound or is incomplete')
            for run in event_runs:
                poll.check(isinstance(run, dict) and run.get('event') == event,
                           'Actions API event filter returned a different event')
                run_id = run.get('id')
                poll.check(type(run_id) is int and run_id not in seen,
                           'duplicate or invalid run across filtered Actions API responses')
                seen.add(run_id)
                runs.append(run)
        poll.check(len(runs) <= MAX_RUNS, 'combined discovery history exceeds its bound')
        return {'total_count': len(runs), 'workflow_runs': runs}
    return doc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-response', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--genesis', choices=('true', 'false'), required=True)
    parser.add_argument('--prior-run', default='')
    parser.add_argument('--prior-attempt', default='')
    parser.add_argument('--current-run', default='')
    parser.add_argument('--current-event', choices=CHAIN_EVENTS,
                        default='workflow_dispatch')
    parser.add_argument('--resolve-latest', action='store_true',
                        help='resolve the latest successful predecessor for a scheduled successor')
    args = parser.parse_args(argv)
    try:
        result = verify(read_api(args.api_response), args.repository,
                        args.genesis == 'true', args.prior_run, args.prior_attempt,
                        args.current_run, args.current_event, args.resolve_latest)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (poll.PollError, OSError, ValueError, TypeError, KeyError,
            RecursionError) as exc:
        print('discovery predecessor rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
