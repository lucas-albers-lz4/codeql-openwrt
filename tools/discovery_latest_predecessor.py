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

MAX_API_BYTES = 1_000_000
MAX_RUNS = 100
WORKFLOW = '.github/workflows/incoming-discovery-manual.yml'


def verify(doc: dict, repository: str, genesis: bool,
           prior_run: str, prior_attempt: str) -> dict:
    poll.check(isinstance(doc, dict), 'latest discovery API response is not an object')
    count, runs = doc.get('total_count'), doc.get('workflow_runs')
    poll.check(type(count) is int and 0 <= count <= MAX_RUNS and
               isinstance(runs, list) and len(runs) == count,
               'invalid latest discovery run API response')
    poll.check(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)),
               'invalid repository')
    completed = []
    seen = set()
    for run in runs:
        poll.check(isinstance(run, dict) and isinstance(run.get('repository'), dict),
                   'invalid completed discovery run')
        run_id, attempt = run.get('id'), run.get('run_attempt')
        poll.check(type(run_id) is int and run_id > 0 and run_id not in seen and
                   type(attempt) is int and attempt == 1 and
                   run['repository'].get('full_name') == repository and
                   run.get('path') == WORKFLOW and
                   run.get('event') == 'workflow_dispatch' and
                   run.get('head_branch') == 'main' and
                   run.get('status') == 'completed' and
                   isinstance(run.get('conclusion'), str) and run['conclusion'] and
                   isinstance(run.get('created_at'), str),
                   'invalid or rerun discovery history requires reconciliation')
        try:
            created = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
        except ValueError as exc:
            raise poll.PollError('invalid completed discovery timestamp') from exc
        poll.check(created.tzinfo is not None, 'missing discovery timestamp timezone')
        seen.add(run_id)
        if run['conclusion'] == 'success':
            completed.append((created, run_id, run))
    latest = max(completed, default=None)
    if genesis:
        poll.check(latest is None and not prior_run,
                   'genesis requires no successful prior run')
        return {'status': 'genesis_allowed', 'latest_run_id': None}
    poll.check(latest is not None and bool(re.fullmatch(r'[1-9][0-9]*', prior_run)) and
               bool(re.fullmatch(r'[1-9][0-9]*', prior_attempt)),
               'successor requires a successful prior run')
    run_id, attempt = latest[2]['id'], latest[2]['run_attempt']
    poll.check(str(run_id) == prior_run and str(attempt) == prior_attempt,
               'predecessor is not the latest successful main discovery run')
    return {'status': 'latest_predecessor_verified', 'latest_run_id': run_id,
            'latest_run_attempt': attempt}


def read_api(path: Path) -> dict:
    info = path.lstat()
    poll.check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
               info.st_size <= MAX_API_BYTES, 'unsafe latest discovery API file')
    raw = path.read_bytes()
    poll.check(len(raw) <= MAX_API_BYTES, 'latest discovery API file exceeds byte limit')
    return json.loads(raw, object_pairs_hook=poll.unique_object)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-response', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--genesis', choices=('true', 'false'), required=True)
    parser.add_argument('--prior-run', default='')
    parser.add_argument('--prior-attempt', default='')
    args = parser.parse_args(argv)
    try:
        result = verify(read_api(args.api_response), args.repository,
                        args.genesis == 'true', args.prior_run, args.prior_attempt)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (poll.PollError, OSError, ValueError, TypeError, KeyError,
            RecursionError) as exc:
        print('discovery predecessor rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
