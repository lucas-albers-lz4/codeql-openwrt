#!/usr/bin/env python3
"""Prepare, but do not issue, exact manual event inputs from a discovery record.

The supplied API response is an operator-retained observation. The event
workflow must fetch and verify a new canonical response and source tree.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

from tools.incoming_poll import (MAX_RECORD, REPOS as POLL_REPOS, PollError,
                                 plan, read_checkpoint, snapshot, unique_object)

SHA = re.compile(r'[0-9a-f]{40}\Z')
REPOS = {'openwrt/openwrt': 'openwrt', 'openwrt/luci': 'luci'}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PollError(message)


def replay_observed(checkpoint: Path, expected_digest: str) -> list[dict]:
    with checkpoint.open('rb') as handle:
        raw = handle.read(MAX_RECORD + 1)
    require(len(raw) <= MAX_RECORD and hashlib.sha256(raw).hexdigest() == expected_digest,
            'checkpoint changed after validation')
    doc = json.loads(raw, object_pairs_hook=unique_object)
    requests = iter(doc['requests'])

    def get(path: str):
        request = next(requests, None)
        require(request is not None and request['path'] == path,
                'retained API request order or path differs from replay')
        body = base64.b64decode(request['body_base64'], validate=True)
        return json.loads(body, object_pairs_hook=unique_object), request['link']

    observed = []
    for repo in POLL_REPOS:
        observed.extend(snapshot(repo, get, 401))
    require(next(requests, None) is None, 'unused API request in checkpoint')
    return observed


def prepare(checkpoint: Path, api_response: Path, repository: str,
            number: int, source_sha: str) -> dict:
    require(repository in REPOS, 'unsupported upstream repository')
    require(type(number) is int and number > 0, 'invalid PR number')
    require(isinstance(source_sha, str) and SHA.fullmatch(source_sha) is not None,
            'invalid source SHA')
    decisions, checkpoint_digest = read_checkpoint(checkpoint)
    plan(decisions, [], 0)  # Validate event identities and decision multiplicity.
    observed = replay_observed(checkpoint, checkpoint_digest)
    matched = [row for row in decisions if row['event']['repository'] == repository
               and row['event']['kind'] == 'pull_request'
               and row['event']['number'] == number
               and row['event']['source']['commit'] == source_sha]
    require(len(matched) == 1, 'exact PR head absent or duplicated in checkpoint')
    event = matched[0]['event']
    require(sum(candidate == event for candidate in observed) == 1,
            'PR head was not derived from retained current API responses')
    with api_response.open('rb') as handle:
        raw_api = handle.read(2_000_001)
    require(len(raw_api) <= 2_000_000, 'PR API response exceeds byte limit')
    api = json.loads(raw_api, object_pairs_hook=unique_object)
    require(isinstance(api, dict) and type(api.get('number')) is int and
            api.get('number') == number and
            api.get('state') == 'open', 'canonical PR response does not identify an open PR')
    base, head = api.get('base'), api.get('head')
    require(isinstance(base, dict) and isinstance(head, dict) and
            isinstance(base.get('repo'), dict) and isinstance(head.get('repo'), dict),
            'PR response lacks base or head repository')
    require(base['repo'].get('full_name') == repository and
            head['repo'].get('full_name') == event['head_repository'] and
            head['repo'].get('fork') is event['head_fork'],
            'PR repository identity changed')
    require(base.get('ref') == event['base_ref'] and
            head.get('ref') == event['head_ref'], 'PR branch identity changed')
    require(base.get('sha') == event['base_commit'] == event['base']['commit'] and
            head.get('sha') == source_sha, 'PR head or base changed since discovery')
    require(SHA.fullmatch(base['sha']) is not None, 'invalid base SHA')
    require(base['sha'] != source_sha, 'PR head and control candidate are identical')
    return {
        'schema': 'incoming-pr-dispatch-inputs-v1',
        'status': 'prepared_only',
        'upstream': REPOS[repository],
        'pr_number': number,
        'source_sha': source_sha,
        'control_sha': base['sha'],
        'discovery_checkpoint_sha256': checkpoint_digest,
        'discovery_decision': matched[0]['decision'],
        'api_response_sha256': hashlib.sha256(raw_api).hexdigest(),
        'limitations': [
            'An explicit operator may choose a backlog row; this is not the poller-selected work item or scan authorization.',
            'The PR event is replayed from retained response bodies, but this helper does not authenticate their original fetch or the full decision policy.',
            'The API response was supplied by the operator; this helper does not authenticate its fetch.',
            'The proposed base is a control candidate, not an established clean scan.',
            'No dispatch, source tree resolution, CodeQL execution, SARIF or queue completion occurred.',
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint', type=Path, required=True)
    parser.add_argument('--api-response', type=Path, required=True)
    parser.add_argument('--repository', choices=sorted(REPOS), required=True)
    parser.add_argument('--number', type=int, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.checkpoint, args.api_response, args.repository,
                         args.number, args.source_sha)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as handle:
            json.dump(result, handle, indent=2)
            handle.write('\n')
        print(json.dumps({key: result[key] for key in ('status', 'upstream', 'pr_number', 'source_sha', 'control_sha')}))
        return 0
    except (PollError, ValueError, KeyError, TypeError, OSError, RecursionError) as exc:
        print('dispatch inputs rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
