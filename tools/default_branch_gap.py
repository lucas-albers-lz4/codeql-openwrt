#!/usr/bin/env python3
"""Read-only, bounded first-parent gap preflight for two discovery checkpoints.

This enumerates observed default-branch history; it does not approve a scan or
claim that intermediate commits were observed as branch tips in real time.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

from tools import incoming_poll as poll


MAX_COMPARE_COMMITS = 100


def tips(events):
    result = {}
    for event in events:
        if event['kind'] != 'default_branch':
            continue
        repo = event['repository']
        poll.check(repo in poll.REPOS and repo not in result, 'duplicate default branch')
        poll.validate_event(event)
        result[repo] = event
    poll.check(set(result) == set(poll.REPOS), 'missing default branch')
    return result


def first_parent_interval(old, new, data, link, repo_id=None):
    """Validate one complete compare response and return first-parent commits."""
    old_sha, new_sha = old['source']['commit'], new['source']['commit']
    poll.check(old['repository'] == new['repository'] and old['ref'] == new['ref'],
               'default branch identity changed')
    poll.check(old_sha != new_sha, 'unchanged tip must not be compared')
    links = poll.link_values(link)
    poll.check(len(links) <= 1, 'paginated compare response')
    if links:
        url, relations = links[0]
        parsed = urlsplit(url)
        suffix = '/compare/' + old_sha + '...' + new_sha
        path = parsed.path
        expected_repo_path = '/repos/' + old['repository'] + suffix
        numeric_repo_path = (type(repo_id) is int and repo_id > 0 and
                             path == '/repositories/' + str(repo_id) + suffix)
        poll.check(relations == ['first'] and parsed.scheme == 'https' and
                   parsed.netloc == 'api.github.com' and not parsed.fragment and
                   (path == expected_repo_path or numeric_repo_path) and
                   parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True) ==
                   {'per_page': [str(MAX_COMPARE_COMMITS)], 'page': ['1']},
                   'unexpected compare pagination link')
    poll.check(isinstance(data, dict), 'invalid compare response')
    poll.check(data.get('status') == 'ahead' and data.get('behind_by') == 0,
               'default branch is not a verified fast-forward')
    count = data.get('total_commits')
    poll.check(type(count) is int and 1 <= count <= MAX_COMPARE_COMMITS and
               data.get('ahead_by') == count, 'compare commit count outside bound')
    commits = data.get('commits')
    poll.check(isinstance(commits, list) and len(commits) == count,
               'compare commits truncated or duplicated')
    base, merge_base = data.get('base_commit'), data.get('merge_base_commit')
    poll.check(isinstance(base, dict) and isinstance(merge_base, dict) and
               base.get('sha') == old_sha and merge_base.get('sha') == old_sha,
               'compare base does not match prior tip')
    base_commit = base.get('commit')
    poll.check(isinstance(base_commit, dict) and isinstance(base_commit.get('tree'), dict),
               'invalid compare base tree')
    old_tree = base_commit['tree'].get('sha')
    poll.check(poll.full_sha(old_tree) == old['source']['tree'],
               'prior tip tree changed')

    by_sha = {}
    for commit in commits:
        poll.check(isinstance(commit, dict), 'invalid compare commit')
        sha = poll.full_sha(commit.get('sha'))
        parents = commit.get('parents')
        details = commit.get('commit')
        poll.check(sha not in by_sha and isinstance(parents, list) and parents,
                   'duplicate or parentless compare commit')
        poll.check(isinstance(details, dict) and isinstance(details.get('tree'), dict) and
                   all(isinstance(parent, dict) for parent in parents),
                   'invalid compare commit fields')
        tree = details['tree'].get('sha')
        parent_shas = [poll.full_sha(parent.get('sha')) for parent in parents]
        by_sha[sha] = {'commit': sha, 'tree': poll.full_sha(tree),
                       'first_parent': parent_shas[0]}
    poll.check(new_sha in by_sha and by_sha[new_sha]['tree'] == new['source']['tree'],
               'new tip or tree missing from compare')

    path = []
    current = new_sha
    while current != old_sha:
        poll.check(current in by_sha and len(path) < count,
                   'first-parent path missing or cyclic')
        path.append(by_sha[current])
        current = by_sha[current]['first_parent']
    path.reverse()
    return path


def preflight(previous_doc, current_doc, current_observed, get):
    prior = tips(poll.replay_observed_doc(previous_doc))
    retained = {poll.key(row['event']) for row in previous_doc['decisions']}
    poll.check(all(poll.key(event) in retained for event in prior.values()),
               'prior observed tip missing from predecessor decisions')
    current = tips(current_observed)
    intervals = []
    for repo in poll.REPOS:
        old, new = prior[repo], current[repo]
        repo_id = repo_id_from_checkpoint(previous_doc, repo)
        poll.check(repo_id == repo_id_from_checkpoint(current_doc, repo),
                   'repository numeric identity changed between checkpoints')
        if old['source'] == new['source']:
            commits = []
            state = 'unchanged'
        else:
            poll.check(old['source']['commit'] != new['source']['commit'],
                       'same commit has changed tree')
            path = f"/repos/{repo}/compare/{old['source']['commit']}...{new['source']['commit']}?per_page={MAX_COMPARE_COMMITS}&page=1"
            data, link = get(path)
            commits = first_parent_interval(old, new, data, link, repo_id)
            state = 'bounded_fast_forward'
        intervals.append({'repository': repo, 'ref': new['ref'], 'prior': old['source'],
                          'observed': new['source'], 'state': state,
                          'first_parent_commits': commits})
    return intervals


def repo_id_from_checkpoint(doc, repo):
    rows = [row for row in doc['requests'] if row['path'] == '/repos/' + repo]
    poll.check(len(rows) == 1, 'missing or duplicate retained repository metadata')
    raw = base64.b64decode(rows[0]['body_base64'], validate=True)
    metadata = json.loads(raw, object_pairs_hook=poll.unique_object)
    poll.check(isinstance(metadata, dict) and metadata.get('full_name') == repo and
               type(metadata.get('id')) is int and metadata['id'] > 0,
               'invalid retained repository identity')
    return metadata['id']


def replay_record(record, previous_doc, current_doc, current_observed):
    """Recompute intervals from retained compare responses without network."""
    poll.check(isinstance(record, dict) and set(record) == {
        'schema', 'status', 'observed_at', 'previous_sha256', 'current_sha256',
        'intervals', 'requests', 'http_errors', 'limitations'}, 'invalid gap record fields')
    poll.check(record['schema'] == 'default-branch-gap-preflight-v1' and
               record['status'] == 'complete' and isinstance(record['requests'], list) and
               isinstance(record['http_errors'], list),
               'invalid gap record metadata')
    requests = iter(record['requests'])

    def get(path):
        request = next(requests, None)
        poll.check(isinstance(request, dict) and set(request) == {
            'path', 'status', 'time', 'link', 'rate_remaining', 'sha256', 'body_base64'},
            'missing or invalid retained compare request')
        poll.check(request['path'] == path and request['status'] == 200 and
                   isinstance(request['link'], str), 'retained compare request differs')
        try:
            raw = base64.b64decode(request['body_base64'], validate=True)
        except (ValueError, TypeError) as exc:
            raise poll.PollError('invalid retained compare encoding') from exc
        poll.check(len(raw) <= poll.MAX_RESPONSE and
                   hashlib.sha256(raw).hexdigest() == request['sha256'],
                   'retained compare digest differs')
        return json.loads(raw, object_pairs_hook=poll.unique_object), request['link']

    intervals = preflight(previous_doc, current_doc, current_observed, get)
    poll.check(next(requests, None) is None, 'unused retained compare response')
    poll.check(record['intervals'] == intervals, 'gap decisions differ from retained responses')
    return intervals


def load_gap(path):
    with path.open('rb') as handle:
        raw = handle.read(poll.MAX_RECORD + 1)
    poll.check(len(raw) <= poll.MAX_RECORD, 'gap record exceeds byte limit')
    return json.loads(raw, object_pairs_hook=poll.unique_object)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument('--output-dir', type=Path)
    output.add_argument('--verify-gap', type=Path)
    args = parser.parse_args(argv)
    created = False
    try:
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=False)
            created = True
        current_doc, current_sha, current_observed, prior_sha, _ = poll.verify_checkpoint_decisions(
            args.current, args.previous)
        poll.check(prior_sha is not None, 'gap preflight requires successor checkpoint')
        previous_doc, previous_sha = poll.load_checkpoint(args.previous)
        poll.check(previous_sha == prior_sha, 'predecessor digest mismatch')
        if args.verify_gap:
            record = load_gap(args.verify_gap)
            poll.check(isinstance(record, dict), 'invalid gap record')
            poll.check(record.get('previous_sha256') == previous_sha and
                       record.get('current_sha256') == current_sha,
                       'gap record checkpoint digests differ')
            replay_record(record, previous_doc, current_doc, current_observed)
            return 0
        intervals = preflight(previous_doc, current_doc, current_observed, poll.fetch)
        result = {'schema': 'default-branch-gap-preflight-v1', 'status': 'complete',
                  'observed_at': datetime.now(timezone.utc).isoformat(),
                  'previous_sha256': previous_sha, 'current_sha256': current_sha,
                  'intervals': intervals, 'requests': poll.REQUEST_LOG,
                  'http_errors': poll.HTTP_ERRORS,
                  'limitations': ['First-parent commits only; not a source or scan approval.',
                                  'Prior checkpoint custody is supplied by the caller.',
                                  'PR head transitions and commits outside the bounded compare are not covered.']}
        replay_record(result, previous_doc, current_doc, current_observed)
        poll.atomic_write(args.output_dir / 'gap.json', result)
        return 0
    except (poll.PollError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        if created:
            try:
                poll.atomic_write(args.output_dir / 'failure.json',
                                  {'status': 'failed', 'error': str(exc),
                                   'failed_request': exc.detail if isinstance(exc, poll.PollError) else None,
                                   'requests': poll.REQUEST_LOG, 'http_errors': poll.HTTP_ERRORS})
            except (poll.PollError, OSError) as failure_exc:
                print('failure record could not be written: ' + str(failure_exc), file=sys.stderr)
        print('default branch gap preflight failed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
