#!/usr/bin/env python3
"""Resolve one first-parent default-branch commit from a verified gap record.

This is an identity-only operator preflight. It does not select source files,
run CodeQL, approve a scan, or treat a historical commit as a live PR event.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from tools import default_branch_gap as gap
from tools import incoming_event
from tools import incoming_poll as poll


def selected_commit(intervals, repository, source_sha):
    poll.full_sha(source_sha)
    poll.check(repository in poll.REPOS, 'unsupported upstream repository')
    matching = [item for item in intervals if item['repository'] == repository]
    poll.check(len(matching) == 1, 'missing or duplicate repository interval')
    interval = matching[0]
    poll.check(interval['state'] == 'bounded_fast_forward',
               'source is not in a verified fast-forward interval')
    rows = interval['first_parent_commits']
    hits = [i for i, row in enumerate(rows) if row['commit'] == source_sha]
    poll.check(len(hits) == 1, 'source commit is not uniquely enumerated')
    index = hits[0]
    source = rows[index]
    base = interval['prior'] if index == 0 else rows[index - 1]
    poll.check(source['first_parent'] == base['commit'],
               'gap first-parent identity differs')
    return interval, source, base


def safe_git(checkout, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    try:
        result = subprocess.run(['git', '-C', str(checkout), *args], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=True, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise poll.PollError(f'local Git command failed: {args[0]}') from exc
    poll.check(len(result.stdout) <= 1_048_576, 'local Git output exceeds byte limit')
    return result.stdout.decode('utf-8', errors='strict').strip()


def checkout_identity(checkout, expected_url, commit):
    poll.full_sha(commit)
    poll.check(safe_git(checkout, 'rev-parse', '--show-toplevel') == str(checkout.resolve()),
               'Git checkout path differs')
    urls = safe_git(checkout, 'remote', 'get-url', '--all', 'origin').splitlines()
    normalized = {url.removesuffix('/').removesuffix('.git') for url in urls}
    poll.check(normalized == {expected_url.removesuffix('.git')}, 'checkout origin differs')
    poll.check(safe_git(checkout, 'rev-parse', '--verify', f'{commit}^{{commit}}') == commit,
               'resolved commit differs')
    poll.check(safe_git(checkout, 'rev-parse', 'HEAD') == commit, 'checkout HEAD differs')
    poll.check(not safe_git(checkout, 'status', '--porcelain=v1', '--untracked-files=all'),
               'checkout is dirty')
    tree = safe_git(checkout, 'rev-parse', f'{commit}^{{tree}}')
    poll.full_sha(tree)
    return {'commit': commit, 'tree': tree}


def first_parent_from_object(checkout, commit):
    size = safe_git(checkout, 'cat-file', '-s', commit)
    poll.check(size.isdecimal() and int(size) <= 1_048_576, 'commit object exceeds byte limit')
    raw = safe_git(checkout, 'cat-file', '-p', commit)
    poll.check('\n\n' in raw, 'commit object lacks header separator')
    headers = raw.split('\n\n', 1)[0]
    poll.check(any(line.startswith('tree ') and re.fullmatch(r'tree [0-9a-f]{40}', line)
                   for line in headers.splitlines()), 'commit object lacks tree header')
    parents = [line.removeprefix('parent ') for line in headers.splitlines()
               if line.startswith('parent ')]
    poll.check(all(re.fullmatch(r'[0-9a-f]{40}', parent) for parent in parents),
               'malformed parent header')
    poll.check(parents, 'source commit has no first parent')
    return poll.full_sha(parents[0])


def canonical_fetch(repository, commit):
    key = repository.removeprefix('openwrt/')
    poll.check(key in incoming_event.REPOSITORIES, 'unsupported canonical repository')
    return incoming_event._fetch_commit_identity(
        incoming_event.REPOSITORIES[key], commit, 'https')


def write_receipt_exclusive(path, receipt):
    raw = (json.dumps(receipt, indent=2) + '\n').encode()
    poll.check(len(raw) <= poll.MAX_RECORD, 'receipt exceeds byte limit')
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def resolve(intervals, repository, source_sha, source_checkout, control_sha,
            control_checkout, gap_sha, previous_sha, current_sha):
    """Resolve exact Git identities after the caller has replayed the gap."""
    poll.full_sha(control_sha)
    poll.check(all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                   for value in (gap_sha, previous_sha, current_sha)),
               'invalid evidence digest')
    poll.check(source_sha != control_sha, 'source and control must differ')
    interval, selected, base_row = selected_commit(intervals, repository, source_sha)
    key = repository.removeprefix('openwrt/')
    url = incoming_event.REPOSITORIES[key]
    source = checkout_identity(source_checkout, url, source_sha)
    control = checkout_identity(control_checkout, url, control_sha)
    poll.check(source['tree'] == selected['tree'], 'source tree differs from gap')
    poll.check(first_parent_from_object(source_checkout, source_sha) == base_row['commit'],
               'source object first parent differs from gap')
    base = canonical_fetch(repository, base_row['commit'])
    poll.check(base == {'commit': base_row['commit'], 'tree': base_row['tree']},
               'canonical base object differs from gap')
    poll.check(canonical_fetch(repository, source_sha) == source,
               'canonical source object differs from checkout')
    poll.check(canonical_fetch(repository, control_sha) == control,
               'canonical control object differs from checkout')
    poll.check(checkout_identity(source_checkout, url, source_sha) == source,
               'source checkout changed during lookup')
    poll.check(checkout_identity(control_checkout, url, control_sha) == control,
               'control checkout changed during lookup')
    return {
        'schema': 'default-branch-event-identity-v1',
        'status': 'identities_resolved_only',
        'repository': repository,
        'repository_url': url,
        'ref': interval['ref'],
        'source': source,
        'base': base,
        'control': control,
        'gap_sha256': gap_sha,
        'previous_checkpoint_sha256': previous_sha,
        'current_checkpoint_sha256': current_sha,
        'limitations': [
            'Gap replay proves internal consistency, not external API custody.',
            'Canonical object availability and a gap record do not prove runtime reachability or scan approval.',
            'The distinct control object is not validated as a fixed or no-alert comparator.',
            'No source selection, package-byte mapping, CodeQL scan, SARIF, or consumer handoff occurred.',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--gap', type=Path, required=True)
    parser.add_argument('--repository', choices=poll.REPOS, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--source-checkout', type=Path, required=True)
    parser.add_argument('--control-sha', required=True)
    parser.add_argument('--control-checkout', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt_path = args.receipt.resolve()
        for checkout in (args.source_checkout.resolve(), args.control_checkout.resolve()):
            poll.check(not receipt_path.is_relative_to(checkout),
                       'receipt must be outside source and control checkouts')
        current_doc, current_sha, observed, prior_sha, _ = poll.verify_checkpoint_decisions(
            args.current, args.previous)
        previous_doc, previous_sha = poll.load_checkpoint(args.previous)
        poll.check(prior_sha == previous_sha, 'checkpoint predecessor differs')
        with args.gap.open('rb') as handle:
            raw = handle.read(poll.MAX_RECORD + 1)
        poll.check(len(raw) <= poll.MAX_RECORD, 'gap input exceeds byte limit')
        gap_record = json.loads(raw, object_pairs_hook=poll.unique_object)
        poll.check(isinstance(gap_record, dict), 'invalid gap record')
        poll.check(gap_record.get('previous_sha256') == previous_sha and
                   gap_record.get('current_sha256') == current_sha,
                   'gap checkpoint digests differ')
        intervals = gap.replay_record(gap_record, previous_doc, current_doc, observed)
        receipt = resolve(intervals, args.repository, args.source_sha,
                          args.source_checkout, args.control_sha,
                          args.control_checkout, hashlib.sha256(raw).hexdigest(),
                          previous_sha, current_sha)
        write_receipt_exclusive(args.receipt, receipt)
        return 0
    except (poll.PollError, incoming_event.InvalidEvent, OSError, ValueError,
            KeyError, TypeError, RecursionError) as exc:
        print('default-branch event rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
