#!/usr/bin/env python3
"""Retain an unverified reservation assertion bound to one resolved branch scan.

This is an evidence link only. It does not inspect the private queue, authorize
the scan, or mark a reservation started or completed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from tools import default_branch_gap as gap
from tools import incoming_poll as poll


SHA1 = re.compile(r'[0-9a-f]{40}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
QUEUE_ID = re.compile(r'[0-9a-f]{32}\Z')
POSITIVE_INTEGER = re.compile(r'[1-9][0-9]*\Z')
MAX_INPUT = 16 * 1024 * 1024


class ClaimError(ValueError):
    """Invalid or mismatched reservation assertion."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ClaimError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path, label: str) -> tuple[bytes, dict]:
    try:
        with path.open('rb') as handle:
            raw = handle.read(MAX_INPUT + 1)
        need(len(raw) <= MAX_INPUT, label + ' exceeds byte limit')
        value = json.loads(raw, object_pairs_hook=poll.unique_object)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise ClaimError('invalid ' + label) from exc
    need(isinstance(value, dict), label + ' is not an object')
    return raw, value


def positive_input(value: object, label: str) -> int:
    need(isinstance(value, str) and POSITIVE_INTEGER.fullmatch(value) is not None,
         'invalid ' + label)
    return int(value)


def claim(fields: dict, identity: dict, manifest: dict,
          previous_path: Path, current_path: Path, gap_path: Path,
          dispatch: dict, execution: dict, identity_raw: bytes,
          manifest_raw: bytes) -> dict:
    """Build a claim only when the linked inputs agree on exact source identity."""
    keys = ('queue_id', 'reservation_sequence', 'reservation_sha256')
    need(isinstance(fields, dict) and set(fields) == set(keys),
         'invalid reservation claim fields')
    asserted = [fields[key] for key in keys]
    need(all(isinstance(value, str) for value in asserted),
         'reservation claim fields must be strings')
    present = [bool(value) for value in asserted]
    need(all(present) or not any(present), 'reservation claim is incomplete')
    if all(present):
        queue_id, sequence, reservation_sha256 = asserted
        need(QUEUE_ID.fullmatch(queue_id) is not None and
             POSITIVE_INTEGER.fullmatch(sequence) is not None and
             SHA256.fullmatch(reservation_sha256) is not None,
             'invalid reservation claim fields')

    previous_doc, previous_sha = poll.load_checkpoint(previous_path)
    current_doc, current_sha, observed, prior_sha, _ = poll.verify_checkpoint_decisions(
        current_path, previous_path)
    need(prior_sha == previous_sha and current_doc.get('previous_sha256') == previous_sha,
         'linked checkpoint predecessor differs')
    gap_raw, gap_record = read_json(gap_path, 'gap record')
    gap_sha = digest(gap_raw)
    need(gap_record.get('previous_sha256') == previous_sha and
         gap_record.get('current_sha256') == current_sha,
         'gap checkpoint digests differ')
    intervals = gap.replay_record(gap_record, previous_doc, current_doc, observed)

    need(identity.get('schema') == 'default-branch-event-identity-v1' and
         identity.get('status') == 'identities_resolved_only',
         'canonical default-branch identity is unresolved')
    repository = identity.get('repository')
    source = identity.get('source')
    base = identity.get('base')
    control = identity.get('control')
    need(repository in poll.REPOS and isinstance(source, dict) and
         isinstance(base, dict) and isinstance(control, dict),
         'resolved default-branch identity is incomplete')
    source_sha = source.get('commit')
    tree_sha = source.get('tree')
    base_sha = base.get('commit')
    base_tree = base.get('tree')
    control_sha = control.get('commit')
    need(isinstance(source_sha, str) and SHA1.fullmatch(source_sha) and
         isinstance(tree_sha, str) and SHA1.fullmatch(tree_sha),
         'resolved source identity is malformed')
    need(isinstance(base_sha, str) and SHA1.fullmatch(base_sha) and
         isinstance(base_tree, str) and SHA1.fullmatch(base_tree) and
         isinstance(control_sha, str) and SHA1.fullmatch(control_sha) and
         source_sha != control_sha,
         'resolved base or control identity is malformed')
    matching = [interval for interval in intervals
                if interval.get('repository') == repository]
    need(len(matching) == 1 and matching[0].get('state') == 'bounded_fast_forward',
         'resolved source is not in one linked first-parent interval')
    interval = matching[0]
    rows = interval.get('first_parent_commits')
    need(isinstance(rows, list), 'linked first-parent interval is malformed')
    matches = [index for index, row in enumerate(rows)
               if isinstance(row, dict) and row.get('commit') == source_sha]
    need(len(matches) == 1, 'resolved source is not uniquely enumerated in linked gap')
    index = matches[0]
    row = rows[index]
    predecessor = interval.get('prior') if index == 0 else rows[index - 1]
    first_parent = row.get('first_parent')
    need(row.get('tree') == tree_sha and isinstance(predecessor, dict) and
         predecessor.get('commit') == first_parent and
         predecessor.get('commit') == base_sha and
         predecessor.get('tree') == base_tree,
         'resolved commit, tree, or first parent differs from linked gap')
    ref = interval.get('ref')
    need(isinstance(ref, str) and identity.get('ref') == ref and
         identity.get('gap_sha256') == gap_sha and
         identity.get('previous_checkpoint_sha256') == previous_sha and
         identity.get('current_checkpoint_sha256') == current_sha,
         'resolved identity differs from linked gap origin')

    event = manifest.get('event')
    need(isinstance(event, dict), 'source-first manifest event is malformed')
    need(event.get('identity_receipt_sha256') == digest(identity_raw),
         'manifest identity receipt digest differs')
    need(manifest.get('schema') == 'mvp-default-branch-commit-corpus-v1' and
         manifest.get('status') == 'source_first_default_branch_oracle_only' and
         event.get('kind') == 'default_branch_commit' and
         event.get('source_role') == 'incoming_default_branch_first_parent' and
         event.get('repository') == repository.removeprefix('openwrt/') and
         event.get('head_commit') == source_sha and event.get('head_tree') == tree_sha and
         event.get('base_commit') == base_sha and
         event.get('base_tree') == base_tree and
         event.get('first_parent_commit') == first_parent and
         event.get('control_commit') == control_sha and
         event.get('gap_sha256') == gap_sha and
         event.get('previous_checkpoint_sha256') == previous_sha and
         event.get('current_checkpoint_sha256') == current_sha,
         'source-first manifest differs from resolved linked identity')

    previous_run = positive_input(dispatch.get('previous_run_id'), 'predecessor run ID')
    previous_attempt = positive_input(dispatch.get('previous_run_attempt'), 'predecessor attempt')
    current_run = positive_input(dispatch.get('current_run_id'), 'successor run ID')
    current_attempt = positive_input(dispatch.get('current_run_attempt'), 'successor attempt')
    need(previous_run != current_run and dispatch.get('previous_sha256') == previous_sha and
         dispatch.get('current_sha256') == current_sha and
         dispatch.get('gap_sha256') == gap_sha and
         dispatch.get('repository') == repository and
         dispatch.get('source_sha') == source_sha and
         dispatch.get('control_sha') == control_sha,
         'workflow dispatch inputs differ from derived linked identity')

    workflow_run = positive_input(execution.get('run_id'), 'workflow run ID')
    workflow_attempt = positive_input(execution.get('run_attempt'), 'workflow run attempt')
    consumer_head = execution.get('consumer_head')
    actual_head = execution.get('actual_head')
    need(isinstance(consumer_head, str) and SHA1.fullmatch(consumer_head) and
         consumer_head == actual_head == event.get('consumer_commit'),
         'consumer head differs from manifest')

    origin = {
        'previous_run_id': previous_run,
        'previous_attempt': previous_attempt,
        'previous_checkpoint_sha256': previous_sha,
        'current_run_id': current_run,
        'current_attempt': current_attempt,
        'current_checkpoint_sha256': current_sha,
        'gap_sha256': gap_sha,
    }
    result = {
        'schema': 'default-branch-reservation-claim-v1',
        'status': 'claimed_unverified' if all(present) else 'absent',
        'asserted_reservation': None,
        'derived_source': {
            'repository': repository,
            'ref': ref,
            'commit_sha': source_sha,
            'tree_sha': tree_sha,
            'first_parent_sha': first_parent,
            'ordinal': index + 1,
        },
        'linked_discovery_origin': origin,
        'execution': {
            'workflow_run_id': workflow_run,
            'workflow_run_attempt': workflow_attempt,
            'consumer_head': consumer_head,
        },
        'linked_input_sha256': {
            'identity_receipt': digest(identity_raw),
            'manifest': digest(manifest_raw),
            'previous_checkpoint': previous_sha,
            'current_checkpoint': current_sha,
            'gap': gap_sha,
        },
        'limitations': [
            'The reservation triplet is caller asserted and was not checked against the private queue.',
            'This record binds the assertion to the resolved scan input; it does not authorize or start a scan.',
            'The intake origin replays retained checkpoint and gap bytes but does not authenticate their capture origin.',
            'This pre-scan claim does not establish that a scan ran or that a consumer accepted its output.',
        ],
    }
    if all(present):
        queue_id, sequence, reservation_sha256 = asserted
        result['asserted_reservation'] = {
            'queue_id': queue_id,
            'reservation_sequence': int(sequence),
            'reservation_sha256': reservation_sha256,
        }
    return result


def write_exclusive(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(not path.exists() and not path.is_symlink(), 'claim output already exists')
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def write_failure(path: Path, exc: BaseException) -> None:
    """Attempt a small non-success record without copying dispatch values."""
    failure = {
        'schema': 'default-branch-reservation-claim-failure-v1',
        'status': 'claim_failed',
        'error_type': type(exc).__name__,
        'reason': ' '.join(str(exc).split())[:512],
    }
    raw = (json.dumps(failure, sort_keys=True, indent=2) + '\n').encode()
    if len(raw) > 2048 or path.exists() or path.is_symlink():
        return
    try:
        with path.open('xb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        # The command still fails and logs the original reason; artifact output
        # must not replace or hide that failure.
        return


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--gap', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    failure_path = args.output.parent / 'reservation-claim-failure.json'
    try:
        identity_raw, identity = read_json(args.identity, 'identity receipt')
        manifest_raw, manifest = read_json(args.manifest, 'manifest')
        fields = {key: os.environ.get(key.upper(), '') for key in
                  ('queue_id', 'reservation_sequence', 'reservation_sha256')}
        dispatch = {key: os.environ.get(key.upper(), '') for key in
                    ('previous_run_id', 'previous_run_attempt', 'previous_sha256',
                     'current_run_id', 'current_run_attempt', 'current_sha256',
                     'gap_sha256', 'repository', 'source_sha', 'control_sha')}
        execution = {
            'run_id': os.environ.get('GITHUB_RUN_ID', ''),
            'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT', ''),
            'consumer_head': os.environ.get('GITHUB_SHA', ''),
            'actual_head': os.environ.get('CONSUMER_HEAD', ''),
        }
        result = claim(fields, identity, manifest, args.previous, args.current,
                       args.gap, dispatch, execution, identity_raw, manifest_raw)
        write_exclusive(args.output, result)
        return 0
    except (ClaimError, poll.PollError, OSError, ValueError, KeyError,
            TypeError, RecursionError) as exc:
        write_failure(failure_path, exc)
        print('default-branch reservation claim rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
