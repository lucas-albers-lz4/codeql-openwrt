#!/usr/bin/env python3
"""Bind one linked default-branch first-parent commit to a source-first corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from tools import default_branch_event as branch_event
from tools import default_branch_gap as gap
from tools import event_corpus_manifest as corpus
from tools import full_tree_candidates as candidates
from tools import incoming_poll as poll

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'docs/current-corpus-source-v0.6.json'
POLICY_SHA256 = candidates.EXPECTED_MANIFESTS['mvp-bounded-corpus-v0.6']
MAX_SMALL_INPUT = 2_000_000


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read_small(path: Path) -> tuple[bytes, dict]:
    with path.open('rb') as handle:
        raw = handle.read(MAX_SMALL_INPUT + 1)
    poll.check(len(raw) <= MAX_SMALL_INPUT, 'default-branch input exceeds byte limit')
    doc = json.loads(raw, object_pairs_hook=poll.unique_object)
    poll.check(isinstance(doc, dict), 'default-branch input is not an object')
    return raw, doc


def build(previous: Path, current: Path, gap_path: Path, identity_path: Path,
          inventory_path: Path, source_checkout: Path, control_checkout: Path) -> dict:
    poll.check(not branch_event.safe_git(ROOT, 'status', '--porcelain=v1',
                                         '--untracked-files=all'),
               'consumer checkout is dirty')
    poll.check(digest(POLICY) == POLICY_SHA256, 'frozen v0.6 policy digest differs')
    policy_raw, policy = read_small(POLICY)
    identity_raw, identity = read_small(identity_path)
    inventory_raw, inventory = read_small(inventory_path)
    current_doc, current_sha, observed, prior_sha, _ = poll.verify_checkpoint_decisions(
        current, previous)
    previous_doc, previous_sha = poll.load_checkpoint(previous)
    poll.check(prior_sha == previous_sha, 'checkpoint predecessor differs')
    gap_record = gap.load_gap(gap_path)
    poll.check(isinstance(gap_record, dict) and
               gap_record.get('previous_sha256') == previous_sha and
               gap_record.get('current_sha256') == current_sha,
               'linked gap checkpoint digests differ')
    intervals = gap.replay_record(gap_record, previous_doc, current_doc, observed)
    poll.check(identity.get('schema') == 'default-branch-event-identity-v1' and
               identity.get('status') == 'identities_resolved_only' and
               identity.get('repository') in poll.REPOS and
               identity.get('gap_sha256') == digest(gap_path) and
               identity.get('previous_checkpoint_sha256') == previous_sha and
               identity.get('current_checkpoint_sha256') == current_sha,
               'default-branch event identity differs')
    source, base, control = (identity.get(role) for role in ('source', 'base', 'control'))
    poll.check(all(isinstance(row, dict) for row in (source, base, control)),
               'default-branch source/base/control missing')
    fresh_identity = branch_event.resolve(
        intervals, identity['repository'], source['commit'], source_checkout,
        control['commit'], control_checkout, digest(gap_path), previous_sha, current_sha)
    poll.check(identity == fresh_identity, 'default-branch event differs from fresh Git resolution')
    repository = identity['repository'].removeprefix('openwrt/')
    fresh_inventory = candidates.compare(source_checkout, base['commit'],
                                         source['commit'], policy, policy_raw,
                                         repository)
    poll.check(inventory == fresh_inventory and inventory.get('status') == 'inventory_ready',
               'default-branch candidate inventory differs from fresh Git objects')
    derived = dict(identity, repository=repository)
    manifest = corpus.build(policy, derived, inventory, source_checkout,
                            policy_sha256=POLICY_SHA256)
    manifest['schema'] = 'mvp-default-branch-commit-corpus-v1'
    manifest['event'].pop('pr_number', None)
    manifest['event'].update(
        kind='default_branch_commit', source_role='incoming_default_branch_first_parent',
        first_parent_commit=base['commit'], control_commit=control['commit'],
        policy_base_commit=policy['pins'][repository],
        identity_receipt_sha256=hashlib.sha256(identity_raw).hexdigest(),
        candidate_inventory_sha256=hashlib.sha256(inventory_raw).hexdigest(),
        gap_sha256=digest(gap_path), previous_checkpoint_sha256=previous_sha,
        current_checkpoint_sha256=current_sha,
        policy_sha256=POLICY_SHA256,
        route_oracle_script_sha256=digest(ROOT / 'tools/event_corpus_manifest.py'),
        selector_script_sha256=digest(ROOT / 'tools/full_tree_candidates.py'),
        default_branch_resolver_script_sha256=digest(ROOT / 'tools/default_branch_event.py'),
        builder_script_sha256=digest(Path(__file__)),
        consumer_commit=branch_event.safe_git(ROOT, 'rev-parse', 'HEAD'))
    manifest['boundaries'] = [
        'The linked gap establishes a bounded first-parent discovery interval; it does not approve a scan or prove that the commit was observed as a tip.',
        'The full selected corpus is staged from source at reviewed installed-path projections; actual installed package bytes are unverified.',
        'The control commit is a distinct Git object, not an asserted clean or fixed scan result.',
        'The frozen v0.6 policy governs candidate selection and recipe drift; a new or unreviewed path fails closed.',
        'This is an input oracle; no released CodeQL scan, SARIF or consumer result was produced by this builder.',
    ]
    manifest['status'] = 'source_first_default_branch_oracle_only'
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('previous', 'current', 'gap', 'identity', 'inventory',
                 'source_checkout', 'control_checkout', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        poll.check(not branch_event.safe_git(ROOT, 'status', '--porcelain=v1',
                                             '--untracked-files=all'),
                   'consumer checkout is dirty')
        for checkout in (args.source_checkout.resolve(), args.control_checkout.resolve()):
            poll.check(not args.output.resolve().is_relative_to(checkout),
                       'manifest output must be outside source/control checkout')
        result = build(args.previous, args.current, args.gap, args.identity,
                       args.inventory, args.source_checkout, args.control_checkout)
        branch_event.write_receipt_exclusive(args.output, result)
        return 0
    except (poll.PollError, candidates.SelectorError,
            branch_event.incoming_event.InvalidEvent, OSError,
            ValueError, TypeError, KeyError, RecursionError) as exc:
        print('default-branch corpus manifest rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
