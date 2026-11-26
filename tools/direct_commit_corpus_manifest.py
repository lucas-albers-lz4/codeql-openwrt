#!/usr/bin/env python3
"""Bind a pinned historical direct commit to a source-first corpus manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from tools import default_branch_event as event
from tools import direct_commit_admission as admission
from tools import event_corpus_manifest as corpus
from tools import full_tree_candidates as candidates
from tools import incoming_poll as poll

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'docs/openvpn-historical-source-v0.1.json'
POLICY_SHA256 = candidates.EXPECTED_MANIFESTS['mvp-openvpn-historical-source-v0.1']
MAX_INPUT = 2_000_000


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    return json.loads(raw, object_pairs_hook=poll.unique_object)


def build_manifest(policy_raw, identity_raw, admission_raw, inventory_raw,
                   source_checkout, control_checkout):
    poll.check(digest(policy_raw) == POLICY_SHA256, 'historical policy digest differs')
    policy = parse(policy_raw)
    poll.check(policy.get('schema') == 'mvp-openvpn-historical-source-v0.1',
               'historical policy schema differs')
    identity, admitted, inventory = parse(identity_raw), parse(admission_raw), parse(inventory_raw)
    poll.check(all(isinstance(doc, dict) for doc in (identity, admitted, inventory)),
               'direct-commit input must be objects')
    source = identity.get('source')
    base = identity.get('base')
    poll.check(isinstance(source, dict) and isinstance(base, dict) and
               ((identity.get('schema') == 'default-branch-event-identity-v1' and
                 identity.get('status') == 'identities_resolved_only') or
                (identity.get('schema') == 'historical-direct-commit-source-identity-v1' and
                 identity.get('status') == 'historical_objects_resolved_only')) and
               identity.get('repository') == 'openwrt/luci' and
               ((identity.get('schema') == 'default-branch-event-identity-v1' and
                 identity.get('ref') == 'master') or
                (identity.get('schema') == 'historical-direct-commit-source-identity-v1' and
                 identity.get('policy_ref_context') == 'master' and 'ref' not in identity)),
               'direct-commit identity differs')
    poll.check(source.get('commit') == policy['pins']['luci'] and
               base.get('commit') == policy['admitted_additions'][0]['base_commit'],
               'direct-commit revision differs from historical policy')
    checked = admission.verify(identity, source_checkout, control_checkout)
    checked['identity_receipt_sha256'] = digest(identity_raw)
    poll.check(admitted == checked, 'admission check differs from fresh source verification')
    fresh = candidates.compare(source_checkout, base['commit'], source['commit'],
                               policy, policy_raw, 'luci')
    poll.check(inventory == fresh and inventory.get('status') == 'inventory_ready',
               'historical candidate inventory differs from fresh Git objects')
    path = policy['admitted_additions'][0]['path']
    derived = dict(identity, repository='luci')
    manifest = corpus.build(policy, derived, inventory, source_checkout,
                            policy_sha256=POLICY_SHA256,
                            admitted_additions=(path,),
                            accepted_identity_statuses=(identity['status'],))
    manifest['schema'] = 'mvp-direct-commit-corpus-v1'
    manifest['event'].pop('pr_number', None)
    manifest['event'].update(kind='direct_commit', source_role='historical_direct_commit',
                             identity_receipt_sha256=digest(identity_raw),
                             admission_check_sha256=digest(admission_raw),
                             candidate_inventory_sha256=digest(inventory_raw),
                             historical_policy_sha256=POLICY_SHA256,
                             route_oracle_script_sha256=digest(
                                 (ROOT / 'tools/event_corpus_manifest.py').read_bytes()),
                             direct_builder_script_sha256=digest(Path(__file__).read_bytes()),
                             admission_checker_script_sha256=digest(
                                 (ROOT / 'tools/direct_commit_admission.py').read_bytes()),
                             selector_script_sha256=digest(
                                 (ROOT / 'tools/full_tree_candidates.py').read_bytes()),
                             consumer_commit=event.safe_git(ROOT, 'rev-parse', 'HEAD'))
    manifest['boundaries'] = [
        'Historical policy LuCI pin equals the introduction head, so the generic selected-owner recipe-drift diff is empty; the exact OpenVPN Makefile and luci.mk blobs are checked by the admission verifier.',
        'Other repositories remain at frozen policy pins and have not been refreshed to the historical LuCI commit.',
        'Selected source hashes and routes were checked against Git blobs before extraction; package installation and built IPK bytes remain unverified.',
        'This historical manifest builder does not replay gap/checkpoint bytes; the input identity schema records whether a live interval was supplied or only historical source objects were resolved.',
        'The admission check binds historical source and recipe objects, not actual installed IPK bytes or a no-alert control.',
        'This is a source-first input only; no released CodeQL scan, SARIF or live incoming event was produced.',
    ]
    manifest['status'] = 'historical_direct_commit_source_first_oracle_only'
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--admission-check', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--source-checkout', type=Path, required=True)
    parser.add_argument('--control-checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        poll.check(not event.safe_git(ROOT, 'status', '--porcelain=v1', '--untracked-files=all'),
                   'consumer checkout is dirty')
        for checkout in (args.source_checkout.resolve(), args.control_checkout.resolve()):
            poll.check(not args.output.resolve().is_relative_to(checkout),
                       'manifest output must be outside checkouts')
        policy_raw = admission.read_regular_bounded(POLICY, MAX_INPUT)
        identity_raw = admission.read_regular_bounded(args.identity, MAX_INPUT)
        admission_raw = admission.read_regular_bounded(args.admission_check, MAX_INPUT)
        inventory_raw = admission.read_regular_bounded(args.inventory, MAX_INPUT)
        manifest = build_manifest(policy_raw, identity_raw, admission_raw,
                                  inventory_raw, args.source_checkout,
                                  args.control_checkout)
        event.write_receipt_exclusive(args.output, manifest)
        return 0
    except (poll.PollError, candidates.SelectorError, OSError, ValueError,
            TypeError, KeyError, RecursionError) as exc:
        print('direct-commit corpus manifest rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
