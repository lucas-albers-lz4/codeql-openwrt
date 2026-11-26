#!/usr/bin/env python3
"""Resolve pinned historical LuCI objects without claiming live event custody."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from tools import default_branch_event as event
from tools import direct_commit_admission as admission
from tools import incoming_poll as poll


def resolve(source_checkout: Path, control_checkout: Path) -> dict:
    oracle = admission.frozen_oracle()
    commits = oracle['commits']
    url = event.incoming_event.REPOSITORIES['luci']
    source = event.checkout_identity(source_checkout, url, commits['introduced'])
    control = event.checkout_identity(control_checkout, url, commits['fixed'])
    poll.check(event.first_parent_from_object(source_checkout, source['commit']) ==
               commits['absent_parent'], 'historical source first parent differs')
    base = {'commit': commits['absent_parent'],
            'tree': event.safe_git(source_checkout, 'rev-parse',
                                   commits['absent_parent'] + '^{tree}')}
    for role, identity in (('source', source), ('base', base), ('control', control)):
        poll.check(event.canonical_fetch('openwrt/luci', identity['commit']) == identity,
                   'canonical ' + role + ' object differs')
    poll.check(event.checkout_identity(source_checkout, url, source['commit']) == source and
               event.checkout_identity(control_checkout, url, control['commit']) == control,
               'historical checkout changed during resolution')
    return {
        'schema': 'historical-direct-commit-source-identity-v1',
        'status': 'historical_objects_resolved_only',
        'repository': 'openwrt/luci',
        'repository_url': url,
        'ref': 'master',
        'source': source,
        'base': base,
        'control': control,
        'limitations': [
            'This is a pinned historical object lookup, not a live default-branch event.',
            'No gap record or linked checkpoint was replayed; incoming event custody is unproven.',
            'Object identity does not establish installed package bytes, runtime reachability or a scan.',
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-checkout', type=Path, required=True)
    parser.add_argument('--control-checkout', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        for checkout in (args.source_checkout.resolve(), args.control_checkout.resolve()):
            poll.check(not args.receipt.resolve().is_relative_to(checkout),
                       'receipt must be outside source and control checkouts')
        event.write_receipt_exclusive(args.receipt, resolve(args.source_checkout,
                                                            args.control_checkout))
        return 0
    except (poll.PollError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('historical direct-commit identity rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
