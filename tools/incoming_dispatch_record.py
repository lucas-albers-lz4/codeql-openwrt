#!/usr/bin/env python3
"""Retain manual incoming workflow inputs before canonical PR resolution.

These are caller assertions, not authenticated queue authority.
"""
import json
import os
from pathlib import Path
import re
import sys


def record(env):
    upstream = env['UPSTREAM']
    number = env['PR_NUMBER']
    source = env['SOURCE_SHA']
    control = env['CONTROL_SHA']
    queue_id = env.get('QUEUE_ID', '')
    sequence = env.get('RESERVATION_SEQUENCE', '')
    digest = env.get('RESERVATION_SHA256', '')
    run_id = env['GITHUB_RUN_ID']
    attempt = env['GITHUB_RUN_ATTEMPT']
    if not (upstream in ('openwrt', 'luci') and
            re.fullmatch(r'[1-9][0-9]*', number) and
            all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (source, control)) and
            re.fullmatch(r'[1-9][0-9]*', run_id) and
            re.fullmatch(r'[1-9][0-9]*', attempt)):
        raise ValueError('invalid incoming dispatch identity')
    present = [bool(value) for value in (queue_id, sequence, digest)]
    if not (all(present) or not any(present)):
        raise ValueError('incomplete reservation dispatch claim')
    result = {'schema': 'incoming-dispatch-inputs-v1',
              'run_id': run_id + '-' + attempt,
              'upstream': upstream, 'pr_number': int(number),
              'source_sha': source, 'control_sha': control,
              'status': 'claimed_unverified' if all(present) else 'absent'}
    if all(present):
        if not (re.fullmatch(r'[0-9a-f]{32}', queue_id) and
                re.fullmatch(r'(0|[1-9][0-9]*)', sequence) and
                re.fullmatch(r'[0-9a-f]{64}', digest)):
            raise ValueError('invalid reservation dispatch claim')
        result.update(queue_id=queue_id, reservation_sequence=int(sequence),
                      reservation_sha256=digest)
    return result


def main():
    try:
        path = Path(sys.argv[1])
        with path.open('x') as output:
            output.write(json.dumps(record(os.environ), sort_keys=True, indent=2) + '\n')
        return 0
    except (ValueError, KeyError, TypeError, IndexError, OSError) as exc:
        print('incoming dispatch record rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
