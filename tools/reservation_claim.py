#!/usr/bin/env python3
"""Retain an operator-supplied queue reservation claim in the scan job.

This checks identity against the same-job resolved PR. The queue does not
authorize this claim; it is not a start, signature, or completion.
"""
import json
import os
from pathlib import Path
import re
import sys

from incoming_poll import PollError, unique_object


class ClaimError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise ClaimError(message)


def claim(fields, receipt, run_id):
    queue_id, sequence, digest = (fields[key] for key in
                                  ('queue_id', 'reservation_sequence', 'reservation_sha256'))
    present = [bool(item) for item in (queue_id, sequence, digest)]
    need(all(present) or not any(present), 'reservation claim is incomplete')
    need(re.fullmatch(r'[1-9][0-9]*-[1-9][0-9]*', run_id), 'invalid run identity')
    need(receipt.get('schema') == 'incoming-event-receipt-v1' and
         receipt.get('status') == 'identities_resolved_only' and
         receipt.get('repository') in ('openwrt', 'luci') and
         type(receipt.get('pr_number')) is int and receipt['pr_number'] > 0,
         'unresolved PR identity')
    source, control = receipt['source']['commit'], receipt['control']['commit']
    need(all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (source, control)),
         'invalid source or control commit')
    common = {'schema': 'incoming-reservation-claim-v1', 'run_id': run_id,
              'event_id': json.dumps(['openwrt/' + receipt['repository'],
                                      'pull_request', receipt['pr_number'], source],
                                     separators=(',', ':')),
              'source_sha': source, 'control_sha': control}
    if not any(present):
        return {**common, 'status': 'absent'}
    need(re.fullmatch(r'[0-9a-f]{32}', queue_id) and
         re.fullmatch(r'(0|[1-9][0-9]*)', sequence) and
         re.fullmatch(r'[0-9a-f]{64}', digest), 'invalid reservation claim fields')
    return {**common, 'status': 'claimed_unverified', 'queue_id': queue_id,
            'reservation_sequence': int(sequence), 'reservation_sha256': digest}


def main():
    receipt_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    try:
        need(not output_path.exists() and not output_path.is_symlink(), 'claim output exists')
        receipt = json.loads(receipt_path.read_bytes(), object_pairs_hook=unique_object)
        fields = {key: os.environ.get(key.upper(), '') for key in
                  ('queue_id', 'reservation_sequence', 'reservation_sha256')}
        result = claim(fields, receipt, os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'])
        with output_path.open('x') as output:
            output.write(json.dumps(result, sort_keys=True, indent=2) + '\n')
        return 0
    except (ClaimError, PollError, ValueError, KeyError, TypeError, OSError, IndexError) as exc:
        print('reservation claim rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
