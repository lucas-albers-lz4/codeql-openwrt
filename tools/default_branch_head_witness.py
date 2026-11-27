"""Keyless, read-only comparison of supplied external head-witness bytes.

The caller must authenticate and retain the complete record stream from an
independent monotonic store, and separately authenticate the SQLite queue.
This module opens no paths, initializes no witness, and grants no authority to
sign. A returned decision is an offline fixture classification only.
"""

import hashlib
import json
import re

from tools import default_branch_authenticated_start as authenticated
from tools import default_branch_backlog_issued as issued

SCHEMA = 'default-branch-head-witness-record-v1'
MAX_RECORD_BYTES = 4096
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
FIELDS = frozenset({
    'schema', 'witness_id', 'queue_id', 'queue_generation',
    'reservation_sha256', 'kind', 'sequence', 'issued_sha256',
    'base_issued_sha256', 'previous_record_sha256', 'invocation_id',
})


class WitnessError(ValueError):
    """A supplied witness record or authenticated queue observation is invalid."""


def _need(condition, message):
    if not condition:
        raise WitnessError(message)


def _unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        _need(name not in result, 'duplicate witness field')
        result[name] = value
    return result


def _hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def parse_record(raw):
    """Accept one exact newline-terminated canonical JSON record, no aliases."""
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_RECORD_BYTES,
          'witness record size or type is invalid')
    try:
        record = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                WitnessError('nonfinite witness value')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WitnessError('witness record is not JSON') from exc
    _need(type(record) is dict and set(record) == FIELDS and
          record['schema'] == SCHEMA and
          record['kind'] in ('head', 'pending_intent') and
          type(record['sequence']) is int and record['sequence'] in (1, 2) and
          _hex(record['witness_id'], HEX32) and
          _hex(record['queue_id'], HEX32) and
          _hex(record['queue_generation'], HEX32) and
          _hex(record['reservation_sha256'], HEX64) and
          _hex(record['issued_sha256'], HEX64) and
          _hex(record['base_issued_sha256'], HEX64) and
          _hex(record['previous_record_sha256'], HEX64) and
          _hex(record['invocation_id'], HEX32),
          'witness record fields are invalid')
    _need(raw == issued.canonical_bytes(record),
          'witness record is not canonical JSON')
    return record


def record_sha256(raw):
    parse_record(raw)
    return hashlib.sha256(raw).hexdigest()


def reconcile_records(raw_records, *, witness_id, queue_generation,
                      queue_snapshot):
    """Classify a complete trusted witness stream against an authenticated head.

    `raw_records` must be one fresh authenticated *latest complete* stream,
    not an authentic historical prefix. `queue_snapshot` binds the HMAC-verified
    head, signed start and reservation in one checked read-only SQLite image.
    Pass the direct process-local verifier return, never externally supplied
    JSON with the same field names. The schema marker is not authentication.
    This function cannot authenticate the external witness service or its
    freshness; even `ready` grants no signing authority. Sequence-two verdicts
    require separate exact retained manifest and receipt checks before action.
    """
    for label, value, pattern in (
        ('witness ID', witness_id, HEX32),
        ('queue generation', queue_generation, HEX32),
    ):
        _need(_hex(value, pattern), label + ' is invalid')
    _need(type(queue_snapshot) is dict and
          queue_snapshot.get('schema') == authenticated.HEAD_SNAPSHOT_SCHEMA and
          queue_snapshot.get('hmac_verified') is True and
          _hex(queue_snapshot.get('queue_id'), HEX32) and
          type(queue_snapshot.get('seq')) is int and
          queue_snapshot['seq'] in (1, 2) and
          type(queue_snapshot.get('action_count')) is int and
          queue_snapshot['action_count'] == queue_snapshot['seq'] and
          _hex(queue_snapshot.get('sha256'), HEX64) and
          _hex(queue_snapshot.get('start_sha256'), HEX64) and
          _hex(queue_snapshot.get('reservation_sha256'), HEX64),
          'queue snapshot is not one authenticated issued chain')
    queue_id = queue_snapshot['queue_id']
    start_sha256 = queue_snapshot['start_sha256']
    reservation_sha256 = queue_snapshot['reservation_sha256']
    _need(type(raw_records) in (list, tuple) and len(raw_records) <= 3,
          'witness stream length is invalid')
    if not raw_records:
        return 'freeze'
    records = [parse_record(raw) for raw in raw_records]
    for index, record in enumerate(records):
        _need((record['witness_id'], record['queue_id'],
               record['queue_generation'], record['reservation_sha256']) ==
              (witness_id, queue_id, queue_generation, reservation_sha256),
              'witness custody identity mismatch')
        _need(record['previous_record_sha256'] ==
              (issued.ZERO_HASH if index == 0 else
               hashlib.sha256(raw_records[index - 1]).hexdigest()),
              'witness predecessor mismatch')
    first = records[0]
    _need(first['kind'] == 'head' and first['sequence'] == 1 and
          first['issued_sha256'] == start_sha256 and
          first['base_issued_sha256'] == issued.ZERO_HASH,
          'witness start anchor mismatch')
    if len(records) > 1:
        intent = records[1]
        _need(intent['kind'] == 'pending_intent' and
              intent['sequence'] == 2 and
              intent['base_issued_sha256'] == start_sha256 and
              intent['issued_sha256'] != start_sha256,
              'witness pending intent transition is invalid')
    if len(records) == 3:
        final = records[2]
        _need(final['kind'] == 'head' and final['sequence'] == 2 and
              final['issued_sha256'] == intent['issued_sha256'] and
              final['base_issued_sha256'] == start_sha256 and
              final['invocation_id'] == intent['invocation_id'],
              'witness final transition is invalid')
    seq, digest = queue_snapshot['seq'], queue_snapshot['sha256']
    if len(records) == 1:
        return 'ready' if (seq, digest) == (1, start_sha256) else 'freeze'
    if len(records) == 2:
        if (seq, digest) == (2, intent['issued_sha256']):
            return 'finalize_pending'
        return 'quarantine' if (seq, digest) == (1, start_sha256) else 'freeze'
    return 'existing_terminal' if (seq, digest) == (2, final['issued_sha256']) else 'freeze'
