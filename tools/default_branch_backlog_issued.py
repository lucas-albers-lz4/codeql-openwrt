#!/usr/bin/env python3
"""Offline v2→v3 migration and first issued-start MAC/CAS primitives.

This module intentionally has no command-line entry point and never reads a
key file. It provides bounded primitives for tests and a future reviewed
operator verifier; it does not authenticate live GitHub observations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
import time

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_reservation as reservation


ISSUED_SCHEMA = 'default-branch-issued-action-v1'
START_SCHEMA = 'default-branch-issued-start-v1'
DOMAIN = b'codeql-openwrt/default-branch-issued-action-v1\n'
ZERO_HASH = '0' * 64
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')
QUEUE_ID = re.compile(r'[0-9a-f]{32}\Z')
DATABASE_NAME = reservation.DATABASE_NAME
START_JOB = 'released-default-branch-scan'
MAX_SQLITE_INT = (1 << 63) - 1

START_KEYS = {
    'schema', 'kind', 'queue_id', 'reservation_sequence',
    'reservation_sha256', 'identity', 'origin_receipt_sha256',
    'origin_gap_sha256', 'policy_sha256', 'consumer_commit',
    'release_lock_sha256', 'run_id', 'run_attempt', 'job_id', 'workflow',
    'job', 'early_artifact', 'observation_sha256', 'run_api_sha256',
    'jobs_api_sha256', 'artifacts_api_sha256', 'recheck_run_api_sha256',
    'recheck_jobs_api_sha256',
}
IDENTITY_KEYS = {
    'repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
    'first_parent_sha', 'intake_id', 'receipt_seq',
}
ARTIFACT_KEYS = {'id', 'sha256', 'size'}
APPROVED_POLICY_KEYS = {'consumer_commit', 'release_lock_sha256'}
ENVELOPE_KEYS = {
    'schema', 'issued_seq', 'previous_issued_sha256', 'observed_at',
    'attestation',
}
DOCUMENT_KEYS = ENVELOPE_KEYS | {'mac'}


class IssuedActionError(ValueError):
    """Fail-closed v3 migration or issued-action error."""


def require(condition, message):
    if not condition:
        raise IssuedActionError(message)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def canonical_bytes(value):
    """Canonical sorted compact UTF-8 JSON with its required final newline."""
    try:
        return (canonical_json(value) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise IssuedActionError('value is not canonical JSON') from exc


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _validate_key(key):
    require(type(key) is bytes and len(key) >= 32,
            'issued-action key must be at least 32 bytes')
    return key


def _canonical_time(value, label):
    require(isinstance(value, str), 'invalid ' + label)
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise IssuedActionError('invalid ' + label) from exc
    require(parsed.tzinfo is not None, label + ' needs a timezone')
    normalized = parsed.astimezone(timezone.utc).isoformat(
        timespec='seconds').replace('+00:00', 'Z')
    require(value == normalized, label + ' must be canonical UTC')
    return parsed.astimezone(timezone.utc)


def _parse_json(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=intake.unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IssuedActionError('invalid ' + label) from exc
    require(type(value) is dict, 'invalid ' + label + ' object')
    return value


def _check_v3_schema(conn):
    require(conn.execute('PRAGMA application_id').fetchone()[0] == intake.APP_ID and
            conn.execute('PRAGMA user_version').fetchone()[0] ==
            intake.ISSUED_SCHEMA_VERSION,
            'backlog database requires explicit v2 to v3 migration')
    # This verifies the exact pre-existing v1/v2 objects and all v3 table
    # columns/triggers. No v1/v2 schema object is rewritten by this module.
    reservation._check_v2_schema(conn)


def _open_existing(private_root):
    try:
        return reservation._open_existing(private_root)
    except reservation.ReservationError as exc:
        raise IssuedActionError(str(exc)) from exc


def _v1_v2_snapshot(conn):
    """Snapshot row values plus existing schema text before additive DDL."""
    rows = {}
    for table, order in (
            ('cursor', 'singleton'),
            ('intakes', 'receipt_seq'),
            ('commit_backlog', 'repository,ref,commit_sha'),
            ('receipts', 'receipt_seq'),
            ('queue_metadata', 'singleton'),
            ('reservation_actions', 'action_seq'),
            ('action_head', 'singleton')):
        rows[table] = [tuple(row) for row in conn.execute(
            'SELECT * FROM ' + table + ' ORDER BY ' + order)]
    schema = [tuple(row) for row in conn.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE substr(name,1,7) != 'sqlite_' AND name NOT IN "
        "('issued_actions','issued_head','issued_actions_no_update',"
        "'issued_actions_no_delete') ORDER BY type,name")]
    return rows, schema


def _create_v3_objects(conn, queue_id):
    for statement in (
            '''CREATE TABLE issued_actions (
                seq INTEGER PRIMARY KEY,
                previous_sha256 TEXT NOT NULL,
                document_json TEXT NOT NULL,
                action_sha256 TEXT NOT NULL UNIQUE
            )''',
            '''CREATE TABLE issued_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                queue_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                hash TEXT NOT NULL
            )''',
            "CREATE TRIGGER issued_actions_no_update BEFORE UPDATE ON issued_actions "
            "BEGIN SELECT RAISE(ABORT, 'issued actions are append-only'); END",
            "CREATE TRIGGER issued_actions_no_delete BEFORE DELETE ON issued_actions "
            "BEGIN SELECT RAISE(ABORT, 'issued actions are append-only'); END",
    ):
        conn.execute(statement)
    conn.execute('INSERT INTO issued_head VALUES (1, ?, 0, ?)',
                 (queue_id, ZERO_HASH))


def migrate_v2_to_v3(private_root):
    """Add the issued chain atomically while preserving all v1/v2 rows/bytes."""
    conn = _open_existing(private_root)
    try:
        conn.execute('BEGIN IMMEDIATE')
        try:
            require(conn.execute('PRAGMA application_id').fetchone()[0] == intake.APP_ID and
                    conn.execute('PRAGMA user_version').fetchone()[0] ==
                    intake.RESERVATION_SCHEMA_VERSION,
                    'explicit migration requires the v2 reservation backlog schema')
            intake._initialize_or_check_schema(conn)
            intake._verify_receipt_chain(conn)
            before_chain = reservation.verify_action_chain(conn)
            before_rows, before_schema = _v1_v2_snapshot(conn)
            _create_v3_objects(conn, before_chain['queue_id'])
            conn.execute('PRAGMA user_version=' + str(intake.ISSUED_SCHEMA_VERSION))
            intake._initialize_or_check_schema(conn)
            intake._verify_receipt_chain(conn)
            after_chain = reservation.verify_action_chain(conn)
            after_rows, _ = _v1_v2_snapshot(conn)
            require(after_rows == before_rows,
                    'v1 or v2 table bytes changed during issued-action migration')
            require(after_chain == before_chain,
                    'v2 reservation chain changed during issued-action migration')
            require(before_schema == [tuple(row) for row in conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE substr(name,1,7) != 'sqlite_' AND name NOT IN "
                "('issued_actions','issued_head','issued_actions_no_update',"
                "'issued_actions_no_delete') ORDER BY type,name")],
                    'v1 or v2 schema bytes changed during issued-action migration')
            conn.commit()
            return {
                'status': 'migrated_v2_to_v3',
                'queue_id': before_chain['queue_id'],
                'receipt_count': len(before_rows['receipts']),
                'intake_count': len(before_rows['intakes']),
                'commit_count': len(before_rows['commit_backlog']),
                'reservation_action_count': before_chain['action_count'],
                'issued_sequence': 0,
                'issued_sha256': ZERO_HASH,
            }
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.close()


def _validate_start(attestation):
    require(type(attestation) is dict and set(attestation) == START_KEYS,
            'invalid issued-start attestation fields')
    require(attestation.get('schema') == START_SCHEMA and
            attestation.get('kind') == 'start' and
            isinstance(attestation.get('queue_id'), str) and
            QUEUE_ID.fullmatch(attestation['queue_id']) is not None and
            type(attestation.get('reservation_sequence')) is int and
            attestation['reservation_sequence'] == 1 and
            isinstance(attestation.get('reservation_sha256'), str) and
            SHA256.fullmatch(attestation['reservation_sha256']) is not None,
            'invalid issued-start queue or reservation identity')
    identity = attestation.get('identity')
    require(type(identity) is dict and set(identity) == IDENTITY_KEYS and
            identity.get('repository') in intake.poll.REPOS and
            isinstance(identity.get('ref'), str) and
            reservation._valid_repository_ref(identity['repository'], identity['ref']) and
            type(identity.get('ordinal')) is int and
            0 < identity['ordinal'] <= MAX_SQLITE_INT and
            isinstance(identity.get('commit_sha'), str) and
            FULL_SHA.fullmatch(identity['commit_sha']) is not None and
            isinstance(identity.get('tree_sha'), str) and
            FULL_SHA.fullmatch(identity['tree_sha']) is not None and
            isinstance(identity.get('first_parent_sha'), str) and
            FULL_SHA.fullmatch(identity['first_parent_sha']) is not None and
            isinstance(identity.get('intake_id'), str) and identity['intake_id'] and
            type(identity.get('receipt_seq')) is int and
            0 < identity['receipt_seq'] <= MAX_SQLITE_INT,
            'invalid issued-start exact identity')
    for key in ('origin_receipt_sha256', 'origin_gap_sha256',
                'policy_sha256', 'release_lock_sha256',
                'observation_sha256', 'run_api_sha256', 'jobs_api_sha256',
                'artifacts_api_sha256', 'recheck_run_api_sha256',
                'recheck_jobs_api_sha256'):
        require(isinstance(attestation.get(key), str) and
                SHA256.fullmatch(attestation[key]) is not None,
                'invalid issued-start digest: ' + key)
    require(isinstance(attestation.get('consumer_commit'), str) and
            FULL_SHA.fullmatch(attestation['consumer_commit']) is not None and
            type(attestation.get('run_id')) is int and
            0 < attestation['run_id'] <= MAX_SQLITE_INT and
            type(attestation.get('run_attempt')) is int and
            0 < attestation['run_attempt'] <= MAX_SQLITE_INT and
            type(attestation.get('job_id')) is int and
            0 < attestation['job_id'] <= MAX_SQLITE_INT and
            attestation.get('workflow') == reservation.WORKFLOW and
            attestation.get('job') == START_JOB,
            'invalid issued-start run, job or approved policy identity')
    artifact = attestation.get('early_artifact')
    require(type(artifact) is dict and set(artifact) == ARTIFACT_KEYS and
            type(artifact.get('id')) is int and
            0 < artifact['id'] <= MAX_SQLITE_INT and
            isinstance(artifact.get('sha256'), str) and
            SHA256.fullmatch(artifact['sha256']) is not None and
            type(artifact.get('size')) is int and
            0 < artifact['size'] <= MAX_SQLITE_INT,
            'invalid issued-start early artifact identity')


def _validate_approved_policy(policy):
    require(type(policy) is dict and set(policy) == APPROVED_POLICY_KEYS and
            isinstance(policy.get('consumer_commit'), str) and
            FULL_SHA.fullmatch(policy['consumer_commit']) is not None and
            isinstance(policy.get('release_lock_sha256'), str) and
            SHA256.fullmatch(policy['release_lock_sha256']) is not None,
            'invalid explicit approved policy')


def _signed_document(attestation, key, observed_at):
    _validate_key(key)
    _validate_start(attestation)
    observed = _canonical_time(observed_at, 'issued observation time')
    unsigned = {
        'schema': ISSUED_SCHEMA,
        'issued_seq': 1,
        'previous_issued_sha256': ZERO_HASH,
        'observed_at': observed.isoformat(timespec='seconds').replace('+00:00', 'Z'),
        'attestation': attestation,
    }
    mac = hmac.new(key, DOMAIN + canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    document = dict(unsigned)
    document['mac'] = mac
    document_raw = canonical_bytes(document)
    return document, document_raw, digest(document_raw)


def _check_monotonic_deadline(deadline):
    if deadline is None:
        return
    require(type(deadline) in (int, float) and math.isfinite(deadline) and
            time.monotonic() <= deadline,
            'live observation deadline expired before issued start CAS')


def _load_document(document_json):
    require(isinstance(document_json, str), 'invalid issued document bytes')
    raw = document_json.encode('utf-8')
    document = _parse_json(raw, 'issued document')
    require(set(document) == DOCUMENT_KEYS and
            canonical_bytes(document) == raw,
            'issued document is not canonical JSON')
    unsigned = {key: value for key, value in document.items() if key != 'mac'}
    require(set(unsigned) == ENVELOPE_KEYS and
            unsigned.get('schema') == ISSUED_SCHEMA and
            type(unsigned.get('issued_seq')) is int and unsigned['issued_seq'] == 1 and
            unsigned.get('previous_issued_sha256') == ZERO_HASH,
            'unsupported issued document envelope')
    require(isinstance(document.get('mac'), str) and
            SHA256.fullmatch(document['mac']) is not None,
            'invalid issued document MAC')
    return unsigned, document, raw


def _load_reservation(conn):
    chain = reservation.verify_action_chain(conn)
    require(chain['action_count'] == 1 and chain['action_seq'] == 1,
            'issued start requires exactly one v2 reservation action')
    rows = conn.execute(
        'SELECT body_json,action_hash FROM reservation_actions WHERE action_seq=1').fetchall()
    require(len(rows) == 1, 'issued start reservation action is missing')
    body = reservation._parse_json(rows[0]['body_json'], 'reservation action')
    return chain, body, rows[0]['action_hash']


def _validate_start_binding(attestation, observed_at, body, action_hash):
    _validate_start(attestation)
    identity = body.get('identity')
    origin = body.get('origin')
    policy = body.get('policy')
    require(attestation['queue_id'] == body.get('queue_id') and
            attestation['reservation_sequence'] == body.get('action_seq') == 1 and
            attestation['reservation_sha256'] == action_hash and
            attestation['identity'] == identity and
            attestation['origin_receipt_sha256'] == origin.get('receipt_hash') and
            attestation['origin_gap_sha256'] == origin.get('gap_sha256') and
            attestation['policy_sha256'] == policy.get('policy_sha256') and
            attestation['consumer_commit'] == policy.get('consumer_commit') and
            attestation['release_lock_sha256'] == policy.get('release_lock_sha256'),
            'issued start differs from exact v2 reservation identity, origin or policy')
    observed = _canonical_time(observed_at, 'issued observation time')
    created = reservation._iso_time(body.get('created_at'), 'reservation creation time')
    expires = reservation._iso_time(body.get('expires_at'), 'reservation expiry')
    require(created < observed < expires,
            'issued start must be observed after an unexpired reservation')


def verify_issued_chain(conn, key=None):
    """Verify issued chain bytes/head; verify MAC too when a key is supplied."""
    _check_v3_schema(conn)
    if key is not None:
        _validate_key(key)
    chain = reservation.verify_action_chain(conn)
    queue_rows = conn.execute(
        'SELECT queue_id FROM queue_metadata WHERE singleton=1').fetchall()
    head_rows = conn.execute('SELECT * FROM issued_head WHERE singleton=1').fetchall()
    require(len(queue_rows) == 1 and len(head_rows) == 1 and
            queue_rows[0]['queue_id'] == head_rows[0]['queue_id'] == chain['queue_id'],
            'issued queue metadata or head is missing')
    rows = conn.execute(
        'SELECT seq,previous_sha256,document_json,action_sha256 '
        'FROM issued_actions ORDER BY seq').fetchall()
    require(len(rows) <= 1,
            'issued start chain supports only the first start action')
    previous = ZERO_HASH
    verified = False
    if rows:
        reservation_chain, body, action_hash = _load_reservation(conn)
        require(reservation_chain == chain,
                'reservation chain changed while verifying issued start')
        row = rows[0]
        require(row['seq'] == 1 and row['previous_sha256'] == ZERO_HASH,
                'issued action sequence or predecessor mismatch')
        unsigned, document, raw = _load_document(row['document_json'])
        require(digest(raw) == row['action_sha256'],
                'issued action hash mismatch')
        attestation = unsigned.get('attestation')
        _validate_start_binding(attestation, unsigned.get('observed_at'), body, action_hash)
        if key is not None:
            expected_mac = hmac.new(
                key, DOMAIN + canonical_bytes(unsigned), hashlib.sha256).hexdigest()
            require(hmac.compare_digest(document['mac'], expected_mac),
                    'issued action MAC mismatch')
            verified = True
        previous = row['action_sha256']
    head = head_rows[0]
    require(head['seq'] == len(rows) and head['hash'] == previous,
            'issued action head differs from append-only history')
    return {'queue_id': chain['queue_id'], 'seq': head['seq'],
            'sha256': head['hash'], 'action_count': len(rows),
            'hmac_verified': verified}


def issue_start(private_root, expected_seq, expected_sha256, key,
                approved_policy, attestation, observed_at, *,
                deadline_monotonic=None):
    """Append the one exact start under an immediate transaction and CAS.

    `attestation` is a typed, exact-field mapping. This offline primitive does
    not authenticate its API or artifact claims; a private verifier must
    construct it from freshly checked canonical responses and ZIP bytes.
    When supplied, `deadline_monotonic` is checked after acquiring the write
    transaction, before signing, and before commit so a delayed local CAS
    cannot use an observation past its freshness window.
    """
    _validate_key(key)
    _validate_approved_policy(approved_policy)
    _validate_start(attestation)
    _canonical_time(observed_at, 'issued observation time')
    conn = _open_existing(private_root)
    try:
        conn.execute('BEGIN IMMEDIATE')
        try:
            _check_monotonic_deadline(deadline_monotonic)
            intake._initialize_or_check_schema(conn)
            require(conn.execute('PRAGMA user_version').fetchone()[0] ==
                    intake.ISSUED_SCHEMA_VERSION,
                    'backlog database requires explicit v2 to v3 migration')
            intake._verify_receipt_chain(conn)
            reservation_chain, body, reservation_hash = _load_reservation(conn)
            require(body.get('status') == 'reserved_only' and
                    reservation_chain['action_count'] == 1,
                    'issued start requires one reserved-only action')
            _validate_start_binding(attestation, observed_at, body, reservation_hash)
            policy = body['policy']
            require(approved_policy == {
                'consumer_commit': policy['consumer_commit'],
                'release_lock_sha256': policy['release_lock_sha256'],
            } and attestation['policy_sha256'] == policy['policy_sha256'],
                    'approved policy differs from exact v2 reservation policy')
            _check_monotonic_deadline(deadline_monotonic)
            document, document_raw, action_hash = _signed_document(
                attestation, key, observed_at)
            head = verify_issued_chain(conn, key)
            require(type(expected_seq) is int and expected_seq == 0 and
                    isinstance(expected_sha256, str) and expected_sha256 == ZERO_HASH and
                    (head['seq'], head['sha256']) == (expected_seq, expected_sha256),
                    'stale issued action head')
            require(head['action_count'] == 0,
                    'an issued start already occupies the issued-action chain')
            conn.execute('INSERT INTO issued_actions VALUES (1, ?, ?, ?)',
                         (ZERO_HASH, document_raw.decode('utf-8'), action_hash))
            changed = conn.execute('''
                UPDATE issued_head SET seq=1, hash=?
                WHERE singleton=1 AND queue_id=? AND seq=0 AND hash=?
            ''', (action_hash, reservation_chain['queue_id'], ZERO_HASH)).rowcount
            require(changed == 1, 'compare-and-swap issued head update failed')
            final = verify_issued_chain(conn, key)
            require(final['seq'] == 1 and final['sha256'] == action_hash and
                    final['hmac_verified'],
                    'issued start append did not advance exact authenticated head')
            _check_monotonic_deadline(deadline_monotonic)
            conn.commit()
            return {'status': 'issued_start', 'queue_id': reservation_chain['queue_id'],
                    'issued_seq': 1, 'issued_sha256': action_hash,
                    'reservation_sha256': reservation_hash,
                    'run_id': attestation['run_id'],
                    'run_attempt': attestation['run_attempt'],
                    'job_id': attestation['job_id']}
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.close()


def issued_head(private_root, key=None):
    conn = _open_existing(private_root)
    try:
        conn.execute('BEGIN')
        try:
            intake._initialize_or_check_schema(conn)
            result = verify_issued_chain(conn, key)
            conn.commit()
            return result
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.close()
