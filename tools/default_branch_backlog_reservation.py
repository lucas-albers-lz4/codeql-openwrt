#!/usr/bin/env python3
"""Explicit v1 migration and one queue-only reservation for the default-branch backlog.

This records a reservation action only. It cannot dispatch a scan, record a
start, or record an outcome.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid

from tools import default_branch_backlog_intake as intake


DATABASE_NAME = 'default-branch-backlog.sqlite3'
WORKFLOW = '.github/workflows/default-branch-commit-scan.yml'
POLICY_SCHEMA = 'default-branch-backlog-reservation-policy-v1'
ACTION_SCHEMA = 'default-branch-backlog-reservation-action-v1'
ZERO_HASH = '0' * 64
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')
OPERATOR = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}\Z')
MAX_POLICY = 64 * 1024
MAX_RELEASE_LOCK = 1024 * 1024
MAX_RESERVATION_AGE = timedelta(days=7)
DEFAULT_REF_PATTERN = re.compile(r'[A-Za-z0-9._/-]+\Z')

IDENTITY_KEYS = {
    'repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
    'first_parent_sha', 'intake_id', 'receipt_seq',
}
ORIGIN_KEYS = {
    'receipt_hash', 'previous_run_id', 'previous_attempt',
    'current_run_id', 'current_attempt', 'previous_artifact_id',
    'previous_zip_sha256', 'current_artifact_id', 'current_zip_sha256',
    'previous_checkpoint_sha256', 'current_checkpoint_sha256', 'gap_sha256',
    'bootstrap', 'receipt_seq',
}
POLICY_KEYS = {
    'schema', 'policy_sha256', 'consumer_commit', 'workflow',
    'release_lock_sha256', 'release_tag', 'release_commit',
    'release_asset_sha256', 'release_manifest_sha256',
}
ACTION_KEYS = {
    'schema', 'action', 'status', 'action_seq', 'previous_action_sha256',
    'queue_id', 'reservation_id', 'created_at', 'expires_at', 'operator',
    'identity', 'origin', 'policy',
}


class ReservationError(ValueError):
    """Fail-closed migration or reservation error."""


def require(condition, message):
    if not condition:
        raise ReservationError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _parse_json(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=intake.unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReservationError('invalid ' + label) from exc
    require(isinstance(value, dict), 'invalid ' + label + ' object')
    return value


def _normal_sql(sql):
    return ' '.join((sql or '').split())


def _valid_repository_ref(repository, ref):
    """Match the poller's source-reported default-branch ref contract."""
    return (repository in intake.poll.REPOS and isinstance(ref, str) and
            DEFAULT_REF_PATTERN.fullmatch(ref) is not None and '..' not in ref)


def _check_v2_schema(conn):
    require(conn.execute('PRAGMA application_id').fetchone()[0] == intake.APP_ID and
            conn.execute('PRAGMA user_version').fetchone()[0] ==
            intake.RESERVATION_SCHEMA_VERSION,
            'backlog database requires explicit v1 migration')
    expected_objects = {('table', name) for name in (
        'cursor', 'intakes', 'commit_backlog', 'receipts', 'queue_metadata',
        'reservation_actions', 'action_head')}
    expected_objects |= {('trigger', name) for name in (
        'reservation_actions_no_update', 'reservation_actions_no_delete')}
    actual_objects = {(row['type'], row['name']) for row in conn.execute(
        "SELECT type,name FROM sqlite_master WHERE substr(name,1,7) != 'sqlite_'")}
    require(actual_objects == expected_objects,
            'reservation database has an unexpected table, view, index or trigger')
    expected_columns = {
        'queue_metadata': ('singleton', 'queue_id'),
        'reservation_actions': ('action_seq', 'previous_hash', 'body_json', 'action_hash'),
        'action_head': ('singleton', 'queue_id', 'action_seq', 'action_hash'),
    }
    for table, expected in expected_columns.items():
        actual = tuple(row['name'] for row in conn.execute(
            'PRAGMA table_info(' + table + ')'))
        require(actual == expected, 'unsupported reservation table schema: ' + table)
    triggers = {row['name']: _normal_sql(row['sql']) for row in conn.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    require(triggers == {
        'reservation_actions_no_update': _normal_sql(
            "CREATE TRIGGER reservation_actions_no_update BEFORE UPDATE ON reservation_actions "
            "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END"),
        'reservation_actions_no_delete': _normal_sql(
            "CREATE TRIGGER reservation_actions_no_delete BEFORE DELETE ON reservation_actions "
            "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END"),
    }, 'reservation action immutability triggers differ')


def _legacy_snapshot(conn):
    """Small deterministic snapshot used to prove migration preserved v1 rows."""
    queries = {
        'cursor': 'SELECT * FROM cursor ORDER BY singleton',
        'intakes': 'SELECT * FROM intakes ORDER BY receipt_seq',
        'commit_backlog': 'SELECT * FROM commit_backlog ORDER BY repository,ref,commit_sha',
        'receipts': 'SELECT * FROM receipts ORDER BY receipt_seq',
    }
    return {name: [dict(row) for row in conn.execute(query)]
            for name, query in queries.items()}


def _create_v2_objects(conn, queue_id):
    for statement in (
            '''CREATE TABLE queue_metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                queue_id TEXT NOT NULL UNIQUE
            )''',
            '''CREATE TABLE reservation_actions (
                action_seq INTEGER PRIMARY KEY,
                previous_hash TEXT NOT NULL,
                body_json TEXT NOT NULL,
                action_hash TEXT NOT NULL UNIQUE
            )''',
            '''CREATE TABLE action_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                queue_id TEXT NOT NULL,
                action_seq INTEGER NOT NULL,
                action_hash TEXT NOT NULL
            )''',
            "CREATE TRIGGER reservation_actions_no_update BEFORE UPDATE ON reservation_actions "
            "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END",
            "CREATE TRIGGER reservation_actions_no_delete BEFORE DELETE ON reservation_actions "
            "BEGIN SELECT RAISE(ABORT, 'reservation actions are append-only'); END",
    ):
        conn.execute(statement)
    conn.execute('INSERT INTO queue_metadata VALUES (1, ?)', (queue_id,))
    conn.execute('INSERT INTO action_head VALUES (1, ?, 0, ?)', (queue_id, ZERO_HASH))


def _open_existing(private_root):
    try:
        root = intake.private_root(Path(private_root))
    except intake.IntakeError as exc:
        raise ReservationError(str(exc)) from exc
    database = root / DATABASE_NAME
    try:
        intake._safe_path(database, 'backlog database')
    except intake.IntakeError as exc:
        raise ReservationError(str(exc)) from exc
    try:
        info = database.lstat()
    except OSError as exc:
        raise ReservationError('backlog database is missing') from exc
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'backlog database must be a private, singly linked regular file')
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = root / (DATABASE_NAME + suffix)
        require(not sidecar.exists() and not sidecar.is_symlink(),
                'backlog database has a SQLite sidecar; inspect or recover it first')
    descriptor = os.open(database, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(descriptor)
        header = os.read(descriptor, 20)
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino) and
                header[:16] == b'SQLite format 3\x00' and header[18:20] == b'\x01\x01',
                'backlog store is not a DELETE-journal SQLite database')
    finally:
        os.close(descriptor)
    try:
        conn = intake._connect(database)
    except (sqlite3.Error, intake.IntakeError) as exc:
        raise ReservationError('cannot open operator backlog database') from exc
    try:
        after = database.lstat()
        require((after.st_dev, after.st_ino) == (info.st_dev, info.st_ino) and
                after.st_nlink == 1 and stat.S_IMODE(after.st_mode) == 0o600,
                'backlog database changed during SQLite open')
        return conn
    except BaseException:
        conn.close()
        raise


def migrate_v1(private_root):
    """Explicitly add the v2 action chain without rewriting v1 receipt data."""
    conn = _open_existing(private_root)
    try:
        conn.execute('BEGIN IMMEDIATE')
        try:
            require(conn.execute('PRAGMA application_id').fetchone()[0] == intake.APP_ID and
                    conn.execute('PRAGMA user_version').fetchone()[0] == intake.SCHEMA_VERSION,
                    'explicit migration requires the pending-only v1 backlog schema')
            intake._initialize_or_check_schema(conn)
            intake._verify_receipt_chain(conn)
            before = _legacy_snapshot(conn)
            _create_v2_objects(conn, uuid.uuid4().hex)
            conn.execute('PRAGMA user_version=' + str(intake.RESERVATION_SCHEMA_VERSION))
            intake._initialize_or_check_schema(conn)
            intake._verify_receipt_chain(conn)
            require(_legacy_snapshot(conn) == before,
                    'v1 intake rows or receipts changed during migration')
            conn.commit()
            return {'status': 'migrated_v1_to_v2',
                    'queue_id': conn.execute(
                        'SELECT queue_id FROM queue_metadata WHERE singleton=1').fetchone()[0],
                    'receipt_count': len(before['receipts']),
                    'commit_count': len(before['commit_backlog'])}
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.close()


def _iso_time(value, label):
    require(isinstance(value, str), 'invalid ' + label)
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ReservationError('invalid ' + label) from exc
    require(parsed.tzinfo is not None, label + ' needs a timezone')
    return parsed.astimezone(timezone.utc)


def _format_time(value):
    return value.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _read_policy(policy_path, release_lock_path):
    policy_path = Path(policy_path)
    policy_info = policy_path.lstat()
    require(stat.S_ISREG(policy_info.st_mode) and policy_info.st_uid == os.geteuid() and
            stat.S_IMODE(policy_info.st_mode) == 0o600 and policy_info.st_nlink == 1,
            'reservation policy must be a private, singly linked regular file')
    policy_raw = intake.read_regular(policy_path, MAX_POLICY, 'reservation policy')
    policy = _parse_json(policy_raw, 'reservation policy')
    require(set(policy) == {'schema', 'consumer_commit', 'workflow', 'release_lock_sha256'} and
            policy.get('schema') == POLICY_SCHEMA and
            isinstance(policy.get('consumer_commit'), str) and
            FULL_SHA.fullmatch(policy['consumer_commit']) and
            policy.get('workflow') == WORKFLOW and
            isinstance(policy.get('release_lock_sha256'), str) and
            SHA256.fullmatch(policy['release_lock_sha256']),
            'unsupported or invalid reservation policy')
    release_raw = intake.read_regular(Path(release_lock_path), MAX_RELEASE_LOCK,
                                      'pinned R3 release lock')
    release_lock = _parse_json(release_raw, 'pinned R3 release lock')
    require(release_lock.get('schema') == 'ucode-r3-release-lock-v1' and
            digest(release_raw) == policy['release_lock_sha256'],
            'reservation policy does not bind exact release-lock bytes')
    release = release_lock.get('release')
    require(isinstance(release, dict) and
            isinstance(release.get('tag'), str) and release['tag'] and
            isinstance(release.get('commit'), str) and FULL_SHA.fullmatch(release['commit']) and
            isinstance(release.get('asset_sha256'), str) and SHA256.fullmatch(release['asset_sha256']) and
            isinstance(release.get('manifest_sha256'), str) and SHA256.fullmatch(release['manifest_sha256']),
            'release lock has incomplete pinned release identity')
    return {
        'schema': POLICY_SCHEMA,
        'policy_sha256': digest(policy_raw),
        'consumer_commit': policy['consumer_commit'],
        'workflow': policy['workflow'],
        'release_lock_sha256': digest(release_raw),
        'release_tag': release['tag'],
        'release_commit': release['commit'],
        'release_asset_sha256': release['asset_sha256'],
        'release_manifest_sha256': release['manifest_sha256'],
    }


def _origin_for_row(conn, row):
    intake_row = conn.execute(
        'SELECT i.*, r.receipt_hash FROM intakes AS i JOIN receipts AS r '
        'ON r.receipt_seq=i.receipt_seq WHERE i.intake_id=?',
        (row['intake_id'],)).fetchone()
    require(intake_row is not None and intake_row['receipt_seq'] == row['receipt_seq'],
            'selected commit has no exact intake receipt')
    return {
        'receipt_hash': intake_row['receipt_hash'],
        'previous_run_id': intake_row['previous_run_id'],
        'previous_attempt': intake_row['previous_attempt'],
        'current_run_id': intake_row['current_run_id'],
        'current_attempt': intake_row['current_attempt'],
        'previous_artifact_id': intake_row['previous_artifact_id'],
        'previous_zip_sha256': intake_row['previous_zip_sha256'],
        'current_artifact_id': intake_row['current_artifact_id'],
        'current_zip_sha256': intake_row['current_zip_sha256'],
        'previous_checkpoint_sha256': intake_row['previous_checkpoint_sha256'],
        'current_checkpoint_sha256': intake_row['current_checkpoint_sha256'],
        'gap_sha256': intake_row['gap_sha256'],
        'bootstrap': bool(intake_row['bootstrap']),
        'receipt_seq': intake_row['receipt_seq'],
    }


def verify_action_chain(conn):
    """Validate the append-only action chain, head and every bound pending row."""
    _check_v2_schema(conn)
    queue_rows = conn.execute('SELECT queue_id FROM queue_metadata WHERE singleton=1').fetchall()
    head_rows = conn.execute('SELECT * FROM action_head WHERE singleton=1').fetchall()
    require(len(queue_rows) == 1 and len(head_rows) == 1,
            'reservation queue metadata or action head is missing')
    queue_id = queue_rows[0]['queue_id']
    require(isinstance(queue_id, str) and re.fullmatch(r'[0-9a-f]{32}', queue_id) and
            head_rows[0]['queue_id'] == queue_id,
            'reservation queue identity mismatch')
    previous_hash = ZERO_HASH
    expected_seq = 1
    reserved = set()
    actions = conn.execute(
        'SELECT action_seq,previous_hash,body_json,action_hash '
        'FROM reservation_actions ORDER BY action_seq').fetchall()
    require(len(actions) <= 1,
            'queue-only reservation pilot supports one outstanding reservation')
    for action in actions:
        require(action['action_seq'] == expected_seq and
                action['previous_hash'] == previous_hash,
                'reservation action sequence or predecessor mismatch')
        body = _parse_json(action['body_json'], 'reservation action')
        require(canonical_json(body) == action['body_json'] and set(body) == ACTION_KEYS and
                body.get('schema') == ACTION_SCHEMA and body.get('action') == 'reserve' and
                body.get('status') == 'reserved_only' and
                body.get('action_seq') == expected_seq and
                body.get('previous_action_sha256') == previous_hash and
                body.get('queue_id') == queue_id and
                body.get('reservation_id') == f'{queue_id}:{expected_seq}',
                'unsupported or malformed reservation action')
        expected_hash = digest((previous_hash + '\n' + action['body_json']).encode('utf-8'))
        require(action['action_hash'] == expected_hash,
                'reservation action hash mismatch')
        identity, origin, policy = body.get('identity'), body.get('origin'), body.get('policy')
        require(isinstance(identity, dict) and set(identity) == IDENTITY_KEYS and
                _valid_repository_ref(identity.get('repository'), identity.get('ref')) and
                isinstance(origin, dict) and set(origin) == ORIGIN_KEYS and
                isinstance(policy, dict) and set(policy) == POLICY_KEYS and
                policy.get('schema') == POLICY_SCHEMA and
                isinstance(policy.get('policy_sha256'), str) and
                SHA256.fullmatch(policy['policy_sha256']) and
                isinstance(policy.get('release_lock_sha256'), str) and
                SHA256.fullmatch(policy['release_lock_sha256']) and
                isinstance(policy.get('consumer_commit'), str) and
                FULL_SHA.fullmatch(policy['consumer_commit']) and
                policy.get('workflow') == WORKFLOW and
                isinstance(policy.get('release_commit'), str) and
                FULL_SHA.fullmatch(policy['release_commit']) and
                isinstance(policy.get('release_asset_sha256'), str) and
                SHA256.fullmatch(policy['release_asset_sha256']) and
                isinstance(policy.get('release_manifest_sha256'), str) and
                SHA256.fullmatch(policy['release_manifest_sha256']) and
                isinstance(policy.get('release_tag'), str) and policy['release_tag'],
                'reservation action lacks exact row or policy binding')
        require(body.get('operator') and OPERATOR.fullmatch(body['operator']),
                'invalid recorded operator identity')
        created = _iso_time(body.get('created_at'), 'action creation time')
        expires = _iso_time(body.get('expires_at'), 'reservation expiry')
        require(created < expires <= created + MAX_RESERVATION_AGE,
                'reservation expiry is outside the supported window')
        stored = conn.execute('''
            SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
                   b.first_parent_sha,b.status,b.intake_id,i.receipt_seq
            FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
            WHERE b.repository=? AND b.ref=? AND b.commit_sha=?
        ''', (identity.get('repository'), identity.get('ref'),
              identity.get('commit_sha'))).fetchall()
        require(len(stored) == 1 and stored[0]['status'] == 'pending' and
                all(stored[0][key] == identity.get(key) for key in
                    ('repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                     'first_parent_sha', 'intake_id', 'receipt_seq')) and
                _origin_for_row(conn, stored[0]) == origin,
                'reservation action no longer binds its exact pending intake row')
        key = (identity['repository'], identity['ref'], identity['commit_sha'])
        require(key not in reserved, 'duplicate reservation action')
        reserved.add(key)
        previous_hash = action['action_hash']
        expected_seq += 1
    head = head_rows[0]
    require(head['action_seq'] == expected_seq - 1 and head['action_hash'] == previous_hash,
            'reservation action head differs from append-only history')
    return {'queue_id': queue_id, 'action_seq': head['action_seq'],
            'action_sha256': head['action_hash'], 'action_count': len(actions)}


def action_head(private_root):
    conn = _open_existing(private_root)
    try:
        # A single read transaction prevents a concurrent writer from making
        # the returned head combine two committed snapshots.
        conn.execute('BEGIN')
        try:
            intake._initialize_or_check_schema(conn)
            require(conn.execute('PRAGMA user_version').fetchone()[0] ==
                    intake.RESERVATION_SCHEMA_VERSION,
                    'pending-only v1 database needs explicit migration')
            intake._verify_receipt_chain(conn)
            result = verify_action_chain(conn)
            conn.commit()
            return result
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.close()


def _selected_row(conn, identity):
    row = conn.execute('''
        SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
               b.first_parent_sha,b.status,b.intake_id,i.receipt_seq
        FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
        WHERE b.repository=? AND b.ref=? AND b.commit_sha=?
    ''', (identity['repository'], identity['ref'], identity['commit_sha'])).fetchall()
    require(len(row) == 1 and row[0]['status'] == 'pending' and
            all(row[0][key] == identity[key] for key in IDENTITY_KEYS),
            'selected pending identity or intake origin is stale')
    return row[0]


def reserve(private_root, expected_seq, expected_hash, identity, policy_path,
            release_lock_path, operator, expires_at, *, now=None):
    require(type(expected_seq) is int and expected_seq >= 0 and
            isinstance(expected_hash, str) and SHA256.fullmatch(expected_hash),
            'invalid expected action head')
    require(isinstance(operator, str) and OPERATOR.fullmatch(operator),
            'invalid operator identity')
    require(isinstance(identity, dict) and set(identity) == IDENTITY_KEYS and
            _valid_repository_ref(identity.get('repository'), identity.get('ref')) and
            type(identity.get('ordinal')) is int and
            identity['ordinal'] > 0 and isinstance(identity.get('commit_sha'), str) and
            FULL_SHA.fullmatch(identity['commit_sha']) and
            isinstance(identity.get('tree_sha'), str) and FULL_SHA.fullmatch(identity['tree_sha']) and
            isinstance(identity.get('first_parent_sha'), str) and FULL_SHA.fullmatch(identity['first_parent_sha']) and
            isinstance(identity.get('intake_id'), str) and identity['intake_id'] and
            type(identity.get('receipt_seq')) is int and identity['receipt_seq'] > 0,
            'invalid exact pending identity')
    policy = _read_policy(policy_path, release_lock_path)
    now = now or datetime.now(timezone.utc)
    require(now.tzinfo is not None, 'reservation time needs a timezone')
    now = now.astimezone(timezone.utc)
    expires = _iso_time(expires_at, 'reservation expiry')
    require(now < expires <= now + MAX_RESERVATION_AGE,
            'reservation expiry must be in the next seven days')
    created_text, expires_text = _format_time(now), _format_time(expires)
    conn = _open_existing(private_root)
    try:
        intake._initialize_or_check_schema(conn)
        require(conn.execute('PRAGMA user_version').fetchone()[0] ==
                intake.RESERVATION_SCHEMA_VERSION,
                'pending-only v1 database needs explicit migration')
        conn.execute('BEGIN IMMEDIATE')
        try:
            intake._verify_receipt_chain(conn)
            head = verify_action_chain(conn)
            require((head['action_seq'], head['action_sha256']) ==
                    (expected_seq, expected_hash), 'stale reservation action head')
            row = _selected_row(conn, identity)
            require(head['action_count'] == 0,
                    'a reserved-only action already occupies the pilot queue')
            origin = _origin_for_row(conn, row)
            action = {
                'schema': ACTION_SCHEMA, 'action': 'reserve', 'status': 'reserved_only',
                'action_seq': expected_seq + 1, 'previous_action_sha256': expected_hash,
                'queue_id': head['queue_id'],
                'reservation_id': f"{head['queue_id']}:{expected_seq + 1}",
                'created_at': created_text, 'expires_at': expires_text,
                'operator': operator,
                'identity': {key: identity[key] for key in sorted(IDENTITY_KEYS)},
                'origin': origin, 'policy': policy,
            }
            body_json = canonical_json(action)
            action_hash = digest((expected_hash + '\n' + body_json).encode('utf-8'))
            conn.execute('INSERT INTO reservation_actions VALUES (?, ?, ?, ?)',
                         (expected_seq + 1, expected_hash, body_json, action_hash))
            changed = conn.execute('''
                UPDATE action_head SET action_seq=?, action_hash=?
                WHERE singleton=1 AND queue_id=? AND action_seq=? AND action_hash=?
            ''', (expected_seq + 1, action_hash, head['queue_id'],
                  expected_seq, expected_hash)).rowcount
            require(changed == 1, 'compare-and-swap action head update failed')
            final = verify_action_chain(conn)
            require(final['action_seq'] == expected_seq + 1 and
                    final['action_sha256'] == action_hash,
                    'reservation append did not advance exact action head')
            conn.commit()
            return {'status': 'reserved_only', 'queue_id': head['queue_id'],
                    'action_seq': expected_seq + 1, 'action_sha256': action_hash,
                    'reservation_id': action['reservation_id'], 'identity': action['identity'],
                    'origin': origin, 'policy': policy, 'expires_at': expires_text}
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.close()


def _load_identity(args):
    return {
        'repository': args.repository, 'ref': args.ref, 'ordinal': args.ordinal,
        'commit_sha': args.commit_sha, 'tree_sha': args.tree_sha,
        'first_parent_sha': args.first_parent_sha, 'intake_id': args.intake_id,
        'receipt_seq': args.receipt_seq,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', required=True, type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--migrate-v1', action='store_true',
                       help='explicitly add the append-only v2 reservation action schema')
    modes.add_argument('--head', action='store_true', help='print the current v2 action head')
    modes.add_argument('--reserve', action='store_true', help='append one exact pending reservation')
    parser.add_argument('--expected-action-sequence', type=int)
    parser.add_argument('--expected-action-sha256')
    parser.add_argument('--repository', choices=('openwrt/openwrt', 'openwrt/luci'))
    parser.add_argument('--ref', default='main')
    parser.add_argument('--ordinal', type=int)
    parser.add_argument('--commit-sha')
    parser.add_argument('--tree-sha')
    parser.add_argument('--first-parent-sha')
    parser.add_argument('--intake-id')
    parser.add_argument('--receipt-seq', type=int)
    parser.add_argument('--policy', type=Path)
    parser.add_argument('--release-lock', type=Path,
                        default=Path('docs/r3-release-lock.json'))
    parser.add_argument('--operator')
    parser.add_argument('--expires-at')
    args = parser.parse_args(argv)
    try:
        if args.migrate_v1:
            result = migrate_v1(args.private_root)
        elif args.head:
            result = action_head(args.private_root)
        else:
            required = (args.expected_action_sequence, args.expected_action_sha256,
                        args.repository, args.ordinal, args.commit_sha, args.tree_sha,
                        args.first_parent_sha, args.intake_id, args.receipt_seq,
                        args.policy, args.operator, args.expires_at)
            require(all(value is not None for value in required),
                    'reservation requires action head, exact row identity, policy, operator and expiry')
            result = reserve(args.private_root, args.expected_action_sequence,
                             args.expected_action_sha256, _load_identity(args),
                             args.policy, args.release_lock, args.operator,
                             args.expires_at)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ReservationError, intake.IntakeError, sqlite3.Error, OSError,
            ValueError, TypeError, KeyError, RecursionError) as exc:
        print('default branch backlog reservation rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
