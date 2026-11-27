"""Read-only authentication of one retained sequence-one private start.

The caller supplies key bytes. This module never obtains credentials, fetches
remote data, issues an action, or assigns a terminal scan outcome.
"""
from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from typing import TypedDict

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools import default_branch_live_observation as live
from tools import default_branch_private_final_capture as capture
from tools import default_branch_reservation_reconcile as reconcile

SCHEMA = 'operator-default-branch-authenticated-start-preflight-v1'
SCOPE = 'authenticated_sequence_one_start_and_retained_observation_only'
HEAD_SNAPSHOT_SCHEMA = 'operator-default-branch-authenticated-head-snapshot-v1'
MAX_START = 1024 * 1024
MAX_DATABASE = 256 * 1024 * 1024


class AuthenticatedStartError(ValueError):
    """The private start or retained observation could not be authenticated."""


class AuthenticatedStartReceipt(TypedDict):
    schema: str
    status: str
    verification_scope: str
    queue_id: str
    issued_seq: int
    start_sha256: str
    reservation_sequence: int
    reservation_sha256: str
    identity: dict
    run_id: int
    run_attempt: int
    job_id: int
    workflow: str
    job: str
    early_artifact: dict
    observation_sha256: str
    raw_sha256: dict[str, str]
    completed_scan_verified: bool
    final_proof_verified: bool


def _need(condition, message):
    if not condition:
        raise AuthenticatedStartError(message)


def _db_fingerprint(info):
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
          stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
          0 < info.st_size <= MAX_DATABASE,
          'private backlog database is unsafe or unbounded')
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _sidecars_absent(root_fd):
    for suffix in ('-journal', '-wal', '-shm'):
        name = issued.DATABASE_NAME + suffix
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise AuthenticatedStartError('SQLite sidecar requires recovery: ' + name)


def _open_read_only(root_fd):
    """Deserialize only bytes read from the checked no-follow database FD."""
    _sidecars_absent(root_fd)
    name = issued.DATABASE_NAME
    before = _db_fingerprint(os.stat(name, dir_fd=root_fd, follow_symlinks=False))
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=root_fd)
    try:
        _need(_db_fingerprint(os.fstat(descriptor)) == before,
              'backlog database changed before opening')
        chunks = []
        remaining = before[2]
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            _need(chunk, 'backlog database was truncated during snapshot')
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        _need(raw[:16] == b'SQLite format 3\x00' and
              raw[18:20] == b'\x01\x01',
              'backlog database is not a DELETE-journal SQLite store')
        _need(_db_fingerprint(os.fstat(descriptor)) == before and
              _db_fingerprint(os.stat(name, dir_fd=root_fd,
                                      follow_symlinks=False)) == before,
              'backlog database changed during snapshot')
        _sidecars_absent(root_fd)
    finally:
        os.close(descriptor)
    conn = sqlite3.connect(':memory:', isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA temp_store=MEMORY')
        conn.execute('PRAGMA query_only=ON')
        conn.execute('PRAGMA trusted_schema=OFF')
        conn.deserialize(raw)
        _need(conn.execute('PRAGMA query_only').fetchone()[0] == 1 and
              conn.execute('PRAGMA temp_store').fetchone()[0] == 2,
              'in-memory SQLite snapshot lost read-only configuration')
        conn.execute('BEGIN')
        return conn, before
    except BaseException:
        conn.close()
        raise


def read_authenticated_head_snapshot(private_root: Path, key: bytes) -> dict:
    """Bind issued head, signed start and reservation from one read-only DB image.

    This verifies local HMACs but cannot detect a restored older valid image.
    An external witness supplies that independent rollback comparison.
    """
    try:
        issued._validate_key(key)
        root = intake.private_root(Path(private_root))
        root_before = os.stat(root, follow_symlinks=False)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(root_fd)
            _need(stat.S_ISDIR(opened.st_mode) and
                  opened.st_uid == os.geteuid() and
                  stat.S_IMODE(opened.st_mode) == 0o700 and
                  (opened.st_dev, opened.st_ino) ==
                  (root_before.st_dev, root_before.st_ino),
                  'private root changed before database read')
            conn, database_before = _open_read_only(root_fd)
            try:
                issued._check_v3_schema(conn)
                intake._verify_receipt_chain(conn)
                head = issued.verify_issued_chain(conn, key)
                _need(head['hmac_verified'] and head['seq'] in (1, 2) and
                      head['action_count'] == head['seq'],
                      'issued head is not an authenticated start or terminal')
                rows = conn.execute(
                    'SELECT document_json,action_sha256 FROM issued_actions '
                    'WHERE seq=1').fetchall()
                _need(len(rows) == 1, 'authenticated start row is missing')
                start, _, start_raw = issued._load_document(rows[0]['document_json'])
                start_sha = issued.digest(start_raw)
                _need(0 < len(start_raw) <= MAX_START and
                      start_sha == rows[0]['action_sha256'],
                      'authenticated start digest differs')
                chain, body, reservation_sha = issued._load_reservation(conn)
                _need(chain['queue_id'] == head['queue_id'] and
                      body['status'] == 'reserved_only' and
                      start['attestation']['reservation_sha256'] == reservation_sha,
                      'signed start reservation differs')
                issued._validate_start_binding(
                    start['attestation'], start['observed_at'], body,
                    reservation_sha)
                after = os.stat(root, follow_symlinks=False)
                current = os.fstat(root_fd)
                _need(stat.S_ISDIR(after.st_mode) and
                      after.st_uid == current.st_uid == os.geteuid() and
                      stat.S_IMODE(after.st_mode) ==
                      stat.S_IMODE(current.st_mode) == 0o700 and
                      (after.st_dev, after.st_ino) ==
                      (current.st_dev, current.st_ino) ==
                      (root_before.st_dev, root_before.st_ino) and
                      _db_fingerprint(os.stat(issued.DATABASE_NAME,
                          dir_fd=root_fd, follow_symlinks=False)) ==
                      database_before,
                      'private root or database changed during head snapshot')
                _sidecars_absent(root_fd)
                return {
                    'schema': HEAD_SNAPSHOT_SCHEMA,
                    'queue_id': head['queue_id'], 'seq': head['seq'],
                    'sha256': head['sha256'],
                    'action_count': head['action_count'],
                    'hmac_verified': True,
                    'start_sha256': start_sha,
                    'reservation_sha256': reservation_sha,
                }
            finally:
                conn.close()
        finally:
            os.close(root_fd)
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, OverflowError, sqlite3.Error) as exc:
        raise AuthenticatedStartError('authenticated head snapshot failed') from exc


def verify_authenticated_start(private_root: Path, key: bytes) -> AuthenticatedStartReceipt:
    """Return identities proven by the exact sequence-one HMAC and raw start.

    A valid older store is not distinguishable from rollback without an
    independent durable head checkpoint. The returned receipt is local and
    does not prove the subsequent scan or a final artifact.
    """
    try:
        issued._validate_key(key)
        root = intake.private_root(Path(private_root))
        root_before = os.stat(root, follow_symlinks=False)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_opened = os.fstat(root_fd)
            _need(stat.S_ISDIR(root_opened.st_mode) and
                  root_opened.st_uid == os.geteuid() and
                  stat.S_IMODE(root_opened.st_mode) == 0o700 and
                  (root_opened.st_dev, root_opened.st_ino) ==
                  (root_before.st_dev, root_before.st_ino),
                  'private root changed before database read')
            conn, database_before = _open_read_only(root_fd)
        except BaseException:
            os.close(root_fd)
            raise
        try:
            issued._check_v3_schema(conn)
            intake._verify_receipt_chain(conn)
            head = issued.verify_issued_chain(conn, key)
            _need(head['seq'] == head['action_count'] == 1 and
                  head['hmac_verified'],
                  'expected exact authenticated sequence-one issued head')
            row = conn.execute(
                'SELECT document_json, action_sha256 FROM issued_actions WHERE seq=1'
            ).fetchone()
            _need(row is not None and row['action_sha256'] == head['sha256'],
                  'sequence-one document differs from issued head')
            start, _, start_raw = issued._load_document(row['document_json'])
            _need(0 < len(start_raw) <= MAX_START and
                  issued.digest(start_raw) == head['sha256'],
                  'sequence-one start bytes differ from issued head')
            att = start['attestation']
            chain, reservation_body, reservation_hash = issued._load_reservation(conn)
            _need(chain['queue_id'] == head['queue_id'] and
                  reservation_body['status'] == 'reserved_only' and
                  reservation_hash == att['reservation_sha256'],
                  'sequence-one reservation differs')
            issued._validate_start_binding(att, start['observed_at'],
                                           reservation_body, reservation_hash)

            expected = {'receipt.json'} | {
                value[0] for value in capture.START_RAW.values()
            }
            # This checks every raw file through directory-relative, no-follow
            # reads, exact receipt inventory, API identities, timing and ZIP.
            observed_att, _, _, _, early = capture._start_evidence(
                root_fd, start_raw, att['run_id'], att['run_attempt'],
                expected_entries=expected)
            _need(observed_att == att and
                  capture._zip_identity(early) == att['early_artifact'],
                  'retained observation differs from authenticated start')
            root_after = os.stat(root, follow_symlinks=False)
            root_fd_after = os.fstat(root_fd)
            _need(stat.S_ISDIR(root_after.st_mode) and
                  root_after.st_uid == root_fd_after.st_uid == os.geteuid() and
                  stat.S_IMODE(root_after.st_mode) ==
                  stat.S_IMODE(root_fd_after.st_mode) == 0o700 and
                  (root_after.st_dev, root_after.st_ino) ==
                  (root_fd_after.st_dev, root_fd_after.st_ino) ==
                  (root_before.st_dev, root_before.st_ino),
                  'private root changed during start preflight')
            _need(_db_fingerprint(os.stat(issued.DATABASE_NAME, dir_fd=root_fd,
                                          follow_symlinks=False)) == database_before,
                  'backlog database changed during start preflight')
            _sidecars_absent(root_fd)
            return {
                'schema': SCHEMA, 'status': 'authenticated_start',
                'verification_scope': SCOPE,
                'queue_id': head['queue_id'], 'issued_seq': 1,
                'start_sha256': head['sha256'],
                'reservation_sequence': 1,
                'reservation_sha256': reservation_hash,
                'identity': att['identity'],
                'run_id': att['run_id'], 'run_attempt': att['run_attempt'],
                'job_id': att['job_id'], 'workflow': att['workflow'],
                'job': att['job'], 'early_artifact': att['early_artifact'],
                'observation_sha256': att['observation_sha256'],
                'raw_sha256': {
                    role: (att[digest_key] if digest_key else
                           att['early_artifact']['sha256'])
                    for role, (_, digest_key) in capture.START_RAW.items()
                },
                'completed_scan_verified': False,
                'final_proof_verified': False,
            }
        finally:
            conn.rollback()
            conn.close()
            os.close(root_fd)
    except (OSError, sqlite3.Error, intake.IntakeError,
            reservation.ReservationError, issued.IssuedActionError,
            capture.CaptureError, reconcile.ReconcileError,
            live.LiveObservationError, KeyError, TypeError, UnicodeError,
            AttributeError, RecursionError, ValueError) as exc:
        raise AuthenticatedStartError('private start preflight failed') from exc
