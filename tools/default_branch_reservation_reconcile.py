#!/usr/bin/env python3
"""Read-only operator reconciliation of one retained default-branch claim.

This compares a completed GitHub run's retained claim artifact to the local
reservation action and replays the exact retained discovery inputs referenced
by the intake receipt. It never writes the backlog database or records a scan
start, completion, result, or coverage state.
"""
from __future__ import annotations

import argparse
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools import default_branch_reservation_claim as scan_claim
from tools import incoming_poll as poll


REPOSITORY = 'lucas-albers-lz4/codeql-openwrt'
SCAN_WORKFLOW = '.github/workflows/default-branch-commit-scan.yml'
SCAN_JOB = 'released-default-branch-scan'
SCAN_ARTIFACT_PREFIX = 'default-branch-scan-'
MAX_API = 16 * 1024 * 1024
MAX_ZIP = 64 * 1024 * 1024
MAX_FILES = 10000
MAX_UNPACKED = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000
GH_TIMEOUT_SECONDS = 300
READ_CHUNK = 64 * 1024
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
ARTIFACT_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
QUEUE_ID = re.compile(r'[0-9a-f]{32}\Z')
POSITIVE = re.compile(r'[1-9][0-9]{0,19}\Z')
SCAN_REQUIRED = {
    'previous-run-api.json', 'current-run-api.json',
    'previous/decisions.json', 'current/decisions.json',
    'current/gap/gap.json', 'identity.json', 'manifest.json',
}


class ReconcileError(ValueError):
    """A retained claim or its local origin failed reconciliation."""


def require(condition, message):
    if not condition:
        raise ReconcileError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _reject_constant(_value):
    raise ValueError('non-finite JSON number')


def parse_json(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=intake.unique_object,
                           parse_constant=_reject_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ReconcileError('invalid ' + label) from exc
    require(isinstance(value, dict), label + ' is not an object')
    return value


def _private_root(root):
    try:
        return intake.private_root(Path(root))
    except (intake.IntakeError, OSError) as exc:
        raise ReconcileError(str(exc)) from exc


def _safe_private_file(path, limit, label):
    try:
        path = intake._safe_path(Path(path), label)
        info = path.lstat()
    except (intake.IntakeError, OSError) as exc:
        raise ReconcileError(label + ' is unavailable or unsafe') from exc
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
            0 < info.st_size <= limit,
            label + ' must be a bounded private singly linked regular file')
    try:
        raw = intake.read_regular(path, limit, label)
    except intake.IntakeError as exc:
        raise ReconcileError(str(exc)) from exc
    after = path.lstat()
    require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
             info.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns), label + ' changed while being read')
    return raw


def _relative_archive_path(root, value, label):
    require(isinstance(value, str) and value and '\\' not in value,
            'invalid ' + label + ' path in intake receipt')
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and
            all(part not in ('', '.', '..') for part in relative.parts),
            'unsafe ' + label + ' path in intake receipt')
    path = root.joinpath(*relative.parts)
    try:
        resolved_check = intake._safe_path(path, label)
    except intake.IntakeError as exc:
        raise ReconcileError(str(exc)) from exc
    require(resolved_check == path, 'unexpected ' + label + ' archive path')
    return path


def _read_archive_group(root, receipt, role):
    """Reopen the exact private archive paths named by the chained receipt."""
    prefix = role + '_'
    run_id = receipt.get(prefix + 'run_id')
    attempt = receipt.get(prefix + 'attempt')
    artifact_id = receipt.get(prefix + 'artifact_id')
    zip_sha = receipt.get(prefix + 'zip_sha256')
    run_sha = receipt.get(prefix + 'run_api_sha256')
    artifacts_sha = receipt.get(prefix + 'artifacts_api_sha256')
    archive = receipt.get(prefix + 'archive')
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0 and
            type(artifact_id) is int and artifact_id > 0 and
            isinstance(zip_sha, str) and SHA256.fullmatch(zip_sha) and
            isinstance(run_sha, str) and SHA256.fullmatch(run_sha) and
            isinstance(artifacts_sha, str) and SHA256.fullmatch(artifacts_sha) and
            isinstance(archive, dict) and set(archive) == {'zip', 'run_api', 'artifacts_api'},
            'intake receipt has incomplete ' + role + ' archive identity')
    directory = f'archives/{run_id}-{attempt}'
    stem = f'{artifact_id}-{zip_sha}-{run_sha}-{artifacts_sha}'
    expected = {
        'zip': directory + '/' + stem + '.zip',
        'run_api': directory + '/' + stem + '.run-api.json',
        'artifacts_api': directory + '/' + stem + '.artifacts-api.json',
    }
    require(archive == expected,
            'intake receipt ' + role + ' archive paths do not match its digests')
    zip_raw = _safe_private_file(_relative_archive_path(root, archive['zip'], role + ' ZIP'),
                                intake.MAX_ZIP, role + ' archived ZIP')
    run_raw = _safe_private_file(_relative_archive_path(root, archive['run_api'], role + ' run API'),
                                 intake.MAX_API, role + ' archived run API')
    artifacts_raw = _safe_private_file(
        _relative_archive_path(root, archive['artifacts_api'], role + ' artifacts API'),
        intake.MAX_API, role + ' archived artifacts API')
    require(digest(zip_raw) == zip_sha and digest(run_raw) == run_sha and
            digest(artifacts_raw) == artifacts_sha,
            'archived ' + role + ' bytes differ from intake receipt digests')
    try:
        identity = intake._run_identity(run_raw, artifacts_raw, zip_raw)
    except (intake.IntakeError, poll.PollError, ValueError, TypeError,
            KeyError, AttributeError, OverflowError) as exc:
        raise ReconcileError('archived ' + role + ' discovery identity did not replay') from exc
    expected_identity = {
        'run_id': run_id, 'attempt': attempt,
        'run_event': receipt.get(prefix + 'run_event'),
        'run_head_sha': receipt.get(prefix + 'run_head_sha'),
        'artifact_id': artifact_id, 'zip_sha256': zip_sha,
        'run_api_sha256': run_sha, 'artifacts_api_sha256': artifacts_sha,
        'capture_status': 'offline_retained_api_metadata',
    }
    require(all(identity.get(key) == value for key, value in expected_identity.items()),
            'archived ' + role + ' run/artifact identity differs from intake receipt')
    return {'zip': zip_raw, 'run_api': run_raw, 'artifacts_api': artifacts_raw,
            'identity': identity}


def _read_only_connection(root):
    database = root / reservation.DATABASE_NAME
    try:
        database = intake._safe_path(database, 'backlog database')
        info = database.lstat()
    except (intake.IntakeError, OSError) as exc:
        raise ReconcileError('backlog database is missing or unsafe') from exc
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'backlog database must be a private singly linked regular file')
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = root / (reservation.DATABASE_NAME + suffix)
        require(not sidecar.exists() and not sidecar.is_symlink(),
                'backlog database has a SQLite sidecar; inspect or recover it first')
    descriptor = os.open(database, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(descriptor)
        header = os.read(descriptor, 20)
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino) and
                header[:16] == b'SQLite format 3\x00' and header[18:20] == b'\x01\x01',
                'backlog database is not a DELETE-journal SQLite file')
    finally:
        os.close(descriptor)
    uri = 'file:' + quote(str(database), safe='/') + '?mode=ro'
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        opened_paths = conn.execute('PRAGMA database_list').fetchall()
        require(len(opened_paths) == 1 and opened_paths[0][1] == 'main' and
                opened_paths[0][2] == str(database),
                'SQLite opened a different backlog path')
        conn.execute('PRAGMA trusted_schema=OFF')
        conn.execute('PRAGMA query_only=ON')
        conn.execute('BEGIN')
        require(conn.in_transaction,
                'SQLite did not establish a stable read transaction')
        after = database.lstat()
        require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns) ==
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                 info.st_ctime_ns), 'backlog database changed during read-only open')
        return conn, database, info
    except BaseException:
        if 'conn' in locals():
            conn.close()
        raise


def _check_database_unchanged(conn, database, before):
    after = database.lstat()
    require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns) ==
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns), 'backlog database changed during reconciliation')
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = database.parent / (database.name + suffix)
        require(not sidecar.exists() and not sidecar.is_symlink(),
                'backlog database sidecar appeared during reconciliation')
    require(conn.in_transaction, 'read-only database snapshot ended unexpectedly')


def _load_local_action(conn, root, requested_queue_id, requested_sequence,
                       requested_hash, *, require_v3=False,
                       supplied_start_sha256=None):
    try:
        intake._initialize_or_check_schema(conn)
        expected_version = (intake.ISSUED_SCHEMA_VERSION if
                            (require_v3 or supplied_start_sha256 is not None) else
                            intake.RESERVATION_SCHEMA_VERSION)
        require(conn.execute('PRAGMA application_id').fetchone()[0] == intake.APP_ID and
                conn.execute('PRAGMA user_version').fetchone()[0] == expected_version,
                'reservation reconciliation requires backlog schema v' +
                str(expected_version))
        intake._verify_receipt_chain(conn)
        reservation.verify_action_chain(conn)
        if require_v3:
            issued_head = issued.verify_issued_chain(conn)
            require(issued_head['seq'] == 0 and
                    issued_head['sha256'] == issued.ZERO_HASH and
                    issued_head['action_count'] == 0,
                    'live observation requires an empty v3 issued head')
        if supplied_start_sha256 is not None:
            require(not require_v3 and isinstance(supplied_start_sha256, str) and
                    SHA256.fullmatch(supplied_start_sha256) is not None,
                    'supplied start digest is invalid')
            # Structural binding only: a key-owning issuer must separately
            # verify the sequence-one HMAC before trusting this result.
            issued_head = issued.verify_issued_chain(conn)
            require(issued_head['seq'] == issued_head['action_count'] == 1 and
                    issued_head['sha256'] == supplied_start_sha256 and
                    issued_head['queue_id'] == requested_queue_id,
                    'supplied start differs from exact v3 issued head')
    except ReconcileError:
        raise
    except (intake.IntakeError, reservation.ReservationError, sqlite3.Error,
            ValueError, TypeError, KeyError, AttributeError, OverflowError,
            RecursionError) as exc:
        raise ReconcileError('backlog receipt or action chain did not verify') from exc
    try:
        queue_rows = conn.execute(
            'SELECT queue_id FROM queue_metadata WHERE singleton=1').fetchall()
        require(len(queue_rows) == 1 and queue_rows[0]['queue_id'] == requested_queue_id,
                'claim queue ID differs from local queue')
        rows = conn.execute(
            'SELECT action_seq,previous_hash,body_json,action_hash '
            'FROM reservation_actions WHERE action_seq=?',
            (requested_sequence,)).fetchall()
        require(len(rows) == 1, 'claim action sequence is absent from local queue')
        stored = rows[0]
        require(stored['action_hash'] == requested_hash,
                'claim action hash differs from local queue')
        body = reservation._parse_json(stored['body_json'], 'local reservation action')
        require(reservation.canonical_json(body) == stored['body_json'] and
                body.get('status') == 'reserved_only' and body.get('action') == 'reserve' and
                body.get('queue_id') == requested_queue_id and
                body.get('action_seq') == requested_sequence and
                body.get('reservation_id') == f'{requested_queue_id}:{requested_sequence}',
                'local action is not the exact queue-only reservation')
        expected_hash = reservation.digest(
            (stored['previous_hash'] + '\n' + stored['body_json']).encode('utf-8'))
        require(expected_hash == requested_hash,
                'local reservation action hash did not replay')
        body = dict(body)
        body['action_hash'] = stored['action_hash']
        identity = body.get('identity')
        require(isinstance(identity, dict), 'local reservation lacks row identity')
        receipts = conn.execute(
            'SELECT i.*,r.receipt_hash,r.body_json FROM intakes AS i JOIN receipts AS r '
            'ON r.receipt_seq=i.receipt_seq WHERE i.receipt_seq=?',
            (identity.get('receipt_seq'),)).fetchall()
        require(len(receipts) == 1,
                'reservation origin receipt is missing or ambiguous')
        intake_row = receipts[0]
        receipt_body = intake.parse_json(intake_row['body_json'], 'intake receipt')
        require(intake.canonical_json(receipt_body) == intake_row['body_json'] and
                body.get('origin', {}).get('receipt_hash') == intake_row['receipt_hash'] and
                body.get('origin') == reservation._origin_for_row(conn, {
                    'intake_id': identity.get('intake_id'),
                    'receipt_seq': identity.get('receipt_seq'),
                    'repository': identity.get('repository'),
                    'ref': identity.get('ref'),
                    'commit_sha': identity.get('commit_sha'),
                }),
                'reservation action origin differs from exact intake receipt')
        backlog_rows = conn.execute('''
            SELECT b.repository,b.ref,b.ordinal,b.commit_sha,b.tree_sha,
                   b.first_parent_sha,b.status,b.intake_id,i.receipt_seq
            FROM commit_backlog AS b JOIN intakes AS i USING (intake_id)
            WHERE b.repository=? AND b.ref=? AND b.commit_sha=?
        ''', (identity.get('repository'), identity.get('ref'),
              identity.get('commit_sha'))).fetchall()
        require(len(backlog_rows) == 1 and backlog_rows[0]['status'] == 'pending' and
                all(backlog_rows[0][key] == identity.get(key) for key in
                    ('repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                     'first_parent_sha', 'intake_id', 'receipt_seq')),
                'local reservation row differs from its exact pending identity')
        require(isinstance(receipt_body.get('commits'), list) and
                any(item == {key: identity[key] for key in (
                    'repository', 'ref', 'ordinal', 'commit_sha', 'tree_sha',
                    'first_parent_sha')} for item in receipt_body['commits']),
                'local intake receipt does not contain the reserved source identity')
        archive_pair = {
            'previous': _read_archive_group(root, receipt_body, 'previous'),
            'current': _read_archive_group(root, receipt_body, 'current'),
        }
        return body, receipt_body, archive_pair
    except (intake.IntakeError, reservation.ReservationError, sqlite3.Error,
            ValueError, TypeError, KeyError, AttributeError, OverflowError,
            OSError, RecursionError) as exc:
        if isinstance(exc, ReconcileError):
            raise
        raise ReconcileError('local reservation origin did not reconcile') from exc


def _historical_run_matches(scan_run, archived_identity, role):
    document = parse_json(scan_run, role + ' scan artifact run API')
    required = {
        'id': archived_identity['run_id'],
        'run_attempt': archived_identity['attempt'],
        'path': intake.WORKFLOW,
        'event': archived_identity['run_event'],
        'head_branch': 'main',
        'head_sha': archived_identity['run_head_sha'],
        'status': 'completed',
        'conclusion': 'success',
    }
    require(all(document.get(key) == value for key, value in required.items()) and
            isinstance(document.get('repository'), dict) and
            document['repository'].get('full_name') == intake.REPOSITORY and
            document['repository'].get('id') == archived_identity['repository_id'] and
            isinstance(document.get('head_repository'), dict) and
            document['head_repository'].get('full_name') == intake.REPOSITORY and
            document['head_repository'].get('id') == archived_identity['repository_id'],
            role + ' scan artifact API identity differs from retained intake origin')
    return document


def _read_scan_zip(raw, run_id, attempt):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ZIP,
            'scan artifact ZIP is empty or exceeds byte bound')
    members = {}
    seen_dirs = set()
    try:
        with ZipFile(BytesIO(raw), 'r') as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= MAX_FILES,
                    'scan artifact member count is outside bound')
            require(sum(info.file_size for info in infos) <= MAX_UNPACKED,
                    'scan artifact expansion exceeds byte bound')
            for info in infos:
                name = info.filename
                require(name and not name.startswith('/') and '\\' not in name,
                        'unsafe scan artifact member name')
                parts = name[:-1].split('/') if info.is_dir() and name.endswith('/') else name.split('/')
                require(all(part not in ('', '.', '..') for part in parts),
                        'unsafe scan artifact member path')
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if info.is_dir():
                    require(kind in (0, stat.S_IFDIR) and name not in seen_dirs,
                            'invalid or duplicate scan artifact directory')
                    seen_dirs.add(name)
                    continue
                require(name not in members and kind in (0, stat.S_IFREG) and
                        not (info.flag_bits & 0x1),
                        'duplicate, nonregular, or encrypted scan artifact member')
                require(info.file_size <= MAX_UNPACKED and
                        (info.file_size == 0 or info.compress_size > 0) and
                        (info.compress_size == 0 or
                         info.file_size <= info.compress_size * MAX_COMPRESSION_RATIO),
                        'scan artifact member violates decompression bounds')
                with archive.open(info, 'r') as source:
                    chunks = []
                    copied = 0
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        copied += len(block)
                        require(copied <= info.file_size and copied <= MAX_UNPACKED,
                                'scan artifact member expanded beyond its declared size')
                        chunks.append(block)
                    require(copied == info.file_size,
                            'scan artifact member is truncated')
                members[name] = b''.join(chunks)
    except (BadZipFile, OSError, RuntimeError, EOFError, NotImplementedError) as exc:
        if isinstance(exc, ReconcileError):
            raise
        raise ReconcileError('invalid scan artifact ZIP') from exc
    prefix = f'default-branch-inputs-{run_id}-{attempt}/'
    selected = {}
    for name, body in members.items():
        if name.startswith(prefix):
            relative = name[len(prefix):]
            require(relative and relative not in selected,
                    'duplicate default-branch input artifact member')
            selected[relative] = body
    require(SCAN_REQUIRED <= set(selected),
            'scan artifact is missing required claim input members')
    return selected


def _replay_archived_discovery(archive_pair, temp_root):
    staged = {}
    for role in ('previous', 'current'):
        path = temp_root / (role + '-discovery.zip')
        with path.open('xb') as handle:
            handle.write(archive_pair[role]['zip'])
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
        try:
            staged[role] = intake._read_artifact_inputs(path, archive_pair[role]['identity'],
                                                        role, temp_root)
            intake._validate_run_input(staged[role], archive_pair[role]['identity'], role)
        except (intake.IntakeError, poll.PollError, OSError, ValueError,
                TypeError, KeyError, AttributeError, OverflowError,
                RecursionError) as exc:
            raise ReconcileError('retained ' + role + ' discovery artifact did not replay') from exc
    try:
        intake._validate_link(staged['previous'], staged['current'],
                              archive_pair['previous']['identity'],
                              archive_pair['current']['identity'])
        rows = intake._verify_gap(staged['previous'], staged['current'])
    except (intake.IntakeError, poll.PollError, OSError, ValueError, TypeError,
            KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise ReconcileError('retained linked discovery gap did not replay') from exc
    return staged, rows


def _verify_scan_claim(members, canonical_run, action, receipt_body,
                       archive_pair, work_parent):
    failure_raw = members.get('reservation-claim-failure.json')
    claim_raw = members.get('reservation-claim.json')
    require(not (failure_raw is not None and claim_raw is not None),
            'scan artifact contains both claim and claim-failure records')
    require(claim_raw is not None,
            'scan artifact has no claim record; claim_failed cannot be reconciled'
            if failure_raw is not None else
            'scan artifact has neither a claim record nor a claim-failure record')
    recorded_claim = parse_json(claim_raw, 'reservation claim')
    require(recorded_claim.get('schema') == 'default-branch-reservation-claim-v1' and
            recorded_claim.get('status') == 'claimed_unverified',
            'reservation claim is absent or not an unverified assertion')
    asserted = recorded_claim.get('asserted_reservation')
    require(isinstance(asserted, dict) and
            set(asserted) == {'queue_id', 'reservation_sequence', 'reservation_sha256'} and
            type(asserted.get('reservation_sequence')) is int and
            asserted['reservation_sequence'] > 0,
            'reservation claim does not assert one complete triplet')
    require(asserted == {
        'queue_id': action.get('queue_id'),
        'reservation_sequence': action.get('action_seq'),
        'reservation_sha256': action.get('action_hash'),
    }, 'scan claim triplet differs from the exact local reservation action')
    identity_raw = members['identity.json']
    manifest_raw = members['manifest.json']
    identity = parse_json(identity_raw, 'source identity receipt')
    manifest = parse_json(manifest_raw, 'source-first manifest')
    source_doc = identity.get('source')
    control_doc = identity.get('control')
    require(isinstance(source_doc, dict) and isinstance(control_doc, dict),
            'source identity receipt has malformed source or control objects')
    linked_hashes = recorded_claim.get('linked_input_sha256')
    require(isinstance(linked_hashes, dict),
            'claim linked input digest record is malformed')
    require(linked_hashes.get('identity_receipt') ==
            digest(identity_raw) and
            linked_hashes.get('manifest') == digest(manifest_raw),
            'claim identity or manifest digest differs from retained scan members')
    with tempfile.TemporaryDirectory(prefix='reservation-replay-', dir=work_parent) as temp:
        os.chmod(temp, 0o700)
        temp_root = Path(temp)
        staged, replayed_rows = _replay_archived_discovery(archive_pair, temp_root)
        for member_name, source_path, label in (
                ('previous/decisions.json', staged['previous']['decisions_path'],
                 'predecessor checkpoint'),
                ('current/decisions.json', staged['current']['decisions_path'],
                 'successor checkpoint'),
                ('current/gap/gap.json', staged['current']['gap_path'],
                 'linked gap')):
            require(members[member_name] == source_path.read_bytes(),
                    'scan artifact ' + label + ' differs from exact retained archive bytes')
        _historical_run_matches(members['previous-run-api.json'],
                                archive_pair['previous']['identity'], 'previous')
        _historical_run_matches(members['current-run-api.json'],
                                archive_pair['current']['identity'], 'current')
        require(replayed_rows == receipt_body.get('commits'),
                'replayed discovery commit identities differ from chained intake receipt')
        previous_input = staged['previous']['run_input']
        current_input = staged['current']['run_input']
        require(previous_input.get('run_id') == str(archive_pair['previous']['identity']['run_id']) and
                previous_input.get('run_attempt') == str(archive_pair['previous']['identity']['attempt']) and
                current_input.get('run_id') == str(archive_pair['current']['identity']['run_id']) and
                current_input.get('run_attempt') == str(archive_pair['current']['identity']['attempt']),
                'replayed discovery run-input identities differ from retained API records')
        dispatch = {
            'previous_run_id': str(archive_pair['previous']['identity']['run_id']),
            'previous_run_attempt': str(archive_pair['previous']['identity']['attempt']),
            'previous_sha256': staged['previous']['decisions_sha256'],
            'current_run_id': str(archive_pair['current']['identity']['run_id']),
            'current_run_attempt': str(archive_pair['current']['identity']['attempt']),
            'current_sha256': staged['current']['decisions_sha256'],
            'gap_sha256': staged['current']['gap_sha256'],
            'repository': identity.get('repository'),
            'source_sha': source_doc.get('commit'),
            'control_sha': control_doc.get('commit'),
        }
        execution = {
            'run_id': str(canonical_run['id']),
            'run_attempt': str(canonical_run['run_attempt']),
            'consumer_head': canonical_run['head_sha'],
            'actual_head': canonical_run['head_sha'],
        }
        fields = {
            'queue_id': asserted['queue_id'],
            'reservation_sequence': str(asserted['reservation_sequence']),
            'reservation_sha256': asserted['reservation_sha256'],
        }
        try:
            replayed_claim = scan_claim.claim(
                fields, identity, manifest,
                staged['previous']['decisions_path'],
                staged['current']['decisions_path'],
                staged['current']['gap_path'], dispatch, execution,
                identity_raw, manifest_raw)
        except (scan_claim.ClaimError, poll.PollError, OSError, ValueError,
                TypeError, KeyError, AttributeError, OverflowError,
                RecursionError) as exc:
            raise ReconcileError('retained source claim did not replay') from exc
        require(replayed_claim == recorded_claim,
                'retained reservation claim differs from exact source replay')
        policy = action.get('policy')
        require(isinstance(policy, dict) and
                policy.get('schema') == reservation.POLICY_SCHEMA and
                policy.get('workflow') == SCAN_WORKFLOW and
                policy.get('consumer_commit') == canonical_run['head_sha'] and
                policy.get('consumer_commit') == execution['consumer_head'] and
                policy.get('consumer_commit') == manifest.get('event', {}).get('consumer_commit'),
                'operator policy consumer_commit differs from canonical scan run head')
        origin = action.get('origin')
        claim_origin = replayed_claim.get('linked_discovery_origin')
        origin_keys = ('previous_run_id', 'previous_attempt',
                       'previous_checkpoint_sha256', 'current_run_id',
                       'current_attempt', 'current_checkpoint_sha256', 'gap_sha256')
        require(isinstance(origin, dict) and isinstance(claim_origin, dict) and
                all(origin.get(key) == claim_origin.get(key) for key in origin_keys),
                'claim linked discovery origin differs from exact local intake origin')
        identity_binding = replayed_claim.get('derived_source')
        expected_identity = {
            'repository': action['identity']['repository'],
            'ref': action['identity']['ref'],
            'commit_sha': action['identity']['commit_sha'],
            'tree_sha': action['identity']['tree_sha'],
            'first_parent_sha': action['identity']['first_parent_sha'],
            'ordinal': action['identity']['ordinal'],
        }
        require(identity_binding == expected_identity,
                'replayed claim source identity differs from local reservation row')
        require(receipt_body.get('custody') == 'offline_retained_api_metadata',
                'intake receipt custody mode differs from expected offline metadata')
        return replayed_claim


def reconcile_bytes(private_root, run_raw, jobs_raw, artifacts_raw, zip_raw,
                    run_id, attempt, work_parent, *, start_raw=None):
    """Replay supplied API/ZIP bytes against v2 or one supplied v3 start.

    The v3 path checks canonical start bytes and the unkeyed issued head.
    A private issuer must authenticate the start MAC separately.
    """
    root = _private_root(private_root)
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'run ID and attempt must be positive integers')
    run = parse_json(run_raw, 'canonical scan run API')
    jobs = parse_json(jobs_raw, 'complete scan jobs API')
    artifacts = parse_json(artifacts_raw, 'complete scan artifacts API')
    job, artifact = verify_github_metadata(run, jobs, artifacts, run_id, attempt)
    require(type(zip_raw) is bytes and len(zip_raw) == artifact['size_in_bytes'],
            'downloaded scan artifact size differs from canonical listing')
    zip_sha = digest(zip_raw)
    require(artifact['digest'] == 'sha256:' + zip_sha,
            'downloaded scan artifact ZIP digest differs from canonical listing')
    members = _read_scan_zip(zip_raw, run_id, attempt)
    if 'reservation-claim.json' not in members:
        if 'reservation-claim-failure.json' in members:
            failure = parse_json(members['reservation-claim-failure.json'],
                                 'reservation claim failure')
            require(failure.get('schema') ==
                    'default-branch-reservation-claim-failure-v1' and
                    failure.get('status') == 'claim_failed',
                    'scan artifact failure record has an unsupported schema')
            raise ReconcileError('scan claim failed and has no successful claim record')
        raise ReconcileError('scan artifact has no reservation claim record')
    claim_record = parse_json(members['reservation-claim.json'], 'reservation claim')
    require(claim_record.get('status') != 'absent',
            'reservation claim is explicitly absent')
    asserted = claim_record.get('asserted_reservation')
    require(isinstance(asserted, dict) and
            set(asserted) == {'queue_id', 'reservation_sequence', 'reservation_sha256'} and
            isinstance(asserted.get('queue_id'), str) and
            QUEUE_ID.fullmatch(asserted['queue_id']) is not None and
            type(asserted.get('reservation_sequence')) is int and
            0 < asserted['reservation_sequence'] <= 0x7fffffffffffffff and
            isinstance(asserted.get('reservation_sha256'), str) and
            SHA256.fullmatch(asserted['reservation_sha256']) is not None,
            'reservation claim triplet is incomplete or absent')
    start_sha256 = None
    if start_raw is not None:
        require(type(start_raw) is bytes and 0 < len(start_raw) <= 1024 * 1024,
                'supplied start bytes are empty or unbounded')
        try:
            start, _, canonical = issued._load_document(start_raw.decode('utf-8'))
            issued._validate_start(start['attestation'])
        except (issued.IssuedActionError, UnicodeError, TypeError, KeyError,
                AttributeError, RecursionError) as exc:
            raise ReconcileError('supplied start document is invalid') from exc
        start_att = start['attestation']
        require(canonical == start_raw and
                start_att['queue_id'] == asserted['queue_id'] and
                start_att['reservation_sequence'] == asserted['reservation_sequence'] and
                start_att['reservation_sha256'] == asserted['reservation_sha256'] and
                start_att['run_id'] == run_id and
                start_att['run_attempt'] == attempt and
                start_att['job_id'] == job['id'],
                'supplied start differs from claimed run/job/reservation')
        start_sha256 = digest(start_raw)
    conn, database, database_info = _read_only_connection(root)
    try:
        action, receipt_body, archive_pair = _load_local_action(
            conn, root, asserted['queue_id'], asserted['reservation_sequence'],
            asserted['reservation_sha256'], supplied_start_sha256=start_sha256)
        _verify_scan_claim(members, run, action, receipt_body, archive_pair,
                           Path(work_parent))
        _check_database_unchanged(conn, database, database_info)
        return {
            'schema': 'operator-default-branch-reservation-reconciliation-v1',
            'status': 'claim_reconciled_read_only',
            'claim_status': 'claimed_unverified',
            'reservation': {
                'queue_id': action['queue_id'],
                'action_sequence': action['action_seq'],
                'action_sha256': asserted['reservation_sha256'],
                'reservation_id': action['reservation_id'],
                'identity': action['identity'],
                'origin_receipt_sequence': action['origin']['receipt_seq'],
                'origin_receipt_sha256': action['origin']['receipt_hash'],
                'created_at': action['created_at'],
                'expires_at': action['expires_at'],
                'policy_claim': action['policy'],
                'policy_consumer_commit': action['policy']['consumer_commit'],
                'policy_sha256': action['policy']['policy_sha256'],
                'operator_name_claim': action['operator'],
            },
            'canonical_run': {
                'run_id': run_id, 'attempt': attempt, 'head_sha': run['head_sha'],
                'job_id': job['id'], 'artifact_id': artifact['id'],
                'artifact_sha256': zip_sha, 'artifact_size': len(zip_raw),
                'run_api_sha256': digest(run_raw),
                'jobs_api_sha256': digest(jobs_raw),
                'artifacts_api_sha256': digest(artifacts_raw),
            },
            'database': {'read_only': True, 'schema_version': (
                intake.ISSUED_SCHEMA_VERSION if start_sha256 is not None else
                intake.RESERVATION_SCHEMA_VERSION),
                         'receipt_chain_verified': True, 'action_chain_verified': True,
                         **({'supplied_start_head_bound': True,
                             'supplied_start_sha256': start_sha256,
                             'start_mac_verified': False,
                             'head_scope': 'read_only_snapshot_unkeyed'}
                            if start_sha256 is not None else {})},
            'limitations': [
                'The reservation action hash, operator name, policy bytes and policy digest are unkeyed local claims; this check does not authenticate them.',
                'GitHub artifact metadata binds the ZIP to the workflow run, not directly to a particular job; matching the expected job is a same-run inference.',
                'The discovery ZIPs and API JSON were replayed from the private intake archive and correspond to its receipt; the historical capture origin is not authenticated by this local ledger.',
                'This is a read-only claim reconciliation. It records no start, completion, scan outcome, coverage, or authorization.',
            ],
        }
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()
        _check_database_unchanged_after_close(database, database_info)


def _check_database_unchanged_after_close(database, before):
    after = database.lstat()
    require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns) ==
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns), 'backlog database changed during reconciliation')
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = database.parent / (database.name + suffix)
        require(not sidecar.exists() and not sidecar.is_symlink(),
                'backlog database sidecar appeared during reconciliation')


def verify_github_metadata(run, jobs, artifacts, run_id, attempt):
    """Require a complete scan run, its expected job and the exact run artifact."""
    require(type(run.get('id')) is int and run['id'] == run_id and
            type(run.get('run_attempt')) is int and run['run_attempt'] == attempt and
            isinstance(run.get('repository'), dict) and
            run['repository'].get('full_name') == REPOSITORY and
            type(run['repository'].get('id')) is int and run['repository']['id'] > 0 and
            run.get('path') == SCAN_WORKFLOW and run.get('event') == 'workflow_dispatch' and
            run.get('head_branch') == 'main' and run.get('status') == 'completed' and
            isinstance(run.get('conclusion'), str) and
            isinstance(run.get('head_sha'), str) and FULL_SHA.fullmatch(run['head_sha']) and
            isinstance(run.get('head_repository'), dict) and
            run['head_repository'].get('full_name') == REPOSITORY and
            run['head_repository'].get('id') == run['repository']['id'],
            'canonical scan run identity is incomplete or mismatched')
    job_list = jobs.get('jobs')
    require(type(jobs.get('total_count')) is int and isinstance(job_list, list) and
            jobs['total_count'] == len(job_list) and len(job_list) <= 100,
            'jobs API listing is incomplete or exceeds its one-page bound')
    matches = [item for item in job_list if isinstance(item, dict) and
               item.get('name') == SCAN_JOB]
    require(len(matches) == 1, 'expected scan job is missing or ambiguous')
    job = matches[0]
    require(type(job.get('id')) is int and job['id'] > 0 and
            type(job.get('run_id')) is int and job['run_id'] == run_id and
            type(job.get('run_attempt')) is int and job['run_attempt'] == attempt and
            job.get('head_sha') == run['head_sha'] and job.get('status') == 'completed' and
            isinstance(job.get('conclusion'), str),
            'expected scan job does not match canonical run identity')
    artifact_list = artifacts.get('artifacts')
    require(type(artifacts.get('total_count')) is int and
            isinstance(artifact_list, list) and
            artifacts['total_count'] == len(artifact_list) and
            len(artifact_list) <= 100,
            'artifacts API listing is incomplete or exceeds its one-page bound')
    artifact_ids = set()
    for item in artifact_list:
        require(isinstance(item, dict) and type(item.get('id')) is int and item['id'] > 0 and
                item['id'] not in artifact_ids,
                'artifacts API listing contains an invalid or duplicate ID')
        artifact_ids.add(item['id'])
    expected_name = f'{SCAN_ARTIFACT_PREFIX}{run_id}-{attempt}'
    named = [item for item in artifact_list if item.get('name') == expected_name]
    require(len(named) == 1, 'exact default-branch scan artifact is missing or ambiguous')
    artifact = named[0]
    linkage = artifact.get('workflow_run')
    require(artifact.get('expired') is False and
            type(artifact.get('size_in_bytes')) is int and
            0 < artifact['size_in_bytes'] <= MAX_ZIP and
            isinstance(artifact.get('digest'), str) and
            ARTIFACT_DIGEST.fullmatch(artifact['digest']) is not None and
            isinstance(linkage, dict) and type(linkage.get('id')) is int and
            linkage['id'] == run_id and
            linkage.get('repository_id') == run['repository']['id'] and
            linkage.get('head_repository_id') == run['repository']['id'] and
            linkage.get('head_branch') == 'main' and
            linkage.get('head_sha') == run['head_sha'],
            'scan artifact run linkage, expiry, size, or digest is invalid')
    return job, artifact


def _private_work_root(work_root):
    root = Path(work_root)
    require(root.is_absolute() and root != Path(root.anchor) and '..' not in root.parts,
            'work root must be an absolute path without parent traversal')
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ReconcileError('work-root path is unavailable') from exc
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                'work-root path contains a non-directory or symlink')
        if current == root:
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    'work root must be an operator-owned mode 0700 directory')
        else:
            require(info.st_uid in (0, os.geteuid()) and
                    not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                    'unsafe work-root ancestor: ' + str(current))
    return root


def _fetch_to_file(endpoint, target, limit):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise ReconcileError('cannot create exclusive GitHub capture file') from exc
    process = None
    selector = None
    size = 0
    hasher = hashlib.sha256()
    started = time.monotonic()
    try:
        env = os.environ.copy()
        env['GH_PROMPT_DISABLED'] = '1'
        process = subprocess.Popen(
            ['gh', 'api', '--hostname', 'github.com', endpoint],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, env=env)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        with os.fdopen(descriptor, 'wb') as output:
            descriptor = -1
            while True:
                remaining = GH_TIMEOUT_SECONDS - (time.monotonic() - started)
                require(remaining > 0, 'gh api request timed out')
                ready = selector.select(min(remaining, 1.0))
                if not ready:
                    if process.poll() is not None:
                        continue
                    continue
                block = os.read(process.stdout.fileno(), READ_CHUNK)
                if not block:
                    selector.unregister(process.stdout)
                    break
                size += len(block)
                require(size <= limit, 'GitHub API or artifact response exceeds byte bound')
                output.write(block)
                hasher.update(block)
            remaining = GH_TIMEOUT_SECONDS - (time.monotonic() - started)
            require(remaining > 0, 'gh api request timed out')
            try:
                exit_status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ReconcileError('gh api request timed out') from exc
            require(exit_status == 0, 'gh api request failed: ' + endpoint)
            output.flush()
            os.fsync(output.fileno())
        return {
            'endpoint': endpoint,
            'command': ['gh', 'api', '--hostname', 'github.com', endpoint],
            'size': size, 'sha256': hasher.hexdigest(), 'exit_status': exit_status,
            'elapsed_seconds': round(time.monotonic() - started, 3),
        }
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
        if process is not None:
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
        if descriptor >= 0:
            os.close(descriptor)
        try:
            target.unlink()
        except OSError:
            pass
        raise
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _fetch_json(endpoint, target):
    result = _fetch_to_file(endpoint, target, MAX_API)
    raw = _safe_private_file(target, MAX_API, 'captured API file')
    require(len(raw) == result['size'] and digest(raw) == result['sha256'],
            'captured API bytes changed after download')
    return raw, result


def capture(private_root, work_root, run_id, attempt):
    root = _private_root(private_root)
    work = _private_work_root(work_root)
    require(type(run_id) is int and run_id > 0 and len(str(run_id)) <= 20 and
            type(attempt) is int and attempt > 0 and len(str(attempt)) <= 20,
            'run ID and attempt must be positive integers')
    stage = Path(tempfile.mkdtemp(prefix=f'reservation-reconcile-{run_id}-{attempt}-',
                                  dir=work))
    os.chmod(stage, 0o700)
    endpoint_root = f'repos/{REPOSITORY}/actions/runs/{run_id}'
    run_ep = endpoint_root
    jobs_ep = endpoint_root + '/jobs?per_page=100'
    artifacts_ep = endpoint_root + '/artifacts?per_page=100'
    try:
        requests = []
        run_raw, run_file = _fetch_json(run_ep, stage / 'run-api.json')
        jobs_raw, jobs_file = _fetch_json(jobs_ep, stage / 'jobs-api.json')
        artifacts_raw, artifacts_file = _fetch_json(artifacts_ep, stage / 'artifacts-api.json')
        requests.extend((run_file, jobs_file, artifacts_file))
        run = parse_json(run_raw, 'canonical scan run API')
        jobs = parse_json(jobs_raw, 'complete scan jobs API')
        artifacts = parse_json(artifacts_raw, 'complete scan artifacts API')
        job, artifact = verify_github_metadata(run, jobs, artifacts, run_id, attempt)
        zip_endpoint = (f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip')
        zip_file = _fetch_to_file(zip_endpoint, stage / 'scan-artifact.zip', MAX_ZIP)
        requests.append(zip_file)
        require(zip_file['size'] == artifact['size_in_bytes'] and
                artifact['digest'] == 'sha256:' + zip_file['sha256'],
                'downloaded scan artifact size or digest differs from API listing')
        for filename, endpoint in (('run-api-confirm.json', run_ep),
                                   ('jobs-api-confirm.json', jobs_ep),
                                   ('artifacts-api-confirm.json', artifacts_ep)):
            raw, request = _fetch_json(endpoint, stage / filename)
            requests.append(request)
            expected = {'run-api-confirm.json': run_raw,
                        'jobs-api-confirm.json': jobs_raw,
                        'artifacts-api-confirm.json': artifacts_raw}[filename]
            require(raw == expected,
                    'canonical GitHub API response changed during artifact download')
        zip_raw = _safe_private_file(stage / 'scan-artifact.zip', MAX_ZIP,
                                     'captured scan artifact ZIP')
        require(len(zip_raw) == zip_file['size'] and digest(zip_raw) == zip_file['sha256'],
                'scan artifact ZIP changed after download')
        result = reconcile_bytes(root, run_raw, jobs_raw, artifacts_raw, zip_raw,
                                 run_id, attempt, work)
        result['capture'] = {
            'source': 'gh api --hostname github.com',
            'operator_workspace': str(stage),
            'job_id': job['id'], 'artifact_id': artifact['id'],
            're_fetched_api_bytes_match': True,
            'requests': requests,
        }
        return result
    except (ReconcileError, intake.IntakeError, reservation.ReservationError,
            scan_claim.ClaimError, poll.PollError, OSError, sqlite3.Error,
            ValueError, TypeError, KeyError, AttributeError, OverflowError,
            RecursionError,
            subprocess.SubprocessError) as exc:
        raise ReconcileError(f'{exc} (operator capture retained at {stage})') from exc


def _positive_integer(value):
    if not POSITIVE.fullmatch(value):
        raise argparse.ArgumentTypeError('must be a positive integer of at most 20 digits')
    return int(value, 10)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', required=True, type=Path,
                        help='existing operator-owned default-branch backlog root')
    parser.add_argument('--work-root', required=True, type=Path,
                        help='existing operator-owned mode-0700 capture directory')
    parser.add_argument('--run-id', required=True, type=_positive_integer)
    parser.add_argument('--attempt', required=True, type=_positive_integer)
    args = parser.parse_args(argv)
    try:
        result = capture(args.private_root, args.work_root, args.run_id, args.attempt)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ReconcileError, intake.IntakeError, reservation.ReservationError,
            scan_claim.ClaimError, poll.PollError, OSError, sqlite3.Error,
            ValueError, TypeError, KeyError, AttributeError, OverflowError,
            RecursionError,
            subprocess.SubprocessError) as exc:
        print('default-branch reservation reconciliation rejected: ' + str(exc),
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
