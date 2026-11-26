#!/usr/bin/env python3
"""Offline, metadata-bound intake of linked default-branch first-parent gaps.

This creates only an operator-maintained backlog. It does not reserve, scan,
dispatch, record outcomes, or establish coverage. Retained API JSON is checked
for consistency but its capture origin is not authenticated by this tool.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
import tempfile
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile

from tools import default_branch_gap as gap
from tools import discovery_latest_predecessor as latest
from tools import incoming_poll as poll


REPOSITORY = 'lucas-albers-lz4/codeql-openwrt'
WORKFLOW = '.github/workflows/incoming-discovery-manual.yml'
ARTIFACT_PREFIX = 'incoming-discovery-'
MAX_ZIP = 64 * 1024 * 1024
MAX_API = 16 * 1024 * 1024
MAX_FILES = 256
MAX_UNPACKED = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000
ZERO_HASH = '0' * 64
APP_ID = 0x44424931  # DBI1
SCHEMA_VERSION = 1
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')
RUN_INPUT_V1 = 'incoming-discovery-run-input-v1'
RUN_INPUT_V2 = 'incoming-discovery-run-input-v2'
REQUIRED_PREVIOUS = {'run-input.json', 'decisions.json', 'decisions.sha256'}
REQUIRED_CURRENT = REQUIRED_PREVIOUS | {'gap/gap.json', 'gap/gap.sha256'}
OPTIONAL_MEMBERS = {
    'poll/decisions.json', 'manual-run-history-api.json',
    'scheduled-run-history-api.json', 'discovery-history-api.json',
    'predecessor-run-api.json', 'predecessor-decisions.sha256',
    'latest-successful-run-api.json',
}
ALLOWED_MEMBERS = REQUIRED_CURRENT | OPTIONAL_MEMBERS


class IntakeError(ValueError):
    """Fail-closed intake error."""


def require(condition, message):
    if not condition:
        raise IntakeError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse_json(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IntakeError('invalid ' + label) from exc
    require(isinstance(value, dict), 'invalid ' + label + ' object')
    return value


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _safe_path(path, label, *, must_exist=True):
    path = Path(os.path.abspath(path))
    require(path.is_absolute(), label + ' path must be absolute')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not must_exist:
                break
            raise IntakeError(label + ' path does not exist: ' + str(current))
        require(not stat.S_ISLNK(info.st_mode), label + ' path has a symlink component')
    return path


def private_root(root):
    """Require a pre-created, operator-owned mode-0700 store before any DB I/O."""
    root = _safe_path(root, 'private store')
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            'private store must be an operator-owned mode 0700 directory')
    current = root.parent
    while current != Path(current.anchor):
        parent_info = current.lstat()
        require(stat.S_ISDIR(parent_info.st_mode) and
                parent_info.st_uid in (0, os.geteuid()) and
                not parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                'unsafe private-store ancestor: ' + str(current))
        current = current.parent
    return root


def read_regular(path, limit, label):
    path = _safe_path(path, label)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
            before.st_nlink == 1 and before.st_size <= limit,
            label + ' must be an operator-owned bounded regular file with one link')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IntakeError('cannot open ' + label) from exc
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and
                opened.st_nlink == 1 and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                label + ' changed before open')
        blocks = []
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= limit, label + ' exceeds byte bound')
            blocks.append(block)
        after = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size,
                 opened.st_mtime_ns, opened.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns),
                label + ' changed while being read')
        return b''.join(blocks)
    finally:
        os.close(descriptor)


def _private_file(path, *, create=False, raw=None):
    """Create or verify one immutable 0600 regular file in a private store."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'archived file is not private and singly linked')
        existing = read_regular(path, MAX_ZIP + MAX_API, 'archived file')
        require(raw is not None and existing == raw,
                'existing archive path contains different bytes')
        return
    except OSError as exc:
        raise IntakeError('cannot create private archive file') from exc
    try:
        with os.fdopen(descriptor, 'wb', closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'created archive file failed privacy check')


def archive_bytes(root, identity, role, zip_raw, run_raw, artifacts_raw):
    archives_dir = root / 'archives'
    if not archives_dir.exists():
        archives_dir.mkdir(mode=0o700)
    archives_info = archives_dir.lstat()
    require(stat.S_ISDIR(archives_info.st_mode) and
            not stat.S_ISLNK(archives_info.st_mode) and
            archives_info.st_uid == os.geteuid() and
            stat.S_IMODE(archives_info.st_mode) == 0o700,
            'archive parent directory is not private')
    run_dir = archives_dir / f"{identity['run_id']}-{identity['attempt']}"
    if not run_dir.exists():
        run_dir.mkdir(mode=0o700, parents=True)
    info = run_dir.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
            info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'archive run directory is not private')
    stem = (f"{identity['artifact_id']}-{identity['zip_sha256']}-"
            f"{identity['run_api_sha256']}-{identity['artifacts_api_sha256']}")
    files = {
        stem + '.zip': zip_raw,
        stem + '.run-api.json': run_raw,
        stem + '.artifacts-api.json': artifacts_raw,
    }
    for name, raw in files.items():
        _private_file(run_dir / name, create=True, raw=raw)
    descriptor = os.open(run_dir, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    identity = dict(identity)
    identity['archive_dir'] = str(run_dir)
    identity['archive_zip'] = str(run_dir / (stem + '.zip'))
    identity['archive_run_api'] = str(run_dir / (stem + '.run-api.json'))
    identity['archive_artifacts_api'] = str(run_dir / (stem + '.artifacts-api.json'))
    identity['archive_rel'] = {
        'zip': (run_dir / (stem + '.zip')).relative_to(root).as_posix(),
        'run_api': (run_dir / (stem + '.run-api.json')).relative_to(root).as_posix(),
        'artifacts_api': (run_dir / (stem + '.artifacts-api.json')).relative_to(root).as_posix(),
    }
    return identity


def _safe_members(zip_path, role, extraction_root):
    required = REQUIRED_PREVIOUS if role == 'previous' else REQUIRED_CURRENT
    extracted = {}
    try:
        with ZipFile(zip_path, 'r') as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= MAX_FILES, 'artifact member count outside bound')
            require(sum(info.file_size for info in infos) <= MAX_UNPACKED,
                    'artifact expansion exceeds byte bound')
            seen = set()
            seen_dirs = set()
            for info in infos:
                name = info.filename
                if info.is_dir():
                    stripped = name[:-1] if name.endswith('/') else name
                    parts = stripped.split('/')
                    require(stripped and all(part not in ('', '.', '..') for part in parts) and
                            '\\' not in name and not name.startswith('/') and
                            stripped in ('poll', 'gap') and stripped not in seen_dirs,
                            'unsafe archive directory')
                    mode = info.external_attr >> 16
                    require(stat.S_IFMT(mode) in (0, stat.S_IFDIR),
                            'archive directory is not a directory')
                    seen_dirs.add(stripped)
                    continue
                parts = name.split('/')
                require(name and not name.startswith('/') and '\\' not in name and
                        all(part not in ('', '.', '..') for part in parts) and
                        name not in seen and name in ALLOWED_MEMBERS,
                        'unsafe, duplicate, or unexpected archive member')
                seen.add(name)
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                require(kind in (0, stat.S_IFREG) and not (info.flag_bits & 0x1),
                        'archive member is not an unencrypted regular file')
                per_member_limit = (MAX_API if name.endswith('.json') and
                                    'api' in name else
                                    poll.MAX_RECORD if name in
                                    ('decisions.json', 'poll/decisions.json', 'gap/gap.json')
                                    else 1024 * 1024)
                require(info.file_size <= per_member_limit and
                        (info.file_size == 0 or info.compress_size > 0) and
                        (info.compress_size == 0 or
                         info.file_size <= info.compress_size * MAX_COMPRESSION_RATIO),
                        'archive member expansion ratio outside bound')
            require(required <= seen, 'artifact is missing required members')
            for name in sorted(seen):
                target = extraction_root / role / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                parent_info = target.parent.lstat()
                require(stat.S_ISDIR(parent_info.st_mode) and
                        not stat.S_ISLNK(parent_info.st_mode) and
                        parent_info.st_uid == os.geteuid(),
                        'unsafe extraction parent')
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
                expected = next(info for info in infos if info.filename == name)
                copied = 0
                try:
                    with os.fdopen(descriptor, 'wb') as output, archive.open(expected) as source:
                        while block := source.read(1024 * 1024):
                            copied += len(block)
                            require(copied <= expected.file_size,
                                    'archive member exceeded declared size')
                            output.write(block)
                        output.flush()
                        os.fsync(output.fileno())
                    require(copied == expected.file_size,
                            'archive member length differs from ZIP directory')
                except BaseException:
                    try:
                        target.unlink()
                    except OSError:
                        pass
                    raise
                extracted[name] = target
    except (BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError) as exc:
        if isinstance(exc, IntakeError):
            raise
        raise IntakeError('invalid discovery artifact ZIP') from exc
    return extracted


def _sidecar_sha(path, expected_path):
    require(path.stat().st_size <= 256, 'checkpoint digest sidecar exceeds byte bound')
    raw = path.read_bytes()
    require(len(raw) <= 256 and raw.endswith(b'\n'), 'invalid checkpoint digest sidecar')
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError as exc:
        raise IntakeError('invalid checkpoint digest sidecar') from exc
    match = re.fullmatch(r'([0-9a-f]{64})[ \t]+(?:\*?)([^\r\n]+)\n', text)
    require(match is not None and match.group(2) == expected_path,
            'checkpoint digest sidecar has an unexpected format')
    return match.group(1)


def _run_identity(run_raw, artifacts_raw, zip_raw):
    run = parse_json(run_raw, 'run API response')
    artifacts_doc = parse_json(artifacts_raw, 'artifact API response')
    run_id = run.get('id')
    attempt = run.get('run_attempt')
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'invalid run ID or attempt in retained API fields')
    require(run.get('repository', {}).get('full_name') == REPOSITORY and
            run.get('path') == WORKFLOW and run.get('head_branch') == 'main' and
            run.get('event') in ('workflow_dispatch', 'schedule') and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            isinstance(run.get('head_sha'), str) and FULL_SHA.fullmatch(run['head_sha']),
            'retained run API fields are not a successful main discovery run')
    repo_id = run['repository'].get('id')
    head_repo = run.get('head_repository')
    require(type(repo_id) is int and repo_id > 0 and isinstance(head_repo, dict) and
            head_repo.get('full_name') == REPOSITORY and head_repo.get('id') == repo_id,
            'run API repository identity mismatch')
    if 'id' in artifacts_doc and 'name' in artifacts_doc:
        artifacts = [artifacts_doc]
    else:
        artifacts = artifacts_doc.get('artifacts')
        require(type(artifacts_doc.get('total_count')) is int and
                isinstance(artifacts, list) and len(artifacts) == artifacts_doc['total_count'] and
                len(artifacts) <= 100,
                'artifact API page is incomplete or over bound')
    name = f'{ARTIFACT_PREFIX}{run_id}-{attempt}'
    matches = [item for item in artifacts if isinstance(item, dict) and item.get('name') == name]
    require(len(matches) == 1, 'missing or duplicate exact discovery artifact')
    artifact = matches[0]
    artifact_id = artifact.get('id')
    require(type(artifact_id) is int and artifact_id > 0 and
            artifact.get('expired') is False and
            type(artifact.get('size_in_bytes')) is int and
            artifact['size_in_bytes'] == len(zip_raw) and
            re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')) is not None,
            'artifact ID, expiry, size, or digest field mismatch')
    workflow_run = artifact.get('workflow_run')
    require(isinstance(workflow_run, dict) and workflow_run.get('id') == run_id and
            workflow_run.get('repository_id') == repo_id and
            workflow_run.get('head_repository_id') == repo_id and
            workflow_run.get('head_branch') == 'main' and
            workflow_run.get('head_sha') == run['head_sha'],
            'artifact API run linkage mismatch')
    zip_sha = digest(zip_raw)
    require(artifact['digest'] == 'sha256:' + zip_sha,
            'artifact ZIP bytes differ from retained API digest')
    return {
        'run_id': run_id,
        'attempt': attempt,
        'run_event': run['event'],
        'run_head_sha': run['head_sha'],
        'repository_id': repo_id,
        'artifact_id': artifact_id,
        'artifact_name': name,
        'zip_sha256': zip_sha,
        'zip_size': len(zip_raw),
        'run_api_sha256': digest(run_raw),
        'artifacts_api_sha256': digest(artifacts_raw),
        'capture_status': 'offline_retained_api_metadata',
    }


def _read_artifact_inputs(zip_path, identity, role, root):
    scratch = Path(tempfile.mkdtemp(prefix='intake-validate-', dir=root))
    os.chmod(scratch, 0o700)
    try:
        members = _safe_members(zip_path, role, scratch)
        run_input = parse_json(members['run-input.json'].read_bytes(), role + ' run-input')
        decisions_raw = members['decisions.json'].read_bytes()
        decisions_sha = digest(decisions_raw)
        require(_sidecar_sha(members['decisions.sha256'],
                             'discovery-output/decisions.json') == decisions_sha,
                role + ' decisions sidecar digest mismatch')
        if 'poll/decisions.json' in members:
            require(members['poll/decisions.json'].read_bytes() == decisions_raw,
                    role + ' poll and top-level decisions differ')
        decisions_path = members['decisions.json']
        doc, actual_sha = poll.load_checkpoint(decisions_path)
        require(actual_sha == decisions_sha, role + ' checkpoint digest mismatch')
        result = {'run_input': run_input, 'decisions_path': decisions_path,
                  'decisions_sha256': decisions_sha, 'checkpoint_doc': doc,
                  'members': members, 'scratch': scratch}
        if role == 'current':
            gap_raw = members['gap/gap.json'].read_bytes()
            gap_sha = digest(gap_raw)
            require(_sidecar_sha(members['gap/gap.sha256'],
                                 'discovery-output/gap/gap.json') == gap_sha,
                    'current gap sidecar digest mismatch')
            record = gap.load_gap(members['gap/gap.json'])
            result.update(gap_record=record, gap_sha256=gap_sha,
                          gap_path=members['gap/gap.json'])
        return result
    except BaseException:
        # Retain only the exact source ZIP/API bytes. Extracted validation copies
        # are transient and are deleted on both success and failure.
        raise


def _validate_run_input(info, identity, role):
    value = info['run_input']
    schema = value.get('schema')
    require(schema in (RUN_INPUT_V1, RUN_INPUT_V2), role + ' run-input schema unsupported')
    require(value.get('run_id') == str(identity['run_id']) and
            value.get('run_attempt') == str(identity['attempt']) and
            value.get('consumer_sha') == identity['run_head_sha'],
            role + ' run-input does not match retained run API fields')
    require(value.get('genesis') is (info['checkpoint_doc']['genesis']) and
            type(value.get('capacity')) is int and
            value['capacity'] == info['checkpoint_doc']['capacity'] == 1,
            role + ' run-input and checkpoint mode differ')
    require(not info['checkpoint_doc']['genesis'],
            role + ' checkpoint is genesis; intake requires linked non-genesis checkpoints')
    if schema == RUN_INPUT_V1:
        require(identity['run_event'] == 'workflow_dispatch',
                'v1 run-input is allowed only for a manual discovery run')
    else:
        require(value.get('event') == identity['run_event'] and
                value.get('scan_dispatched') is False,
                role + ' v2 run-input event or scan-dispatch claim mismatch')
        for field, member in (
                ('manual_run_history_api_sha256', 'manual-run-history-api.json'),
                ('scheduled_run_history_api_sha256', 'scheduled-run-history-api.json'),
                ('discovery_history_api_sha256', 'discovery-history-api.json')):
            expected = value.get(field)
            require(isinstance(expected, str) and SHA256.fullmatch(expected) and
                    member in info['members'] and
                    digest(info['members'][member].read_bytes()) == expected,
                    role + ' run-input history API digest mismatch')
        manual_history = parse_json(
            info['members']['manual-run-history-api.json'].read_bytes(),
            role + ' manual history API')
        scheduled_history = parse_json(
            info['members']['scheduled-run-history-api.json'].read_bytes(),
            role + ' scheduled history API')
        combined_history = parse_json(
            info['members']['discovery-history-api.json'].read_bytes(),
            role + ' combined history API')
        require(combined_history == {
            'schema': 'incoming-discovery-history-api-v1',
            'workflow_dispatch': manual_history,
            'schedule': scheduled_history,
        }, role + ' combined history differs from raw event responses')
        prior_run = value.get('previous_run_id')
        prior_attempt = value.get('previous_run_attempt')
        require(isinstance(prior_run, str) and
                re.fullmatch(r'[1-9][0-9]*', prior_run) and
                isinstance(prior_attempt, str) and
                re.fullmatch(r'[1-9][0-9]*', prior_attempt),
                role + ' v2 predecessor run identity is invalid')
        resolution = latest.verify(
            latest.read_api(info['members']['discovery-history-api.json']),
            REPOSITORY, False, prior_run, prior_attempt,
            str(identity['run_id']), identity['run_event'])
        require(resolution['latest_run_event'] == value.get('previous_run_event'),
                role + ' v2 history predecessor event differs')
        history_rows = (manual_history['workflow_runs'] +
                        scheduled_history['workflow_runs'])
        current_rows = [item for item in history_rows
                        if item['id'] == identity['run_id']]
        require(len(current_rows) == 1 and
                current_rows[0].get('run_attempt') == identity['attempt'] and
                current_rows[0].get('event') == identity['run_event'] and
                current_rows[0].get('head_sha') == identity['run_head_sha'] and
                current_rows[0].get('repository', {}).get('id') == identity['repository_id'],
                role + ' v2 current history run differs from completed run API')
        predecessor_api_sha = value.get('predecessor_run_api_sha256')
        if value['genesis']:
            require(predecessor_api_sha is None,
                    role + ' genesis run-input unexpectedly names predecessor API')
        else:
            require(isinstance(predecessor_api_sha, str) and
                    SHA256.fullmatch(predecessor_api_sha) and
                    'predecessor-run-api.json' in info['members'] and
                    digest(info['members']['predecessor-run-api.json'].read_bytes()) == predecessor_api_sha,
                    role + ' run-input predecessor API digest mismatch')
            predecessor_api = parse_json(
                info['members']['predecessor-run-api.json'].read_bytes(),
                role + ' bundled predecessor API')
            require(predecessor_api.get('id') == int(prior_run) and
                    predecessor_api.get('run_attempt') == int(prior_attempt) and
                    predecessor_api.get('event') == value.get('previous_run_event') and
                    predecessor_api.get('path') == WORKFLOW and
                    predecessor_api.get('head_branch') == 'main' and
                    predecessor_api.get('status') == 'completed' and
                    predecessor_api.get('conclusion') == 'success' and
                    isinstance(predecessor_api.get('repository'), dict) and
                    predecessor_api['repository'].get('full_name') == REPOSITORY,
                    role + ' v2 predecessor API identity differs')
            prior_rows = [item for item in history_rows
                          if item['id'] == int(prior_run)]
            require(len(prior_rows) == 1 and
                    all(prior_rows[0].get(field) == predecessor_api.get(field)
                        for field in ('id', 'run_attempt', 'event', 'head_sha',
                                      'path', 'head_branch', 'status', 'conclusion')) and
                    prior_rows[0].get('repository', {}).get('full_name') == REPOSITORY and
                    prior_rows[0].get('repository', {}).get('id') ==
                    predecessor_api['repository'].get('id'),
                    role + ' v2 selected history run differs from predecessor API')


def _commit_rows(record):
    rows = []
    seen = set()
    intervals = record.get('intervals')
    require(isinstance(intervals, list) and len(intervals) == len(poll.REPOS),
            'gap interval inventory incomplete')
    for interval in intervals:
        require(isinstance(interval, dict) and interval.get('repository') in poll.REPOS and
                isinstance(interval.get('ref'), str) and interval.get('state') in
                ('unchanged', 'bounded_fast_forward'),
                'invalid gap interval')
        commits = interval.get('first_parent_commits')
        require(isinstance(commits, list), 'invalid first-parent commit list')
        for ordinal, item in enumerate(commits, 1):
            require(isinstance(item, dict) and set(item) == {'commit', 'tree', 'first_parent'} and
                    all(isinstance(item[key], str) and FULL_SHA.fullmatch(item[key])
                        for key in ('commit', 'tree', 'first_parent')),
                    'invalid first-parent commit identity')
            key = (interval['repository'], item['commit'])
            require(key not in seen, 'duplicate first-parent commit identity in gap')
            seen.add(key)
            rows.append({'repository': interval['repository'], 'ref': interval['ref'],
                         'ordinal': ordinal,
                         'commit_sha': item['commit'], 'tree_sha': item['tree'],
                         'first_parent_sha': item['first_parent']})
    require(len(rows) <= gap.MAX_COMPARE_COMMITS * len(poll.REPOS),
            'first-parent backlog exceeds interval bound')
    return rows


def _ensure_database(root):
    database = root / 'default-branch-backlog.sqlite3'
    _safe_path(database, 'backlog database', must_exist=False)
    try:
        info = database.lstat()
    except FileNotFoundError:
        descriptor = os.open(database, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                             getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.close(descriptor)
        info = database.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'backlog database must be a private, singly linked regular file')
    return database, (info.st_dev, info.st_ino)


def _connect(database):
    old_umask = os.umask(0o077)
    try:
        # Encode URI delimiters in operator-chosen directory names. Otherwise
        # `?` or `#` could redirect SQLite away from the checked path.
        uri = 'file:' + quote(str(database), safe='/') + '?mode=rw'
        conn = sqlite3.connect(uri, uri=True,
                               timeout=10.0, isolation_level=None)
    except sqlite3.Error as exc:
        raise IntakeError('cannot open operator backlog database') from exc
    finally:
        os.umask(old_umask)
    try:
        conn.row_factory = sqlite3.Row
        opened = conn.execute('PRAGMA database_list').fetchall()
        require(len(opened) == 1 and opened[0][1] == 'main' and
                opened[0][2] == str(database),
                'SQLite opened a different backlog path')
        conn.execute('PRAGMA trusted_schema=OFF')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.execute('PRAGMA synchronous=FULL')
        return conn
    except BaseException:
        conn.close()
        raise


def _initialize_or_check_schema(conn):
    application_id = conn.execute('PRAGMA application_id').fetchone()[0]
    version = conn.execute('PRAGMA user_version').fetchone()[0]
    tables = {row['name'] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if application_id == 0 and version == 0 and not tables:
        conn.execute('BEGIN IMMEDIATE')
        try:
            # Use individual statements: sqlite3.executescript() implicitly
            # commits any transaction that is already open.
            for statement in (
                    '''CREATE TABLE cursor (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        checkpoint_sha256 TEXT NOT NULL,
                        run_id INTEGER NOT NULL,
                        attempt INTEGER NOT NULL,
                        receipt_seq INTEGER NOT NULL
                    )''',
                    '''CREATE TABLE intakes (
                        intake_id TEXT PRIMARY KEY,
                        previous_run_id INTEGER NOT NULL,
                        previous_attempt INTEGER NOT NULL,
                        current_run_id INTEGER NOT NULL,
                        current_attempt INTEGER NOT NULL,
                        previous_artifact_id INTEGER NOT NULL,
                        previous_zip_sha256 TEXT NOT NULL,
                        current_artifact_id INTEGER NOT NULL,
                        current_zip_sha256 TEXT NOT NULL,
                        previous_checkpoint_sha256 TEXT NOT NULL,
                        current_checkpoint_sha256 TEXT NOT NULL,
                        gap_sha256 TEXT NOT NULL,
                        commit_count INTEGER NOT NULL,
                        bootstrap INTEGER NOT NULL CHECK(bootstrap IN (0, 1)),
                        receipt_seq INTEGER NOT NULL UNIQUE,
                        UNIQUE(current_run_id, current_attempt),
                        UNIQUE(current_artifact_id)
                    )''',
                    '''CREATE TABLE commit_backlog (
                        repository TEXT NOT NULL,
                        ref TEXT NOT NULL,
                        ordinal INTEGER NOT NULL,
                        commit_sha TEXT NOT NULL,
                        tree_sha TEXT NOT NULL,
                        first_parent_sha TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status = 'pending'),
                        intake_id TEXT NOT NULL REFERENCES intakes(intake_id),
                        previous_checkpoint_sha256 TEXT NOT NULL,
                        current_checkpoint_sha256 TEXT NOT NULL,
                        gap_sha256 TEXT NOT NULL,
                        PRIMARY KEY(repository, ref, commit_sha)
                    )''',
                    '''CREATE TABLE receipts (
                        receipt_seq INTEGER PRIMARY KEY,
                        previous_hash TEXT NOT NULL,
                        body_json TEXT NOT NULL,
                        receipt_hash TEXT NOT NULL UNIQUE
                    )'''):
                conn.execute(statement)
            conn.execute('PRAGMA application_id=' + str(APP_ID))
            conn.execute('PRAGMA user_version=' + str(SCHEMA_VERSION))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        application_id = conn.execute('PRAGMA application_id').fetchone()[0]
        version = conn.execute('PRAGMA user_version').fetchone()[0]
    require(application_id == APP_ID and version == SCHEMA_VERSION,
            'database is not the default-branch backlog schema')
    expected = {('table', name) for name in
                ('cursor', 'intakes', 'commit_backlog', 'receipts')}
    actual = {(row['type'], row['name']) for row in conn.execute(
        "SELECT type,name FROM sqlite_master WHERE substr(name,1,7) != 'sqlite_'")}
    require(actual == expected,
            'backlog database has an unexpected table, view, index or trigger')


def _verify_receipt_chain(conn):
    previous = ZERO_HASH
    expected_seq = 1
    last_body = None
    expected_commit_total = 0
    for row in conn.execute(
            'SELECT receipt_seq, previous_hash, body_json, receipt_hash '
            'FROM receipts ORDER BY receipt_seq'):
        require(row['receipt_seq'] == expected_seq and row['previous_hash'] == previous,
                'receipt chain sequence or predecessor mismatch')
        body = parse_json(row['body_json'], 'receipt body')
        require(canonical_json(body) == row['body_json'], 'receipt body is not canonical JSON')
        expected_hash = digest((previous + '\n' + row['body_json']).encode('utf-8'))
        require(row['receipt_hash'] == expected_hash, 'receipt chain hash mismatch')
        require(body.get('schema') == 'default-branch-backlog-intake-v1' and
                body.get('status') == 'intake_recorded' and
                body.get('receipt_seq') == expected_seq and
                body.get('previous_receipt_hash') == previous and
                isinstance(body.get('commits'), list),
                'stored intake receipt fields differ')
        intake_id = (f"{body['current_run_id']}:{body['current_attempt']}:"
                     f"{body['current_artifact_id']}")
        intake_row = conn.execute('SELECT * FROM intakes WHERE receipt_seq=?',
                                  (expected_seq,)).fetchone()
        require(intake_row is not None and
                intake_row['intake_id'] == intake_id and
                intake_row['previous_run_id'] == body['previous_run_id'] and
                intake_row['previous_attempt'] == body['previous_attempt'] and
                intake_row['current_run_id'] == body['current_run_id'] and
                intake_row['current_attempt'] == body['current_attempt'] and
                intake_row['previous_artifact_id'] == body['previous_artifact_id'] and
                intake_row['previous_zip_sha256'] == body['previous_zip_sha256'] and
                intake_row['current_artifact_id'] == body['current_artifact_id'] and
                intake_row['current_zip_sha256'] == body['current_zip_sha256'] and
                intake_row['previous_checkpoint_sha256'] == body['previous_checkpoint_sha256'] and
                intake_row['current_checkpoint_sha256'] == body['current_checkpoint_sha256'] and
                intake_row['gap_sha256'] == body['gap_sha256'] and
                intake_row['commit_count'] == len(body['commits']) and
                intake_row['bootstrap'] == int(body['bootstrap']),
                'stored intake row differs from receipt')
        expected_rows = sorted(({
            'repository': item['repository'], 'ref': item['ref'],
            'ordinal': item['ordinal'], 'commit_sha': item['commit_sha'],
            'tree_sha': item['tree_sha'],
            'first_parent_sha': item['first_parent_sha'], 'status': 'pending',
            'previous_checkpoint_sha256': body['previous_checkpoint_sha256'],
            'current_checkpoint_sha256': body['current_checkpoint_sha256'],
            'gap_sha256': body['gap_sha256']}
            for item in body['commits']),
            key=lambda item: (item['repository'], item['ref'], item['ordinal']))
        stored_rows = [dict(item) for item in conn.execute(
            'SELECT repository, ref, ordinal, commit_sha, tree_sha, '
            'first_parent_sha, status, previous_checkpoint_sha256, '
            'current_checkpoint_sha256, gap_sha256 FROM commit_backlog '
            'WHERE intake_id=? ORDER BY repository, ref, ordinal', (intake_id,))]
        require(stored_rows == expected_rows,
                'stored backlog rows differ from receipt')
        expected_commit_total += len(expected_rows)
        last_body = body
        previous = row['receipt_hash']
        expected_seq += 1
    require(conn.execute('SELECT COUNT(*) FROM intakes').fetchone()[0] == expected_seq - 1 and
            conn.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0] == expected_commit_total,
            'backlog table counts differ from receipt chain')
    cursor = conn.execute('SELECT * FROM cursor WHERE singleton=1').fetchone()
    if last_body is None:
        require(cursor is None, 'cursor exists without an intake receipt')
    else:
        require(cursor is not None and
                cursor['checkpoint_sha256'] == last_body['current_checkpoint_sha256'] and
                cursor['run_id'] == last_body['current_run_id'] and
                cursor['attempt'] == last_body['current_attempt'] and
                cursor['receipt_seq'] == expected_seq - 1,
                'backlog cursor differs from last intake receipt')
    return expected_seq, previous


def _validate_link(previous, current, previous_identity, current_identity):
    old_input, new_input = previous['run_input'], current['run_input']
    require(current_identity['run_id'] != previous_identity['run_id'] and
            current_identity['attempt'] > 0,
            'predecessor and successor run identities must differ')
    require(new_input.get('genesis') is False and
            new_input.get('previous_run_id') == str(previous_identity['run_id']) and
            new_input.get('previous_run_attempt') == str(previous_identity['attempt']) and
            new_input.get('previous_sha256') == previous['decisions_sha256'] and
            previous['checkpoint_doc'].get('genesis') is False,
            'successor run-input does not link the supplied predecessor checkpoint')
    if new_input.get('previous_run_event') is not None:
        require(new_input.get('previous_run_event') == previous_identity['run_event'],
                'successor names a different predecessor event')
    require(current['checkpoint_doc'].get('previous_sha256') ==
            previous['decisions_sha256'],
            'successor checkpoint does not link exact predecessor bytes')
    require(old_input.get('run_id') == str(previous_identity['run_id']) and
            old_input.get('run_attempt') == str(previous_identity['attempt']),
            'predecessor run-input identity mismatch')
    if new_input.get('schema') == RUN_INPUT_V2:
        predecessor_api = parse_json(
            current['members']['predecessor-run-api.json'].read_bytes(),
            'successor bundled predecessor API response')
        require(predecessor_api.get('id') == previous_identity['run_id'] and
                predecessor_api.get('run_attempt') == previous_identity['attempt'] and
                predecessor_api.get('event') == previous_identity['run_event'] and
                predecessor_api.get('head_sha') == previous_identity['run_head_sha'] and
                predecessor_api.get('path') == WORKFLOW and
                predecessor_api.get('head_branch') == 'main' and
                predecessor_api.get('status') == 'completed' and
                predecessor_api.get('conclusion') == 'success' and
                isinstance(predecessor_api.get('repository'), dict) and
                predecessor_api['repository'].get('full_name') == REPOSITORY,
                'successor bundled predecessor API identity differs')
        history = latest.read_api(current['members']['discovery-history-api.json'])
        resolution = latest.verify(
            history, REPOSITORY, False,
            str(previous_identity['run_id']), str(previous_identity['attempt']),
            str(current_identity['run_id']), current_identity['run_event'])
        require(resolution['latest_run_id'] == previous_identity['run_id'] and
                resolution['latest_run_event'] == previous_identity['run_event'],
                'successor discovery history names another predecessor')


def _verify_gap(previous, current):
    prev_path = previous['decisions_path']
    current_path = current['decisions_path']
    previous_doc, previous_sha = poll.load_checkpoint(prev_path)
    current_doc, current_sha, observed, prior_sha, _ = poll.verify_checkpoint_decisions(
        current_path, prev_path)
    require(previous_sha == previous['decisions_sha256'] and
            current_sha == current['decisions_sha256'] and
            prior_sha == previous_sha,
            'linked checkpoint bytes changed during replay')
    record = current['gap_record']
    require(record.get('previous_sha256') == previous_sha and
            record.get('current_sha256') == current_sha,
            'gap record checkpoint digests differ from supplied artifacts')
    gap.replay_record(record, previous_doc, current_doc, observed)
    return _commit_rows(record)


def _intake_record(previous_identity, current_identity, previous, current, rows):
    return {
        'schema': 'default-branch-backlog-intake-v1',
        'custody': 'offline_retained_api_metadata',
        'custody_limit': 'API JSON capture origin and ZIP download source are not authenticated by this offline tool.',
        'previous_run_id': previous_identity['run_id'],
        'previous_attempt': previous_identity['attempt'],
        'previous_artifact_id': previous_identity['artifact_id'],
        'previous_zip_sha256': previous_identity['zip_sha256'],
        'previous_checkpoint_sha256': previous['decisions_sha256'],
        'previous_run_event': previous_identity['run_event'],
        'previous_run_head_sha': previous_identity['run_head_sha'],
        'previous_run_api_sha256': previous_identity['run_api_sha256'],
        'previous_artifacts_api_sha256': previous_identity['artifacts_api_sha256'],
        'previous_archive': previous_identity['archive_rel'],
        'current_run_id': current_identity['run_id'],
        'current_attempt': current_identity['attempt'],
        'current_artifact_id': current_identity['artifact_id'],
        'current_zip_sha256': current_identity['zip_sha256'],
        'current_checkpoint_sha256': current['decisions_sha256'],
        'current_run_event': current_identity['run_event'],
        'current_run_head_sha': current_identity['run_head_sha'],
        'current_run_api_sha256': current_identity['run_api_sha256'],
        'current_artifacts_api_sha256': current_identity['artifacts_api_sha256'],
        'current_archive': current_identity['archive_rel'],
        'gap_sha256': current['gap_sha256'],
        'commits': rows,
    }


def _store_intake(conn, previous_identity, current_identity, previous, current,
                  rows, record):
    intake_id = f"{current_identity['run_id']}:{current_identity['attempt']}:{current_identity['artifact_id']}"
    expected_values = (
        previous_identity['run_id'], previous_identity['attempt'],
        current_identity['run_id'], current_identity['attempt'],
        previous_identity['artifact_id'], previous_identity['zip_sha256'],
        current_identity['artifact_id'], current_identity['zip_sha256'],
        previous['decisions_sha256'], current['decisions_sha256'],
        current['gap_sha256'], len(rows))
    conn.execute('BEGIN IMMEDIATE')
    try:
        next_seq, previous_receipt_hash = _verify_receipt_chain(conn)
        existing = conn.execute(
            'SELECT * FROM intakes WHERE current_run_id=? AND current_attempt=?',
            (current_identity['run_id'], current_identity['attempt'])).fetchone()
        if existing is not None:
            actual = tuple(existing[key] for key in (
                'previous_run_id', 'previous_attempt', 'current_run_id',
                'current_attempt', 'previous_artifact_id', 'previous_zip_sha256',
                'current_artifact_id', 'current_zip_sha256',
                'previous_checkpoint_sha256', 'current_checkpoint_sha256',
                'gap_sha256', 'commit_count'))
            require(actual == expected_values and existing['intake_id'] == intake_id,
                    'conflicting repeated intake identity')
            stored_rows = [dict(row) for row in conn.execute(
                'SELECT repository, ref, ordinal, commit_sha, tree_sha, first_parent_sha, status, '
                'previous_checkpoint_sha256, current_checkpoint_sha256, gap_sha256 '
                'FROM commit_backlog WHERE intake_id=? ORDER BY repository, ref, ordinal',
                (intake_id,))]
            expected_rows = sorted(({
                'repository': row['repository'], 'ref': row['ref'],
                'ordinal': row['ordinal'],
                'commit_sha': row['commit_sha'], 'tree_sha': row['tree_sha'],
                'first_parent_sha': row['first_parent_sha'], 'status': 'pending',
                'previous_checkpoint_sha256': previous['decisions_sha256'],
                'current_checkpoint_sha256': current['decisions_sha256'],
                'gap_sha256': current['gap_sha256']}
                for row in rows), key=lambda row: (row['repository'], row['ref'], row['ordinal']))
            require(stored_rows == expected_rows,
                    'stored backlog rows conflict with repeated intake')
            receipt = conn.execute('SELECT * FROM receipts WHERE receipt_seq=?',
                                   (existing['receipt_seq'],)).fetchone()
            require(receipt is not None, 'existing intake receipt is missing')
            receipt_body = parse_json(receipt['body_json'], 'existing receipt body')
            require(all(receipt_body.get(key) == value for key, value in record.items()),
                    'existing receipt does not bind repeated intake bytes')
            conn.commit()
            return {'status': 'idempotent', 'intake_id': intake_id,
                    'receipt_seq': receipt['receipt_seq'],
                    'receipt_hash': receipt['receipt_hash'],
                    'commits_added': existing['commit_count'],
                    'cursor_sha256': current['decisions_sha256']}

        cursor = conn.execute('SELECT * FROM cursor WHERE singleton=1').fetchone()
        bootstrap = cursor is None
        if cursor is not None:
            require(cursor['checkpoint_sha256'] == previous['decisions_sha256'] and
                    cursor['run_id'] == previous_identity['run_id'] and
                    cursor['attempt'] == previous_identity['attempt'],
                    'predecessor does not match current backlog cursor')
        else:
            require(conn.execute('SELECT COUNT(*) FROM intakes').fetchone()[0] == 0 and
                    conn.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0] == 0,
                    'cursor is missing from a nonempty backlog database')

        for row in rows:
            duplicate = conn.execute(
                'SELECT * FROM commit_backlog WHERE repository=? AND commit_sha=?',
                (row['repository'], row['commit_sha'])).fetchone()
            require(duplicate is None,
                    'first-parent commit already exists with another intake origin or ref')

        conn.execute('''
            INSERT INTO intakes (
                intake_id, previous_run_id, previous_attempt, current_run_id,
                current_attempt, previous_artifact_id, previous_zip_sha256,
                current_artifact_id, current_zip_sha256,
                previous_checkpoint_sha256, current_checkpoint_sha256,
                gap_sha256, commit_count, bootstrap, receipt_seq
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (intake_id, *expected_values, int(bootstrap), next_seq))
        for row in rows:
            conn.execute('''
                INSERT INTO commit_backlog (
                    repository, ref, ordinal, commit_sha, tree_sha, first_parent_sha,
                    status, intake_id, previous_checkpoint_sha256,
                    current_checkpoint_sha256, gap_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
            ''', (row['repository'], row['ref'], row['ordinal'], row['commit_sha'], row['tree_sha'],
                  row['first_parent_sha'], intake_id, previous['decisions_sha256'],
                  current['decisions_sha256'], current['gap_sha256']))

        if cursor is None:
            conn.execute('INSERT INTO cursor VALUES (1, ?, ?, ?, ?)',
                         (current['decisions_sha256'], current_identity['run_id'],
                          current_identity['attempt'], next_seq))
        else:
            changed = conn.execute('''
                UPDATE cursor SET checkpoint_sha256=?, run_id=?, attempt=?, receipt_seq=?
                WHERE singleton=1 AND checkpoint_sha256=? AND run_id=? AND attempt=?
            ''', (current['decisions_sha256'], current_identity['run_id'],
                  current_identity['attempt'], next_seq,
                  previous['decisions_sha256'], previous_identity['run_id'],
                  previous_identity['attempt'])).rowcount
            require(changed == 1, 'compare-and-swap cursor update failed')

        body = dict(record)
        body.update(receipt_seq=next_seq, previous_receipt_hash=previous_receipt_hash,
                    observed_at=datetime.now(timezone.utc).isoformat(),
                    bootstrap=bootstrap, status='intake_recorded')
        body_json = canonical_json(body)
        receipt_hash = digest((previous_receipt_hash + '\n' + body_json).encode('utf-8'))
        conn.execute('INSERT INTO receipts VALUES (?, ?, ?, ?)',
                     (next_seq, previous_receipt_hash, body_json, receipt_hash))
        post_seq, post_hash = _verify_receipt_chain(conn)
        require(post_seq == next_seq + 1 and post_hash == receipt_hash,
                'backlog changed during intake transaction')
        conn.commit()
        return {'status': 'intake_recorded', 'intake_id': intake_id,
                'receipt_seq': next_seq, 'receipt_hash': receipt_hash,
                'commits_added': len(rows), 'cursor_sha256': current['decisions_sha256'],
                'custody': 'offline_retained_api_metadata'}
    except BaseException:
        conn.rollback()
        raise


def intake(database_root, previous_zip, previous_run_api, previous_artifacts_api,
           current_zip, current_run_api, current_artifacts_api):
    root = private_root(database_root)
    previous_zip_raw = read_regular(previous_zip, MAX_ZIP, 'previous artifact ZIP')
    previous_run_raw = read_regular(previous_run_api, MAX_API, 'previous run API JSON')
    previous_artifacts_raw = read_regular(previous_artifacts_api, MAX_API,
                                          'previous artifacts API JSON')
    current_zip_raw = read_regular(current_zip, MAX_ZIP, 'current artifact ZIP')
    current_run_raw = read_regular(current_run_api, MAX_API, 'current run API JSON')
    current_artifacts_raw = read_regular(current_artifacts_api, MAX_API,
                                         'current artifacts API JSON')
    previous_identity = _run_identity(previous_run_raw, previous_artifacts_raw,
                                      previous_zip_raw)
    current_identity = _run_identity(current_run_raw, current_artifacts_raw,
                                     current_zip_raw)
    with tempfile.TemporaryDirectory(prefix='intake-verify-', dir=root) as tmp:
        os.chmod(tmp, 0o700)
        previous_staged = Path(tmp) / 'previous-input.zip'
        current_staged = Path(tmp) / 'current-input.zip'
        previous_staged.write_bytes(previous_zip_raw)
        current_staged.write_bytes(current_zip_raw)
        previous_staged.chmod(0o600)
        current_staged.chmod(0o600)
        previous = _read_artifact_inputs(previous_staged,
                                         previous_identity, 'previous', Path(tmp))
        current = _read_artifact_inputs(current_staged,
                                        current_identity, 'current', Path(tmp))
        _validate_run_input(previous, previous_identity, 'previous')
        _validate_run_input(current, current_identity, 'current')
        _validate_link(previous, current, previous_identity, current_identity)
        rows = _verify_gap(previous, current)
        # Invalid input must not reserve the archive name or poison a retry.
        previous_identity = archive_bytes(root, previous_identity, 'previous',
                                          previous_zip_raw, previous_run_raw,
                                          previous_artifacts_raw)
        current_identity = archive_bytes(root, current_identity, 'current',
                                         current_zip_raw, current_run_raw,
                                         current_artifacts_raw)
        record = _intake_record(previous_identity, current_identity,
                                previous, current, rows)

    database, database_identity = _ensure_database(root)
    before_open = database.lstat()
    require((before_open.st_dev, before_open.st_ino) == database_identity,
            'backlog database path changed before SQLite open')
    connection = _connect(database)
    try:
        after_open = database.lstat()
        require((after_open.st_dev, after_open.st_ino) == database_identity,
                'backlog database path changed during SQLite open')
        _initialize_or_check_schema(connection)
        # Re-check after SQLite's first open; the private parent prevents other
        # users from substituting the file, and hard links remain forbidden.
        info = database.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'backlog database changed or is no longer private')
        return _store_intake(connection, previous_identity, current_identity,
                             previous, current, rows, record)
    except sqlite3.Error as exc:
        raise IntakeError('backlog transaction failed') from exc
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', type=Path, required=True,
                        help='existing operator-owned mode 0700 store')
    parser.add_argument('--previous-zip', type=Path, required=True)
    parser.add_argument('--previous-run-api', type=Path, required=True)
    parser.add_argument('--previous-artifacts-api', type=Path, required=True)
    parser.add_argument('--current-zip', type=Path, required=True)
    parser.add_argument('--current-run-api', type=Path, required=True)
    parser.add_argument('--current-artifacts-api', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = intake(args.private_root, args.previous_zip, args.previous_run_api,
                        args.previous_artifacts_api, args.current_zip,
                        args.current_run_api, args.current_artifacts_api)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IntakeError, poll.PollError, OSError, sqlite3.Error, ValueError,
            KeyError, TypeError, RecursionError) as exc:
        print('default branch backlog intake failed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
