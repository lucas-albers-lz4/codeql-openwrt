#!/usr/bin/env python3
"""Capture linked discovery artifacts through an operator's authenticated gh session.

This read-only wrapper fetches canonical GitHub run and artifact API responses,
downloads the uniquely named checkpoint ZIPs, verifies the captured bytes, and
passes those verified bytes to the existing offline backlog intake. It does not
reserve, dispatch, scan, record an outcome, or establish coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from tools import default_branch_backlog_intake as intake
from tools import incoming_poll as poll


REPOSITORY = intake.REPOSITORY
WORKFLOW = intake.WORKFLOW
ARTIFACT_PREFIX = intake.ARTIFACT_PREFIX
MAX_API = intake.MAX_API
MAX_ZIP = intake.MAX_ZIP
MAX_ARTIFACTS = 100
GH_TIMEOUT_SECONDS = 300
READ_CHUNK = 64 * 1024
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')
ARTIFACT_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


class CaptureError(ValueError):
    """Fail-closed operator capture error."""


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def _private_root(root):
    root = Path(root)
    require(root.is_absolute() and root != Path(root.anchor) and
            '..' not in root.parts,
            'private root must be an absolute path without parent traversal')
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise CaptureError('private root path is unavailable') from exc
        require(stat.S_ISDIR(info.st_mode),
                'private root path contains a non-directory or symlink')
        if current == root:
            require(info.st_uid == os.geteuid() and
                    stat.S_IMODE(info.st_mode) == 0o700,
                    'private root must be operator-owned mode 0700')
        else:
            require(info.st_uid in (0, os.geteuid()) and
                    not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                    'unsafe private-root ancestor: ' + str(current))
    return root


def _private_file_info(path, limit):
    try:
        before = path.lstat()
    except OSError as exc:
        raise CaptureError('captured file is unavailable') from exc
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
            stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
            before.st_size <= limit,
            'captured file is not a bounded private regular file')
    return before


def _read_private(path, limit):
    before = _private_file_info(path, limit)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CaptureError('cannot read captured file') from exc
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and
                opened.st_nlink == 1 and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                'captured file changed before read')
        parts = []
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= limit, 'captured file exceeds byte bound')
            parts.append(block)
        after = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size,
                 opened.st_mtime_ns, opened.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns),
                'captured file changed while being read')
        return b''.join(parts)
    finally:
        os.close(descriptor)


def _fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o700,
                'capture staging directory changed')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor, block):
    view = memoryview(block)
    while view:
        count = os.write(descriptor, view)
        require(count > 0, 'short write to capture staging file')
        view = view[count:]


def _fetch_to_file(endpoint, target, limit):
    """Stream one gh response to a fresh 0600 file, stopping at its byte bound."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise CaptureError('cannot create exclusive capture file') from exc

    process = None
    selector = None
    size = 0
    digest = hashlib.sha256()
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
        while True:
            remaining = GH_TIMEOUT_SECONDS - (time.monotonic() - started)
            require(remaining > 0, 'gh api response timed out')
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
            require(size <= limit, 'gh api response exceeds byte bound')
            _write_all(descriptor, block)
            digest.update(block)
        remaining = GH_TIMEOUT_SECONDS - (time.monotonic() - started)
        require(remaining > 0, 'gh api response timed out')
        try:
            status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise CaptureError('gh api request timed out') from exc
        require(status == 0, 'gh api request failed: ' + endpoint)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _private_file_info(target, limit)
        _fsync_directory(target.parent)
        return {'size': size, 'sha256': digest.hexdigest(),
                'command': ['gh', 'api', '--hostname', 'github.com', endpoint],
                'exit_status': status,
                'elapsed_seconds': round(time.monotonic() - started, 3)}
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
    raw = _read_private(target, MAX_API)
    require(len(raw) == result['size'] and
            hashlib.sha256(raw).hexdigest() == result['sha256'],
            'captured API response changed after download')
    return raw, result


def _parse_run(raw, run_id, attempt):
    run = intake.parse_json(raw, 'canonical run API response')
    repository = run.get('repository')
    require(type(run.get('id')) is int and run['id'] == run_id and
            type(run.get('run_attempt')) is int and run['run_attempt'] == attempt,
            'canonical run API identity differs from requested run and attempt')
    require(isinstance(repository, dict) and
            repository.get('full_name') == REPOSITORY and
            run.get('path') == WORKFLOW and run.get('head_branch') == 'main' and
            run.get('event') in ('workflow_dispatch', 'schedule') and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            isinstance(run.get('head_sha'), str) and FULL_SHA.fullmatch(run['head_sha']),
            'run is not a successful default-branch discovery attempt')
    repo_id = repository.get('id')
    head_repository = run.get('head_repository')
    require(type(repo_id) is int and repo_id > 0 and
            isinstance(head_repository, dict) and
            head_repository.get('full_name') == REPOSITORY and
            type(head_repository.get('id')) is int and
            head_repository.get('id') == repo_id,
            'canonical run repository identity mismatch')
    return run, repo_id


def _parse_artifacts(raw, run, run_id, attempt, repo_id):
    document = intake.parse_json(raw, 'complete artifacts API response')
    artifacts = document.get('artifacts')
    total = document.get('total_count')
    require(type(total) is int and isinstance(artifacts, list) and
            len(artifacts) == total and total <= MAX_ARTIFACTS,
            'artifacts API response is incomplete or exceeds the 100-record bound')
    ids = set()
    for item in artifacts:
        require(isinstance(item, dict) and type(item.get('id')) is int and
                item['id'] > 0,
                'artifacts API response contains an invalid record')
        require(item['id'] not in ids, 'artifacts API response repeats an artifact ID')
        ids.add(item['id'])
    expected_name = f'{ARTIFACT_PREFIX}{run_id}-{attempt}'
    matches = [item for item in artifacts if item.get('name') == expected_name]
    require(len(matches) == 1, 'missing or ambiguous exact discovery artifact')
    artifact = matches[0]
    artifact_digest = artifact.get('digest')
    require(artifact.get('expired') is False and
            type(artifact.get('size_in_bytes')) is int and
            0 < artifact['size_in_bytes'] <= MAX_ZIP and
            isinstance(artifact_digest, str) and
            ARTIFACT_DIGEST.fullmatch(artifact_digest) is not None,
            'artifact is expired or its size/digest metadata is invalid')
    workflow_run = artifact.get('workflow_run')
    require(isinstance(workflow_run, dict) and
            type(workflow_run.get('id')) is int and workflow_run.get('id') == run_id and
            type(workflow_run.get('repository_id')) is int and
            workflow_run.get('repository_id') == repo_id and
            type(workflow_run.get('head_repository_id')) is int and
            workflow_run.get('head_repository_id') == repo_id and
            workflow_run.get('head_branch') == 'main' and
            workflow_run.get('head_sha') == run['head_sha'],
            'artifact API run linkage mismatch')
    return artifact


def _role_capture(stage, role, run_id, attempt):
    run_endpoint = (f'repos/{REPOSITORY}/actions/runs/{run_id}/'
                    f'attempts/{attempt}')
    artifacts_endpoint = (f'repos/{REPOSITORY}/actions/runs/{run_id}/'
                         'artifacts?per_page=100&page=1')
    run_path = stage / f'{role}-run-api.json'
    artifacts_path = stage / f'{role}-artifacts-api.json'
    zip_path = stage / f'{role}.zip'
    run_raw, run_file = _fetch_json(run_endpoint, run_path)
    run, repo_id = _parse_run(run_raw, run_id, attempt)
    artifacts_raw, artifacts_file = _fetch_json(artifacts_endpoint, artifacts_path)
    artifact = _parse_artifacts(artifacts_raw, run, run_id, attempt, repo_id)
    zip_file = _fetch_to_file(
        f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip',
        zip_path, MAX_ZIP)
    require(zip_file['size'] == artifact['size_in_bytes'],
            'downloaded artifact size differs from canonical API listing')
    zip_raw = _read_private(zip_path, MAX_ZIP)
    require(len(zip_raw) == zip_file['size'] and
            hashlib.sha256(zip_raw).hexdigest() == zip_file['sha256'],
            'captured ZIP changed after download')
    require('sha256:' + hashlib.sha256(zip_raw).hexdigest() == artifact['digest'],
            'downloaded artifact digest differs from canonical API listing')

    # Re-read the API around the download. Byte equality detects metadata that
    # changed while the ZIP was in flight; no later custody is claimed.
    run_confirm_path = stage / f'{role}-run-api-confirm.json'
    artifacts_confirm_path = stage / f'{role}-artifacts-api-confirm.json'
    run_confirm_raw, run_confirm_file = _fetch_json(run_endpoint, run_confirm_path)
    artifacts_confirm_raw, artifacts_confirm_file = _fetch_json(
        artifacts_endpoint, artifacts_confirm_path)
    require(run_confirm_raw == run_raw and artifacts_confirm_raw == artifacts_raw,
            'canonical GitHub API responses changed during artifact capture')

    # Reuse the offline intake's full identity predicate before writing any DB
    # state. The intake invokes it again on the same in-memory bytes.
    identity = intake._run_identity(run_raw, artifacts_raw, zip_raw)
    return {
        '_raw': (zip_raw, run_raw, artifacts_raw),
        'role': role,
        'run_id': run_id,
        'attempt': attempt,
        'artifact_id': identity['artifact_id'],
        'artifact_name': identity['artifact_name'],
        'zip_size': zip_file['size'],
        'zip_sha256': zip_file['sha256'],
        'run_api_sha256': run_file['sha256'],
        'artifacts_api_sha256': artifacts_file['sha256'],
        'confirmation_run_api_sha256': run_confirm_file['sha256'],
        'confirmation_artifacts_api_sha256': artifacts_confirm_file['sha256'],
        'requests': [run_file, artifacts_file, zip_file,
                     run_confirm_file, artifacts_confirm_file],
    }


def capture(private_root, previous_run_id, previous_attempt,
            current_run_id, current_attempt):
    root = _private_root(private_root)
    for label, value in (('previous run ID', previous_run_id),
                         ('previous attempt', previous_attempt),
                         ('current run ID', current_run_id),
                         ('current attempt', current_attempt)):
        require(type(value) is int and value > 0 and len(str(value)) <= 20,
                label + ' must be a positive integer')
    require(previous_run_id != current_run_id,
            'previous and current run IDs must differ')
    prefix = (f'default-branch-capture-{previous_run_id}-{previous_attempt}-'
              f'{current_run_id}-{current_attempt}-')
    stage = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    try:
        os.chmod(stage, 0o700)
        _fsync_directory(root)
        previous = _role_capture(stage, 'previous', previous_run_id, previous_attempt)
        current = _role_capture(stage, 'current', current_run_id, current_attempt)
        intake_result = intake.intake_bytes(root, *previous.pop('_raw'),
                                           *current.pop('_raw'))
        _fsync_directory(stage)
        return {
            'schema': 'operator-default-branch-backlog-capture-v1',
            'status': 'capture_and_intake_completed',
            'capture': {
                'status': 'gh_api_responses_verified',
                'source': 'gh api --hostname github.com',
                'private_staging_directory': str(stage),
                'runs': [previous, current],
                'limitations': [
                    'This records the API bytes observed during this command; it is not a signed transcript or an attestation of operator identity.',
                    'The API responses were re-fetched around each ZIP download and matched byte-for-byte; this does not establish continuous custody after capture.',
                    'The nested intake remains offline_retained_api_metadata and records pending commit identities only.',
                    'No scan reservation, dispatch, scan result, outcome, or coverage state is created.',
                ],
            },
            'intake': intake_result,
        }
    except (CaptureError, intake.IntakeError, poll.PollError, OSError, sqlite3.Error,
            ValueError, TypeError, KeyError, RecursionError,
            subprocess.SubprocessError) as exc:
        raise CaptureError(f'{exc} (private staging retained at {stage})') from exc


def _positive_integer(value):
    if not re.fullmatch(r'[1-9][0-9]{0,19}', value):
        raise argparse.ArgumentTypeError('must be a positive integer of at most 20 digits')
    return int(value, 10)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', type=Path, required=True,
                        help='existing operator-owned mode 0700 backlog store')
    parser.add_argument('--previous-run-id', type=_positive_integer, required=True)
    parser.add_argument('--previous-attempt', type=_positive_integer, required=True)
    parser.add_argument('--current-run-id', type=_positive_integer, required=True)
    parser.add_argument('--current-attempt', type=_positive_integer, required=True)
    args = parser.parse_args(argv)
    try:
        result = capture(args.private_root, args.previous_run_id,
                         args.previous_attempt, args.current_run_id,
                         args.current_attempt)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (CaptureError, intake.IntakeError, poll.PollError, OSError, sqlite3.Error,
            ValueError, TypeError, KeyError, RecursionError,
            subprocess.SubprocessError) as exc:
        print('default branch backlog capture rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
