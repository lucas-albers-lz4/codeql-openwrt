#!/usr/bin/env python3
"""Trusted local entry point for one live default-branch issued start.

The CLI accepts only a private-root path and a run/attempt identity. It fetches
the canonical GitHub bytes itself, invokes the merged object-only verifier,
retains an exclusive observation receipt, then reads the local key and calls
the v3 CAS signer. No API, attestation, or observation JSON is accepted from
the caller.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_live_observation as live
from tools import default_branch_reservation_reconcile as reconcile


POLICY_NAME = 'approved-start-policy.json'
KEY_NAME = 'issuer.key'
OBSERVATION_DIR = 'observations'
POLICY_SCHEMA = 'mvp-default-branch-private-start-policy-v1'
RECEIPT_SCHEMA = 'operator-default-branch-live-observation-receipt-v1'
POLICY_KEYS = {
    'schema', 'status', 'queue_id', 'consumer_repository', 'consumer_commit',
    'release_lock_sha256', 'workflow', 'job', 'approval',
}
APPROVAL_KEYS = {'approver', 'source', 'reference', 'approved_at'}
QUEUE_ID = re.compile(r'[0-9a-f]{32}\Z')
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
POSITIVE = re.compile(r'[1-9][0-9]{0,18}\Z')
MAX_POLICY = 64 * 1024
MAX_KEY = 4096
GH_TIMEOUT_SECONDS = 300
MAX_SIGNING_AGE_SECONDS = 30.0
READ_CHUNK = 64 * 1024
ZERO_HASH = issued.ZERO_HASH
REPOSITORY = reconcile.REPOSITORY
WORKFLOW = live.SCAN_WORKFLOW
JOB = issued.START_JOB
RELEASE_LOCK_RELATIVE = Path('docs/r3-release-lock.json')
TRUSTED_TOOL_PATH = '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/home/linuxbrew/.linuxbrew/bin'
NETWORK_OVERRIDE_NAMES = {
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE',
    'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS',
}


class PrivateStartError(ValueError):
    """A trusted live-start precondition failed."""


def require(condition, message):
    if not condition:
        raise PrivateStartError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _inside(path, parent):
    return path == parent or parent in path.parents


def _root_is_durable(root, repository_root):
    """Validate a pre-created private root and reject all checkout/work paths."""
    try:
        root = intake.private_root(Path(root))
    except (intake.IntakeError, OSError) as exc:
        raise PrivateStartError('private root is missing or unsafe') from exc
    repository_root = Path(repository_root).resolve()
    require(not _inside(root, repository_root),
            'private root must be outside the repository checkout and work')
    temp_roots = {Path('/tmp'), Path('/private/tmp')}
    for candidate in (tempfile.gettempdir(), os.environ.get('TMPDIR')):
        if candidate:
            temp_roots.add(Path(candidate))
            try:
                temp_roots.add(Path(candidate).resolve())
            except OSError:
                pass
    require(not any(_inside(root, candidate) for candidate in temp_roots),
            'private root must be outside recognized temporary directories')
    canonical_root = root.resolve()
    for candidate in (Path('/var/folders'), Path('/private/var/folders')):
        if _inside(canonical_root, candidate):
            suffix = canonical_root.relative_to(candidate).parts
            require(len(suffix) < 3 or suffix[2] != 'T',
                    'private root must be outside macOS per-user temporary storage')
    current = root.parent
    while current != Path(current.anchor):
        if (current / '.git').exists() or (current / '.git').is_symlink():
            raise PrivateStartError('private root is inside a Git checkout/work tree')
        current = current.parent
    return root


def _safe_private_file(path, limit, label, *, exact_mode=0o600):
    try:
        path = intake._safe_path(Path(path), label)
        before = path.lstat()
    except (intake.IntakeError, OSError) as exc:
        raise PrivateStartError(label + ' is unavailable or unsafe') from exc
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
            stat.S_IMODE(before.st_mode) == exact_mode and before.st_nlink == 1 and
            0 < before.st_size <= limit,
            label + ' must be a bounded 0600 singly-linked regular file owned by the operator')
    try:
        raw = intake.read_regular(path, limit, label)
    except intake.IntakeError as exc:
        raise PrivateStartError(str(exc)) from exc
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns), label + ' changed while being read')
    return raw


def _load_policy(private_root):
    raw = _safe_private_file(private_root / POLICY_NAME, MAX_POLICY,
                             'approved private start policy')
    try:
        policy = reconcile.parse_json(raw, 'approved private start policy')
        issued._validate_approved_policy({
            'consumer_commit': policy.get('consumer_commit'),
            'release_lock_sha256': policy.get('release_lock_sha256'),
        })
    except (reconcile.ReconcileError, issued.IssuedActionError) as exc:
        raise PrivateStartError('approved private start policy is invalid') from exc
    require(set(policy) == POLICY_KEYS and
            policy.get('schema') == POLICY_SCHEMA and
            policy.get('status') == 'approved' and
            isinstance(policy.get('queue_id'), str) and
            QUEUE_ID.fullmatch(policy['queue_id']) is not None and
            policy.get('consumer_repository') == REPOSITORY and
            policy.get('workflow') == WORKFLOW and
            policy.get('job') == JOB,
            'approved private start policy fields or fixed scope differ')
    approval = policy.get('approval')
    require(type(approval) is dict and set(approval) == APPROVAL_KEYS and
            approval.get('source') == 'independent_human_review' and
            isinstance(approval.get('approver'), str) and
            1 <= len(approval['approver'].strip()) <= 200 and
            isinstance(approval.get('reference'), str) and
            1 <= len(approval['reference'].strip()) <= 1000,
            'approved private start policy lacks independent review provenance')
    try:
        approved_at = issued._canonical_time(approval.get('approved_at'),
                                              'policy approval time')
    except issued.IssuedActionError as exc:
        raise PrivateStartError('approved policy time is invalid') from exc
    require(approved_at <= datetime.now(timezone.utc),
            'approved policy time is in the future')
    return policy, raw


def _git(root, *arguments):
    executable = _resolve_git()
    try:
        before = Path(executable).stat()
    except OSError as exc:
        raise PrivateStartError('Git executable changed before checkout inspection') from exc
    env = {
        'PATH': '/usr/bin:/bin',
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': os.devnull,
    }
    for name in ('HOME', 'LANG', 'LC_ALL', 'TZ'):
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    command = [executable, '-c', 'core.fsmonitor=false',
               '-c', 'core.untrackedCache=false', '-C', str(root), *arguments]
    try:
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
            timeout=15, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PrivateStartError('cannot inspect the trusted consumer checkout') from exc
    try:
        after = Path(executable).stat()
    except OSError as exc:
        raise PrivateStartError('Git executable changed during checkout inspection') from exc
    require((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
            'Git executable changed during checkout inspection')
    require(completed.returncode == 0,
            'cannot inspect the trusted consumer checkout')
    return completed.stdout


def _check_checkout(repository_root, policy):
    repository_root = Path(repository_root).resolve()
    try:
        top = _git(repository_root, 'rev-parse', '--show-toplevel').decode('utf-8').strip()
        head = _git(repository_root, 'rev-parse', '--verify', 'HEAD').decode('ascii').strip()
        status = _git(repository_root, 'status', '--porcelain=v1', '--untracked-files=all')
    except UnicodeError as exc:
        raise PrivateStartError('consumer checkout identity is not valid text') from exc
    require(Path(top).resolve() == repository_root and
            FULL_SHA.fullmatch(head) is not None and
            head == policy['consumer_commit'] and not status,
            'consumer checkout is dirty or does not equal the approved full SHA')
    lock_path = repository_root / RELEASE_LOCK_RELATIVE
    try:
        lock_raw = intake.read_regular(lock_path, MAX_POLICY * 16,
                                       'tracked release lock')
    except (intake.IntakeError, OSError) as exc:
        raise PrivateStartError('approved release lock is unavailable or unsafe') from exc
    require(_digest(lock_raw) == policy['release_lock_sha256'],
            'tracked release lock differs from the approved policy')
    return {'consumer_commit': head,
            'release_lock_sha256': _digest(lock_raw)}


def _observation_path(private_root, run_id, attempt):
    parent = private_root / OBSERVATION_DIR
    try:
        info = parent.lstat()
    except FileNotFoundError:
        capture = parent / f'default-branch-start-{run_id}-{attempt}'
        return parent, capture, capture / 'receipt.json'
    except OSError as exc:
        raise PrivateStartError('observation directory is unavailable') from exc
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            'observation directory must be a private operator-owned directory')
    capture = parent / f'default-branch-start-{run_id}-{attempt}'
    try:
        capture.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise PrivateStartError('observation capture path is unavailable') from exc
    else:
        raise PrivateStartError('an observation capture already exists for this run attempt')
    return parent, capture, capture / 'receipt.json'


def _check_receipt_absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PrivateStartError('observation receipt path is unavailable') from exc
    raise PrivateStartError('an observation receipt already exists for this run attempt')


def _resolve_gh(gh_path=None):
    candidate = gh_path or shutil.which('gh', path=TRUSTED_TOOL_PATH)
    require(isinstance(candidate, str) and candidate,
            'GitHub CLI executable is unavailable')
    try:
        path = Path(candidate).resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise PrivateStartError('GitHub CLI executable is unavailable or unsafe') from exc
    require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid()) and
            not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and os.access(path, os.X_OK),
            'GitHub CLI executable is not a trusted regular executable')
    current = path.parent
    while current != Path(current.anchor):
        parent_info = current.lstat()
        require(stat.S_ISDIR(parent_info.st_mode) and
                parent_info.st_uid in (0, os.geteuid()) and
                not parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                'GitHub CLI executable has an unsafe ancestor')
        current = current.parent
    return str(path)


def _resolve_git():
    candidate = shutil.which('git', path=TRUSTED_TOOL_PATH)
    require(isinstance(candidate, str) and candidate,
            'Git executable is unavailable')
    try:
        path = Path(candidate).resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise PrivateStartError('Git executable is unavailable or unsafe') from exc
    require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid()) and
            not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and os.access(path, os.X_OK),
            'Git executable is not a trusted regular executable')
    current = path.parent
    while current != Path(current.anchor):
        parent_info = current.lstat()
        require(stat.S_ISDIR(parent_info.st_mode) and
                parent_info.st_uid in (0, os.geteuid()) and
                not parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                'Git executable has an unsafe ancestor')
        current = current.parent
    return str(path)


def _trusted_network_environment(test_overrides=None):
    if test_overrides is not None:
        env = os.environ.copy()
        env.update(test_overrides)
        env['GH_PROMPT_DISABLED'] = '1'
        return env
    require(os.environ.get('GITHUB_ACTIONS', '').lower() != 'true',
            'private issuer must not run in a hosted GitHub Actions process')
    forbidden = [name for name in os.environ
                 if name.upper() in NETWORK_OVERRIDE_NAMES or
                 name.upper().startswith('GIT_SSL_')]
    require(not forbidden,
            'network proxy or custom CA environment overrides are unsupported')
    env = {'PATH': '/usr/bin:/bin', 'GH_PROMPT_DISABLED': '1'}
    for name in ('HOME', 'GH_CONFIG_DIR', 'XDG_CONFIG_HOME',
                 'GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN',
                 'LANG', 'LC_ALL', 'TZ'):
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    return env


def _fetch(endpoint, limit, gh_path, env):
    command = [gh_path, 'api', '--hostname', 'github.com', endpoint]
    _resolve_gh(gh_path)
    executable_info = Path(gh_path).stat()
    executable_identity = (executable_info.st_dev, executable_info.st_ino,
                           executable_info.st_mtime_ns, executable_info.st_ctime_ns)
    started = time.monotonic()
    process = None
    selector = None
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, env=env)
        after_exec = Path(gh_path).stat()
        require((after_exec.st_dev, after_exec.st_ino, after_exec.st_mtime_ns,
                 after_exec.st_ctime_ns) == executable_identity,
                'GitHub CLI executable changed during process start')
        selector = selectors.DefaultSelector()
        chunks = []
        size = 0
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = GH_TIMEOUT_SECONDS - (time.monotonic() - started)
            require(remaining > 0, 'GitHub API request timed out')
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
            require(size <= limit, 'GitHub API or early ZIP response exceeds its byte bound')
            chunks.append(block)
        remaining = GH_TIMEOUT_SECONDS - (time.monotonic() - started)
        require(remaining > 0, 'GitHub API request timed out')
        try:
            exit_status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise PrivateStartError('GitHub API request timed out') from exc
        require(exit_status == 0, 'GitHub API request failed: ' + endpoint)
        output = b''.join(chunks)
        record = {
            'endpoint': endpoint,
            'argv': command,
            'exit_status': exit_status,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'size': len(output),
            'sha256': _digest(output),
        }
        return output, record
    except OSError as exc:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
        raise PrivateStartError('cannot complete GitHub API request') from exc
    except BaseException:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
        raise
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _create_observations_dir(private_root, parent, capture):
    created_parent = False
    try:
        parent.mkdir(mode=0o700)
        created_parent = True
    except FileExistsError:
        pass
    except OSError as exc:
        raise PrivateStartError('cannot create private observation directory') from exc
    try:
        info = parent.lstat()
    except OSError as exc:
        raise PrivateStartError('private observation directory is unavailable') from exc
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            'observation directory must be a private operator-owned directory')
    if created_parent:
        _fsync_directory(private_root)
    try:
        capture.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise PrivateStartError('observation capture already exists for this run attempt') from exc
    except OSError as exc:
        raise PrivateStartError('cannot create exclusive private observation capture') from exc
    try:
        info = capture.lstat()
    except OSError as exc:
        raise PrivateStartError('private observation capture is unavailable') from exc
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            'capture directory must be a private operator-owned directory')
    _fsync_directory(parent)


def _fsync_directory(path):
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        os.fsync(descriptor)
    except OSError as exc:
        raise PrivateStartError('cannot durably sync private observation directory') from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_raw_exclusive(private_root, capture, name, raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit,
            'captured raw response is empty or exceeds its bound')
    path = capture / name
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, 'O_NOFOLLOW', 0), 0o600)
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and
                stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_nlink == 1,
                'captured raw response is not a private regular file')
        with os.fdopen(descriptor, 'wb', closefd=True) as handle:
            descriptor = -1
            written = handle.write(raw)
            require(written == len(raw), 'captured raw response write was incomplete')
            handle.flush()
            os.fsync(handle.fileno())
        after = path.lstat()
        require(stat.S_ISREG(after.st_mode) and after.st_uid == os.geteuid() and
                stat.S_IMODE(after.st_mode) == 0o600 and after.st_nlink == 1 and
                (after.st_dev, after.st_ino) == (opened.st_dev, opened.st_ino) and
                after.st_size == len(raw),
                'captured raw response changed after write')
        reread = _safe_private_file(path, limit, 'retained raw response')
        require(reread == raw and _digest(reread) == _digest(raw),
                'captured raw response failed exact readback')
        return {
            'path': path.relative_to(private_root).as_posix(),
            'size': len(raw),
            'sha256': _digest(raw),
        }
    except FileExistsError as exc:
        raise PrivateStartError('captured raw response path already exists') from exc
    except (OSError, intake.IntakeError) as exc:
        raise PrivateStartError('cannot retain exact raw GitHub response') from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_receipt_exclusive(path, raw):
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, 'O_NOFOLLOW', 0), 0o600)
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and
                stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_nlink == 1,
                'new observation receipt is not a private regular file')
        with os.fdopen(descriptor, 'wb', closefd=True) as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        after = path.lstat()
        require(stat.S_ISREG(after.st_mode) and after.st_uid == os.geteuid() and
                stat.S_IMODE(after.st_mode) == 0o600 and after.st_nlink == 1 and
                (after.st_dev, after.st_ino) == (opened.st_dev, opened.st_ino),
                'retained observation receipt changed after creation')
        _fsync_directory(path.parent)
        reread = _safe_private_file(path, max(len(raw), 1), 'retained observation receipt')
        require(reread == raw, 'retained observation receipt bytes changed')
    except FileExistsError as exc:
        raise PrivateStartError('an observation receipt already exists for this run attempt') from exc
    except (OSError, intake.IntakeError) as exc:
        raise PrivateStartError('cannot retain exclusive observation receipt') from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_key(private_root):
    path = private_root / KEY_NAME
    try:
        path = intake._safe_path(path, 'issuer key')
        before = path.lstat()
    except (intake.IntakeError, OSError) as exc:
        raise PrivateStartError('issuer key is unavailable or unsafe') from exc
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
            stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
            32 <= before.st_size <= MAX_KEY,
            'issuer key must be a private 0600 singly-linked raw key of at least 32 bytes')
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and
                stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_nlink == 1 and
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                 opened.st_ctime_ns) ==
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns),
                'issuer key changed before open')
        blocks = []
        size = 0
        while True:
            block = os.read(descriptor, min(READ_CHUNK, MAX_KEY + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= MAX_KEY, 'issuer key exceeds its byte bound')
            blocks.append(block)
        after = os.fstat(descriptor)
        require((after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) and
                size == opened.st_size and size >= 32,
                'issuer key changed while being read')
        return b''.join(blocks)
    except OSError as exc:
        raise PrivateStartError('cannot read protected issuer key') from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_verified_policy(policy, components, verified):
    require(verified.get('status') == 'verified_bytes_only' and
            isinstance(verified.get('database'), dict) and
            verified['database'].get('schema_version') == intake.ISSUED_SCHEMA_VERSION and
            verified['database'].get('issued_head_empty') is True,
            'live verifier did not return a verified empty v3 issued head')
    require(components.get('queue_id') == policy['queue_id'] and
            components.get('consumer_commit') == policy['consumer_commit'] and
            components.get('release_lock_sha256') == policy['release_lock_sha256'] and
            components.get('workflow') == policy['workflow'] == WORKFLOW and
            components.get('job') == policy['job'] == JOB,
            'verified reservation or live job differs from approved private policy')


def launch(private_root, run_id, attempt, *, gh_path=None, env_overrides=None,
           repository_root=None, enforce_durable_root=True,
           enforce_checkout=True):
    """Fetch and issue one live start; test seams are absent from the CLI."""
    require(type(run_id) is int and 0 < run_id <= issued.MAX_SQLITE_INT and
            type(attempt) is int and 0 < attempt <= issued.MAX_SQLITE_INT,
            'run ID and attempt must be positive bounded integers')
    repository_root = (Path(__file__).resolve().parents[1] if repository_root is None
                       else Path(repository_root).resolve())
    if enforce_durable_root:
        root = _root_is_durable(private_root, repository_root)
    else:
        try:
            root = intake.private_root(Path(private_root))
        except (intake.IntakeError, OSError) as exc:
            raise PrivateStartError('private root is missing or unsafe') from exc

    policy, policy_raw = _load_policy(root)
    if enforce_checkout:
        checkout_identity = _check_checkout(repository_root, policy)
    else:
        lock_raw = (repository_root / RELEASE_LOCK_RELATIVE).read_bytes()
        require(_digest(lock_raw) == policy['release_lock_sha256'],
                'tracked release lock differs from the approved policy')
        checkout_identity = {'consumer_commit': policy['consumer_commit'],
                             'release_lock_sha256': _digest(lock_raw)}

    observation_parent, observation_directory, receipt_path = _observation_path(
        root, run_id, attempt)
    _check_receipt_absent(receipt_path)

    gh = _resolve_gh(gh_path)
    api_env = _trusted_network_environment(env_overrides)
    endpoint_root = f'repos/{REPOSITORY}/actions/runs/{run_id}'
    run_endpoint = endpoint_root
    jobs_endpoint = endpoint_root + '/jobs?per_page=100'
    artifacts_endpoint = endpoint_root + '/artifacts?per_page=100'
    requests = []

    run_raw, request = _fetch(run_endpoint, reconcile.MAX_API, gh, api_env)
    requests.append(request)
    jobs_raw, request = _fetch(jobs_endpoint, reconcile.MAX_API, gh, api_env)
    requests.append(request)
    artifacts_raw, request = _fetch(artifacts_endpoint, reconcile.MAX_API, gh, api_env)
    requests.append(request)
    try:
        run = reconcile.parse_json(run_raw, 'canonical run API')
        jobs = reconcile.parse_json(jobs_raw, 'complete jobs API')
        artifacts = reconcile.parse_json(artifacts_raw, 'complete artifacts API')
        job = live._live_run_and_job(run, jobs, run_id, attempt, {
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
        })
        artifact = live._early_artifact(artifacts, run, run_id, attempt)
    except (reconcile.ReconcileError, live.LiveObservationError) as exc:
        raise PrivateStartError('initial canonical GitHub observation is invalid') from exc

    zip_endpoint = f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'
    early_zip_raw, request = _fetch(zip_endpoint, reconcile.MAX_ZIP, gh, api_env)
    requests.append(request)

    recheck_run_raw, request = _fetch(run_endpoint, reconcile.MAX_API, gh, api_env)
    requests.append(request)
    recheck_jobs_raw, request = _fetch(jobs_endpoint, reconcile.MAX_API, gh, api_env)
    requests.append(request)
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    observed_at = observed.isoformat(timespec='seconds').replace('+00:00', 'Z')
    observed_monotonic = time.monotonic()

    try:
        verified = live.verify_live_observation_bytes(
            root, run_raw, jobs_raw, artifacts_raw, early_zip_raw,
            run_id, attempt,
            {'consumer_commit': policy['consumer_commit'],
             'release_lock_sha256': policy['release_lock_sha256']},
            recheck_run_raw, recheck_jobs_raw)
    except (live.LiveObservationError, reconcile.ReconcileError,
            issued.IssuedActionError, intake.IntakeError,
            OSError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError) as exc:
        raise PrivateStartError('live byte verification failed') from exc
    components = verified.get('attestation_components')
    require(type(components) is dict and 'observation_sha256' not in components,
            'live verifier returned unexpected attestation components')
    _validate_verified_policy(policy, components, verified)
    require(components.get('job_id') == job['id'] and
            components.get('early_artifact', {}).get('id') == artifact['id'],
            'verified job or early artifact differs from fetched identity')

    policy_recheck_raw = _safe_private_file(root / POLICY_NAME, MAX_POLICY,
                                            'rechecked approved private start policy')
    require(policy_recheck_raw == policy_raw,
            'approved private start policy changed during live capture')
    if enforce_checkout:
        checkout_recheck = _check_checkout(repository_root, policy)
        require(checkout_recheck == checkout_identity,
                'approved consumer checkout changed during live capture')
    else:
        lock_recheck_raw = (repository_root / RELEASE_LOCK_RELATIVE).read_bytes()
        checkout_recheck = {
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': _digest(lock_recheck_raw),
        }
        require(checkout_recheck == checkout_identity,
                'approved release lock changed during live capture')

    verification_age = time.monotonic() - observed_monotonic
    require(0 <= verification_age <= MAX_SIGNING_AGE_SECONDS,
            'second live fetch is stale after local verification')

    _create_observations_dir(root, observation_parent, observation_directory)
    raw_files = {}
    for key, name, raw, limit in (
            ('run', 'run-api.json', run_raw, reconcile.MAX_API),
            ('jobs', 'jobs-api.json', jobs_raw, reconcile.MAX_API),
            ('artifacts', 'artifacts-api.json', artifacts_raw, reconcile.MAX_API),
            ('early_artifact_zip', 'early-artifact.zip', early_zip_raw,
             reconcile.MAX_ZIP),
            ('recheck_run', 'recheck-run-api.json', recheck_run_raw,
             reconcile.MAX_API),
            ('recheck_jobs', 'recheck-jobs-api.json', recheck_jobs_raw,
             reconcile.MAX_API)):
        raw_files[key] = _write_raw_exclusive(root, observation_directory,
                                              name, raw, limit)
    _fsync_directory(observation_directory)

    receipt = {
        'schema': RECEIPT_SCHEMA,
        'status': 'verified_observation_retained',
        'observed_at': observed_at,
        'repository': REPOSITORY,
        'run_id': run_id,
        'run_attempt': attempt,
        'consumer_commit': policy['consumer_commit'],
        'release_lock_sha256': policy['release_lock_sha256'],
        'workflow': WORKFLOW,
        'job': JOB,
        'job_id': job['id'],
        'early_artifact': {
            'id': artifact['id'],
            'name': artifact['name'],
            'sha256': _digest(early_zip_raw),
            'size': len(early_zip_raw),
        },
        'queue_id': components['queue_id'],
        'reservation_sequence': components['reservation_sequence'],
        'reservation_sha256': components['reservation_sha256'],
        'private_policy': {
            'sha256': _digest(policy_raw),
            'schema': policy['schema'],
            'status': policy['status'],
            'queue_id': policy['queue_id'],
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
            'workflow': policy['workflow'],
            'job': policy['job'],
            'approval': policy['approval'],
        },
        'checkout': checkout_identity,
        'policy_recheck': {
            'sha256': _digest(policy_recheck_raw),
            'equal_to_preflight': True,
        },
        'checkout_recheck': checkout_recheck,
        'raw_files': raw_files,
        'fetches': requests,
        'verified_api_sha256': {
            'run': _digest(run_raw),
            'jobs': _digest(jobs_raw),
            'artifacts': _digest(artifacts_raw),
            'recheck_run': _digest(recheck_run_raw),
            'recheck_jobs': _digest(recheck_jobs_raw),
        },
        'verifier_status': verified['status'],
        'limitations': [
            'The six raw API and early ZIP bodies are retained at the exclusive private paths listed above; their sizes and SHA-256 digests are bound into this receipt.',
            'The verifier establishes byte consistency and the observed live state, not an atomic guarantee that the job remains in progress through SQLite CAS.',
        ],
    }
    receipt_raw = issued.canonical_bytes(receipt)
    _check_receipt_absent(receipt_path)
    _write_receipt_exclusive(receipt_path, receipt_raw)
    receipt_sha256 = _digest(receipt_raw)

    final_policy_raw = _safe_private_file(root / POLICY_NAME, MAX_POLICY,
                                          'final approved private start policy')
    require(final_policy_raw == policy_raw,
            'approved private start policy changed before key access')
    if enforce_checkout:
        final_checkout = _check_checkout(repository_root, policy)
        require(final_checkout == checkout_identity,
                'approved consumer checkout changed before key access')
    require(time.monotonic() - observed_monotonic <= MAX_SIGNING_AGE_SECONDS,
            'second live fetch is stale before key access')
    attestation = dict(components)
    attestation['observation_sha256'] = receipt_sha256
    try:
        issued._validate_approved_policy({
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
        })
        issued._validate_start(attestation)
        issued._canonical_time(observed_at, 'issued observation time')
    except issued.IssuedActionError as exc:
        raise PrivateStartError('verified start components failed the v3 schema') from exc
    key = _read_key(root)
    require(time.monotonic() - observed_monotonic <= MAX_SIGNING_AGE_SECONDS,
            'second live fetch is stale before issue CAS')
    try:
        result = issued.issue_start(
            root, 0, ZERO_HASH, key,
            {'consumer_commit': policy['consumer_commit'],
             'release_lock_sha256': policy['release_lock_sha256']},
            attestation, observed_at,
            deadline_monotonic=observed_monotonic + MAX_SIGNING_AGE_SECONDS)
    except issued.IssuedActionError as exc:
        raise PrivateStartError('v3 issue_start CAS failed') from exc
    return {
        **result,
        'observation_receipt': {
            'path': str(receipt_path),
            'sha256': receipt_sha256,
            'observed_at': observed_at,
        },
        'fetch_count': len(requests),
        'signing_age_seconds': round(time.monotonic() - observed_monotonic, 3),
    }


def _positive_id(value):
    if not POSITIVE.fullmatch(value):
        raise argparse.ArgumentTypeError('must be a positive integer of at most 19 digits')
    number = int(value, 10)
    if number > issued.MAX_SQLITE_INT:
        raise argparse.ArgumentTypeError('exceeds the supported integer bound')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', required=True,
                        help='pre-created durable mode-0700 private operator root')
    parser.add_argument('--run-id', required=True, type=_positive_id)
    parser.add_argument('--attempt', required=True, type=_positive_id)
    args = parser.parse_args(argv)
    try:
        result = launch(args.private_root, args.run_id, args.attempt)
    except (PrivateStartError, issued.IssuedActionError, reconcile.ReconcileError,
            intake.IntakeError, OSError, ValueError, TypeError) as exc:
        print('private default-branch start failed: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
