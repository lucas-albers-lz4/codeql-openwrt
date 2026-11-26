"""Retain canonical terminal success bytes for a supplied sequence-one start.

This in-process stage has no queue, key, ZIP extraction or signing interface.
Its result is a custody receipt for later verification.
"""
from contextlib import ExitStack, contextmanager, suppress
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from urllib.parse import urlsplit

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_live_observation as live
from tools import default_branch_private_start as private
from tools import default_branch_reservation_reconcile as reconcile


SCHEMA = 'operator-default-branch-private-final-capture-v1'
REPOSITORY_ID = 1454767376
WORKFLOW_ID = 431720768
MAX_START = 1024 * 1024
MAX_RECEIPT = 64 * 1024
MAX_HEADERS = 64 * 1024
REQUEST_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 60
CAPTURE_DIR = 'terminal-captures'
PENDING_RECEIPT = '.receipt.pending'
RECEIPT = 'receipt.json'
TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{1,512}\Z')
DOWNLOAD_HOST = re.compile(r'productionresultssa[0-9]+\.blob\.core\.windows\.net\Z')
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW

START_RAW = {
    'run': ('run-api.json', 'run_api_sha256'),
    'jobs': ('jobs-api.json', 'jobs_api_sha256'),
    'artifacts': ('artifacts-api.json', 'artifacts_api_sha256'),
    'recheck_run': ('recheck-run-api.json', 'recheck_run_api_sha256'),
    'recheck_jobs': ('recheck-jobs-api.json', 'recheck_jobs_api_sha256'),
    'early_artifact_zip': ('early-artifact.zip', None),
}


class CaptureError(ValueError):
    """The private terminal capture failed a custody or identity check."""


def _require(condition, message):
    if not condition:
        raise CaptureError(message)


def _owned(info, kind, mode):
    return (kind(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == mode)


def _identity(info):
    return info.st_dev, info.st_ino


@contextmanager
def _directory(parent, name, *, create=False, exclusive=False):
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            _require(not exclusive, 'terminal capture already exists for this attempt')
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _require(_owned(before, stat.S_ISDIR, 0o700),
             'capture or observation directory is unsafe')
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
    try:
        _require(_identity(os.fstat(descriptor)) == _identity(before),
                 'capture or observation directory changed while opening')
        yield descriptor
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(_owned(after, stat.S_ISDIR, 0o700) and
                 _identity(after) == _identity(before),
                 'capture or observation directory changed during use')
    finally:
        os.close(descriptor)


def _read(parent, name, limit, *, expected_inode=None):
    def fingerprint(info):
        _require(_owned(info, stat.S_ISREG, 0o600) and info.st_nlink == 1 and
                 0 < info.st_size <= limit, 'private capture file is unsafe or unbounded')
        return _identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns

    before = fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False))
    _require(expected_inode is None or before[0] == expected_inode,
             'retained capture file changed after writing')
    with os.fdopen(os.open(name, READ_FLAGS, dir_fd=parent), 'rb') as handle:
        _require(fingerprint(os.fstat(handle.fileno())) == before,
                 'private capture file changed while opening')
        raw = handle.read(limit + 1)
        _require(len(raw) == before[1] and fingerprint(os.fstat(handle.fileno())) == before and
                 fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before,
                 'private capture file changed during read')
    return raw


def _write(parent, name, raw, limit):
    _require(type(raw) is bytes and 0 < len(raw) <= limit,
             'canonical body is empty or exceeds its bound')
    with os.fdopen(os.open(name, WRITE_FLAGS, 0o600, dir_fd=parent), 'wb') as handle:
        opened = os.fstat(handle.fileno())
        _require(_owned(opened, stat.S_ISREG, 0o600) and opened.st_nlink == 1,
                 'new private capture file is unsafe')
        _require(handle.write(raw) == len(raw), 'private capture write was incomplete')
        handle.flush()
        os.fsync(handle.fileno())
    os.fsync(parent)
    _require(_read(parent, name, limit, expected_inode=_identity(opened)) == raw,
             'private capture file failed exact readback')
    return {'size': len(raw), 'sha256': reconcile.digest(raw)}


def _time(value, label):
    return issued._canonical_time(value, label)


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc(value):
    return value.isoformat(timespec='seconds').replace('+00:00', 'Z')


def _run_ids(run):
    _require(run.get('workflow_id') == WORKFLOW_ID and
             type(run.get('workflow_id')) is int and
             type(run.get('head_repository', {}).get('id')) is int and
             run.get('repository', {}).get('id') == REPOSITORY_ID and
             run['head_repository']['id'] == REPOSITORY_ID,
             'canonical repository or workflow ID differs')


def _zip_identity(artifact):
    return {'id': artifact['id'], 'size': artifact['size_in_bytes'],
            'sha256': artifact['digest'].removeprefix('sha256:')}


def _artifact_times(artifact):
    return tuple(_time(artifact.get(key), 'artifact ' + key)
                 for key in ('created_at', 'updated_at', 'expires_at'))


def _start_evidence(root, start_raw, run_id, attempt, *, expected_entries=None):
    _require(type(start_raw) is bytes and 0 < len(start_raw) <= MAX_START,
             'supplied sequence-one bytes are empty or unbounded')
    start, _, canonical = issued._load_document(start_raw.decode('utf-8'))
    att = start['attestation']
    issued._validate_start(att)
    _require(canonical == start_raw and att['run_id'] == run_id and
             att['run_attempt'] == attempt, 'supplied start bytes or attempt differ')
    observed = _time(start['observed_at'], 'start observation time')
    path = f'default-branch-start-{run_id}-{attempt}'
    with _directory(root, private.OBSERVATION_DIR) as observations:
        with _directory(observations, path) as directory:
            if expected_entries is not None:
                _require(set(os.listdir(directory)) == expected_entries,
                         'retained start directory inventory differs')
            receipt_raw = _read(directory, 'receipt.json', MAX_RECEIPT)
            receipt = reconcile.parse_json(receipt_raw, 'retained start observation receipt')
            _require(reconcile.digest(receipt_raw) == att['observation_sha256'] and
                     receipt.get('schema') == private.RECEIPT_SCHEMA and
                     receipt.get('status') == 'verified_observation_retained' and
                     receipt.get('repository') == reconcile.REPOSITORY and
                     receipt.get('observed_at') == start['observed_at'] and
                     all(receipt.get(key) == att[key] for key in (
                         'run_id', 'run_attempt', 'job_id', 'consumer_commit',
                         'release_lock_sha256', 'workflow', 'job', 'queue_id',
                         'reservation_sequence', 'reservation_sha256')),
                     'start observation receipt differs from the supplied start')
            _require(type(receipt.get('raw_files')) is dict and
                     set(receipt['raw_files']) == set(START_RAW),
                     'retained start raw inventory differs')
            bodies = {}
            for role, (name, digest_key) in START_RAW.items():
                limit = reconcile.MAX_API if digest_key else reconcile.MAX_ZIP
                raw = _read(directory, name, limit)
                relative = f'{private.OBSERVATION_DIR}/{path}/{name}'
                expected_digest = (att[digest_key] if digest_key else
                                   att['early_artifact']['sha256'])
                _require(reconcile.digest(raw) == expected_digest and
                         receipt['raw_files'][role] == {
                             'path': relative, 'size': len(raw), 'sha256': expected_digest,
                         }, 'retained start raw file differs: ' + role)
                if digest_key:
                    bodies[role] = reconcile.parse_json(raw, 'retained start ' + role)
                else:
                    _require(len(raw) == att['early_artifact']['size'],
                             'retained early ZIP size differs')
            if expected_entries is not None:
                _require(set(os.listdir(directory)) == expected_entries,
                         'retained start directory changed during read')
    run = bodies['run']
    second_run = bodies['recheck_run']
    job = live._live_run_and_job(run, bodies['jobs'], run_id, attempt, att)
    second_job = live._live_run_and_job(second_run, bodies['recheck_jobs'], run_id, attempt, att)
    early = live._early_artifact(bodies['artifacts'], run, run_id, attempt)
    _run_ids(run)
    _run_ids(second_run)
    _require(job['id'] == second_job['id'] == att['job_id'] and
             _zip_identity(early) == att['early_artifact'] and
             receipt.get('early_artifact') == {**att['early_artifact'], 'name': early['name']},
             'retained start job or early artifact binding differs')
    run_started = _time(run.get('run_started_at'), 'start run began')
    job_started = _time(job.get('started_at'), 'start job began')
    _require(run_started == _time(second_run.get('run_started_at'), 'rechecked run began') and
             job_started == _time(second_job.get('started_at'), 'rechecked job began'),
             'retained start timing differs between observations')
    early_created, early_updated, early_expires = _artifact_times(early)
    _require(run_started <= job_started <= early_created <= early_updated <= observed <
             early_expires, 'retained early artifact timing differs from the start')
    return att, observed, run_started, job_started, early


def _terminal(bodies, start, run_id, attempt, observed):
    att, start_time, run_started, job_started, retained_early = start
    run, jobs, artifacts = (bodies[key] for key in ('run', 'jobs', 'artifacts'))
    job, final = reconcile.verify_github_metadata(run, jobs, artifacts, run_id, attempt)
    _run_ids(run)
    all_jobs = live._complete_listing(jobs, 'jobs', 'terminal jobs API')
    early = live._early_artifact(artifacts, run, run_id, attempt)
    linkage = final['workflow_run']
    _require(run['head_sha'] == att['consumer_commit'] and job['id'] == att['job_id'] and
             run['conclusion'] == job['conclusion'] == 'success' and
             type(linkage['repository_id']) is int and
             type(linkage['head_repository_id']) is int,
             'terminal run or scan job differs from the supplied start or is not successful')
    _require(early['id'] != final['id'] and _zip_identity(early) == att['early_artifact'] and
             _artifact_times(early) == _artifact_times(retained_early),
             'terminal early artifact differs from the retained start')
    completed = _time(job.get('completed_at'), 'job completion time')
    updated = _time(run.get('updated_at'), 'run update time')
    final_created, final_updated, final_expires = _artifact_times(final)
    _require(run_started == _time(run.get('run_started_at'), 'terminal run start time') and
             job_started == _time(job.get('started_at'), 'terminal job start time') and
             job_started <= start_time <= completed <= updated <= observed and
             start_time <= final_created <= final_updated <= updated and
             observed < min(_artifact_times(early)[2], final_expires),
             'terminal job or artifact timing differs from the retained start')
    return {
        'identity': {
            'repository_id': REPOSITORY_ID, 'workflow_id': WORKFLOW_ID,
            'consumer_commit': run['head_sha'], 'job_id': job['id'],
            'run_updated_at': run['updated_at'], 'job_completed_at': job['completed_at'],
            'run_conclusion': run['conclusion'], 'job_conclusion': job['conclusion'],
            'early_artifact': _zip_identity(early), 'final_artifact': _zip_identity(final),
        },
        'jobs': sorted(all_jobs, key=lambda item: item['id']),
        'artifacts': sorted(artifacts['artifacts'], key=lambda item: item['id']),
    }


def _download_host(location):
    _require(len(location) <= 3000 and
             re.fullmatch(r'https://[!-~]+', location) is not None and
             '"' not in location and '\\' not in location,
             'artifact redirect URL is unsafe')
    url = urlsplit(location)
    _require(url.hostname is not None and DOWNLOAD_HOST.fullmatch(url.hostname) and
             url.netloc == url.hostname and url.path.startswith('/actions-results/') and
             url.query and not url.fragment,
             'artifact redirect host or path is unsupported')
    return url.hostname


def _curl(url, limit, timeout, *, token=None):
    # Credentials and signed URLs use stdin and never appear in argv, the
    # environment, retained logs or exception text.
    config = f'url = "{url}"\n'
    if token is not None:
        config += (f'header = "Authorization: Bearer {token}"\n'
                   'header = "Accept: application/vnd.github+json"\n')
    argv = ['/usr/bin/curl', '--disable', '--config', '-', '--silent', '--include',
            '--http1.1', '--globoff', '--proto', '=https', '--noproxy', '*', '--max-time',
            str(timeout), '--max-filesize', str(limit)]
    deadline = time.monotonic() + timeout
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, close_fds=True,
                          env={'PATH': '/usr/bin:/bin'}) as process:
        try:
            process.stdin.write(config.encode('ascii'))
            process.stdin.close()
            chunks, size = [], 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    _require(remaining > 0 and selector.select(remaining),
                             'artifact download timed out')
                    block = os.read(process.stdout.fileno(), 64 * 1024)
                    if not block:
                        break
                    size += len(block)
                    _require(size <= MAX_HEADERS + limit, 'artifact response exceeds its bound')
                    chunks.append(block)
            _require(process.wait(timeout=max(0, deadline - time.monotonic())) == 0,
                     'artifact HTTPS request failed')
        finally:
            if process.poll() is None:
                process.kill()
    header, separator, body = b''.join(chunks).partition(b'\r\n\r\n')
    _require(bool(separator) and len(header) <= MAX_HEADERS and len(body) <= limit,
             'artifact response does not fit HTTP header or body bounds')
    status_line, *headers = header.split(b'\r\n')
    code = re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?', status_line)
    _require(code is not None, 'artifact HTTP status is invalid')
    locations = [line.partition(b':')[2].strip() for line in headers
                 if line.partition(b':')[0].lower() == b'location']
    return int(code[1]), locations, body


def _download_zip(endpoint, limit, token):
    started = time.monotonic()
    status, locations, _ = _curl('https://api.github.com/' + endpoint,
                                 MAX_HEADERS, REQUEST_TIMEOUT, token=token)
    _require(status == 302 and len(locations) == 1,
             'canonical artifact endpoint did not give exactly one redirect')
    location = locations[0].decode('ascii')
    host = _download_host(location)
    status, locations, raw = _curl(location, limit, DOWNLOAD_TIMEOUT)
    _require(status == 200 and not locations, 'artifact download did not return a direct ZIP body')
    return raw, {
        'endpoint': endpoint, 'redirect_count': 1, 'download_host': host,
        'exit_status': 0, 'elapsed_seconds': round(time.monotonic() - started, 3),
        'size': len(raw), 'sha256': reconcile.digest(raw),
    }


def _fetch_metadata(endpoint, limit, token):
    started = time.monotonic()
    status, locations, raw = _curl('https://api.github.com/' + endpoint,
                                    limit, REQUEST_TIMEOUT, token=token)
    _require(status == 200 and not locations,
             'canonical metadata endpoint did not return direct HTTP 200')
    return raw, {
        'endpoint': endpoint, 'http_status': status, 'exit_status': 0,
        'elapsed_seconds': round(time.monotonic() - started, 3),
        'size': len(raw), 'sha256': reconcile.digest(raw),
    }


def _network():
    # The token stays in memory and in stdin for canonical API requests.
    _require(os.environ.get('GITHUB_ACTIONS', '').lower() != 'true',
             'private capture must run outside GitHub Actions')
    token = os.environ.get('GH_TOKEN', '')
    _require(TOKEN_RE.fullmatch(token) is not None, 'a scoped GitHub token is required')
    return (
        lambda endpoint, limit: _fetch_metadata(endpoint, limit, token),
        lambda endpoint, limit: _download_zip(endpoint, limit, token),
    )


def _publish_receipt(directory, expected):
    # Link is atomic and fails if the destination already exists. The pending
    # bytes were synced and reread before any directory context closed.
    _require(_read(directory, PENDING_RECEIPT, MAX_RECEIPT) == expected,
             'pending receipt changed after directory revalidation')
    os.link(PENDING_RECEIPT, RECEIPT, src_dir_fd=directory, dst_dir_fd=directory,
            follow_symlinks=False)
    try:
        os.unlink(PENDING_RECEIPT, dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        # Compensate for reported publication failures. An uncatchable process
        # or host failure still requires recovery from the raw inventory.
        os.unlink(RECEIPT, dir_fd=directory)
        os.fsync(directory)
        raise


def _capture(root, start_raw, run_id, attempt, network):
    _require(type(run_id) is int and 0 < run_id <= issued.MAX_SQLITE_INT and
             type(attempt) is int and 0 < attempt <= issued.MAX_SQLITE_INT,
             'run ID and attempt must be positive bounded integers')
    name = f'default-branch-final-{run_id}-{attempt}'
    endpoint = f'repos/{reconcile.REPOSITORY}/actions/runs/{run_id}'
    endpoints = {
        'run': endpoint,
        'jobs': f'{endpoint}/attempts/{attempt}/jobs?per_page=100',
        'artifacts': f'{endpoint}/artifacts?per_page=100',
    }
    with ExitStack() as publisher:
        with ExitStack() as stack:
            root_fd = stack.enter_context(_directory(None, root))
            start = _start_evidence(root_fd, start_raw, run_id, attempt)
            parent = stack.enter_context(_directory(root_fd, CAPTURE_DIR, create=True))
            capture = stack.enter_context(_directory(parent, name, create=True, exclusive=True))
            fetch, download = network()
            files, requests, observations = {}, [], []

            def retain(filename, raw, limit):
                files[filename] = _write(capture, filename, raw, limit)

            def observe(prefix):
                bodies = {}
                for role, url in endpoints.items():
                    raw, request = fetch(url, reconcile.MAX_API)
                    retain(f'{prefix}-{role}-api.json', raw, reconcile.MAX_API)
                    requests.append(request)
                    bodies[role] = reconcile.parse_json(raw, 'canonical terminal ' + role)
                now = _now()
                observations.append(_utc(now))
                return _terminal(bodies, start, run_id, attempt, now)

            first = observe('first')
            final = first['identity']['final_artifact']
            zip_endpoint = f'repos/{reconcile.REPOSITORY}/actions/artifacts/{final["id"]}/zip'
            raw, request = download(zip_endpoint, final['size'])
            retain('final-artifact.zip', raw, final['size'])
            _require(len(raw) == final['size'] and reconcile.digest(raw) == final['sha256'],
                     'downloaded final ZIP differs from metadata')
            requests.append(request)
            second = observe('second')
            _require(first == second, 'canonical terminal observations differ')
            _require(observations[0] <= observations[1], 'terminal observation clock moved backwards')

            receipt = {
                'schema': SCHEMA, 'status': 'captured_bytes_only',
                'repository': reconcile.REPOSITORY, 'workflow': reconcile.SCAN_WORKFLOW,
                'run_id': run_id, 'attempt': attempt, **first['identity'],
                'supplied_start_sha256': reconcile.digest(start_raw),
                'supplied_start_observation_sha256': start[0]['observation_sha256'],
                'start_authenticated': False,
                'observed_at': observations, 'raw_files': files, 'fetches': requests,
            }
            for filename, record in files.items():
                limit = final['size'] if filename == 'final-artifact.zip' else reconcile.MAX_API
                retained = _read(capture, filename, limit)
                _require(record == {'size': len(retained), 'sha256': reconcile.digest(retained)},
                         'retained raw inventory changed before receipt publication')
            receipt_bytes = issued.canonical_bytes(receipt)
            receipt_file = _write(capture, PENDING_RECEIPT, receipt_bytes, MAX_RECEIPT)
            publish_fd = os.dup(capture)
            # Closing the duplicated read-only descriptor carries no custody state.
            @publisher.callback
            def close_publish_fd():
                with suppress(OSError):
                    os.close(publish_fd)
            result = {**receipt, 'receipt_sha256': receipt_file['sha256'],
                      'capture_path': f'{CAPTURE_DIR}/{name}'}

        _publish_receipt(publish_fd, receipt_bytes)
        return result


def capture(private_root: Path, start_raw: bytes, run_id: int, attempt: int) -> dict:
    """Fetch and retain bytes in a private operator root, with no issuer access."""
    try:
        root = private._root_is_durable(private_root, Path(__file__).resolve().parents[1])
        return _capture(root, start_raw, run_id, attempt, _network)
    except CaptureError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, subprocess.SubprocessError, intake.IntakeError):
        # API parse errors and transport exceptions may carry sensitive contents.
        raise CaptureError('terminal capture failed its private input or transport checks') from None
