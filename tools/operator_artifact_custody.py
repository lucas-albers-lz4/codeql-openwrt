#!/usr/bin/env python3
"""Read-only local custody check for one released incoming scan artifact.

GitHub API and archive bytes are fetched by the operator's authenticated gh
session. This does not issue, start, complete, or sign a queue transition.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from zipfile import ZipFile, BadZipFile

import queue_scan_link

REPO = 'lucas-albers-lz4/codeql-openwrt'
WORKFLOW = '.github/workflows/incoming-event-preflight.yml'
MAX_API = 16 * 1024 * 1024
MAX_ZIP = 64 * 1024 * 1024
MAX_FILES = 10000
MAX_UNPACKED = 128 * 1024 * 1024


class CustodyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CustodyError(message)


def private_root(root):
    require(root.is_absolute(), 'work root must be absolute')
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()) and
                not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                'unsafe work-root ancestor: ' + str(current))
    info = root.lstat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'work root must be operator-owned mode 0700')


def fetch(endpoint, owner, filename, limit=MAX_API):
    target = owner / filename
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        process = subprocess.Popen(['gh', 'api', '--hostname', 'github.com', endpoint],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
    except BaseException:
        os.close(descriptor)
        raise
    size = 0
    try:
        with os.fdopen(descriptor, 'wb') as output:
            while block := process.stdout.read(1024 * 1024):
                size += len(block)
                require(size <= limit, 'GitHub API response exceeds bound')
                output.write(block)
        require(process.wait() == 0, 'GitHub API request failed: ' + endpoint)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    return target.read_bytes()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def verify_api(run, jobs, artifacts, run_id, attempt, consumer_commit):
    require(type(run.get('id')) is int and run['id'] == run_id and
            type(run.get('run_attempt')) is int and run['run_attempt'] == attempt and
            run.get('repository', {}).get('full_name') == REPO and
            run.get('path') == WORKFLOW and run.get('event') == 'workflow_dispatch' and
            run.get('head_sha') == consumer_commit and run.get('status') == 'completed' and
            run.get('conclusion') == 'success', 'run identity or conclusion mismatch')
    require(type(jobs.get('total_count')) is int and
            jobs['total_count'] == len(jobs.get('jobs', [])), 'incomplete jobs API page')
    require(type(artifacts.get('total_count')) is int and
            artifacts['total_count'] == len(artifacts.get('artifacts', [])),
            'incomplete artifacts API page')
    matches = [job for job in jobs.get('jobs', []) if job.get('name') == 'released-event-scan'
               and job.get('run_id') == run_id and job.get('run_attempt') == attempt]
    require(len(matches) == 1 and matches[0].get('status') == 'completed' and
            matches[0].get('conclusion') == 'success' and
            matches[0].get('head_sha') == consumer_commit and
            type(matches[0].get('id')) is int,
            'released scan job identity or conclusion mismatch')
    name = f'released-event-{run_id}-{attempt}'
    entries = [artifact for artifact in artifacts.get('artifacts', [])
               if artifact.get('name') == name]
    require(len(entries) == 1, 'missing or duplicate released artifact')
    artifact = entries[0]
    require(type(artifact.get('id')) is int and artifact['id'] > 0 and
            artifact.get('expired') is False and
            type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ZIP and
            artifact.get('workflow_run', {}).get('id') == run_id and
            re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')),
            'released artifact identity or digest invalid')
    return matches[0], artifact


def unpack_checked(raw, destination):
    require(len(raw) <= MAX_ZIP, 'archive exceeds byte bound')
    archive = destination / 'artifact.zip'
    archive.write_bytes(raw)
    extracted = destination / 'extracted'
    extracted.mkdir(mode=0o700)
    with ZipFile(archive) as zipfile:
        members = zipfile.infolist()
        require(0 < len(members) <= MAX_FILES, 'archive member count invalid')
        require(sum(info.file_size for info in members) <= MAX_UNPACKED,
                'archive expansion exceeds bound')
        seen = set()
        for info in members:
            name = info.filename
            parts = name.split('/')
            require(name and not name.startswith('/') and '\\' not in name and
                    not info.is_dir() and all(part not in ('', '.', '..') for part in parts) and
                    name not in seen, 'unsafe or duplicate archive member')
            seen.add(name)
            mode = info.external_attr >> 16
            require(stat.S_IFMT(mode) == stat.S_IFREG and info.file_size <= MAX_UNPACKED,
                    'nonregular archive member')
        for info in members:
            parts = info.filename.split('/')
            parent = extracted
            for part in parts[:-1]:
                parent = parent / part
                if not parent.exists():
                    parent.mkdir(mode=0o700)
                require(parent.is_dir() and not parent.is_symlink(), 'archive directory alias')
            target = parent / parts[-1]
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o400)
            with os.fdopen(descriptor, 'wb') as output, zipfile.open(info) as source:
                copied = 0
                while block := source.read(1024 * 1024):
                    copied += len(block)
                    require(copied <= info.file_size, 'archive member size drift')
                    output.write(block)
                require(copied == info.file_size, 'archive member truncated')
    return extracted


def check(database, work_root, run_id, attempt, consumer_commit):
    private_root(work_root)
    owner = Path(tempfile.mkdtemp(prefix=f'custody-{run_id}-{attempt}-', dir=work_root))
    os.chmod(owner, 0o700)
    run_raw = fetch(f'repos/{REPO}/actions/runs/{run_id}', owner, 'run-api.json')
    jobs_raw = fetch(f'repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100',
                     owner, 'jobs-api.json')
    artifacts_raw = fetch(f'repos/{REPO}/actions/runs/{run_id}/artifacts?per_page=100',
                          owner, 'artifacts-api.json')
    run, jobs, artifacts = map(parse, (run_raw, jobs_raw, artifacts_raw))
    job, artifact = verify_api(run, jobs, artifacts, run_id, attempt, consumer_commit)
    archive_raw = fetch(f'repos/{REPO}/actions/artifacts/{artifact["id"]}/zip',
                        owner, 'download.zip', MAX_ZIP)
    digest = hashlib.sha256(archive_raw).hexdigest()
    require(artifact['digest'] == 'sha256:' + digest, 'downloaded artifact digest mismatch')
    extracted = unpack_checked(archive_raw, owner)
    link = queue_scan_link.verify(database, extracted, owner / 'run-api.json',
                                  str(run_id), attempt, consumer_commit, True)
    require(link['status'] == 'linked_only' and link['claim_bound'] is True,
            'queue scan link did not pass')
    require(link.get('started_job_id') is None or
            link['started_job_id'] == job['id'],
            'recorded start job ID differs from canonical completed job')
    return {'schema': 'operator-artifact-custody-v1', 'status': 'verified_read_only',
            'queue_attestation_verified': False,
            'run_id': run_id, 'attempt': attempt, 'consumer_commit': consumer_commit,
            'job_id': job['id'], 'artifact_id': artifact['id'], 'artifact_sha256': digest,
            'run_api_sha256': hashlib.sha256(run_raw).hexdigest(),
            'jobs_api_sha256': hashlib.sha256(jobs_raw).hexdigest(),
            'artifacts_api_sha256': hashlib.sha256(artifacts_raw).hexdigest(),
            'link': link, 'operator_workspace': str(owner),
            'limitations': ['Read-only local custody check; queue start MAC and running-job evidence not verified here.',
                            'No queue start or completion.']}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--work-root', required=True, type=Path)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    parser.add_argument('--consumer-commit', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.database, args.work_root, args.run_id,
                               args.attempt, args.consumer_commit), sort_keys=True))
        return 0
    except (CustodyError, queue_scan_link.LinkError, OSError, BadZipFile,
            ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print('operator custody rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
