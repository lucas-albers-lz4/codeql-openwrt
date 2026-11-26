#!/usr/bin/env python3
"""Object-only verification of a claimed live default-branch early artifact.

This module consumes supplied bytes. It does not fetch GitHub data, read a key,
write the private queue, or sign an issued start. Its result describes byte
consistency only; capture freshness belongs to a later private launcher.
"""
from __future__ import annotations

from io import BytesIO
import re
import stat
import tempfile
from pathlib import Path
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

from tools import default_branch_backlog_intake as intake
from tools import default_branch_backlog_issued as issued
from tools import default_branch_backlog_reservation as reservation
from tools import default_branch_reservation_reconcile as reconcile
from tools import default_branch_start_artifact as early


REPOSITORY = reconcile.REPOSITORY
SCAN_WORKFLOW = reconcile.SCAN_WORKFLOW
SCAN_JOB = issued.START_JOB
EARLY_ARTIFACT_PREFIX = 'default-branch-start-'
EARLY_RECEIPT_SCHEMA = 'mvp-default-branch-early-start-observation-v1'
EARLY_SOURCE_NAMES = frozenset(output for _, output in early.SOURCES)
EARLY_REQUIRED_NAMES = EARLY_SOURCE_NAMES | {'receipt.json'}
MAX_ZIP = reconcile.MAX_ZIP
MAX_UNPACKED = early.MAX_TOTAL_BYTES
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')


class LiveObservationError(ValueError):
    """A live observation byte set failed its exact contract."""


def _need(condition, message):
    if not condition:
        raise LiveObservationError(message)


def _read_early_zip(raw, run_id, attempt):
    """Read exactly the early artifact's ten expected regular file members."""
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_ZIP,
          'early artifact ZIP is empty or exceeds byte bound')
    expected = EARLY_REQUIRED_NAMES
    members = {}
    try:
        with ZipFile(BytesIO(raw), 'r') as archive:
            infos = archive.infolist()
            _need(len(infos) == len(expected),
                  'early artifact ZIP does not contain exactly ten members')
            _need(sum(info.file_size for info in infos) <= MAX_UNPACKED,
                  'early artifact ZIP expansion exceeds byte bound')
            for info in infos:
                name = info.filename
                _need(name in expected and not info.is_dir() and
                      not name.startswith('/') and '\\' not in name and
                      all(part not in ('', '.', '..') for part in name.split('/')),
                      'unexpected or unsafe early artifact member')
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                _need(name not in members and kind in (0, stat.S_IFREG) and
                      not (info.flag_bits & 0x1),
                      'duplicate, nonregular, or encrypted early artifact member')
                _need(info.compress_type in (ZIP_STORED, ZIP_DEFLATED),
                      'unsupported early artifact compression method')
                _need(0 <= info.file_size <= early.MAX_FILE_BYTES and
                      (info.file_size == 0 or info.compress_size > 0) and
                      (info.compress_size == 0 or
                       info.file_size <= info.compress_size * reconcile.MAX_COMPRESSION_RATIO),
                      'early artifact member violates decompression bounds')
                with archive.open(info, 'r') as source:
                    chunks = []
                    copied = 0
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        copied += len(block)
                        _need(copied <= info.file_size and copied <= MAX_UNPACKED,
                              'early artifact member expanded beyond its declared size')
                        chunks.append(block)
                    _need(copied == info.file_size,
                          'early artifact member is truncated')
                members[name] = b''.join(chunks)
    except (BadZipFile, OSError, RuntimeError, EOFError, NotImplementedError) as exc:
        raise LiveObservationError('invalid early artifact ZIP') from exc
    _need(set(members) == expected,
          'early artifact ZIP member set differs from exact contract')
    return members


def _complete_listing(value, key, label):
    items = value.get(key)
    _need(type(value.get('total_count')) is int and
          isinstance(items, list) and value['total_count'] == len(items) and
          len(items) <= 100,
          label + ' listing is incomplete or exceeds its one-page bound')
    ids = set()
    for item in items:
        _need(isinstance(item, dict) and type(item.get('id')) is int and
              item['id'] > 0 and item['id'] not in ids,
              label + ' listing has an invalid or duplicate ID')
        ids.add(item['id'])
    return items


def _live_run_and_job(run, jobs, run_id, attempt, approved_policy):
    repository = run.get('repository')
    head_repository = run.get('head_repository')
    _need(type(run.get('id')) is int and run['id'] == run_id and
          type(run.get('run_attempt')) is int and run['run_attempt'] == attempt and
          isinstance(repository, dict) and
          repository.get('full_name') == REPOSITORY and
          type(repository.get('id')) is int and repository['id'] > 0 and
          isinstance(head_repository, dict) and
          head_repository.get('full_name') == REPOSITORY and
          head_repository.get('id') == repository['id'] and
          run.get('path') == SCAN_WORKFLOW and
          run.get('event') == 'workflow_dispatch' and
          run.get('head_branch') == 'main' and
          run.get('head_sha') == approved_policy['consumer_commit'] and
          FULL_SHA.fullmatch(run.get('head_sha', '')) is not None and
          run.get('status') == 'in_progress' and run.get('conclusion') is None,
          'canonical run is not the exact in-progress approved main attempt')
    job_list = _complete_listing(jobs, 'jobs', 'jobs API')
    matches = [item for item in job_list if item.get('name') == SCAN_JOB]
    _need(len(matches) == 1,
          'expected in-progress scan job is missing or ambiguous')
    job = matches[0]
    _need(type(job.get('run_id')) is int and job['run_id'] == run_id and
          type(job.get('run_attempt')) is int and job['run_attempt'] == attempt and
          job.get('head_sha') == run['head_sha'] and
          job.get('status') == 'in_progress' and job.get('conclusion') is None,
          'expected scan job does not match the live run identity')
    return job


def _early_artifact(artifacts, run, run_id, attempt):
    artifact_list = _complete_listing(artifacts, 'artifacts', 'artifacts API')
    expected_name = f'{EARLY_ARTIFACT_PREFIX}{run_id}-{attempt}'
    matches = [item for item in artifact_list if item.get('name') == expected_name]
    _need(len(matches) == 1,
          'exact early artifact is missing or ambiguous')
    artifact = matches[0]
    linkage = artifact.get('workflow_run')
    _need(artifact.get('expired') is False and
          type(artifact.get('size_in_bytes')) is int and
          0 < artifact['size_in_bytes'] <= MAX_ZIP and
          isinstance(artifact.get('digest'), str) and
          reconcile.ARTIFACT_DIGEST.fullmatch(artifact['digest']) is not None and
          isinstance(linkage, dict) and type(linkage.get('id')) is int and
          linkage['id'] == run_id and
          type(linkage.get('repository_id')) is int and
          linkage['repository_id'] == run['repository']['id'] and
          type(linkage.get('head_repository_id')) is int and
          linkage['head_repository_id'] == run['repository']['id'] and
          linkage.get('head_branch') == 'main' and
          linkage.get('head_sha') == run['head_sha'],
          'early artifact run linkage, expiry, size, or digest is invalid')
    return artifact


def _verify_receipt_files(members, run_id, attempt, approved_policy):
    receipt = reconcile.parse_json(members['receipt.json'], 'early artifact receipt')
    _need(set(receipt) == {
        'schema', 'status', 'run_id', 'consumer_repository', 'consumer_commit',
        'reservation_claim_status', 'files'},
        'early artifact receipt has unsupported fields')
    _need(receipt.get('schema') == EARLY_RECEIPT_SCHEMA and
          receipt.get('status') == 'retained_non_issuing' and
          receipt.get('run_id') == f'{run_id}-{attempt}' and
          receipt.get('consumer_repository') == REPOSITORY and
          receipt.get('consumer_commit') == approved_policy['consumer_commit'] and
          receipt.get('reservation_claim_status') == 'claimed_unverified',
          'early artifact receipt schema, status, or run identity is invalid')
    files = receipt.get('files')
    _need(type(files) is dict and set(files) == EARLY_SOURCE_NAMES,
          'early artifact receipt file set is not exactly nine source files')
    for name in EARLY_SOURCE_NAMES:
        item = files[name]
        raw = members[name]
        _need(type(item) is dict and set(item) == {'bytes', 'sha256'} and
              type(item.get('bytes')) is int and item['bytes'] == len(raw) and
              isinstance(item.get('sha256'), str) and
              SHA256.fullmatch(item['sha256']) is not None and
              item['sha256'] == reconcile.digest(raw),
              'early artifact receipt digest or byte count differs: ' + name)
    claim = reconcile.parse_json(members['reservation-claim.json'],
                                 'early artifact reservation claim')
    _need(claim.get('schema') == 'default-branch-reservation-claim-v1' and
          claim.get('status') == 'claimed_unverified',
          'early artifact does not contain a claimed reservation')
    manifest = reconcile.parse_json(members['manifest.json'],
                                    'early artifact source-first manifest')
    event = manifest.get('event')
    _need(isinstance(event, dict) and
          event.get('candidate_inventory_sha256') ==
          reconcile.digest(members['inventory.json']),
          'early inventory bytes differ from source-first manifest digest')
    return claim


def verify_live_observation_bytes(private_root, run_raw, jobs_raw, artifacts_raw,
                                  early_zip_raw, run_id, attempt, approved_policy,
                                  recheck_run_raw, recheck_jobs_raw):
    """Verify supplied live-observation bytes against one private v3 action.

    `approved_policy` is an explicit mapping with exactly `consumer_commit` and
    `release_lock_sha256`. The function returns validated start components but
    intentionally omits `observation_sha256` and `observed_at`; a later live
    launcher must construct and retain its own receipt at the second fetch.
    """
    _need(type(run_id) is int and 0 < run_id <= issued.MAX_SQLITE_INT and
          type(attempt) is int and 0 < attempt <= issued.MAX_SQLITE_INT,
          'run ID and attempt must be positive integers')
    try:
        issued._validate_approved_policy(approved_policy)
    except issued.IssuedActionError as exc:
        raise LiveObservationError('approved consumer/release-lock policy is invalid') from exc

    for raw, label in (
            (run_raw, 'canonical run API'), (jobs_raw, 'jobs API'),
            (artifacts_raw, 'artifacts API'),
            (recheck_run_raw, 'rechecked run API'),
            (recheck_jobs_raw, 'rechecked jobs API')):
        _need(type(raw) is bytes and 0 < len(raw) <= reconcile.MAX_API,
              label + ' bytes are empty or exceed the API bound')

    root = reconcile._private_root(private_root)
    run = reconcile.parse_json(run_raw, 'canonical in-progress run API')
    jobs = reconcile.parse_json(jobs_raw, 'complete in-progress jobs API')
    artifacts = reconcile.parse_json(artifacts_raw, 'complete early artifacts API')
    job = _live_run_and_job(run, jobs, run_id, attempt, approved_policy)
    artifact = _early_artifact(artifacts, run, run_id, attempt)
    _need(type(early_zip_raw) is bytes and
          len(early_zip_raw) == artifact['size_in_bytes'] and
          'sha256:' + reconcile.digest(early_zip_raw) == artifact['digest'],
          'early artifact ZIP size or digest differs from canonical listing')
    members = _read_early_zip(early_zip_raw, run_id, attempt)
    _verify_receipt_files(members, run_id, attempt, approved_policy)

    conn, database, database_info = reconcile._read_only_connection(root)
    try:
        claim = reconcile.parse_json(members['reservation-claim.json'],
                                     'early artifact reservation claim')
        asserted = claim.get('asserted_reservation')
        _need(isinstance(asserted, dict) and
              set(asserted) == {'queue_id', 'reservation_sequence', 'reservation_sha256'} and
              isinstance(asserted.get('queue_id'), str) and
              reconcile.QUEUE_ID.fullmatch(asserted['queue_id']) is not None and
              type(asserted.get('reservation_sequence')) is int and
              0 < asserted['reservation_sequence'] <= issued.MAX_SQLITE_INT and
              isinstance(asserted.get('reservation_sha256'), str) and
              SHA256.fullmatch(asserted['reservation_sha256']) is not None,
              'early artifact claim triplet is incomplete or malformed')
        action, receipt_body, archive_pair = reconcile._load_local_action(
            conn, root, asserted['queue_id'], asserted['reservation_sequence'],
            asserted['reservation_sha256'], require_v3=True)

        policy = action.get('policy')
        manifest = reconcile.parse_json(members['manifest.json'], 'source-first manifest')
        _need(isinstance(policy, dict) and
              policy.get('schema') == reservation.POLICY_SCHEMA and
              policy.get('workflow') == SCAN_WORKFLOW and
              policy.get('consumer_commit') == approved_policy['consumer_commit'] and
              policy.get('release_lock_sha256') ==
              approved_policy['release_lock_sha256'] and
              policy.get('consumer_commit') == run['head_sha'] and
              isinstance(manifest.get('event'), dict) and
              policy.get('consumer_commit') == manifest['event'].get('consumer_commit'),
              'local reservation policy differs from approved live consumer/release lock')

        with tempfile.TemporaryDirectory(prefix='default-branch-live-observation-') as temp:
            temp_path = Path(temp)
            temp_path.chmod(0o700)
            reconcile._verify_scan_claim(
                members, run, action, receipt_body, archive_pair, temp_path)

        recheck_run = reconcile.parse_json(recheck_run_raw,
                                           'rechecked in-progress run API')
        recheck_jobs = reconcile.parse_json(recheck_jobs_raw,
                                            'rechecked complete in-progress jobs API')
        recheck_job = _live_run_and_job(
            recheck_run, recheck_jobs, run_id, attempt, approved_policy)
        _need(recheck_run['id'] == run['id'] and
              recheck_run['run_attempt'] == run['run_attempt'] and
              recheck_run['head_sha'] == run['head_sha'] and
              recheck_job['id'] == job['id'] and
              recheck_job['run_id'] == job['run_id'] and
              recheck_job['run_attempt'] == job['run_attempt'] and
              recheck_job['head_sha'] == job['head_sha'],
              'rechecked live run or job identity differs from early observation')
        reconcile._check_database_unchanged(conn, database, database_info)

        components = {
            'schema': issued.START_SCHEMA,
            'kind': 'start',
            'queue_id': action['queue_id'],
            'reservation_sequence': action['action_seq'],
            'reservation_sha256': action['action_hash'],
            'identity': action['identity'],
            'origin_receipt_sha256': action['origin']['receipt_hash'],
            'origin_gap_sha256': action['origin']['gap_sha256'],
            'policy_sha256': policy['policy_sha256'],
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
            'run_id': run_id,
            'run_attempt': attempt,
            'job_id': job['id'],
            'workflow': SCAN_WORKFLOW,
            'job': SCAN_JOB,
            'early_artifact': {
                'id': artifact['id'],
                'sha256': reconcile.digest(early_zip_raw),
                'size': len(early_zip_raw),
            },
            'run_api_sha256': reconcile.digest(run_raw),
            'jobs_api_sha256': reconcile.digest(jobs_raw),
            'artifacts_api_sha256': reconcile.digest(artifacts_raw),
            'recheck_run_api_sha256': reconcile.digest(recheck_run_raw),
            'recheck_jobs_api_sha256': reconcile.digest(recheck_jobs_raw),
        }
        return {
            'schema': 'operator-default-branch-live-observation-v1',
            'status': 'verified_bytes_only',
            'attestation_components': components,
            'database': {
                'read_only': True,
                'schema_version': intake.ISSUED_SCHEMA_VERSION,
                'receipt_chain_verified': True,
                'reservation_action_chain_verified': True,
                'issued_chain_verified': True,
                'issued_head_empty': True,
            },
            'limitations': [
                'Supplied API and ZIP bytes are internally reconciled; this object-only function cannot authenticate capture freshness or origin.',
                'The returned components omit observation_sha256 and observed_at and are not a sign-ready attestation.',
                'This function does not read a key, sign, call issue_start, or mutate the private queue.',
            ],
        }
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()
        reconcile._check_database_unchanged_after_close(database, database_info)
