"""Private sequence-two failure issuer core; no command-line or fixture-input API.

Only a fresh, exact terminal failure can reach the signer. Success is reserved
for a separate source-oracle and consumer-verified completion branch. The
operator launcher, independent durable checkpoint, and OS-isolated worker are
still required before using this core with a live key or durable queue.
"""

import os
import time
from pathlib import Path

from tools import default_branch_authenticated_start as authenticated
from tools import default_branch_backlog_issued as issued
from tools import default_branch_failed_execution_capture as failure
from tools import default_branch_private_final_capture as custody
from tools import default_branch_private_start as private
from tools import default_branch_reservation_reconcile as reconcile

MAX_CAPTURE_TO_CAS_SECONDS = 30.0
RAW_NAMES = (
    'first-run-api.json', 'first-jobs-api.json',
    'second-run-api.json', 'second-jobs-api.json',
)


class PrivateTerminalIssuerError(ValueError):
    """The private terminal evidence did not authorize a sequence-two action."""


def _need(condition, message):
    if not condition:
        raise PrivateTerminalIssuerError(message)


def _start_policy_sha256(start_raw):
    start, _, canonical = issued._load_document(start_raw.decode('utf-8'))
    _need(canonical == start_raw and start['issued_seq'] == 1,
          'authenticated start is not canonical sequence one')
    return start['attestation']['policy_sha256']


def _storage_identity(root):
    with custody._directory(None, root) as root_fd:
        identity = os.fstat(root_fd)
        authenticated._sidecars_absent(root_fd)
        database = authenticated._db_fingerprint(os.stat(
            issued.DATABASE_NAME, dir_fd=root_fd, follow_symlinks=False))
        return (identity.st_dev, identity.st_ino), database


def _derive_failure(root, key, signed, start_raw, captured, run_id, attempt):
    """Reopen fixed-path capture bytes; ignore the capture function's summary."""
    name = f'default-branch-failed-{run_id}-{attempt}'
    with custody._directory(None, root) as root_fd:
        start = custody._start_evidence(
            root_fd, start_raw, run_id, attempt,
            expected_entries={'receipt.json'} |
            {item[0] for item in custody.START_RAW.values()},
        )
        with (custody._directory(root_fd, failure.CAPTURE_DIR) as parent,
              custody._directory(parent, name) as directory):
            _need(set(os.listdir(directory)) == set(RAW_NAMES) | {'receipt.json'},
                  'failure capture directory inventory differs')
            receipt_raw = custody._read(directory, 'receipt.json',
                                        custody.MAX_RECEIPT)
            _need(issued.digest(receipt_raw) == captured.get('receipt_sha256') and
                  captured.get('capture_path') ==
                  f'{failure.CAPTURE_DIR}/{name}',
                  'retained failure receipt differs from this invocation')
            receipt = reconcile.parse_json(receipt_raw, 'failure capture receipt')
            _need(issued.canonical_bytes(receipt) == receipt_raw and
                  receipt.get('schema') == failure.SCHEMA and
                  receipt.get('status') == 'verified_failed_execution_bytes' and
                  receipt.get('verification_scope') ==
                  'read_only_authenticated_start_and_two_canonical_failure_observations' and
                  receipt.get('terminal_action_issued') is False and
                  receipt.get('queue_id') == signed['queue_id'] and
                  receipt.get('start_sha256') == signed['start_sha256'] and
                  receipt.get('observation_sha256') == signed['observation_sha256'] and
                  receipt.get('repository') == reconcile.REPOSITORY and
                  receipt.get('workflow') == signed['workflow'] and
                  receipt.get('run_id') == run_id and
                  receipt.get('attempt') == attempt and
                  receipt.get('job_id') == signed['job_id'] and
                  receipt.get('consumer_commit') == start[0]['consumer_commit'],
                  'failure receipt differs from authenticated start')
            _need(type(receipt.get('raw_files')) is dict and
                  set(receipt['raw_files']) == set(RAW_NAMES) and
                  type(receipt.get('observed_at')) is list and
                  len(receipt['observed_at']) == 2,
                  'failure capture inventory or observation times differ')
            snapshots = []
            for prefix in ('first', 'second'):
                bodies = {}
                for role in ('run', 'jobs'):
                    filename = f'{prefix}-{role}-api.json'
                    raw = custody._read(directory, filename, reconcile.MAX_API)
                    _need(receipt['raw_files'][filename] == {
                        'size': len(raw), 'sha256': issued.digest(raw),
                    }, 'failure raw API bytes differ from retained receipt')
                    bodies[role] = reconcile.parse_json(raw, filename)
                    bodies[role + '_sha256'] = issued.digest(raw)
                snapshots.append(bodies)
            _need(set(os.listdir(directory)) == set(RAW_NAMES) | {'receipt.json'},
                  'failure capture directory changed during read')
            observed = [custody._time(value, 'failure capture observation')
                        for value in receipt['observed_at']]
            _need(observed[0] <= observed[1],
                  'failure capture observation clock moved backwards')
            terminal = [failure._terminal(
                body['run'], body['jobs'], signed, start, run_id, attempt,
                at) for body, at in zip(snapshots, observed)]
            _need(snapshots[0]['run'] == snapshots[1]['run'] and
                  snapshots[0]['jobs'] == snapshots[1]['jobs'] and
                  terminal[0] == terminal[1] == receipt.get('terminal'),
                  'failure observations or receipt summary differ')
            return (receipt_raw, snapshots, terminal[1],
                    receipt['observed_at'][1])


def issue_failed_execution(root: Path, key: bytes, run_id: int,
                           attempt: int) -> dict:
    """Capture, rederive, and CAS one exact signed-run failure in this call.

    The only supplied identity is the requested run/attempt. No supplied
    outcome, proof path, digest, attestation, API body, or network callback is
    accepted. The private OS owner must protect the root from same-UID writers.
    """
    try:
        issued._validate_key(key)
        root = private._root_is_durable(root, Path(__file__).resolve().parents[1])
        signed = authenticated.verify_authenticated_start(root, key)
        _need((signed['run_id'], signed['run_attempt']) == (run_id, attempt),
              'requested run differs from authenticated start')
        start_raw = failure._start_bytes(root, key, signed)
        storage_before = _storage_identity(root)
        began = time.monotonic()
        deadline = began + MAX_CAPTURE_TO_CAS_SECONDS
        captured = failure.capture_failed_execution(root, key, run_id, attempt)
        receipt_raw, bodies, terminal, observed_at = _derive_failure(
            root, key, signed, start_raw, captured, run_id, attempt)
        _need(time.monotonic() <= deadline,
              'failure capture aged out before signing')
        _need(_storage_identity(root) == storage_before,
              'private root or database changed during capture')
        again = authenticated.verify_authenticated_start(root, key)
        _need(again == signed and
              failure._start_bytes(root, key, again) == start_raw,
              'authenticated start changed before terminal CAS')
        _need(_storage_identity(root) == storage_before,
              'private root or database changed before terminal CAS')
        evidence = {
            'schema': 'operator-default-branch-terminal-observation-v2',
            'run_api_sha256': bodies[1]['run_sha256'],
            'jobs_api_sha256': bodies[1]['jobs_sha256'],
            'first_run_api_sha256': bodies[0]['run_sha256'],
            'first_jobs_api_sha256': bodies[0]['jobs_sha256'],
            'second_run_api_sha256': bodies[1]['run_sha256'],
            'second_jobs_api_sha256': bodies[1]['jobs_sha256'],
            'capture_receipt_sha256': issued.digest(receipt_raw),
            'reservation_policy_sha256': _start_policy_sha256(start_raw),
            'run_status': terminal['run_status'],
            'run_conclusion': terminal['run_conclusion'],
            'job_status': terminal['job_status'],
            'job_conclusion': terminal['job_conclusion'],
        }
        attestation = {
            'schema': issued.TERMINAL_SCHEMA,
            'kind': 'failed_execution',
            'queue_id': signed['queue_id'],
            'reservation_sequence': signed['reservation_sequence'],
            'reservation_sha256': signed['reservation_sha256'],
            'identity': signed['identity'],
            'run_id': signed['run_id'],
            'run_attempt': signed['run_attempt'],
            'job_id': signed['job_id'],
            'workflow': signed['workflow'],
            'job': signed['job'],
            'start_sha256': signed['start_sha256'],
            'evidence': evidence,
        }
        result = issued.issue_terminal(
            root, 1, signed['start_sha256'], key, attestation, observed_at,
            monotonic_deadline=deadline,
            expected_storage_identity=storage_before)
        head = issued.issued_head(root, key)
        _need(head['seq'] == 2 and head['sha256'] == result['issued_sha256'] and
              head['hmac_verified'], 'committed terminal head differs after CAS')
        return {**result, 'capture_receipt_sha256': issued.digest(receipt_raw)}
    except PrivateTerminalIssuerError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, OverflowError):
        raise PrivateTerminalIssuerError(
            'private failure issuance did not authenticate or commit') from None
