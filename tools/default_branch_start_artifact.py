#!/usr/bin/env python3
"""Freeze a non-issuing early observation of a claimed default-branch scan.

The artifact records exact bounded source bytes before R3 starts. It does not
read or change the private backlog, authorize a scan, or issue a start.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
SHA1 = re.compile(r'[0-9a-f]{40}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
QUEUE_ID = re.compile(r'[0-9a-f]{32}\Z')
POSITIVE_DECIMAL = re.compile(r'[1-9][0-9]*\Z')
RUN_ID = re.compile(r'default-branch-inputs-([1-9][0-9]*)-([1-9][0-9]*)\Z')
OUTPUT_ID = re.compile(r'default-branch-start-([1-9][0-9]*)-([1-9][0-9]*)\Z')
DISCOVERY_WORKFLOW = '.github/workflows/incoming-discovery-manual.yml'

# Output names deliberately preserve the final artifact's directory identity
# for both checkpoints and the linked gap.
SOURCES = (
    ('reservation-claim.json', 'reservation-claim.json'),
    ('identity.json', 'identity.json'),
    ('manifest.json', 'manifest.json'),
    ('inventory.json', 'inventory.json'),
    ('previous/decisions.json', 'previous/decisions.json'),
    ('current/decisions.json', 'current/decisions.json'),
    ('current/gap/gap.json', 'current/gap/gap.json'),
    ('previous-run-api.json', 'previous-run-api.json'),
    ('current-run-api.json', 'current-run-api.json'),
)


class ArtifactError(ValueError):
    """An unsafe, inconsistent, or incomplete early-artifact input."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ArtifactError(reason)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON object key')
        value[key] = item
    return value


def _json_object(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArtifactError('invalid ' + label) from exc
    _need(type(value) is dict, label + ' is not an object')
    return value


def _open_absolute_directory(path: Path) -> int:
    """Open the runner-supplied root without following its final component."""
    _need(path.is_absolute(), 'artifact paths must be absolute')
    _need('..' not in path.parts, 'artifact paths cannot contain parent traversal')
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactError('unsafe or missing artifact directory') from exc
    try:
        opened = os.fstat(descriptor)
        _need(stat.S_ISDIR(opened.st_mode), 'artifact path is not a directory')
        _need(opened.st_uid == os.geteuid(), 'artifact directory owner differs')
        _need(opened.st_mode & 0o022 == 0,
              'artifact directory is group or world writable')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ArtifactError('unsafe or missing input directory: ' + name) from exc
    opened = os.fstat(descriptor)
    if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid() or
            opened.st_mode & 0o022):
        os.close(descriptor)
        raise ArtifactError('unsafe input directory: ' + name)
    return descriptor


def _read_file_at(parent_fd: int, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ArtifactError('unsafe or missing input file: ' + name) from exc
    try:
        before = os.fstat(descriptor)
        _need(stat.S_ISREG(before.st_mode), 'input is not a regular file: ' + name)
        _need(before.st_uid == os.geteuid(), 'input file owner differs: ' + name)
        _need(before.st_nlink == 1, 'input file has aliases: ' + name)
        _need(before.st_mode & 0o022 == 0, 'input file is group or world writable: ' + name)
        _need(before.st_size <= MAX_FILE_BYTES, 'input file exceeds byte limit: ' + name)
        chunks = []
        total = 0
        while total <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(descriptor)
        _need(len(raw) <= MAX_FILE_BYTES, 'input file exceeds byte limit: ' + name)
        _need(len(raw) == before.st_size == after.st_size,
              'input file changed size while reading: ' + name)
        _need((before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
               before.st_mtime_ns, before.st_ctime_ns) ==
              (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
               after.st_mtime_ns, after.st_ctime_ns),
              'input file changed while reading: ' + name)
        return raw
    finally:
        os.close(descriptor)


def _read_relative(root_fd: int, relative: str) -> bytes:
    pieces = relative.split('/')
    _need(all(piece not in ('', '.', '..') for piece in pieces),
          'invalid fixed input path')
    current_fd = os.dup(root_fd)
    try:
        for piece in pieces[:-1]:
            child_fd = _open_child_directory(current_fd, piece)
            os.close(current_fd)
            current_fd = child_fd
        return _read_file_at(current_fd, pieces[-1])
    finally:
        os.close(current_fd)


def _integer(value, label: str) -> int:
    _need(type(value) is int and value > 0, 'invalid ' + label)
    return value


def _environment_identity() -> tuple[str, str, str, str]:
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    consumer_commit = os.environ.get('GITHUB_SHA', '')
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    _need(POSITIVE_DECIMAL.fullmatch(run_id) is not None, 'invalid workflow run ID')
    _need(POSITIVE_DECIMAL.fullmatch(attempt) is not None, 'invalid workflow attempt')
    _need(SHA1.fullmatch(consumer_commit) is not None, 'invalid consumer commit')
    _need(re.fullmatch(r'[^/]+/[^/]+', repository) is not None,
          'invalid consumer repository')
    return run_id, attempt, consumer_commit, repository


def _validate_claim(claim: dict, run_id: str, attempt: str,
                    consumer_commit: str) -> dict | None:
    _need(claim.get('schema') == 'default-branch-reservation-claim-v1',
          'unexpected reservation claim schema')
    status = claim.get('status')
    _need(status in ('absent', 'claimed_unverified'),
          'reservation claim status is not eligible for an early artifact')
    if status == 'absent':
        _need(claim.get('asserted_reservation') is None,
              'absent claim contains a reservation assertion')
        return None

    asserted = claim.get('asserted_reservation')
    _need(type(asserted) is dict and
          set(asserted) == {'queue_id', 'reservation_sequence', 'reservation_sha256'},
          'claimed reservation assertion is incomplete')
    _need(type(asserted['queue_id']) is str and QUEUE_ID.fullmatch(asserted['queue_id']),
          'invalid claimed queue ID')
    _integer(asserted['reservation_sequence'], 'claimed reservation sequence')
    _need(type(asserted['reservation_sha256']) is str and
          SHA256.fullmatch(asserted['reservation_sha256']),
          'invalid claimed reservation digest')

    execution = claim.get('execution')
    _need(type(execution) is dict, 'claim execution identity is missing')
    _need(_integer(execution.get('workflow_run_id'), 'claim workflow run ID') == int(run_id) and
          _integer(execution.get('workflow_run_attempt'), 'claim workflow attempt') == int(attempt),
          'claim workflow identity differs')
    _need(execution.get('consumer_head') == consumer_commit,
          'claim consumer commit differs')

    origin = claim.get('linked_discovery_origin')
    _need(type(origin) is dict, 'claim linked discovery origin is missing')
    for key in ('previous_run_id', 'previous_attempt', 'current_run_id', 'current_attempt'):
        _integer(origin.get(key), 'claim ' + key)
    _need(origin['previous_run_id'] != origin['current_run_id'],
          'claim discovery runs are not distinct')

    hashes = claim.get('linked_input_sha256')
    _need(type(hashes) is dict, 'claim input digests are missing')
    required_hashes = ('identity_receipt', 'manifest', 'previous_checkpoint',
                       'current_checkpoint', 'gap')
    for key in required_hashes:
        _need(type(hashes.get(key)) is str and SHA256.fullmatch(hashes[key]),
              'invalid claim input digest: ' + key)
    return origin


def _validate_run_api(raw: bytes, origin: dict, role: str,
                      repository: str) -> dict:
    api = _json_object(raw, role + ' discovery run API response')
    run_id = origin[role + '_run_id']
    attempt = origin[role + '_attempt']
    repository_object = api.get('repository')
    _need(type(repository_object) is dict, role + ' run API repository is missing')
    _need(api.get('id') == run_id and type(api.get('id')) is int and
          api.get('run_attempt') == attempt and type(api.get('run_attempt')) is int and
          repository_object.get('full_name') == repository and
          api.get('path') == DISCOVERY_WORKFLOW and
          api.get('event') in ('workflow_dispatch', 'schedule') and
          api.get('head_branch') == 'main' and api.get('status') == 'completed' and
          api.get('conclusion') == 'success',
          role + ' discovery run API response differs from claim origin')
    return api


def _write_file_at(parent_fd: int, name: str, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise ArtifactError('cannot create exclusive early-artifact file: ' + name) from exc
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_relative(root_fd: int, relative: str, raw: bytes) -> None:
    pieces = relative.split('/')
    current_fd = os.dup(root_fd)
    try:
        for piece in pieces[:-1]:
            try:
                os.mkdir(piece, mode=0o700, dir_fd=current_fd)
            except FileExistsError:
                # A shared parent may already have been created for another
                # fixed payload path in this same new artifact directory.
                pass
            child_fd = _open_child_directory(current_fd, piece)
            os.close(current_fd)
            current_fd = child_fd
        _write_file_at(current_fd, pieces[-1], raw)
    finally:
        os.close(current_fd)


def freeze(inputs: Path, output: Path) -> str:
    """Create an exact non-issuing artifact, or return `absent` without output."""
    run_id, attempt, consumer_commit, repository = _environment_identity()
    _need(inputs.parent == output.parent,
          'input and output directories must share the run-owned parent')
    input_match = RUN_ID.fullmatch(inputs.name)
    output_match = OUTPUT_ID.fullmatch(output.name)
    _need(input_match is not None and input_match.groups() == (run_id, attempt),
          'input directory name differs from workflow identity')
    _need(output_match is not None and output_match.groups() == (run_id, attempt),
          'output directory name differs from workflow identity')

    inputs_fd = _open_absolute_directory(inputs)
    try:
        claim_raw = _read_relative(inputs_fd, 'reservation-claim.json')
        claim = _json_object(claim_raw, 'reservation claim')
        origin = _validate_claim(claim, run_id, attempt, consumer_commit)
        if origin is None:
            return 'absent'

        files: dict[str, bytes] = {'reservation-claim.json': claim_raw}
        for input_name, output_name in SOURCES[1:]:
            files[output_name] = _read_relative(inputs_fd, input_name)
        _need(sum(map(len, files.values())) <= MAX_TOTAL_BYTES,
              'early-artifact inputs exceed aggregate byte limit')

        claim_hashes = claim['linked_input_sha256']
        expected = {
            'identity.json': claim_hashes['identity_receipt'],
            'manifest.json': claim_hashes['manifest'],
            'previous/decisions.json': claim_hashes['previous_checkpoint'],
            'current/decisions.json': claim_hashes['current_checkpoint'],
            'current/gap/gap.json': claim_hashes['gap'],
        }
        for name, expected_digest in expected.items():
            _need(_digest(files[name]) == expected_digest,
                  'claim-bound source bytes changed: ' + name)

        manifest_doc = _json_object(files['manifest.json'], 'source-first manifest')
        event = manifest_doc.get('event')
        _need(type(event) is dict and
              type(event.get('candidate_inventory_sha256')) is str and
              SHA256.fullmatch(event['candidate_inventory_sha256']) and
              event['candidate_inventory_sha256'] == _digest(files['inventory.json']),
              'candidate inventory bytes differ from source-first manifest')

        _validate_run_api(files['previous-run-api.json'], origin, 'previous', repository)
        _validate_run_api(files['current-run-api.json'], origin, 'current', repository)

        parent_fd = _open_absolute_directory(output.parent)
        output_fd = -1
        try:
            try:
                os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
            except OSError as exc:
                raise ArtifactError('early-artifact output must be new and exclusive') from exc
            output_fd = os.open(output.name,
                                os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) |
                                getattr(os, 'O_NOFOLLOW', 0), dir_fd=parent_fd)
            opened = os.fstat(output_fd)
            _need(stat.S_ISDIR(opened.st_mode) and opened.st_uid == os.geteuid() and
                  opened.st_mode & 0o077 == 0,
                  'early-artifact output directory is not private')

            manifest = {}
            for name, raw in files.items():
                _write_relative(output_fd, name, raw)
                copied = _read_relative(output_fd, name)
                _need(copied == raw, 'frozen artifact bytes differ from source: ' + name)
                manifest[name] = {'bytes': len(raw), 'sha256': _digest(raw)}

            receipt = {
                'schema': 'mvp-default-branch-early-start-observation-v1',
                'status': 'retained_non_issuing',
                'run_id': run_id + '-' + attempt,
                'consumer_repository': repository,
                'consumer_commit': consumer_commit,
                'reservation_claim_status': 'claimed_unverified',
                'files': manifest,
            }
            receipt_raw = (json.dumps(receipt, sort_keys=True, indent=2,
                                      allow_nan=False) + '\n').encode()
            _write_file_at(output_fd, 'receipt.json', receipt_raw)
            _need(_read_file_at(output_fd, 'receipt.json') == receipt_raw,
                  'early-artifact receipt bytes differ after write')
            os.fsync(output_fd)
        finally:
            if output_fd >= 0:
                os.close(output_fd)
            os.close(parent_fd)
        return 'claimed'
    finally:
        os.close(inputs_fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(freeze(args.inputs, args.output))
        return 0
    except (ArtifactError, OSError, ValueError, TypeError, KeyError,
            RecursionError) as exc:
        print('default-branch early artifact rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
