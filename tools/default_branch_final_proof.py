#!/usr/bin/env python3
"""Read-only final artifact proof for one default-branch scan attempt.

The verifier consumes supplied API bodies, early/final ZIP bytes, a supplied
issued-start document, and the local read-only reservation/archive store. It
does not fetch GitHub data, read a key, verify an HMAC, mutate a queue, or
assign alert disposition. Its start result is explicitly only a byte binding
to the supplied start document; a private terminal issuer must authenticate
the issued chain and MAC.
"""
from __future__ import annotations

from collections import Counter
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from urllib.parse import unquote, urlsplit
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

from tools import default_branch_backlog_issued as issued
from tools import default_branch_live_observation as live
from tools import default_branch_reservation_reconcile as reconcile


MAX_INPUT = reconcile.MAX_ZIP
MAX_UNPACKED = reconcile.MAX_UNPACKED
MAX_FILES = reconcile.MAX_FILES
MAX_COMPRESSION_RATIO = reconcile.MAX_COMPRESSION_RATIO
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
FULL_SHA = re.compile(r'[0-9a-f]{40}\Z')

FROZEN_INPUTS = frozenset({
    'previous-run-api.json', 'current-run-api.json',
    'previous/decisions.json', 'current/decisions.json',
    'current/gap/gap.json', 'identity.json', 'inventory.json',
    'manifest.json', 'reservation-claim.json',
})
CORPUS_FIXED = frozenset({
    'commands.json', 'preflight.json', 'receipt.json',
    'validated-default-branch-manifest.json',
    'out/coverage-default-branch.json', 'out/default-suite.sarif',
    'out/errors.bqrs', 'out/errors.json', 'out/event-triage-input.json',
    'out/producer-receipt.json', 'out/routing.json', 'out/successful.bqrs',
    'out/successful.json', 'out/triage.json',
})
R3_FIXED = frozenset({'commands.json', 'receipt.json'})
CHECKOUT_LABELS = frozenset(
    f'{repo}-{step}'
    for repo in ('luci', 'openwrt', 'packages')
    for step in ('init', 'remote', 'fetch', 'checkout', 'head', 'status')
)
TAIL_LABELS = frozenset({
    'db-init', 'db-index', 'db-finalize', 'successful-query',
    'successful-decode', 'errors-query', 'errors-decode',
    'resolve-suite', 'analyze', 'triage',
})
R3_SETUP_LABELS = frozenset({
    'producer-init', 'producer-remote', 'producer-fetch-tag', 'producer-tag-commit',
    'release-api', 'release-immutability', 'producer-download', 'codeql-download',
    'fetch-verifier', 'verify-extract-bundle', 'codeql-version',
    'pack-install-lib', 'pack-install-src', 'resolve-suite',
})
R3_CASE_STEPS = (
    'init', 'remote', 'fetch', 'checkout', 'head', 'status', 'blob',
    'db-init', 'db-index', 'db-finalize', 'successful-query', 'successful-decode',
    'errors-query', 'errors-decode', 'analyze', 'accept', 'event-triage',
)
COMMAND_SUFFIXES = ('.stdout', '.stderr', '.time')
SARIF_ROW_KEYS = {
    'rule_id', 'uri', 'start_line', 'start_column',
    'end_line', 'end_column', 'level',
}


class FinalProofError(ValueError):
    """A supplied final proof object failed its exact contract."""


def need(condition, message):
    if not condition:
        raise FinalProofError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_object(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=reconcile.intake.unique_object,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise FinalProofError('invalid ' + label) from exc
    need(type(value) is dict, label + ' is not an object')
    return value


def parse_value(raw: bytes, label: str):
    try:
        return json.loads(raw, object_pairs_hook=reconcile.intake.unique_object,
                          parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise FinalProofError('invalid ' + label) from exc


def _raw_zip_names(raw: bytes, label: str) -> list[str]:
    """Check raw central/local names before zipfile can normalize NUL bytes."""
    search_from = max(0, len(raw) - (22 + 65535))
    eocd = raw.rfind(b'PK\x05\x06', search_from)
    need(eocd >= 0 and eocd + 22 <= len(raw), label + ' has no end record')
    try:
        (signature, disk, central_disk, disk_entries, total_entries,
         central_size, central_offset, comment_size) = struct.unpack_from(
             '<IHHHHIIH', raw, eocd)
    except struct.error as exc:
        raise FinalProofError(label + ' has a truncated end record') from exc
    need(signature == 0x06054b50 and disk == 0 and central_disk == 0 and
         disk_entries == total_entries and total_entries <= MAX_FILES and
         total_entries != 0xffff and central_size != 0xffffffff and
         central_offset != 0xffffffff and comment_size == len(raw) - (eocd + 22) and
         central_offset + central_size == eocd,
         label + ' has unsupported or inconsistent ZIP directory metadata')
    names = []
    position = central_offset
    local_offsets = set()
    for _ in range(total_entries):
        need(position + 46 <= eocd and raw[position:position + 4] == b'PK\x01\x02',
             label + ' has an invalid central directory entry')
        flags = struct.unpack_from('<H', raw, position + 8)[0]
        method = struct.unpack_from('<H', raw, position + 10)[0]
        name_size, extra_size, comment_size = struct.unpack_from(
            '<HHH', raw, position + 28)
        local_offset = struct.unpack_from('<I', raw, position + 42)[0]
        end = position + 46 + name_size + extra_size + comment_size
        need(end <= eocd and name_size > 0 and local_offset != 0xffffffff,
             label + ' has an unsupported central directory entry')
        name_raw = raw[position + 46:position + 46 + name_size]
        need(b'\x00' not in name_raw, label + ' contains NUL in a raw ZIP member name')
        try:
            name = name_raw.decode('utf-8' if flags & 0x800 else 'cp437')
        except UnicodeError as exc:
            raise FinalProofError(label + ' contains an invalid raw ZIP member name') from exc
        need(local_offset not in local_offsets and local_offset + 30 <= central_offset and
             raw[local_offset:local_offset + 4] == b'PK\x03\x04',
             label + ' has an invalid or aliased local ZIP header')
        local_offsets.add(local_offset)
        local_flags = struct.unpack_from('<H', raw, local_offset + 6)[0]
        local_method = struct.unpack_from('<H', raw, local_offset + 8)[0]
        local_name_size, local_extra_size = struct.unpack_from(
            '<HH', raw, local_offset + 26)
        local_end = local_offset + 30 + local_name_size + local_extra_size
        need(local_end <= central_offset and local_flags == flags and local_method == method,
             label + ' has inconsistent local ZIP metadata')
        local_name = raw[local_offset + 30:local_offset + 30 + local_name_size]
        need(b'\x00' not in local_name and local_name == name_raw,
             label + ' local and central ZIP member names differ')
        names.append(name)
        position = end
    need(position == central_offset + central_size,
         label + ' central directory size differs from its entries')
    return names


def _read_zip(raw: bytes, label: str) -> dict[str, bytes]:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT,
         label + ' is empty or exceeds its byte bound')
    members = {}
    try:
        raw_names = _raw_zip_names(raw, label)
        with ZipFile(BytesIO(raw), 'r') as archive:
            infos = archive.infolist()
            need(0 < len(infos) <= MAX_FILES, label + ' member count is invalid')
            need(len(infos) == len(raw_names) and
                 [info.orig_filename for info in infos] == raw_names,
                 label + ' normalized ZIP names differ from raw directory names')
            need(sum(info.file_size for info in infos) <= MAX_UNPACKED,
                 label + ' expansion exceeds its byte bound')
            for info in infos:
                name = info.filename
                need(name and not name.startswith('/') and '\\' not in name and
                     all(part not in ('', '.', '..') for part in name.split('/')),
                     'unsafe ' + label + ' member path')
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                need(not info.is_dir() and kind in (0, stat.S_IFREG) and
                     not (info.flag_bits & 0x1),
                     'directory, nonregular, or encrypted ' + label + ' member')
                need(info.compress_type in (ZIP_STORED, ZIP_DEFLATED),
                     'unsupported ' + label + ' compression method')
                need(name not in members and info.file_size <= MAX_UNPACKED and
                     (info.file_size == 0 or info.compress_size > 0) and
                     (info.compress_size == 0 or
                      info.file_size <= info.compress_size * MAX_COMPRESSION_RATIO),
                     'duplicate or oversized ' + label + ' member')
                chunks, count = [], 0
                with archive.open(info, 'r') as source:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        count += len(block)
                        need(count <= info.file_size and count <= MAX_UNPACKED,
                             label + ' member expanded beyond declared size')
                        chunks.append(block)
                need(count == info.file_size, label + ' member is truncated')
                members[name] = b''.join(chunks)
    except (BadZipFile, OSError, RuntimeError, EOFError, NotImplementedError) as exc:
        if isinstance(exc, FinalProofError):
            raise
        raise FinalProofError('invalid ' + label + ' ZIP') from exc
    return members


def _final_members(raw: bytes, run_id: int, attempt: int) -> tuple[dict[str, bytes], dict[str, bytes]]:
    members = _read_zip(raw, 'final artifact')
    input_prefix = f'default-branch-inputs-{run_id}-{attempt}/'
    r3_prefix = f'r3-ucode-{run_id}-{attempt}/'
    inputs, r3 = {}, {}
    for name, body in members.items():
        if name.startswith(input_prefix):
            relative = name[len(input_prefix):]
            need(relative in FROZEN_INPUTS and relative not in inputs,
                 'extra or duplicate frozen-input member')
            inputs[relative] = body
        elif name.startswith(r3_prefix):
            relative = name[len(r3_prefix):]
            need(relative and relative not in r3,
                 'duplicate R3 member')
            r3[relative] = body
        else:
            raise FinalProofError('extra final artifact ZIP member')
    need(set(inputs) == FROZEN_INPUTS, 'final artifact frozen-input member set differs')
    return inputs, r3


def _command_labels(manifest: dict) -> set[str]:
    selected = manifest.get('selected')
    excluded = manifest.get('excluded')
    need(isinstance(selected, list) and selected and isinstance(excluded, list),
         'source-first manifest selection inventory is malformed')
    labels = set(CHECKOUT_LABELS) | set(TAIL_LABELS)
    labels.update(f'selected-blob-{index:03d}' for index in range(len(selected)))
    for index, row in enumerate(excluded):
        need(type(row) is dict, 'manifest excluded row is malformed')
        if row.get('git_blob'):
            labels.add(f'excluded-blob-{index:03d}')
    return labels


def _verify_final_inventory(r3: dict[str, bytes], manifest: dict) -> list[dict]:
    labels = _command_labels(manifest)
    expected = set(R3_FIXED)
    expected.update('default-branch-corpus/' + name for name in CORPUS_FIXED)
    expected.update(f'default-branch-corpus/commands/{label}{suffix}'
                    for label in labels for suffix in COMMAND_SUFFIXES)
    need(set(r3) == expected,
         'final artifact R3 member set has missing, extra, or unsafe members')
    value = parse_value(r3['default-branch-corpus/commands.json'],
                        'corpus command receipt')
    need(type(value) is list, 'corpus command receipt is not an array')
    return value


def _compare_frozen_inputs(inputs: dict[str, bytes], early_members: dict[str, bytes]) -> int:
    need(set(inputs) == FROZEN_INPUTS and
         set(FROZEN_INPUTS) <= set(early_members),
         'early/final frozen-input member sets differ')
    for name in FROZEN_INPUTS:
        need(early_members[name] == inputs[name],
             'early/final frozen input bytes differ: ' + name)
    return len(FROZEN_INPUTS)


def _verify_command_receipt(command_rows, r3, manifest, run_id, attempt):
    expected_labels = _command_labels(manifest)
    need(type(command_rows) is list and len(command_rows) == len(expected_labels),
         'corpus command receipt count differs from reviewed recipe')
    found = {}
    for row in command_rows:
        need(type(row) is dict and isinstance(row.get('label'), str),
             'invalid corpus command receipt row')
        label = row['label']
        need(label not in found and label in expected_labels and
             type(row.get('exit')) is int and row['exit'] == 0 and
             isinstance(row.get('argv'), list) and row['argv'],
             'missing, duplicate, or failed corpus command receipt')
        found[label] = row
        for field, suffix in zip(('stdout', 'stderr', 'time'), COMMAND_SUFFIXES):
            expected_path = f'commands/{label}{suffix}'
            need(row.get(field) == expected_path and
                 f'default-branch-corpus/{expected_path}' in r3,
                 'corpus command output identity differs: ' + label)
    need(set(found) == expected_labels,
         'corpus command label set differs from reviewed recipe')
    need(len([x for x in expected_labels if x.startswith('selected-blob-')]) ==
         len(manifest['selected']), 'selected source command multiplicity differs')
    # The captured run's source count is bound to the manifest. A future
    # recipe change must change its fixed command labels and contract tests.
    return sorted(expected_labels)


def _verify_r3_command_receipt(raw: bytes) -> int:
    expected = set(R3_SETUP_LABELS)
    expected.update(f'{case}-{step}' for case in ('openvpn-parent', 'openvpn-fixed')
                    for step in R3_CASE_STEPS)
    rows = parse_value(raw, 'R3 command transcript')
    need(type(rows) is list and len(rows) == len(expected),
         'R3 command transcript count differs from the reviewed handoff recipe')
    found = set()
    row_keys = {'argv', 'cwd', 'exit', 'label', 'peak_rss_bytes', 'stderr',
                'stdout', 'time', 'wall_seconds'}
    for row in rows:
        need(type(row) is dict and set(row) == row_keys and
             isinstance(row.get('label'), str),
             'R3 command transcript row schema differs')
        label = row['label']
        need(label in expected and label not in found and
             type(row.get('exit')) is int and row['exit'] == 0 and
             type(row.get('argv')) is list and row['argv'] and
             all(type(arg) is str for arg in row['argv']) and
             type(row.get('cwd')) is str and row['cwd'] and
             type(row.get('wall_seconds')) in (int, float) and
             type(row.get('wall_seconds')) is not bool and row['wall_seconds'] >= 0 and
             (row.get('peak_rss_bytes') is None or
              (type(row.get('peak_rss_bytes')) is int and row['peak_rss_bytes'] >= 0)),
             'R3 command transcript has a duplicate, unexpected, or failed command')
        found.add(label)
        for field, suffix in zip(('stdout', 'stderr', 'time'), COMMAND_SUFFIXES):
            need(row[field] == f'commands/{label}{suffix}',
                 'R3 command transcript output identity differs: ' + label)
    need(found == expected, 'R3 command label multiset differs from reviewed recipe')
    return len(rows)


def _same_source_identity(left: dict, right: dict) -> bool:
    keys = ('kind', 'repository', 'source_role', 'head_commit', 'head_tree',
            'base_commit', 'base_tree', 'first_parent_commit', 'control_commit',
            'consumer_commit', 'previous_checkpoint_sha256',
            'current_checkpoint_sha256', 'gap_sha256')
    return all(left.get(key) == right.get(key) for key in keys)


def _result_tuple(result: dict, rule_levels: dict[str, str]) -> tuple:
    need(type(result) is dict and isinstance(result.get('ruleId'), str),
         'SARIF result has no rule identifier')
    rule = result['ruleId']
    need(rule in rule_levels, 'SARIF result references an undeclared rule')
    locations = result.get('locations')
    need(type(locations) is list and len(locations) == 1 and
         type(locations[0]) is dict, 'SARIF result has ambiguous primary locations')
    physical = locations[0].get('physicalLocation')
    need(type(physical) is dict, 'SARIF result has no physical location')
    artifact = physical.get('artifactLocation')
    need(type(artifact) is dict and artifact.get('uriBaseId') == '%SRCROOT%',
         'SARIF artifact URI base differs')
    uri = artifact.get('uri')
    need(isinstance(uri, str) and uri, 'SARIF result URI is empty')
    parts = urlsplit(uri)
    need(not parts.scheme and not parts.netloc and not parts.query and not parts.fragment and
         '\\' not in parts.path, 'SARIF result URI is not relative')
    uri = unquote(parts.path)
    components = PurePosixPath(uri).parts
    need(uri and not uri.startswith('/') and
         all(part not in ('', '.', '..') for part in components) and
         str(PurePosixPath(uri)) == uri,
         'SARIF result URI is unsafe or noncanonical')
    region = physical.get('region')
    need(type(region) is dict, 'SARIF result region is missing')
    start_line = region.get('startLine')
    start_col = region.get('startColumn')
    end_line = region.get('endLine', start_line)
    end_col = region.get('endColumn')
    values = (start_line, start_col, end_line, end_col)
    need(all(type(value) is int and value >= 1 for value in values) and
         (end_line, end_col) >= (start_line, start_col),
         'SARIF result region is invalid')
    level = result.get('level', rule_levels[rule])
    need(level in ('error', 'warning', 'note'), 'SARIF result level is invalid')
    return (rule, uri, start_line, start_col, end_line, end_col, level)


def _verify_consumer_results(sarif_raw: bytes, triage: dict, triage_input: dict,
                             expected_paths: Counter, run_token: str) -> tuple[str, int]:
    sarif = parse_object(sarif_raw, 'SARIF output')
    need(sarif.get('version') == '2.1.0' and
         type(sarif.get('runs')) is list and len(sarif['runs']) == 1,
         'SARIF version or run multiplicity differs')
    sarif_run = sarif['runs'][0]
    driver = sarif_run.get('tool', {}).get('driver', {})
    need(driver.get('name') == 'CodeQL' and
         driver.get('semanticVersion') == triage_input.get('producer', {}).get('codeql_version') and
         sarif_run.get('columnKind') == 'utf16CodeUnits',
         'SARIF producer or column identity differs')
    rules = driver.get('rules')
    need(type(rules) is list, 'SARIF rule descriptor inventory is missing')
    rule_levels = {}
    for rule in rules:
        need(type(rule) is dict and isinstance(rule.get('id'), str) and rule['id'] and
             rule['id'] not in rule_levels,
             'SARIF rule descriptor is duplicated or malformed')
        rule_levels[rule['id']] = rule.get('defaultConfiguration', {}).get('level')
    expected_descriptors = triage_input.get('expected_sarif_descriptors')
    need(type(expected_descriptors) is list and
         set(rule_levels) == set(expected_descriptors) and
         len(expected_descriptors) == len(set(expected_descriptors)),
         'SARIF descriptor multiset differs from consumer input')
    results = sarif_run.get('results', [])
    need(type(results) is list, 'SARIF results field is malformed')
    result_rows = Counter(_result_tuple(row, rule_levels) for row in results)
    need(all(row[1] in expected_paths for row in result_rows),
         'SARIF result source URI is outside selected stage')
    triage_rows = triage.get('results_for_triage')
    need(type(triage_rows) is list and all(type(row) is dict and set(row) == SARIF_ROW_KEYS
                                           for row in triage_rows),
         'consumer triage result rows are malformed')
    for row in triage_rows:
        need(all(type(row.get(key)) is int for key in (
            'start_line', 'start_column', 'end_line', 'end_column')) and
             all(isinstance(row.get(key), str) for key in ('rule_id', 'uri', 'level')),
             'consumer triage tuple fields are malformed')
    triage_multiset = Counter(tuple(row[key] for key in (
        'rule_id', 'uri', 'start_line', 'start_column', 'end_line', 'end_column', 'level'))
        for row in triage_rows)
    need(triage_multiset == result_rows and triage.get('result_count') == len(results) and
         triage.get('sarif_sha256') == digest(sarif_raw) and
         triage.get('run_id') == run_token and
         triage.get('successful_files') is not None and
         Counter(triage.get('successful_files', [])) == expected_paths and
         triage.get('producer') == triage_input.get('producer') and
         triage.get('schema') == 'ucode-sarif-event-triage-v1',
         'consumer triage tuple multiplicity or producer identity differs from SARIF')
    expected_status = 'triage_required' if results else 'clean_scan'
    need(triage.get('status') == expected_status,
         'clean_scan/triage_required status does not match exact SARIF result multiplicity')
    return expected_status, len(results)


def _verify_r3_release(r3_receipt: dict, corpus_receipt: dict,
                       producer: dict, triage_input: dict,
                       run_token: str, source_event: dict,
                       approved_policy: dict, root_commands_raw: bytes) -> dict:
    need(type(r3_receipt) is dict and
         set(r3_receipt) == {'cases', 'codeql', 'commands_sha256',
                             'network_dependency_bootstrap', 'packs', 'preflight',
                             'release', 'resolved_rules', 'schema', 'status'} and
         r3_receipt.get('schema') == 'ucode-r3-linux-handoff-v1' and
         r3_receipt.get('status') == 'accepted' and
         r3_receipt.get('commands_sha256') == digest(root_commands_raw),
         'R3 release receipt is not the exact accepted schema or command transcript')
    r3_command_count = _verify_r3_command_receipt(root_commands_raw)
    preflight = r3_receipt.get('preflight')
    release = r3_receipt.get('release')
    codeql = r3_receipt.get('codeql')
    packs = r3_receipt.get('packs')
    need(type(preflight) is dict and type(release) is dict and
         type(codeql) is dict and type(packs) is dict and
         set(release) == {'tag', 'asset_sha256', 'manifest_sha256',
                          'producer_commit', 'isImmutable'} and
         set(preflight) == {'actual_package_installed_bytes_verified',
                            'consumer_dirty', 'consumer_sha', 'free_bytes',
                            'lock_sha256', 'oracle_sha256', 'run_id', 'run_root'} and
         type(preflight.get('consumer_dirty')) is bool and
         preflight.get('consumer_dirty') is False and
         preflight.get('actual_package_installed_bytes_verified') is False and
         preflight.get('run_id') == run_token and
         preflight.get('consumer_sha') == source_event.get('consumer_commit') and
         preflight.get('lock_sha256') == approved_policy.get('release_lock_sha256'),
         'R3 preflight consumer, lock, run, or cleanliness binding differs')
    need(release.get('isImmutable') is True and
         release.get('tag') == approved_policy.get('release_tag') ==
         corpus_receipt.get('release_tag') and
         release.get('producer_commit') == approved_policy.get('release_commit') ==
         corpus_receipt.get('producer_commit') and
         release.get('asset_sha256') == approved_policy.get('release_asset_sha256') and
         release.get('manifest_sha256') == approved_policy.get('release_manifest_sha256'),
         'R3 immutable release identity differs from captured reservation policy')
    query_pack = packs.get('queries')
    need(type(query_pack) is dict and
         query_pack.get('default_suite') == 'codeql-suites/code-scanning.qls' and
         type(codeql.get('version')) is str and
         type(codeql.get('binary_sha256')) is str and
         HEX64.fullmatch(codeql['binary_sha256']) and
         codeql.get('binary_sha256') == producer.get('codeql_binary_sha256'),
         'R3 query suite or CodeQL binary identity differs from producer receipt')
    producer_identity = producer.get('producer')
    consumer_producer = triage_input.get('producer')
    need(type(producer_identity) is dict and type(consumer_producer) is dict and
         producer_identity.get('sha') == release.get('producer_commit') and
         producer_identity.get('pack_sha256') == release.get('asset_sha256') and
         producer_identity.get('codeql_version') == consumer_producer.get('codeql_version') and
         producer_identity.get('suite_sha256') == query_pack.get('default_suite_sha256') and
         consumer_producer == producer_identity and
         isinstance(codeql.get('version'), str) and
         codeql['version'].startswith('CodeQL command-line toolchain release ' +
                                       str(consumer_producer.get('codeql_version')) + '.') and
         r3_receipt.get('resolved_rules') == corpus_receipt.get('resolved_rules') ==
         producer.get('resolved_rules'),
         'R3 release, CodeQL, suite, producer, or resolved-rule identities differ')
    return {'status': 'accepted', 'immutable': True,
            'command_count': r3_command_count,
            'release_tag': release['tag'], 'producer_commit': release['producer_commit'],
            'asset_sha256': release['asset_sha256'],
            'manifest_sha256': release['manifest_sha256'],
            'lock_sha256': preflight['lock_sha256']}


def _verify_scan_receipts(inputs: dict[str, bytes], r3: dict[str, bytes],
                          run_id: int, attempt: int,
                          approved_policy: dict) -> dict:
    corpus_prefix = 'default-branch-corpus/'
    manifest_raw = inputs['manifest.json']
    manifest = parse_object(manifest_raw, 'source-first manifest')
    validated = r3[corpus_prefix + 'validated-default-branch-manifest.json']
    need(validated == manifest_raw,
         'validated R3 manifest differs byte-for-byte from frozen source manifest')
    need(manifest.get('schema') == 'mvp-default-branch-commit-corpus-v1' and
         manifest.get('status') == 'source_first_default_branch_oracle_only',
         'source-first manifest schema or status differs')
    command_rows = _verify_final_inventory(r3, manifest)
    selected = manifest.get('selected')
    excluded = manifest.get('excluded')
    counts = manifest.get('counts')
    need(type(selected) is list and selected and type(excluded) is list and
         type(counts) is dict and counts.get('selected') == len(selected) and
         counts.get('excluded') == len(excluded),
         'manifest selected/excluded identities or counts differ')
    expected_by_path = {}
    for row in selected:
        need(type(row) is dict and isinstance(row.get('proposed_installed_path'), str) and
             isinstance(row.get('expected_route'), dict),
             'manifest selected source identity is malformed')
        path = row['proposed_installed_path']
        need(path not in expected_by_path and not path.startswith('/') and
             '\\' not in path and all(part not in ('', '.', '..')
                                      for part in path.split('/')),
             'manifest selected installed path is duplicate or unsafe')
        expected_by_path[path] = row
    need(len(expected_by_path) == len(selected),
         'manifest selected installed-path identities are ambiguous')
    source_event = manifest.get('event')
    need(type(source_event) is dict and source_event.get('kind') == 'default_branch_commit' and
         source_event.get('source_role') == 'incoming_default_branch_first_parent',
         'manifest source event identity is invalid')
    need(all(type(source_event.get(key)) is str and
             FULL_SHA.fullmatch(source_event[key]) for key in (
                 'head_commit', 'head_tree', 'base_commit', 'base_tree',
                 'first_parent_commit', 'control_commit', 'consumer_commit')),
         'manifest source commit/tree identity is invalid')

    preflight = parse_object(r3[corpus_prefix + 'preflight.json'], 'corpus preflight')
    receipt = parse_object(r3[corpus_prefix + 'receipt.json'], 'corpus consumer receipt')
    coverage_raw = r3[corpus_prefix + 'out/coverage-default-branch.json']
    coverage = parse_object(coverage_raw, 'coverage receipt')
    routing_raw = r3[corpus_prefix + 'out/routing.json']
    routing = parse_object(routing_raw, 'route receipt')
    successful = parse_object(r3[corpus_prefix + 'out/successful.json'],
                              'successful extraction query output')
    errors = parse_object(r3[corpus_prefix + 'out/errors.json'],
                          'extraction error query output')
    triage_input = parse_object(r3[corpus_prefix + 'out/event-triage-input.json'],
                                'consumer triage input')
    producer = parse_object(r3[corpus_prefix + 'out/producer-receipt.json'],
                            'producer receipt')
    triage_raw = r3[corpus_prefix + 'out/triage.json']
    triage = parse_object(triage_raw, 'consumer triage receipt')
    sarif_raw = r3[corpus_prefix + 'out/default-suite.sarif']
    sarif = parse_object(sarif_raw, 'SARIF output')
    corpus_commands_raw = r3[corpus_prefix + 'commands.json']
    _verify_command_receipt(command_rows, r3, manifest, run_id, attempt)

    receipt_digest = digest(r3['receipt.json'])
    commands_digest = digest(corpus_commands_raw)
    manifest_digest = digest(manifest_raw)
    route_digest = digest(routing_raw)
    sarif_digest = digest(sarif_raw)
    coverage_digest = digest(coverage_raw)
    triage_digest = digest(triage_raw)
    run_token = f'{run_id}-{attempt}'
    event_id_keys = ('base_commit', 'base_tree', 'head_commit', 'head_tree',
                     'first_parent_commit', 'control_commit', 'consumer_commit',
                     'previous_checkpoint_sha256', 'current_checkpoint_sha256',
                     'gap_sha256', 'kind', 'source_role', 'repository')
    need(preflight.get('run_id') == run_token and
         preflight.get('consumer_sha') == source_event['consumer_commit'] and
         preflight.get('manifest_sha256') == manifest_digest and
         preflight.get('r3_receipt_sha256') == receipt_digest and
         _same_source_identity(preflight.get('event', {}), source_event) and
         receipt.get('schema') == 'ucode-default-branch-corpus-linux-v1' and
         receipt.get('run_id') == run_token and
         receipt.get('consumer_sha') == source_event['consumer_commit'] and
         receipt.get('manifest_sha256') == manifest_digest and
         _same_source_identity(receipt.get('event', {}), source_event) and
         coverage.get('source_manifest_sha256') == manifest_digest and
         _same_source_identity(coverage.get('event', {}), source_event),
         'preflight/receipt/coverage source identity or manifest digest differs')
    need(set(event_id_keys) <= set(source_event), 'manifest event lacks required identity fields')
    need(receipt.get('status') in ('clean_scan', 'triage_required') and
         receipt.get('actual_package_installed_bytes_verified') is False and
         preflight.get('actual_package_installed_bytes_verified') is False and
         coverage.get('actual_package_installed_bytes_verified') is False and
         all(row.get('installed_bytes_verified') is False for row in selected),
         'scan status or package-byte boundary differs')
    need(receipt.get('selected_count') == len(selected) and
         receipt.get('successful_count') == len(selected) and
         receipt.get('extraction_error_count') == 0 and
         receipt.get('excluded_count', len(excluded)) == len(excluded) and
         receipt.get('route_counts') == {key: routing.get(key) for key in (
             'input_count', 'plain_count', 'markup_count', 'markup_inconclusive_count',
             'uncertain_count', 'excluded_count', 'duplicate_input_count')},
         'corpus receipt counts differ from manifest and routing')
    need(receipt.get('coverage_sha256') == coverage_digest and
         receipt.get('commands_sha256') == commands_digest and
         receipt.get('accepted_sha256') == triage_digest and
         receipt.get('sarif_sha256') == sarif_digest,
         'corpus receipt byte digests differ from retained outputs')
    need(coverage.get('schema') == 'ucode-default-branch-corpus-coverage-v1' and
         coverage.get('excluded') == excluded and
         preflight.get('source_pins') == manifest.get('pins'),
         'coverage exclusion or preflight source-pin identity differs')

    route_rows = routing.get('decisions')
    need(type(route_rows) is list and len(route_rows) == len(selected) and
         routing.get('input_count') == len(selected) and
         routing.get('plain_count') == counts.get('route_classes', {}).get('plain') and
         routing.get('markup_count') == counts.get('route_classes', {}).get('markup') and
         routing.get('markup_inconclusive_count') == counts.get('route_classes', {}).get('markup') and
         routing.get('uncertain_count') == 0 and routing.get('excluded_count') == 0 and
         routing.get('duplicate_input_count') == 0,
         'route receipt counts differ from manifest')
    stage_root = f'/home/runner/work/_temp/r3-ucode-{run_token}/default-branch-corpus/stage'
    expected_routes = Counter()
    for path, source in expected_by_path.items():
        expected_route = source['expected_route']
        classification = expected_route.get('classification')
        reason = expected_route.get('reason')
        status = 'plain_route_selected' if classification == 'plain' else 'inconclusive'
        need(classification in ('plain', 'markup') and isinstance(reason, str) and reason,
             'manifest has unsupported route oracle value')
        expected_routes[(path, classification, reason, status)] += 1
    actual_routes = Counter()
    seen_abs = set()
    for row in route_rows:
        need(type(row) is dict, 'route decision is not an object')
        installed = row.get('installed_path')
        expected_abs = str(PurePosixPath(stage_root) / installed) if isinstance(installed, str) else ''
        need(installed in expected_by_path and row.get('path') == expected_abs and
             expected_abs not in seen_abs,
             'route decision path differs from run-bound stage identity')
        seen_abs.add(expected_abs)
        actual_routes[(installed, row.get('classification'), row.get('reason'),
                       row.get('status'))] += 1
    need(actual_routes == expected_routes,
         'route decision multiset differs from source-first manifest')
    need(producer.get('route_sha256') == route_digest and
         producer.get('sarif_sha256') == sarif_digest and
         producer.get('run_id') == run_token and
         producer.get('consumer_sha') == source_event['consumer_commit'] and
         producer.get('extraction_errors') == [] and
         producer.get('resolved_rules') == receipt.get('resolved_rules') and
         producer.get('release_tag') == receipt.get('release_tag') and
         producer.get('producer', {}).get('sha') == receipt.get('producer_commit') and
         producer.get('commands') and
         all(type(row) is dict and type(row.get('exit')) is int and row['exit'] == 0
             for row in producer['commands']),
         'producer route/SARIF/run/extraction receipt identity differs')
    expected_paths = Counter(expected_by_path.keys())
    need(Counter(producer.get('successful_files', [])) == expected_paths,
         'producer successful-file multiset differs from manifest')

    expected_typed_sources = []
    for path, row in expected_by_path.items():
        expected_typed_sources.append({
            'uri': path, 'sha256': row.get('source_sha256'),
        })
    need(triage_input.get('schema') == 'ucode-sarif-event-triage-manifest-v1' or
         triage_input.get('schema') == 'ucode-sarif-event-triage-v1',
         'consumer triage input schema differs')
    need(Counter(tuple(sorted(x.items())) for x in triage_input.get('sources', [])) ==
         Counter(tuple(sorted(x.items())) for x in expected_typed_sources) and
         Counter(triage_input.get('expected_extracted', [])) == expected_paths and
         triage_input.get('producer') == producer.get('producer'),
         'consumer source/producer inventory differs from selected manifest')
    expected_rules = triage_input.get('expected_rules')
    expected_descriptors = triage_input.get('expected_sarif_descriptors')
    resolved_rules = receipt.get('resolved_rules')
    need(type(expected_rules) is list and type(expected_descriptors) is list and
         type(resolved_rules) is list and len(expected_rules) == len(set(expected_rules)) and
         len(resolved_rules) == len(set(resolved_rules)) and
         set(expected_rules) == set(resolved_rules) and
         len(expected_descriptors) == len(set(expected_descriptors)) and
         set(expected_descriptors) <= set(expected_rules),
         'consumer expected rule and producer rule inventories differ')

    select = successful.get('#select')
    need(type(select) is dict and type(select.get('tuples')) is list and
         len(select['tuples']) == len(selected),
         'successful extraction query shape or row count differs')
    successful_paths = Counter()
    entity_keys = set()
    for row in select['tuples']:
        need(type(row) is list and len(row) == 2 and type(row[0]) is dict,
             'successful extraction tuple shape differs')
        entity = row[0]
        uri = entity.get('url', {}).get('uri') if type(entity.get('url')) is dict else None
        label = entity.get('label')
        need(isinstance(uri, str) and isinstance(label, str) and
             uri.startswith('file://') and uri[7:] == label and
             label.startswith(stage_root + '/'),
             'successful extraction entity URI is not bound to expected stage')
        path = label[len(stage_root) + 1:]
        need(path in expected_by_path, 'successful extraction entity is outside manifest')
        url = entity['url']
        key = (uri, url.get('startLine'), url.get('startColumn'),
               url.get('endLine'), url.get('endColumn'))
        need(key not in entity_keys, 'duplicate successful extraction entity identity')
        entity_keys.add(key)
        successful_paths[path] += 1
    need(successful_paths == expected_paths,
         'successful extraction entity multiset differs from selected source multiset')
    error_select = errors.get('#select')
    need(type(error_select) is dict and type(error_select.get('tuples')) is list and
         error_select['tuples'] == [], 'extraction error query returned rows')
    coverage_selected = coverage.get('selected')
    need(type(coverage_selected) is list and len(coverage_selected) == len(selected),
         'coverage selected identity count differs')
    coverage_by_path = {}
    for row in coverage_selected:
        need(type(row) is dict and isinstance(row.get('staged_path'), str) and
             row['staged_path'] not in coverage_by_path,
             'coverage has duplicate or malformed selected identity')
        coverage_by_path[row['staged_path']] = row
    need(set(coverage_by_path) == set(expected_by_path),
         'coverage selected path multiset differs from manifest')
    for path, selected_row in expected_by_path.items():
        coverage_row = coverage_by_path[path]
        expected_route = selected_row['expected_route']
        expected_status = ('plain_route_selected' if expected_route['classification'] == 'plain'
                           else 'inconclusive')
        need(coverage_row.get('source_sha256') == selected_row.get('source_sha256') and
             coverage_row.get('git_blob') == selected_row.get('git_blob') and
             coverage_row.get('source_path') == selected_row.get('source_path') and
             coverage_row.get('source_commit') == selected_row.get('source_commit') and
             coverage_row.get('repo') == selected_row.get('repo') and
             coverage_row.get('extracted_count') == 1 and
             coverage_row.get('extraction_error_count') == 0 and
             coverage_row.get('route_classification') == expected_route.get('classification') and
             coverage_row.get('route_reason') == expected_route.get('reason') and
             coverage_row.get('route_status') == expected_status,
             'coverage source/route/extraction identity differs: ' + path)
    need(coverage.get('counts') == {
        'errored': 0, 'excluded': len(excluded), 'extracted_once': len(selected),
        'modeled_markup_inconclusive': counts.get('route_classes', {}).get('markup'),
        'selected': len(selected),
    }, 'coverage multiplicity counts differ')

    expected_status, result_count = _verify_consumer_results(
        sarif_raw, triage, triage_input, expected_paths, run_token)
    need(triage.get('status') == expected_status and
         receipt.get('status') == expected_status,
         'clean_scan/triage_required status does not match exact SARIF result multiplicity')
    need(preflight.get('selected_count') == len(selected) and
         preflight.get('excluded_count') == len(excluded) and
         preflight.get('released_route_source_matches_oracle') is True and
         preflight.get('released_route_source_sha256') ==
         receipt.get('released_route_source_sha256'),
         'preflight selected/excluded or released route-source receipt differs')
    need(receipt.get('source_pins') == manifest.get('pins') and
         coverage.get('source_pins') == manifest.get('pins') and
         coverage.get('release_tag') == receipt.get('release_tag') and
         coverage.get('producer_commit') == receipt.get('producer_commit'),
         'source pin or released producer identity differs')

    # The R3 root receipt binds its own command transcript. The retained
    # workflow's larger R3 receipt schema is allowed to evolve only by explicit
    # contract update; this check intentionally keys to byte digests and run.
    r3_receipt = parse_object(r3['receipt.json'], 'R3 release receipt')
    r3_release = _verify_r3_release(r3_receipt, receipt, producer, triage_input,
                                    run_token, source_event, approved_policy,
                                    r3['commands.json'])
    return {
        'manifest_sha256': manifest_digest,
        'route_sha256': route_digest,
        'successful_files': len(successful_paths),
        'extraction_error_rows': len(error_select['tuples']),
        'sarif_sha256': sarif_digest,
        'sarif_result_count': result_count,
        'consumer_status': expected_status,
        'r3_release': r3_release,
        'alert_disposition': 'not_evaluated',
    }


def _verify_start_binding(start_raw: bytes, run: dict, job: dict,
                          early_artifact: dict, early_zip: bytes,
                          claim: dict, reconciliation: dict) -> dict:
    need(type(start_raw) is bytes and 0 < len(start_raw) <= 1024 * 1024,
         'supplied start document is empty or exceeds its byte bound')
    try:
        text = start_raw.decode('utf-8')
        unsigned, document, canonical_raw = issued._load_document(text)
        att = unsigned.get('attestation')
        issued._validate_start(att)
        issued._canonical_time(unsigned.get('observed_at'), 'supplied start time')
    except (issued.IssuedActionError, UnicodeError, ValueError, TypeError,
            KeyError, AttributeError, RecursionError) as exc:
        raise FinalProofError('supplied start document structure is invalid') from exc
    need(canonical_raw == start_raw,
         'supplied start document bytes are not canonical')
    run_id, attempt = run['id'], run['run_attempt']
    identity = reconciliation['reservation']['identity']
    local_policy = reconciliation['reservation']['policy_claim']
    claim_origin = claim.get('linked_discovery_origin')
    asserted = claim.get('asserted_reservation')
    expected_identity = identity
    expected_early = {
        'id': early_artifact['id'], 'sha256': digest(early_zip),
        'size': len(early_zip),
    }
    need(att.get('run_id') == run_id and att.get('run_attempt') == attempt and
         att.get('job_id') == job['id'] and att.get('workflow') == reconcile.SCAN_WORKFLOW and
         att.get('job') == reconcile.SCAN_JOB and
         att.get('consumer_commit') == run.get('head_sha') and
         att.get('queue_id') == asserted.get('queue_id') and
         att.get('reservation_sequence') == asserted.get('reservation_sequence') and
         att.get('reservation_sha256') == asserted.get('reservation_sha256') and
         att.get('identity') == expected_identity and
         att.get('origin_receipt_sha256') ==
         reconciliation['reservation']['origin_receipt_sha256'] and
         att.get('origin_gap_sha256') == claim_origin.get('gap_sha256') and
         att.get('policy_sha256') == reconciliation['reservation']['policy_sha256'] and
         att.get('consumer_commit') == local_policy.get('consumer_commit') and
         att.get('release_lock_sha256') == local_policy.get('release_lock_sha256') and
         att.get('early_artifact') == expected_early,
         'supplied start run/job/reservation/source/policy/early-artifact binding differs')
    return {
        'document_sha256': digest(start_raw), 'run_id': run_id,
        'attempt': attempt, 'job_id': job['id'],
        'mac_present_and_well_formed': True,
        'mac_verified': False,
        'verification_scope': 'supplied_start_binding_only',
    }


def _verify_v3_replay_binding(claim_replay: dict, start_raw: bytes) -> None:
    database = claim_replay.get('database', {})
    need(database.get('schema_version') == reconcile.intake.ISSUED_SCHEMA_VERSION and
         database.get('supplied_start_head_bound') is True and
         database.get('supplied_start_sha256') == digest(start_raw) and
         database.get('start_mac_verified') is False and
         database.get('head_scope') == 'read_only_snapshot_unkeyed',
         'claim replay did not bind the exact supplied v3 start head')


def verify_final_proof(private_root: Path, work_root: Path,
                       run_raw: bytes, jobs_raw: bytes, artifacts_raw: bytes,
                       final_zip: bytes, early_zip: bytes, start_raw: bytes,
                       run_id: int, attempt: int, *,
                       require_issued_start_head: bool = False) -> dict:
    """Verify supplied terminal bytes against one supplied start binding.

    `reconcile_bytes` performs read-only local action/receipt/archive replay.
    The resulting status is not authenticated queue completion: the supplied
    start MAC is deliberately not checked here.
    """
    need(type(require_issued_start_head) is bool,
         'issued start head requirement must be boolean')
    need(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
         'run ID and attempt must be positive integers')
    need(type(start_raw) is bytes and 0 < len(start_raw) <= 1024 * 1024,
         'supplied start document is empty or exceeds its byte bound')
    run = reconcile.parse_json(run_raw, 'canonical completed run API')
    jobs = reconcile.parse_json(jobs_raw, 'complete jobs API')
    artifacts = reconcile.parse_json(artifacts_raw, 'complete artifacts API')
    job, artifact = reconcile.verify_github_metadata(run, jobs, artifacts,
                                                      run_id, attempt)
    need(run.get('status') == 'completed' and run.get('conclusion') == 'success' and
         job.get('status') == 'completed' and job.get('conclusion') == 'success',
         'canonical run or scan job is not terminal success')
    need(len(final_zip) == artifact['size_in_bytes'] and
         digest(final_zip) == artifact['digest'].removeprefix('sha256:'),
         'final ZIP size or digest differs from canonical artifact metadata')
    inputs, r3 = _final_members(final_zip, run_id, attempt)

    # The early artifact remains run-linked in the completed artifacts API;
    # metadata does not identify the uploading job directly.
    early_artifact = live._early_artifact(artifacts, run, run_id, attempt)
    need(len(early_zip) == early_artifact['size_in_bytes'] and
         digest(early_zip) == early_artifact['digest'].removeprefix('sha256:'),
         'early ZIP size or digest differs from completed artifacts API')
    # live._read_early_zip uses zipfile; validate raw central/local names first
    # so NUL truncation cannot turn a malformed member into an accepted name.
    _raw_zip_names(early_zip, 'early artifact')
    early_members = live._read_early_zip(early_zip, run_id, attempt)
    policy_from_start = {
        'consumer_commit': run['head_sha'],
        'release_lock_sha256': '0' * 64,
    }
    # Start parsing below supplies the exact approved policy digest. Validate
    # early file receipt bytes without using a caller `verified` flag.
    start_doc = parse_object(start_raw, 'supplied start document')
    att = start_doc.get('attestation')
    need(type(att) is dict and isinstance(att.get('release_lock_sha256'), str) and
         HEX64.fullmatch(att['release_lock_sha256']),
         'supplied start lacks a well-formed release-lock digest')
    policy_from_start['release_lock_sha256'] = att['release_lock_sha256']
    claim = live._verify_receipt_files(early_members, run_id, attempt,
                                       policy_from_start)
    for name in FROZEN_INPUTS:
        need(early_members[name] == inputs[name],
             'early/final frozen input bytes differ: ' + name)
    receipt = parse_object(early_members['receipt.json'], 'early artifact receipt')
    need(set(receipt.get('files', {})) == FROZEN_INPUTS,
         'early receipt does not inventory exactly nine frozen inputs')

    work_root = Path(work_root)
    need(work_root.is_absolute() and work_root.is_dir() and not work_root.is_symlink(),
         'read-only replay work root must be an existing real directory')
    try:
        claim_replay = reconcile.reconcile_bytes(
            Path(private_root), run_raw, jobs_raw, artifacts_raw, final_zip,
            run_id, attempt, work_root,
            start_raw=start_raw if require_issued_start_head else None)
    except (reconcile.ReconcileError, OSError, ValueError, TypeError,
            KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise FinalProofError('archived claim/origin replay failed') from exc
    need(claim_replay.get('status') == 'claim_reconciled_read_only' and
         claim_replay.get('canonical_run', {}).get('artifact_sha256') == digest(final_zip),
         'archived claim/origin replay did not bind this final artifact')
    if require_issued_start_head:
        _verify_v3_replay_binding(claim_replay, start_raw)
    scan_summary = _verify_scan_receipts(
        inputs, r3, run_id, attempt, claim_replay['reservation']['policy_claim'])
    start_summary = _verify_start_binding(start_raw, run, job, early_artifact,
                                           early_zip, claim, claim_replay)
    return {
        'schema': 'operator-default-branch-final-proof-v1',
        'status': 'verified_against_supplied_start_only',
        'run_id': run_id, 'attempt': attempt,
        'job_id': job['id'], 'final_artifact_id': artifact['id'],
        'final_artifact_size': len(final_zip),
        'final_artifact_sha256': digest(final_zip),
        'early_artifact_id': early_artifact['id'],
        'early_artifact_size': len(early_zip),
        'early_artifact_sha256': digest(early_zip),
        'early_final_equal_frozen_inputs': len(FROZEN_INPUTS),
        'start_binding': start_summary,
        'claim_origin_replay': claim_replay,
        'scan': scan_summary,
        'source_truth': 'open_without_fresh_canonical_git_object_retrieval',
        'actual_package_installed_bytes_verified': False,
        'alert_disposition': 'not_evaluated',
        'limitations': [
            ('The supplied start bytes matched the unkeyed v3 issued head in a read-only snapshot; its MAC was not verified and the head may change after the snapshot.'
             if require_issued_start_head else
             'The supplied start document MAC and durable issued-chain head were not verified.'),
            'GitHub artifact metadata binds the ZIP to the run, not directly to its uploader job; the unique expected job is a same-run inference.',
            'The final ZIP contains source claims but no staged source bytes. Selection and routing source truth require fresh canonical Git objects and an independent oracle replay.',
            'This verifier records exact SARIF/consumer tuples; triage_required means human disposition is still needed and no alert disposition is asserted.',
            'Extraction checks compare the archived decoded JSON rows and receipts; BQRS is not decoded or independently tied to those rows, and CodeQL is not re-executed.',
            ('Claim/origin replay uses a v3 read-only snapshot, its exact sequence-one start head and retained archives; this tool does not migrate or mutate queue state.'
             if require_issued_start_head else
             'Claim/origin replay uses the captured v2 reservation store and retained archives; this tool does not migrate or mutate queue state.'),
        ],
    }


