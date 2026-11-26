#!/usr/bin/env python3
"""Keyless offline tuple proof for one supplied source-first SARIF packet.

This runs the reviewed local consumer against supplied bytes in private
scratch. It neither authenticates a hosted run nor issues a queue action.
The historical OpenVPN oracle is an explicit regression case, not an event
source oracle for arbitrary default-branch commits.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import re
import tempfile
import time
from typing import Any

from tools import default_branch_consumer_replay as replay
from tools import default_branch_final_proof as final_proof


SCHEMA = 'mvp-default-branch-sarif-tuple-proof-v1'
CONSUMER_SHA256 = '7da16c10e1c0b5085a1d8158a24368a900c25a430ebab691c7e7a7591da282aa'
ORACLE_SHA256 = 'cdea67fa3983576df3cea44a19e74eb2d015866ad5d2ebc24141d357055e2fb4'
LOCK_SHA256 = '53ef87cdaa69ae58be3da9386f4e710050309368649f8ae886c0a7f9ee5c2526'
HISTORICAL_PRODUCER_SOURCE_COMMITS = {
    'introduced': 'b45584b4e6068b9b096872dd02494a048d869c36',
    'fixed': 'e4ff45ecbc6ad212951815c8c99b2749fbd7de6b',
}
HISTORICAL_CONSUMER = '929dc12b0434b38d0d17e8b65cfc3450170c5b11'
HISTORICAL_RUN = '45833426577-1'
STAGED_URI = 'usr/share/rpcd/ucode/luci.openvpn.uc'
EVENT_SCHEMA = 'ucode-sarif-event-triage-v1'
RUN_SCHEMA = 'ucode-sarif-run-v1'
FIELDS = replay.TUPLE_FIELDS
MAX_SOURCE = 4 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
HEX40 = re.compile(r'[0-9a-f]{40}\Z')


class TupleProofError(ValueError):
    """Supplied source, oracle, SARIF or consumer packet differs."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise TupleProofError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _object(raw: bytes, label: str) -> dict[str, Any]:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, label + ' is unbounded')
    try:
        return replay._parse_object(raw, label)
    except (replay.ReplayError, final_proof.FinalProofError) as exc:
        raise TupleProofError(str(exc)) from exc


def _guard_uri(raw_uri: Any, label: str) -> str:
    # This historical fixture has exactly one reviewed ASCII installed path.
    # Exact spelling rejects raw controls and URL parser/percent aliases.
    need(type(raw_uri) is str and raw_uri == STAGED_URI,
         label + ' is not the exact staged URI')
    return raw_uri


def _guard_result_uris(sarif: dict, manifest: dict) -> None:
    need(type(manifest.get('sources')) is list and
         type(manifest.get('expected_extracted')) is list,
         'consumer input source inventory is malformed')
    for source in manifest.get('sources', []):
        _guard_uri(source.get('uri'), 'manifest source URI')
    for uri in manifest.get('expected_extracted', []):
        _guard_uri(uri, 'expected extracted URI')
    runs = sarif.get('runs')
    need(type(runs) is list and len(runs) == 1 and type(runs[0]) is dict,
         'SARIF run multiplicity differs')
    results = runs[0].get('results', [])
    need(type(results) is list, 'SARIF results are not a list')
    for row in results:
        try:
            uri = row['locations'][0]['physicalLocation']['artifactLocation']['uri']
        except (KeyError, TypeError, IndexError, AttributeError) as exc:
            raise TupleProofError('SARIF result location is malformed') from exc
        _guard_uri(uri, 'SARIF result URI')


def _source_case(oracle: dict, case_name: str, source: bytes,
                 manifest: dict, producer: dict, lock: dict) -> tuple[str, Counter]:
    need(oracle.get('schema') == 'openvpn-historical-introduction-replay-oracle-v1' and
         case_name in ('introduced', 'fixed') and
         type(oracle.get('cases')) is dict,
         'unsupported source-first regression oracle or case')
    case = oracle['cases'].get(case_name)
    need(type(case) is dict and case.get('source_path_status') == 'present' and
         case.get('staged_path') == oracle.get('installed_path') and
         case.get('source_sha256') == digest(source),
         'source bytes or selected installed path differ from oracle')
    git_blob = hashlib.sha1(b'blob ' + str(len(source)).encode() + b'\0' + source).hexdigest()
    need(case.get('git_blob') == git_blob and HEX40.fullmatch(case.get('commit', '')),
         'source Git blob or commit identity differs from oracle')
    uri = _guard_uri(case['staged_path'], 'oracle staged URI')
    selected = case.get('selected_file_multiset')
    need(type(selected) is dict and selected == {uri: 1} and
         case.get('expected_extraction_errors') == [] and
         case.get('route') == {'classification': 'plain',
                               'reason': 'rpcd_raw_mode_full_path'},
         'source-first route or extraction oracle differs')
    need(manifest.get('schema') == EVENT_SCHEMA and
         manifest.get('expected_extracted') == [uri] and
         manifest.get('sources') == [{'uri': uri, 'sha256': digest(source)}] and
         manifest.get('producer') == producer.get('producer') and
         producer.get('successful_files') == [uri] and
         producer.get('extraction_errors') == [],
         'consumer manifest/producer source or extraction identity differs')
    producer_source = producer.get('source', {})
    need(producer.get('schema') == RUN_SCHEMA and
         producer.get('run_id') == HISTORICAL_RUN and
         producer.get('consumer_sha') == HISTORICAL_CONSUMER and
         type(producer_source) is dict and
         producer_source.get('commit') == HISTORICAL_PRODUCER_SOURCE_COMMITS[case_name] and
         producer_source.get('blob') == git_blob and
         producer_source.get('source_path') == oracle['source_path'] and
         producer_source.get('source_sha256') == digest(source) and
         producer_source.get('stage_path') == uri and
         producer_source.get('stage_sha256') == digest(source) and
         producer_source.get('actual_package_installed_bytes_verified') is False,
         'retained producer source identity differs from historical source bytes')
    release = lock.get('release', {})
    codeql = lock.get('codeql', {})
    wanted_rules = release.get('expected_rules')
    resolved = producer.get('resolved_rules')
    need(lock.get('schema') == 'ucode-r3-release-lock-v1' and
         oracle.get('producer_release_tag') == release.get('tag') ==
         producer.get('release_tag') and
         oracle.get('producer_release_commit') == release.get('commit') ==
         producer.get('producer', {}).get('sha') and
         producer.get('producer', {}).get('pack_sha256') == release.get('asset_sha256') and
         producer.get('producer', {}).get('suite_sha256') == release.get('suite_sha256') and
         producer.get('producer', {}).get('codeql_version') == codeql.get('version') and
         producer.get('codeql_binary_sha256') == release.get('codeql_binary_sha256') and
         type(wanted_rules) is list and len(wanted_rules) == len(set(wanted_rules)) and
         type(resolved) is list and len(resolved) == len(set(resolved)) and
         set(wanted_rules) == set(resolved) == set(manifest.get('expected_rules', [])) and
         manifest.get('expected_sarif_descriptors') ==
         ['ucode/m4/direct-rpc-shell-word'],
         'producer/release lock/rule identity differs')
    expected = Counter()
    rows = case.get('expected_rule_results')
    need(type(rows) is list, 'oracle expected result rows are missing')
    for row in rows:
        need(type(row) is dict and set(row) == set(FIELDS[:-1]) | {'multiplicity'} and
             type(row['multiplicity']) is int and row['multiplicity'] > 0 and
             _guard_uri(row['uri'], 'oracle result URI') == uri,
             'oracle result row is malformed')
        expected[tuple(row[key] for key in FIELDS[:-1]) + ('warning',)] += row['multiplicity']
    return uri, expected


def _run_pinned_consumer(consumer_bytes: bytes, sarif_raw: bytes,
                         manifest_raw: bytes, producer_raw: bytes,
                         source: bytes, uri: str, run_id: int,
                         attempt: int) -> tuple[dict, bytes, bytes]:
    # The system temp parent uses OS sticky-directory semantics; the random
    # scratch directory is owner-only, and no caller-selected path is used.
    with tempfile.TemporaryDirectory(prefix='sarif-tuple-proof-') as temporary:
        scratch = Path(temporary) / 'scratch'
        for relative in ('', 'home', 'tmp', 'consumer', 'consumer/tools',
                         'payload', 'payload/out', 'payload/stage'):
            path = scratch / relative
            if not path.exists():
                replay._mkdir_private(path)
        out = scratch / 'payload/out'
        for filename, body in (('default-suite.sarif', sarif_raw),
                               ('event-triage-input.json', manifest_raw),
                               ('producer-receipt.json', producer_raw)):
            replay._write_exclusive(out / filename, body)
        replay._write_scratch_tree(scratch / 'payload/stage', uri, source)
        consumer_script = scratch / 'consumer/tools/sarif_accept.py'
        replay._write_exclusive(consumer_script, consumer_bytes)
        invocation = replay._invoke_consumer(
            consumer_script, scratch, run_id=run_id, attempt=attempt)
        return invocation, invocation.pop('stdout'), invocation.pop('stderr')


def verify(sarif_raw: bytes, reference_raw: bytes, manifest_raw: bytes,
           producer_raw: bytes, source: bytes, oracle_raw: bytes,
           case_name: str) -> dict:
    """Run the pinned local consumer and compare exact source-derived tuples."""
    started = time.monotonic()
    need(type(source) is bytes and 0 < len(source) <= MAX_SOURCE,
         'source bytes are empty or unbounded')
    need(digest(oracle_raw) == ORACLE_SHA256,
         'source-first oracle bytes differ from frozen ledger oracle')
    lock_raw = replay._read_regular(Path(__file__).resolve().parents[1] /
                                    'docs/r3-release-lock.json', MAX_JSON, 'release lock')
    need(digest(lock_raw) == LOCK_SHA256,
         'release lock bytes differ from reviewed pin')
    lock = _object(lock_raw, 'release lock')
    oracle = _object(oracle_raw, 'source-first oracle')
    manifest = _object(manifest_raw, 'consumer input manifest')
    producer = _object(producer_raw, 'producer receipt')
    sarif = _object(sarif_raw, 'SARIF')
    reference = _object(reference_raw, 'offline reference consumer packet')
    try:
        _guard_result_uris(sarif, manifest)
        uri, expected = _source_case(oracle, case_name, source, manifest,
                                     producer, lock)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise TupleProofError('source/SARIF input shape differs') from exc
    local_consumer = Path(__file__).resolve().parent / 'sarif_accept.py'
    consumer_bytes = replay._read_regular(local_consumer, MAX_JSON, 'reviewed consumer')
    need(digest(consumer_bytes) == CONSUMER_SHA256,
         'local consumer bytes differ from reviewed pin')
    run_id = producer.get('run_id')
    need(type(run_id) is str, 'producer run/attempt token differs')
    match = re.fullmatch(r'([1-9][0-9]*)-([1-9][0-9]*)', run_id)
    need(match is not None, 'producer run/attempt token differs')
    try:
        invocation, stdout, stderr = _run_pinned_consumer(
            consumer_bytes, sarif_raw, manifest_raw, producer_raw, source, uri,
            int(match.group(1)), int(match.group(2)))
    except (replay.ReplayError, OSError, ValueError) as exc:
        raise TupleProofError('pinned consumer replay failed') from exc
    need(invocation['exit'] == 0, 'pinned consumer rejected supplied packet')
    try:
        comparison = replay._assert_output_equal(
            stdout, reference_raw, sarif_raw, manifest, Counter({uri: 1}), run_id)
    except (replay.ReplayError, final_proof.FinalProofError) as exc:
        raise TupleProofError(str(exc)) from exc
    observed = Counter(tuple(row['tuple']) for row in comparison['tuple_multiplicity']
                       for _ in range(row['count']))
    need(observed == expected, 'observed tuple multiset differs from source-first oracle')
    need(reference.get('status') == ('triage_required' if expected else 'clean_scan'),
         'consumer status differs from source-first expected tuple count')
    return {
        'schema': SCHEMA, 'status': 'verified_against_supplied_source_and_output_only',
        'authority': 'none', 'case': case_name,
        'oracle_sha256': digest(oracle_raw),
        'oracle_source_commit': oracle['cases'][case_name]['commit'],
        'producer_receipt_source_commit': producer['source']['commit'],
        'source_blob': oracle['cases'][case_name]['git_blob'],
        'source_sha256': digest(source), 'staged_uri': uri,
        'expected_route': oracle['cases'][case_name]['route'],
        'producer_asserted_file_multiplicity': {uri: 1},
        'producer_asserted_extraction_errors': [],
        'sarif_sha256': digest(sarif_raw), 'consumer_input_sha256': digest(manifest_raw),
        'producer_receipt_sha256': digest(producer_raw),
        'reference_packet_sha256': digest(reference_raw),
        'replayed_packet_sha256': digest(stdout),
        'consumer_script_sha256': digest(consumer_bytes),
        'release_lock_sha256': digest(lock_raw),
        'tuple_fields': list(FIELDS), 'column_kind': 'utf16CodeUnits',
        'end_column': 'exclusive', 'expected_and_observed': comparison['tuple_multiplicity'],
        'result_count': comparison['result_count'], 'consumer_status': comparison['status'],
        'consumer_command': {**invocation, 'stdout_sha256': digest(stdout),
                             'stdout_bytes': len(stdout), 'stderr_sha256': digest(stderr),
                             'stderr_bytes': len(stderr)},
        'wall_seconds': round(time.monotonic() - started, 6),
        'canonical_git_provenance_verified': False,
        'hosted_execution_authenticated': False,
        'signed_live_completion_verified': False,
        'limitations': [
            'Source and output bytes are caller supplied; the pinned source identities were compared to a prepared oracle but canonical Git was not fetched.',
            'The pinned consumer was executed locally; exact output equality does not authenticate hosted execution or freshness.',
            'This historical one-file source-stage fixture is not a default-branch corpus or installed-package-byte claim.',
            'The route is an oracle expectation and extraction rows are producer assertions; this tool does not rederive routing or decode extraction output.',
            'No network, key, queue mutation, signing, CodeQL re-execution or alert disposition is involved.',
            'The implementation tree and same-user process environment are trusted to supply the pinned local consumer and scratch directory.',
        ],
    }
