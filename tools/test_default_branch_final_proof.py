"""Focused byte-contract controls for the read-only final proof verifier."""
from collections import Counter
from io import BytesIO
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import warnings
from pathlib import Path
from contextlib import ExitStack, closing
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo
import stat

from tools import default_branch_backlog_issued as issued
from tools import default_branch_final_proof as proof


RUN_ID = 45875169837
ATTEMPT = 1


def archive(rows):
    out = BytesIO()
    with ZipFile(out, 'w', compression=ZIP_STORED) as z:
        for name, body in rows:
            z.writestr(name, body)
    return out.getvalue()


def minimal_manifest():
    return {
        'selected': [
            {'proposed_installed_path': 'usr/a.uc',
             'expected_route': {'classification': 'plain', 'reason': 'ucode_extension'}},
            {'proposed_installed_path': 'usr/b.ut',
             'expected_route': {'classification': 'markup', 'reason': 'ut_markup_extension'}},
        ],
        'excluded': [
            {'git_blob': 'a' * 40}, {'reason': 'no blob'},
            {'git_blob': 'b' * 40},
        ],
    }


class FinalArtifactZipTests(unittest.TestCase):
    def expected_rows(self, extra=()):
        input_prefix = f'default-branch-inputs-{RUN_ID}-{ATTEMPT}/'
        r3_prefix = f'r3-ucode-{RUN_ID}-{ATTEMPT}/'
        labels = proof._command_labels(minimal_manifest())
        names = [input_prefix + name for name in proof.FROZEN_INPUTS]
        names.extend(r3_prefix + name for name in proof.R3_FIXED)
        names.extend(r3_prefix + 'default-branch-corpus/' + name
                     for name in proof.CORPUS_FIXED)
        names.extend(r3_prefix + f'default-branch-corpus/commands/{label}{suffix}'
                     for label in labels for suffix in proof.COMMAND_SUFFIXES)
        names.extend(name for name, _body in extra)
        return [(name, b'x') for name in sorted(names)]

    def test_exact_inventory_and_recipe_labels(self):
        raw = archive(self.expected_rows())
        inputs, r3 = proof._final_members(raw, RUN_ID, ATTEMPT)
        self.assertEqual(set(inputs), proof.FROZEN_INPUTS)
        labels = proof._command_labels(minimal_manifest())
        rows = []
        for label in sorted(labels):
            rows.append({'label': label, 'exit': 0, 'argv': ['git', 'status'],
                         'stdout': f'commands/{label}.stdout',
                         'stderr': f'commands/{label}.stderr',
                         'time': f'commands/{label}.time'})
        encoded_rows = __import__('json').dumps(rows).encode()
        r3['default-branch-corpus/commands.json'] = encoded_rows
        actual_rows = proof._verify_final_inventory(r3, minimal_manifest())
        self.assertEqual({row['label'] for row in actual_rows}, labels)
        proof._verify_command_receipt(rows, r3, minimal_manifest(), RUN_ID, ATTEMPT)
        with self.assertRaises(proof.FinalProofError):
            proof._verify_command_receipt(rows[:-1], r3, minimal_manifest(), RUN_ID, ATTEMPT)

    def test_retained_final_zip_inventory_control_when_available(self):
        work = Path(__file__).resolve().parents[2]
        final_path = (work / 'default-branch-early-live-retry-20261126' /
                      'live-observation' / 'final.zip')
        if not final_path.is_file():
            self.skipTest('retained live final ZIP is not part of this checkout')
        raw = final_path.read_bytes()
        inputs, r3 = proof._final_members(raw, RUN_ID, ATTEMPT)
        manifest = proof.parse_object(inputs['manifest.json'], 'source-first manifest')
        rows = proof._verify_final_inventory(r3, manifest)
        self.assertEqual(len(raw), 14_906_724)
        self.assertEqual(len(r3), 511)
        self.assertEqual(len(rows), 165)
        self.assertEqual(proof._verify_r3_command_receipt(r3['commands.json']), 48)

    def test_extra_member_rejected(self):
        _inputs, r3 = proof._final_members(archive(self.expected_rows([
            (f'r3-ucode-{RUN_ID}-{ATTEMPT}/notes.txt', b'extra'),
        ])), RUN_ID, ATTEMPT)
        with self.assertRaisesRegex(proof.FinalProofError, 'member set'):
            proof._verify_final_inventory(r3, minimal_manifest())

    def test_duplicate_member_rejected(self):
        name = f'r3-ucode-{RUN_ID}-{ATTEMPT}/receipt.json'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            raw = archive(self.expected_rows() + [(name, b'duplicate')])
        with self.assertRaisesRegex(proof.FinalProofError, 'duplicate'):
            proof._final_members(raw, RUN_ID, ATTEMPT)

    def test_unsafe_and_symlink_members_rejected(self):
        with self.assertRaisesRegex(proof.FinalProofError, 'unsafe'):
            proof._read_zip(archive([('../escape', b'x')]), 'fixture')
        nul_archive = archive([('xA', b'')])
        nul_archive = nul_archive.replace(b'xA', b'x\x00', 2)
        with self.assertRaisesRegex(proof.FinalProofError, 'NUL'):
            proof._read_zip(nul_archive, 'fixture')
        with self.assertRaisesRegex(proof.FinalProofError, 'NUL'):
            proof._raw_zip_names(nul_archive, 'early artifact')
        out = BytesIO()
        with ZipFile(out, 'w') as z:
            link = ZipInfo('link')
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(link, 'target')
        with self.assertRaisesRegex(proof.FinalProofError, 'nonregular'):
            proof._read_zip(out.getvalue(), 'fixture')


class FrozenInputTests(unittest.TestCase):
    def test_nine_byte_equal_inputs_pass_and_change_rejects(self):
        inputs = {name: name.encode() for name in proof.FROZEN_INPUTS}
        early = dict(inputs, **{'receipt.json': b'not a frozen input'})
        self.assertEqual(proof._compare_frozen_inputs(inputs, early), 9)
        early['identity.json'] = b'changed'
        with self.assertRaisesRegex(proof.FinalProofError, 'bytes differ'):
            proof._compare_frozen_inputs(inputs, early)


class V3ReplayBindingTests(unittest.TestCase):
    def test_public_flag_passes_exact_start_bytes_to_reconciliation(self):
        run_id, attempt = 9, 1
        start_raw = b'{"fixture":"start"}\n'
        final_zip, early_zip = b'f', b'e'
        run = {'status': 'completed', 'conclusion': 'success',
               'head_sha': '1' * 40}
        job = {'id': 33, 'status': 'completed', 'conclusion': 'success'}
        final = {'id': 45, 'size_in_bytes': 1,
                 'digest': 'sha256:' + proof.digest(final_zip)}
        early = {'id': 44, 'size_in_bytes': 1,
                 'digest': 'sha256:' + proof.digest(early_zip)}
        inputs = {name: b'x' for name in proof.FROZEN_INPUTS}
        early_members = dict(inputs, **{'receipt.json': b'{}'})
        captured = []

        class StopAtReplay(RuntimeError):
            pass

        def stop_replay(*args, **kwargs):
            captured.append((args, kwargs))
            raise StopAtReplay

        with ExitStack() as stack:
            stack.enter_context(patch.object(
                proof.reconcile, 'parse_json', side_effect=[run, {}, {}] * 2))
            stack.enter_context(patch.object(
                proof.reconcile, 'verify_github_metadata', return_value=(job, final)))
            stack.enter_context(patch.object(proof, '_final_members', return_value=(inputs, {})))
            stack.enter_context(patch.object(proof.live, '_early_artifact', return_value=early))
            stack.enter_context(patch.object(proof, '_raw_zip_names', return_value=[]))
            stack.enter_context(patch.object(proof.live, '_read_early_zip',
                                             return_value=early_members))
            stack.enter_context(patch.object(proof, 'parse_object', side_effect=[
                {'attestation': {'release_lock_sha256': '2' * 64}},
                {'files': dict.fromkeys(proof.FROZEN_INPUTS)},
                {'attestation': {'release_lock_sha256': '2' * 64}},
                {'files': dict.fromkeys(proof.FROZEN_INPUTS)},
            ]))
            stack.enter_context(patch.object(proof.live, '_verify_receipt_files',
                                             return_value={}))
            stack.enter_context(patch.object(proof.reconcile, 'reconcile_bytes',
                                             side_effect=stop_replay))
            for flag in (False, True):
                with self.subTest(flag=flag), self.assertRaises(StopAtReplay):
                    proof.verify_final_proof(
                        Path('/unused/private'), Path(__file__).resolve().parents[1],
                        b'run', b'jobs', b'artifacts', final_zip, early_zip,
                        start_raw, run_id, attempt,
                        require_issued_start_head=flag)
        self.assertEqual([call[1]['start_raw'] for call in captured],
                         [None, start_raw])

    def test_exact_snapshot_receipt_required_without_authentication_claim(self):
        start_raw = b'canonical fixture start bytes\n'
        database = {
            'schema_version': proof.reconcile.intake.ISSUED_SCHEMA_VERSION,
            'supplied_start_head_bound': True,
            'supplied_start_sha256': proof.digest(start_raw),
            'start_mac_verified': False,
            'head_scope': 'read_only_snapshot_unkeyed',
        }
        proof._verify_v3_replay_binding({'database': database}, start_raw)
        for field, value in (
                ('schema_version', proof.reconcile.intake.RESERVATION_SCHEMA_VERSION),
                ('supplied_start_head_bound', False),
                ('supplied_start_sha256', '0' * 64),
                ('start_mac_verified', True),
                ('head_scope', 'claimed_current')):
            with self.subTest(field=field):
                altered = dict(database, **{field: value})
                with self.assertRaisesRegex(proof.FinalProofError,
                                            'exact supplied v3 start head'):
                    proof._verify_v3_replay_binding({'database': altered}, start_raw)


class ConsumerTupleTests(unittest.TestCase):
    def packet(self, results, triage_rows, status, count):
        producer = {'codeql_version': '2.27.4', 'sha': '1' * 40}
        sarif = {
            'version': '2.1.0',
            'runs': [{
                'tool': {'driver': {'name': 'CodeQL', 'semanticVersion': '2.27.4',
                                    'rules': [{'id': 'ucode/test-rule',
                                               'defaultConfiguration': {'level': 'warning'}}]}},
                'columnKind': 'utf16CodeUnits', 'results': results,
            }],
        }
        raw = (__import__('json').dumps(sarif, sort_keys=True) + '\n').encode()
        triage = {
            'schema': 'ucode-sarif-event-triage-v1', 'run_id': '9-1',
            'producer': producer, 'successful_files': ['usr/a.uc'],
            'sarif_sha256': hashlib.sha256(raw).hexdigest(),
            'status': status, 'result_count': count,
            'results_for_triage': triage_rows,
        }
        triage_input = {
            'producer': producer,
            'expected_sarif_descriptors': ['ucode/test-rule'],
        }
        return raw, triage, triage_input

    def test_triage_required_positive_preserves_exact_tuple(self):
        result = {
            'ruleId': 'ucode/test-rule', 'level': 'warning',
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': 'usr/a.uc', 'uriBaseId': '%SRCROOT%'},
                'region': {'startLine': 2, 'startColumn': 3,
                           'endLine': 2, 'endColumn': 8},
            }}],
        }
        row = {'rule_id': 'ucode/test-rule', 'uri': 'usr/a.uc',
               'start_line': 2, 'start_column': 3, 'end_line': 2,
               'end_column': 8, 'level': 'warning'}
        raw, triage, triage_input = self.packet(
            [result], [row], 'triage_required', 1)
        self.assertEqual(proof._verify_consumer_results(
            raw, triage, triage_input, Counter({'usr/a.uc': 1}), '9-1'),
            ('triage_required', 1))

    def test_duplicate_result_multiplicity_cannot_be_collapsed(self):
        result = {
            'ruleId': 'ucode/test-rule', 'level': 'warning',
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': 'usr/a.uc', 'uriBaseId': '%SRCROOT%'},
                'region': {'startLine': 2, 'startColumn': 3,
                           'endLine': 2, 'endColumn': 8},
            }}],
        }
        row = {'rule_id': 'ucode/test-rule', 'uri': 'usr/a.uc',
               'start_line': 2, 'start_column': 3, 'end_line': 2,
               'end_column': 8, 'level': 'warning'}
        raw, triage, triage_input = self.packet(
            [result, result], [row], 'triage_required', 1)
        with self.assertRaises(proof.FinalProofError):
            proof._verify_consumer_results(
                raw, triage, triage_input, Counter({'usr/a.uc': 1}), '9-1')

    def test_clean_scan_cannot_hide_nonzero_sarif(self):
        result = {
            'ruleId': 'ucode/test-rule', 'level': 'warning',
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': 'usr/a.uc', 'uriBaseId': '%SRCROOT%'},
                'region': {'startLine': 2, 'startColumn': 3,
                           'endLine': 2, 'endColumn': 8},
            }}],
        }
        raw, triage, triage_input = self.packet([result], [], 'clean_scan', 0)
        with self.assertRaises(proof.FinalProofError):
            proof._verify_consumer_results(
                raw, triage, triage_input, Counter({'usr/a.uc': 1}), '9-1')


class SuppliedStartScopeTests(unittest.TestCase):
    def test_start_binding_does_not_claim_mac_verification(self):
        identity = {
            'repository': 'openwrt/openwrt', 'ref': 'main', 'ordinal': 1,
            'commit_sha': '1' * 40, 'tree_sha': '2' * 40,
            'first_parent_sha': '3' * 40, 'intake_id': 'intake', 'receipt_seq': 1,
        }
        policy = {'consumer_commit': '4' * 40, 'release_lock_sha256': '5' * 64}
        asserted = {'queue_id': '6' * 32, 'reservation_sequence': 1,
                    'reservation_sha256': '7' * 64}
        origin = {'gap_sha256': '8' * 64}
        early = b'early zip bytes'
        job = {'id': 33}
        run = {'id': 9, 'run_attempt': 1, 'head_sha': policy['consumer_commit']}
        artifact = {'id': 44}
        att = {
            'schema': issued.START_SCHEMA, 'kind': 'start', **asserted,
            'identity': identity, 'origin_receipt_sha256': 'a' * 64,
            'origin_gap_sha256': origin['gap_sha256'], 'policy_sha256': 'b' * 64,
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
            'run_id': 9, 'run_attempt': 1, 'job_id': 33,
            'workflow': '.github/workflows/default-branch-commit-scan.yml',
            'job': 'released-default-branch-scan',
            'early_artifact': {'id': artifact['id'],
                               'sha256': hashlib.sha256(early).hexdigest(),
                               'size': len(early)},
            'observation_sha256': 'c' * 64, 'run_api_sha256': 'd' * 64,
            'jobs_api_sha256': 'e' * 64, 'artifacts_api_sha256': 'f' * 64,
            'recheck_run_api_sha256': '0' * 64,
            'recheck_jobs_api_sha256': '1' * 64,
        }
        unsigned = {'schema': issued.ISSUED_SCHEMA, 'issued_seq': 1,
                    'previous_issued_sha256': issued.ZERO_HASH,
                    'observed_at': '2026-11-26T12:00:00Z', 'attestation': att}
        raw = issued.canonical_bytes({**unsigned, 'mac': '0' * 64})
        claim = {'asserted_reservation': asserted,
                 'linked_discovery_origin': origin}
        replay = {'reservation': {
            'identity': identity, 'policy_claim': policy,
            'origin_receipt_sha256': 'a' * 64,
            'policy_sha256': 'b' * 64,
        }}
        result = proof._verify_start_binding(raw, run, job, artifact, early,
                                             claim, replay)
        self.assertFalse(result['mac_verified'])
        self.assertEqual(result['verification_scope'], 'supplied_start_binding_only')
        att['job_id'] = 34
        raw_bad = issued.canonical_bytes({**unsigned, 'attestation': att, 'mac': '0' * 64})
        with self.assertRaises(proof.FinalProofError):
            proof._verify_start_binding(raw_bad, run, job, artifact, early,
                                        claim, replay)


class RetainedRunV3FullProofTests(unittest.TestCase):
    """Full public v3 replay over the retained 45875169837 ZIP/API bytes.

    The fixture is deliberately opt-in because its raw artifacts live under an
    ignored work directory. It copies the captured v2 queue and archives,
    migrates that disposable copy, and adds a synthetic start using a test-only
    key. No real key, live start, API fetch, source queue mutation, or hosted
    ZIP rewrite is involved; the disposable queue copy is intentionally changed.
    """

    RUN_ID = 45875169837
    ATTEMPT = 1
    EARLY_ARTIFACT_ID = 15144223386
    FINAL_ARTIFACT_ID = 15144917516
    JOB_ID = 140100374363
    EARLY_SIZE = 14_611_319
    EARLY_SHA256 = '179b74ab48757cc1c0966e3b5e313546f072085b3f52677046115007d08f5ea4'
    FINAL_SIZE = 14_906_724
    FINAL_SHA256 = '44ef942823a2a460c9b20dd57730965ca8ae124c5da8407ced4fdebfd195bc1e'
    SYNTHETIC_OBSERVED_AT = '2026-11-26T18:22:00Z'
    # This is a disposable fixture secret, unrelated to any operator key.
    TEST_KEY = b'fixture-v3-final-proof-key-not-secret-0001'

    @staticmethod
    def _json_bytes(value):
        return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')

    @staticmethod
    def _file_records(root, paths=None):
        root = Path(root)
        paths = (sorted(path for path in root.rglob('*') if path.is_file())
                 if paths is None else sorted(Path(path) for path in paths))
        records = []
        for path in paths:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise AssertionError('fixture input is not a regular non-link file: ' + str(path))
            raw = path.read_bytes()
            records.append({'path': path.relative_to(root).as_posix(),
                            'size': len(raw), 'sha256': proof.digest(raw)})
        return records

    def _expect_failure(self, exception_type, expected_reason, *args,
                        cause_reason=None, **kwargs):
        with self.assertRaises(exception_type) as caught:
            proof.verify_final_proof(*args, **kwargs)
        self.assertEqual(str(caught.exception), expected_reason)
        cause_messages = []
        cause = caught.exception.__cause__
        seen = set()
        while cause is not None and id(cause) not in seen:
            seen.add(id(cause))
            cause_messages.append(str(cause))
            cause = cause.__cause__
        if cause_reason is not None:
            self.assertIn(cause_reason, cause_messages)
        return {'reason': str(caught.exception), 'cause_chain': cause_messages}

    def test_full_public_v3_proof_and_discriminating_controls(self):
        retained = os.environ.get('CODEQL_OPENWRT_RETAINED_RUN_ROOT')
        oracle_configured = os.environ.get('CODEQL_OPENWRT_SOURCE_ORACLE')
        if not retained and not oracle_configured:
            self.skipTest('set CODEQL_OPENWRT_RETAINED_RUN_ROOT to the ignored retained-run directory')
        if not retained:
            self.fail('CODEQL_OPENWRT_SOURCE_ORACLE was set but retained-run root is missing')
        retained = Path(retained).resolve()
        live_dir = retained / 'live-observation'
        completed_capture = (retained / 'reconcile-work' /
                            'reservation-reconcile-45875169837-1-pnjqa4sb')
        required = (
            live_dir / 'early.zip', live_dir / 'final.zip',
            live_dir / 'run-api.json', live_dir / 'jobs-api.json',
            live_dir / 'artifacts-api.json',
            completed_capture / 'run-api.json', completed_capture / 'jobs-api.json',
            completed_capture / 'artifacts-api.json',
            retained / 'default-branch-backlog.sqlite3', retained / 'archives',
        )
        if any(not path.exists() for path in required):
            self.fail('configured retained run ZIP/API/queue inputs are incomplete')

        retained_paths = [
            live_dir / 'early.zip', live_dir / 'final.zip',
            live_dir / 'run-api.json', live_dir / 'jobs-api.json',
            live_dir / 'artifacts-api.json',
            completed_capture / 'run-api.json', completed_capture / 'jobs-api.json',
            completed_capture / 'artifacts-api.json',
            retained / 'default-branch-backlog.sqlite3',
        ] + [path for path in (retained / 'archives').rglob('*') if path.is_file()]
        retained_source_before = self._file_records(retained, retained_paths)
        archive_source_before = self._file_records(retained / 'archives')

        if oracle_configured:
            oracle_path = Path(oracle_configured).resolve()
        else:
            oracle_path = (retained.parent / 'source-truth-preflight-45875169837-pr254-20261126' /
                           'rederived-manifest-at-674.json')
        if not oracle_path.is_file():
            self.fail('configured pre-output source-rederived 128/13 oracle is unavailable')
        oracle_raw = oracle_path.read_bytes()
        self.assertEqual(proof.digest(oracle_raw),
                         'b920839d1bd1e19f14b99491fbdc22f0b240e3a4841b46a01edb22f2a6adf506')
        oracle = proof.parse_object(oracle_raw, 'pre-output source-rederived oracle')

        def selected_identity(row):
            route = row['expected_route']
            return (row['repo'], row['source_path'], row['source_commit'],
                    row['git_blob'], row['source_sha256'],
                    row['proposed_installed_path'], route['classification'],
                    route['reason'])

        oracle_selected = Counter(selected_identity(row) for row in oracle['selected'])
        oracle_paths = Counter(row['proposed_installed_path'] for row in oracle['selected'])
        oracle_routes = Counter(row['expected_route']['classification']
                                for row in oracle['selected'])
        oracle_excluded = Counter(tuple(sorted(row.items())) for row in oracle['excluded'])
        self.assertEqual((len(oracle_selected), len(oracle['excluded'])), (128, 13))
        self.assertEqual(oracle_routes, Counter({'plain': 93, 'markup': 35}))

        # Pin the source oracle before parsing archive output.
        early_zip = (live_dir / 'early.zip').read_bytes()
        final_zip = (live_dir / 'final.zip').read_bytes()
        self.assertEqual((len(early_zip), proof.digest(early_zip)),
                         (self.EARLY_SIZE, self.EARLY_SHA256))
        self.assertEqual((len(final_zip), proof.digest(final_zip)),
                         (self.FINAL_SIZE, self.FINAL_SHA256))
        early_run_raw = (live_dir / 'run-api.json').read_bytes()
        early_jobs_raw = (live_dir / 'jobs-api.json').read_bytes()
        early_artifacts_raw = (live_dir / 'artifacts-api.json').read_bytes()
        run_raw = (completed_capture / 'run-api.json').read_bytes()
        jobs_raw = (completed_capture / 'jobs-api.json').read_bytes()
        artifacts_raw = (completed_capture / 'artifacts-api.json').read_bytes()
        api_sha256 = [proof.digest(raw) for raw in (
                early_run_raw, early_jobs_raw, early_artifacts_raw,
                run_raw, jobs_raw, artifacts_raw)]
        self.assertEqual(api_sha256, [
                '761164ad24be6af463b63aada320d8c70435a1907d94983f7162621dd2349955',
                'b04a4b496e5db97ad9af365f1076119efe7b0e4497b922e2293eff555b0129a4',
                '0cbdb203ed6a62c5a0eecf0a6e772ebd288db14e544e8f0b9916f6f330f045d2',
                '17a8d996fc94d5a68251e1079ab1d50e0fd6cfae0348e7afb3c2fd605669d16d',
                '5d04f6628aa5e9d59a4cac26d3750a2d15b9b67d5a0ffef88c39ae303ba90810',
                'f6a503a36cdb127f20cc7c70e35b9c4b043bcc71ab84170cda516565ce20b803',
            ])
        run = proof.reconcile.parse_json(run_raw, 'completed fixture run')
        jobs = proof.reconcile.parse_json(jobs_raw, 'completed fixture jobs')
        artifacts = proof.reconcile.parse_json(artifacts_raw, 'completed fixture artifacts')
        early_run = proof.reconcile.parse_json(early_run_raw, 'in-progress fixture run')
        early_jobs = proof.reconcile.parse_json(early_jobs_raw, 'in-progress fixture jobs')
        early_artifacts = proof.reconcile.parse_json(early_artifacts_raw,
                                                     'in-progress fixture artifacts')
        self.assertEqual((run['id'], run['run_attempt']), (self.RUN_ID, self.ATTEMPT))
        self.assertEqual((early_run['id'], early_run['run_attempt']),
                         (self.RUN_ID, self.ATTEMPT))
        scan_job = next(row for row in jobs['jobs']
                        if row.get('name') == proof.reconcile.SCAN_JOB)
        early_job = next(row for row in early_jobs['jobs']
                         if row.get('name') == proof.reconcile.SCAN_JOB)
        early_artifact = next(row for row in early_artifacts['artifacts']
                              if row.get('id') == self.EARLY_ARTIFACT_ID)
        final_artifact = next(row for row in artifacts['artifacts']
                              if row.get('id') == self.FINAL_ARTIFACT_ID)
        self.assertEqual((scan_job['id'], early_job['id']), (self.JOB_ID, self.JOB_ID))
        self.assertEqual((early_artifact['size_in_bytes'],
                          early_artifact['digest'].removeprefix('sha256:')),
                         (self.EARLY_SIZE, self.EARLY_SHA256))
        self.assertEqual((final_artifact['size_in_bytes'],
                          final_artifact['digest'].removeprefix('sha256:')),
                         (self.FINAL_SIZE, self.FINAL_SHA256))
        completed_job = next(row for row in jobs['jobs']
                             if row.get('name') == proof.reconcile.SCAN_JOB)
        self.assertEqual((early_run['status'], early_job['status']),
                         ('in_progress', 'in_progress'))
        self.assertLess(early_run['run_started_at'], self.SYNTHETIC_OBSERVED_AT)
        self.assertLess(early_job['started_at'], self.SYNTHETIC_OBSERVED_AT)
        self.assertLess(early_artifact['created_at'], self.SYNTHETIC_OBSERVED_AT)
        self.assertLess(self.SYNTHETIC_OBSERVED_AT, completed_job['completed_at'])

        repo_root = Path(__file__).resolve().parents[1]
        work_root = repo_root / 'work'
        work_root.mkdir(mode=0o700, exist_ok=True)
        fixture_root = Path(tempfile.mkdtemp(prefix='default-branch-v3-final-proof-',
                                             dir=work_root))
        fixture_root.chmod(0o700)
        private_root = fixture_root / 'private'
        private_root.mkdir(mode=0o700)
        shutil.copy2(retained / 'default-branch-backlog.sqlite3',
                     private_root / proof.reconcile.reservation.DATABASE_NAME)
        (private_root / proof.reconcile.reservation.DATABASE_NAME).chmod(0o600)
        shutil.copytree(retained / 'archives', private_root / 'archives',
                        copy_function=shutil.copy2)
        for path in private_root.rglob('*'):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)
        database = private_root / proof.reconcile.reservation.DATABASE_NAME
        self.assertEqual(self._file_records(private_root / 'archives'), archive_source_before)
        source_database = retained / 'default-branch-backlog.sqlite3'
        self.assertEqual(proof.digest(database.read_bytes()),
                         proof.digest(source_database.read_bytes()))
        issued.migrate_v2_to_v3(private_root)
        with closing(sqlite3.connect(database)) as db, db:
            row = db.execute(
                'SELECT body_json,action_hash FROM reservation_actions WHERE action_seq=1'
            ).fetchone()
        self.assertIsNotNone(row)
        reservation_body = json.loads(row[0])
        reservation_hash = row[1]
        policy = reservation_body['policy']
        origin = reservation_body['origin']
        self.assertLess(reservation_body['created_at'], self.SYNTHETIC_OBSERVED_AT)
        self.assertLess(self.SYNTHETIC_OBSERVED_AT, reservation_body['expires_at'])
        observation = {
            'schema': 'synthetic-v3-final-proof-observation-v1',
            'run_api_sha256': proof.digest(early_run_raw),
            'jobs_api_sha256': proof.digest(early_jobs_raw),
            'artifacts_api_sha256': proof.digest(early_artifacts_raw),
            'early_artifact_id': self.EARLY_ARTIFACT_ID,
            'early_zip_sha256': self.EARLY_SHA256,
            'early_zip_size': self.EARLY_SIZE,
        }
        attestation = {
            'schema': issued.START_SCHEMA, 'kind': 'start',
            'queue_id': reservation_body['queue_id'],
            'reservation_sequence': 1, 'reservation_sha256': reservation_hash,
            'identity': reservation_body['identity'],
            'origin_receipt_sha256': origin['receipt_hash'],
            'origin_gap_sha256': origin['gap_sha256'],
            'policy_sha256': policy['policy_sha256'],
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
            'run_id': self.RUN_ID, 'run_attempt': self.ATTEMPT,
            'job_id': self.JOB_ID,
            'workflow': proof.reconcile.SCAN_WORKFLOW,
            'job': issued.START_JOB,
            'early_artifact': {
                'id': self.EARLY_ARTIFACT_ID,
                'sha256': self.EARLY_SHA256, 'size': self.EARLY_SIZE,
            },
            'observation_sha256': proof.digest(issued.canonical_bytes(observation)),
            'run_api_sha256': proof.digest(early_run_raw),
            'jobs_api_sha256': proof.digest(early_jobs_raw),
            'artifacts_api_sha256': proof.digest(early_artifacts_raw),
            'recheck_run_api_sha256': proof.digest(early_run_raw),
            'recheck_jobs_api_sha256': proof.digest(early_jobs_raw),
        }
        approved_policy = {
            'consumer_commit': policy['consumer_commit'],
            'release_lock_sha256': policy['release_lock_sha256'],
        }
        issued.issue_start(
            private_root, 0, issued.ZERO_HASH, self.TEST_KEY,
            approved_policy, attestation, self.SYNTHETIC_OBSERVED_AT)
        with closing(sqlite3.connect(database)) as db, db:
            start_json = db.execute(
                'SELECT document_json FROM issued_actions WHERE seq=1').fetchone()[0]
        start_raw = start_json.encode('utf-8')
        start_document = proof.parse_object(start_raw, 'synthetic issued-start document')
        self.assertEqual(start_document['attestation'], attestation)
        with closing(sqlite3.connect(database)) as db, db:
            synthetic_head = db.execute(
                'SELECT seq,hash FROM issued_head WHERE singleton=1').fetchone()
        self.assertEqual(synthetic_head, (1, proof.digest(start_raw)))
        database_sha_before = proof.digest(database.read_bytes())

        replay_work = fixture_root / 'replay-work'
        replay_work.mkdir(mode=0o700)
        positive_args = (
            private_root, replay_work, run_raw, jobs_raw, artifacts_raw,
            final_zip, early_zip, start_raw, self.RUN_ID, self.ATTEMPT,
        )
        result = proof.verify_final_proof(
            *positive_args, require_issued_start_head=True)
        public_proof_raw = self._json_bytes(result)
        public_proof_path = fixture_root / 'public-proof.json'
        public_proof_path.write_bytes(public_proof_raw)
        public_proof_path.chmod(0o600)
        self.assertEqual(result['status'], 'verified_against_supplied_start_only')
        self.assertEqual((result['run_id'], result['attempt'], result['job_id']),
                         (self.RUN_ID, self.ATTEMPT, self.JOB_ID))
        self.assertEqual((result['early_artifact_id'], result['early_artifact_size'],
                          result['early_artifact_sha256']),
                         (self.EARLY_ARTIFACT_ID, self.EARLY_SIZE, self.EARLY_SHA256))
        self.assertEqual((result['final_artifact_id'], result['final_artifact_size'],
                          result['final_artifact_sha256']),
                         (self.FINAL_ARTIFACT_ID, self.FINAL_SIZE, self.FINAL_SHA256))
        self.assertEqual(result['early_final_equal_frozen_inputs'], 9)
        self.assertEqual(result['start_binding'], {
            'document_sha256': proof.digest(start_raw), 'run_id': self.RUN_ID,
            'attempt': self.ATTEMPT, 'job_id': self.JOB_ID,
            'mac_present_and_well_formed': True, 'mac_verified': False,
            'verification_scope': 'supplied_start_binding_only',
        })
        replay = result['claim_origin_replay']
        self.assertEqual(replay['status'], 'claim_reconciled_read_only')
        self.assertEqual(replay['claim_status'], 'claimed_unverified')
        self.assertEqual(replay['database']['schema_version'], issued.intake.ISSUED_SCHEMA_VERSION)
        self.assertTrue(replay['database']['supplied_start_head_bound'])
        self.assertEqual(replay['database']['supplied_start_sha256'], proof.digest(start_raw))
        self.assertFalse(replay['database']['start_mac_verified'])
        self.assertEqual(replay['database']['head_scope'], 'read_only_snapshot_unkeyed')
        self.assertEqual(result['source_truth'],
                         'open_without_fresh_canonical_git_object_retrieval')
        self.assertFalse(result['actual_package_installed_bytes_verified'])
        self.assertEqual(result['alert_disposition'], 'not_evaluated')
        scan = result['scan']
        self.assertEqual((scan['successful_files'], scan['extraction_error_rows']), (128, 0))
        self.assertEqual((scan['consumer_status'], scan['sarif_result_count']),
                         ('clean_scan', 0))
        self.assertEqual(scan['alert_disposition'], 'not_evaluated')

        # Independently retain exact decoded extraction identities and empty
        # SARIF/consumer tuples alongside the public verifier's summary.
        inputs, r3 = proof._final_members(final_zip, self.RUN_ID, self.ATTEMPT)
        corpus_prefix = 'default-branch-corpus/'
        manifest = proof.parse_object(inputs['manifest.json'], 'fixture manifest')
        self.assertEqual(Counter(tuple(sorted(row.items())) for row in manifest['excluded']),
                         oracle_excluded)
        successful = proof.parse_object(
            r3[corpus_prefix + 'out/successful.json'], 'fixture successful rows')
        errors = proof.parse_object(
            r3[corpus_prefix + 'out/errors.json'], 'fixture extraction errors')
        sarif = proof.parse_object(
            r3[corpus_prefix + 'out/default-suite.sarif'], 'fixture SARIF')
        triage = proof.parse_object(
            r3[corpus_prefix + 'out/triage.json'], 'fixture consumer triage')
        routing = proof.parse_object(
            r3[corpus_prefix + 'out/routing.json'], 'fixture routing receipt')
        self.assertEqual(Counter(selected_identity(row) for row in manifest['selected']),
                         oracle_selected)
        expected_paths = oracle_paths
        stage_root = f'/home/runner/work/_temp/r3-ucode-{self.RUN_ID}-{self.ATTEMPT}/default-branch-corpus/stage'
        tuples = successful['#select']['tuples']
        actual_paths = Counter(
            row[0]['label'][len(stage_root) + 1:]
            for row in tuples
            if len(row) == 2 and row[0]['label'].startswith(stage_root + '/'))
        self.assertEqual(len(expected_paths), 128)
        self.assertEqual(actual_paths, expected_paths)
        expected_routes = Counter(
            (row['proposed_installed_path'], row['expected_route']['classification'],
             row['expected_route']['reason'],
             'plain_route_selected' if row['expected_route']['classification'] == 'plain'
             else 'inconclusive')
            for row in oracle['selected'])
        actual_routes = Counter(
            (row['installed_path'], row['classification'], row['reason'], row['status'])
            for row in routing['decisions'])
        self.assertEqual(actual_routes, expected_routes)
        self.assertEqual(errors['#select']['tuples'], [])
        self.assertEqual(sarif['runs'][0]['results'], [])
        self.assertEqual(triage['status'], 'clean_scan')
        self.assertEqual(triage['result_count'], 0)
        self.assertEqual(triage['results_for_triage'], [])
        self.assertEqual(proof._verify_r3_command_receipt(r3['commands.json']), 48)
        corpus_command_rows = proof._verify_final_inventory(r3, manifest)
        self.assertEqual(len(corpus_command_rows), 165)
        self.assertEqual(proof.digest(database.read_bytes()), database_sha_before)

        control_results = {}

        changed_start = json.loads(start_raw)
        mac = changed_start['mac']
        changed_start['mac'] = ('0' if mac[0] != '0' else '1') + mac[1:]
        wrong_start_raw = issued.canonical_bytes(changed_start)
        control_results['wrong_start'] = self._expect_failure(
            proof.FinalProofError, 'archived claim/origin replay failed',
            private_root, replay_work, run_raw, jobs_raw, artifacts_raw,
            final_zip, early_zip, wrong_start_raw, self.RUN_ID, self.ATTEMPT,
            cause_reason='supplied start differs from exact v3 issued head',
            require_issued_start_head=True)

        pristine_database = database.read_bytes()
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('UPDATE issued_head SET hash=? WHERE singleton=1', ('0' * 64,))
        control_results['stale_head'] = self._expect_failure(
            proof.FinalProofError, 'archived claim/origin replay failed',
            *positive_args, cause_reason='issued action head differs from append-only history',
            require_issued_start_head=True)
        database.write_bytes(pristine_database)
        database.chmod(0o600)

        altered_members = proof._read_zip(final_zip, 'retained final fixture')
        frozen_member = f'default-branch-inputs-{self.RUN_ID}-{self.ATTEMPT}/identity.json'
        altered_members[frozen_member] += b' '
        altered_zip_stream = BytesIO()
        with ZipFile(altered_zip_stream, 'w', compression=ZIP_DEFLATED) as archive:
            for name in sorted(altered_members):
                archive.writestr(name, altered_members[name])
        altered_zip = altered_zip_stream.getvalue()
        altered_artifacts = json.loads(artifacts_raw)
        altered_final = next(row for row in altered_artifacts['artifacts']
                             if row.get('id') == self.FINAL_ARTIFACT_ID)
        altered_final['size_in_bytes'] = len(altered_zip)
        altered_final['digest'] = 'sha256:' + proof.digest(altered_zip)
        control_results['altered_frozen_member'] = self._expect_failure(
            proof.FinalProofError, 'early/final frozen input bytes differ: identity.json',
            private_root, replay_work, run_raw, jobs_raw,
            self._json_bytes(altered_artifacts), altered_zip, early_zip,
            start_raw, self.RUN_ID, self.ATTEMPT,
            require_issued_start_head=True)

        wrong_jobs = json.loads(jobs_raw)
        wrong_job = next(row for row in wrong_jobs['jobs']
                         if row.get('name') == proof.reconcile.SCAN_JOB)
        wrong_job['id'] += 1
        control_results['wrong_job'] = self._expect_failure(
            proof.FinalProofError, 'archived claim/origin replay failed',
            private_root, replay_work, run_raw, self._json_bytes(wrong_jobs),
            artifacts_raw, final_zip, early_zip, start_raw,
            self.RUN_ID, self.ATTEMPT,
            cause_reason='supplied start differs from claimed run/job/reservation',
            require_issued_start_head=True)

        control_results['wrong_attempt'] = self._expect_failure(
            proof.reconcile.ReconcileError,
            'canonical scan run identity is incomplete or mismatched',
            private_root, replay_work, run_raw, jobs_raw, artifacts_raw,
            final_zip, early_zip, start_raw, self.RUN_ID, self.ATTEMPT + 1,
            require_issued_start_head=True)
        self.assertEqual(proof.digest(database.read_bytes()), database_sha_before)
        retained_source_after = self._file_records(retained, retained_paths)
        self.assertEqual(retained_source_after, retained_source_before)
        self.assertEqual(self._file_records(retained / 'archives'), archive_source_before)
        self.assertEqual(proof.digest(oracle_path.read_bytes()), proof.digest(oracle_raw))
        source_database_record = next(
            row for row in retained_source_before
            if row['path'] == 'default-branch-backlog.sqlite3')
        self.assertEqual(proof.digest(source_database.read_bytes()),
                         source_database_record['sha256'])

        self.assertEqual(control_results.keys(), {
            'wrong_start', 'stale_head', 'altered_frozen_member', 'wrong_job', 'wrong_attempt'})
        controls_path = fixture_root / 'controls.json'
        controls_path.write_bytes(self._json_bytes(control_results))
        controls_path.chmod(0o600)


class R3ReceiptTests(unittest.TestCase):
    def test_released_immutable_receipt_and_failed_status_rejection(self):
        expected_labels = set(proof.R3_SETUP_LABELS)
        expected_labels.update(
            f'{case}-{step}'
            for case in ('openvpn-parent', 'openvpn-fixed')
            for step in proof.R3_CASE_STEPS)
        command_rows = [{
            'argv': ['true'], 'cwd': '/run', 'exit': 0, 'label': label,
            'peak_rss_bytes': 1,
            'stderr': f'commands/{label}.stderr',
            'stdout': f'commands/{label}.stdout',
            'time': f'commands/{label}.time', 'wall_seconds': 0.1,
        } for label in sorted(expected_labels)]
        raw_commands = (json.dumps(command_rows, sort_keys=True) + '\n').encode()
        producer_identity = {'sha': '1' * 40, 'pack_sha256': '2' * 64,
                             'codeql_version': '2.27.4', 'suite_sha256': '3' * 64}
        producer = {'producer': producer_identity,
                    'codeql_binary_sha256': '4' * 64,
                    'resolved_rules': ['r1']}
        consumer_receipt = {'release_tag': 'v0.1.0-rc.1',
                            'producer_commit': '1' * 40,
                            'resolved_rules': ['r1']}
        triage_input = {'producer': producer_identity}
        approved = {'release_lock_sha256': '5' * 64, 'release_tag': 'v0.1.0-rc.1',
                    'release_commit': '1' * 40, 'release_asset_sha256': '2' * 64,
                    'release_manifest_sha256': '6' * 64}
        preflight = {'actual_package_installed_bytes_verified': False,
                     'consumer_dirty': False, 'consumer_sha': '7' * 40,
                     'free_bytes': 1000, 'lock_sha256': '5' * 64,
                     'oracle_sha256': '8' * 64, 'run_id': '9-1', 'run_root': '/run'}
        release = {'tag': 'v0.1.0-rc.1', 'asset_sha256': '2' * 64,
                   'manifest_sha256': '6' * 64, 'producer_commit': '1' * 40,
                   'isImmutable': True}
        root = {
            'cases': {}, 'codeql': {'version': 'CodeQL command-line toolchain release 2.27.4.\n',
                                    'binary_sha256': '4' * 64},
            'commands_sha256': hashlib.sha256(raw_commands).hexdigest(),
            'network_dependency_bootstrap': True,
            'packs': {'queries': {'default_suite': 'codeql-suites/code-scanning.qls',
                                  'default_suite_sha256': '3' * 64}},
            'preflight': preflight, 'release': release,
            'resolved_rules': ['r1'], 'schema': 'ucode-r3-linux-handoff-v1',
            'status': 'accepted',
        }
        result = proof._verify_r3_release(root, consumer_receipt, producer,
                                          triage_input, '9-1',
                                          {'consumer_commit': '7' * 40},
                                          approved, raw_commands)
        self.assertTrue(result['immutable'])
        self.assertEqual(result['command_count'], 48)
        command_rows[0]['exit'] = 7
        bad_commands = (json.dumps(command_rows, sort_keys=True) + '\n').encode()
        root['commands_sha256'] = hashlib.sha256(bad_commands).hexdigest()
        with self.assertRaisesRegex(proof.FinalProofError, 'failed command'):
            proof._verify_r3_release(root, consumer_receipt, producer,
                                     triage_input, '9-1',
                                     {'consumer_commit': '7' * 40},
                                     approved, bad_commands)
        root['status'] = 'failed'
        root['commands_sha256'] = hashlib.sha256(raw_commands).hexdigest()
        with self.assertRaisesRegex(proof.FinalProofError, 'accepted schema'):
            proof._verify_r3_release(root, consumer_receipt, producer,
                                     triage_input, '9-1',
                                     {'consumer_commit': '7' * 40},
                                     approved, raw_commands)


if __name__ == '__main__':
    unittest.main()
