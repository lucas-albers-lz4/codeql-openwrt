"""Focused byte-contract controls for the read-only final proof verifier."""
from collections import Counter
from io import BytesIO
import hashlib
import json
import unittest
import warnings
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo
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
