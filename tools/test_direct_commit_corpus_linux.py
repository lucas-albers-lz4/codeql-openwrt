import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import current_corpus_linux as runner


class DirectCommitRunnerContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = [self.root / name for name in
                      ('manifest.json', 'identity.json', 'admission.json', 'inventory.json')]
        self.source = self.root / 'source'
        self.control = self.root / 'control'
        self.source.mkdir()
        self.control.mkdir()
        self.expected = {'schema': 'mvp-direct-commit-corpus-v1',
                         'status': 'historical_direct_commit_source_first_oracle_only',
                         'selected': [{} for _ in range(112)],
                         'excluded': [{} for _ in range(11)],
                         'event': {'kind': 'direct_commit',
                                   'source_role': 'historical_direct_commit',
                                   'historical_policy_sha256': runner.direct_manifest.POLICY_SHA256}}
        self.files[0].write_text(json.dumps(self.expected))
        for path in self.files[1:]:
            path.write_text('{}')

    def validate(self):
        with patch.object(runner.direct_manifest, 'build_manifest',
                          return_value=copy.deepcopy(self.expected)):
            return runner.validate_direct_commit_manifest(
                *self.files, self.source, self.control)

    def test_exact_manifest_replay_accepted(self):
        actual, raw = self.validate()
        self.assertEqual(actual, self.expected)
        self.assertEqual(raw, self.files[0].read_bytes())

    def test_tampered_manifest_and_duplicate_keys_rejected(self):
        changed = copy.deepcopy(self.expected)
        changed['event']['pr_number'] = 17
        self.files[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(RuntimeError, 'differs from fresh'):
            self.validate()
        self.files[0].write_text('{"schema":"one","schema":"two"}')
        with self.assertRaises(ValueError):
            self.validate()

    def test_dispatches_five_inputs_only_to_direct_validator(self):
        lock = self.root / 'lock.json'
        lock.write_text('{}')
        sentinel = RuntimeError('direct validator reached')
        with patch.object(runner, 'pinned'), \
             patch.object(runner, 'validate_direct_commit_manifest', side_effect=sentinel) as direct, \
             patch.object(runner, 'validate_event_manifest') as old:
            with self.assertRaisesRegex(RuntimeError, 'direct validator reached'):
                runner.run_current(lock, self.files[0], self.root, 'test-run',
                                   event_context=(*self.files[1:], self.source, self.control))
            direct.assert_called_once()
            old.assert_not_called()
        with patch.object(runner, 'pinned'):
            with self.assertRaisesRegex(RuntimeError, 'separate contract'):
                runner.run_current(lock, self.files[0], self.root, 'test-run',
                                   event_context=(*self.files[1:], self.source, self.control),
                                   run_label='control-corpus')
        with patch.object(runner, 'pinned'), \
             patch.object(runner, 'validate_event_manifest',
                          side_effect=RuntimeError('PR validator reached')) as old, \
             patch.object(runner, 'validate_direct_commit_manifest') as direct:
            with self.assertRaisesRegex(RuntimeError, 'PR validator reached'):
                runner.run_current(lock, self.files[0], self.root, 'test-run',
                                   event_context=(self.files[1], self.files[3], self.source))
            old.assert_called_once()
            direct.assert_not_called()

    def test_source_first_known_alert_tuple_is_required(self):
        source = {'proposed_installed_path': 'usr/share/rpcd/ucode/luci.openvpn.uc',
                  'source_sha256': '051c8162f826683333e11264615806df5ab08415676c0bd098921cb1b05af991',
                  'source_commit': '5306e007656fe9a77aee2d2a94072d003b0b5a7d'}
        manifest = {'event': {'head_commit': source['source_commit'],
                              'historical_policy_sha256': '16d372ac21d87576c3ed3cd90036059e54f3cb0d8082f3094a032bd33190403a'},
                    'selected': [source]}
        oracle = json.loads(runner.DIRECT_ALERT_ORACLE.read_text())
        expected = oracle['expected_result']
        release = {'tag': 'v0.1.0-rc.1'}
        got = runner.assert_direct_known_alert(
            {'status': 'triage_required', 'result_count': 1,
             'results_for_triage': [expected]}, manifest, release)
        self.assertEqual(got['status'], 'known_alert_observed')
        other = {**expected, 'uri': 'usr/share/rpcd/ucode/other.uc'}
        self.assertEqual(runner.assert_direct_known_alert(
            {'status': 'triage_required', 'result_count': 2,
             'results_for_triage': [expected, other]}, manifest, release)['total_triage_results'], 2)
        for rows in ([], [expected, expected], [{**expected, 'start_line': 72}]):
            with self.subTest(rows=rows), self.assertRaisesRegex(RuntimeError, 'tuple/multiplicity'):
                runner.assert_direct_known_alert(
                    {'status': 'triage_required' if rows else 'clean_scan',
                     'result_count': len(rows), 'results_for_triage': rows}, manifest, release)
        with self.assertRaisesRegex(RuntimeError, 'source differs'):
            runner.assert_direct_known_alert(
                {'status': 'triage_required', 'result_count': 1,
                 'results_for_triage': [expected]},
                {**manifest, 'selected': [{**source, 'source_sha256': '0'*64}]}, release)


if __name__ == '__main__':
    unittest.main()
