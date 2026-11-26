"""Fail-closed controls for the control scan contract."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.event_control_scan import assert_clean, prepare, prepare_with_report, verify_and_remove_replay


class ControlContract(unittest.TestCase):
    def test_clean_requires_exact_empty_results(self):
        assert_clean({'status': 'clean_scan', 'result_count': 0, 'results_for_triage': []})
        for value in ({'status': 'triage_required', 'result_count': 1, 'results_for_triage': [{}]},
                      {'status': 'clean_scan', 'result_count': 0, 'results_for_triage': [{}]},
                      {'status': 'clean_scan', 'result_count': 0}):
            with self.assertRaises(Exception):
                assert_clean(value)

    def test_replay_equal_bytes_are_removed_before_artifact_freeze(self):
        names = ('control-derived-receipt.json', 'control-inventory.json',
                 'control-manifest.json', 'control-binding.json')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, replay = root / 'control-oracle', root / 'control-oracle-replay'
            inputs.mkdir()
            replay.mkdir()
            for name in names:
                (inputs / name).write_text(name)
                (replay / name).write_text(name)
            verify_and_remove_replay(inputs, replay)
            self.assertFalse(replay.exists())
            replay.mkdir()
            for name in names:
                (replay / name).write_text(name)
            (replay / 'extra.json').write_text('{}')
            with self.assertRaisesRegex(Exception, 'unexpected entries'):
                verify_and_remove_replay(inputs, replay)
            self.assertTrue(replay.exists())
            (replay / 'extra.json').unlink()
            (replay / names[0]).write_text('mismatch')
            with self.assertRaisesRegex(Exception, 'replay mismatch'):
                verify_and_remove_replay(inputs, replay)
            self.assertTrue(replay.exists())

    def test_mismatched_control_tree_rejected_before_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'schema': 'incoming-event-receipt-v1',
                'status': 'identities_resolved_only', 'repository': 'luci',
                'control': {'commit': 'a' * 40, 'tree': 'b' * 40}}))
            with patch('tools.event_control_scan.git', side_effect=['a' * 40, 'c' * 40]):
                with self.assertRaises(Exception):
                    prepare(receipt, root, root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_oracle_failure_retains_stage_and_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'schema': 'incoming-event-receipt-v1',
                'status': 'identities_resolved_only', 'repository': 'luci',
                'control': {'commit': 'a' * 40, 'tree': 'b' * 40}}))
            output = root / 'output'
            with patch('tools.event_control_scan.git', side_effect=['a' * 40, 'c' * 40]):
                with self.assertRaises(Exception):
                    prepare_with_report(receipt, root, output)
            failure = json.loads((output / 'failure.json').read_text())
            self.assertEqual(failure['stage'], 'control_oracle')
            self.assertIn('control checkout identity mismatch', failure['error'])


if __name__ == '__main__':
    unittest.main()
