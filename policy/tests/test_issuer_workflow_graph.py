import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import issuer_workflow_graph as graph


class WorkflowGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.temp = Path(self.tmp.name)
        self.inputs = self.temp / 'event-input-123-1'
        self.inputs.mkdir()
        self.lock = self.temp / 'docs/r3-release-lock.json'
        self.lock.parent.mkdir()
        self.lock.write_text('{}')
        self.patches = [patch.object(graph, 'ROOT', self.temp),
                        patch.object(graph, 'pinned'),
                        patch.object(graph.subprocess, 'check_output', return_value='a' * 40),
                        patch.object(graph, 'validate_event_manifest', side_effect=[{'event': True}, {'control': True}]),
                        patch.object(graph, 'check_event_and_control', return_value=({'status': 'triage_required'}, {'status': 'clean_scan'}))]
        self.mocks = [p.start() for p in self.patches]
        self.addCleanup(self.stop_patches)

    def stop_patches(self):
        for p in reversed(self.patches):
            p.stop()

    def result(self):
        return json.loads((self.inputs / 'consumer-graph.json').read_text())

    def test_success_uses_replayed_paths_and_records_non_issuing_result(self):
        graph.run(self.temp, '123-1', 'success', 'success')
        self.assertEqual(self.result()['status'], 'checked')
        validation = self.mocks[3]
        self.assertEqual(validation.call_args_list[0].args[0], self.inputs / 'replayed-manifest.json')
        self.assertEqual(validation.call_args_list[1].kwargs['source_role'], 'clean_control')
        self.assertEqual(self.mocks[4].call_args.args[5], self.inputs / 'replayed-receipt.json')

    def test_missing_or_failed_scan_fails_before_check(self):
        for event, control in [('failure', 'success'), ('success', 'skipped'), ('', 'success')]:
            with self.subTest(event=event, control=control), self.assertRaises(Exception):
                (self.inputs / 'consumer-graph.json').unlink(missing_ok=True)
                graph.run(self.temp, '123-1', event, control)
            self.assertEqual(self.result()['status'], 'failed')
        self.mocks[4].assert_not_called()

    def test_graph_rejection_is_retained_and_propagated(self):
        self.mocks[4].side_effect = ValueError('missing assertion')
        with self.assertRaisesRegex(ValueError, 'missing assertion'):
            graph.run(self.temp, '123-1', 'success', 'success')
        self.assertIn('missing assertion', self.result()['error'])

    def test_unpinned_lock_fails(self):
        self.mocks[1].side_effect = ValueError('unpinned')
        with self.assertRaisesRegex(ValueError, 'unpinned'):
            graph.run(self.temp, '123-1', 'success', 'success')
        self.mocks[4].assert_not_called()

    def test_preexisting_output_symlink_rejected_before_write(self):
        target = self.temp / 'target.json'
        target.write_text('untouched')
        (self.inputs / 'consumer-graph.json').symlink_to(target)
        with self.assertRaisesRegex(Exception, 'already exists'):
            graph.run(self.temp, '123-1', 'success', 'success')
        self.assertEqual(target.read_text(), 'untouched')
