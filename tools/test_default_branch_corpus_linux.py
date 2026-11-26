import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import current_corpus_linux as runner
from tools import default_branch_corpus_linux as wrapper


class DefaultBranchRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = [self.root / name for name in
                      ('manifest.json', 'previous.json', 'current.json', 'gap.json',
                       'identity.json', 'inventory.json')]
        for path in self.files[1:]:
            path.write_text('{}')
        self.source, self.control = self.root / 'source', self.root / 'control'
        self.source.mkdir()
        self.control.mkdir()
        self.expected = {
            'schema': 'mvp-default-branch-commit-corpus-v1',
            'status': 'source_first_default_branch_oracle_only',
            'selected': [{} for _ in range(128)],
            'excluded': [{} for _ in range(13)],
            'event': {'kind': 'default_branch_commit',
                      'source_role': 'incoming_default_branch_first_parent',
                      'base_commit': 'a' * 40, 'first_parent_commit': 'a' * 40,
                      'policy_sha256': runner.branch_manifest.POLICY_SHA256}}
        self.files[0].write_text(json.dumps(self.expected))

    def validate(self):
        with patch.object(runner.branch_manifest, 'build',
                          return_value=copy.deepcopy(self.expected)):
            return runner.validate_default_branch_manifest(
                *self.files, self.source, self.control)

    def test_exact_contract_and_tamper(self):
        actual, raw = self.validate()
        self.assertEqual(actual, self.expected)
        self.assertEqual(raw, self.files[0].read_bytes())
        changed = copy.deepcopy(self.expected)
        changed['event']['pr_number'] = 1
        self.files[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(RuntimeError, 'differs from fresh'):
            self.validate()

    def test_named_context_cannot_be_routed_as_pr_or_control(self):
        lock = self.root / 'lock.json'
        lock.write_text('{}')
        context = (*self.files[1:], self.source, self.control)
        with patch.object(runner, 'pinned'), \
             patch.object(runner, 'validate_default_branch_manifest',
                          side_effect=RuntimeError('branch validator reached')) as branch, \
             patch.object(runner, 'validate_event_manifest') as pr:
            with self.assertRaisesRegex(RuntimeError, 'branch validator reached'):
                runner.run_current(lock, self.files[0], self.root, 'test-run',
                                   default_branch_context=context)
            branch.assert_called_once()
            pr.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'conflicting corpus contexts'):
                runner.run_current(lock, self.files[0], self.root, 'test-run',
                                   event_context=(self.files[4], self.files[5], self.source),
                                   default_branch_context=context)
            with self.assertRaisesRegex(RuntimeError, 'separate contract'):
                runner.run_current(lock, self.files[0], self.root, 'test-run',
                                   default_branch_context=context,
                                   run_label='control-corpus')

    def test_wrapper_passes_seven_input_context(self):
        lock = self.root / 'lock.json'
        root = self.root / 'run'
        args = [str(lock), str(self.files[0]),
                *(str(path) for path in self.files[1:]),
                str(self.source), str(self.control), str(root), 'id-1']
        with patch.object(wrapper, 'run_current') as run:
            wrapper.main(args)
        run.assert_called_once_with(lock, self.files[0], root, 'id-1',
                                    default_branch_context=(*self.files[1:],
                                                            self.source, self.control))


if __name__ == '__main__':
    unittest.main()
