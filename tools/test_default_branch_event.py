from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import default_branch_event as event
from tools import incoming_event
from tools import incoming_poll as poll


H = 'a' * 64


class DirectCommitIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.origin = self.root / 'origin'
        self.origin.mkdir()
        self.git('init', '-q', str(self.origin))
        self.git('-C', str(self.origin), 'config', 'user.email', 'test@example.invalid')
        self.git('-C', str(self.origin), 'config', 'user.name', 'Test')
        self.git('-C', str(self.origin), 'remote', 'add', 'origin',
                 incoming_event.REPOSITORIES['luci'])
        (self.origin / 'source.uc').write_text('let value = 0;\n')
        self.git('-C', str(self.origin), 'add', 'source.uc')
        self.git('-C', str(self.origin), 'commit', '-qm', 'base')
        self.base = self.git('-C', str(self.origin), 'rev-parse', 'HEAD')
        self.base_tree = self.tree(self.base)
        (self.origin / 'source.uc').write_text('let value = 1;\n')
        self.git('-C', str(self.origin), 'commit', '-qam', 'introduce')
        self.source = self.git('-C', str(self.origin), 'rev-parse', 'HEAD')
        self.source_tree = self.tree(self.source)
        (self.origin / 'source.uc').write_text('let value = 2;\n')
        self.git('-C', str(self.origin), 'commit', '-qam', 'control')
        self.control = self.git('-C', str(self.origin), 'rev-parse', 'HEAD')
        self.control_tree = self.tree(self.control)
        self.source_checkout = self.root / 'source'
        self.control_checkout = self.root / 'control'
        for checkout, sha in ((self.source_checkout, self.source),
                              (self.control_checkout, self.control)):
            self.git('clone', '-q', str(self.origin), str(checkout))
            self.git('-C', str(checkout), 'remote', 'set-url', 'origin',
                     incoming_event.REPOSITORIES['luci'])
            self.git('-C', str(checkout), 'checkout', '-q', sha)
        self.interval = {'repository': 'openwrt/luci', 'ref': 'master',
                         'prior': {'commit': self.base, 'tree': self.base_tree},
                         'observed': {'commit': self.source, 'tree': self.source_tree},
                         'state': 'bounded_fast_forward',
                         'first_parent_commits': [{'commit': self.source,
                                                   'tree': self.source_tree,
                                                   'first_parent': self.base}]}
        identities = {self.base: self.base_tree, self.source: self.source_tree,
                      self.control: self.control_tree}
        self.fetch = patch.object(event, 'canonical_fetch',
                                  side_effect=lambda _, sha: {'commit': sha,
                                                                'tree': identities[sha]})
        self.fetch.start()
        self.addCleanup(self.fetch.stop)

    @staticmethod
    def git(*args):
        return subprocess.check_output(['git', *args], text=True).strip()

    def tree(self, sha):
        return self.git('-C', str(self.origin), 'rev-parse', sha + '^{tree}')

    def resolve(self, intervals=None, source=None, control=None):
        return event.resolve([self.interval] if intervals is None else intervals,
                             'openwrt/luci', self.source if source is None else source,
                             self.source_checkout, self.control if control is None else control,
                             self.control_checkout, H, H, H)

    def test_resolves_distinct_direct_commit_receipt(self):
        result = self.resolve()
        self.assertEqual(result['status'], 'identities_resolved_only')
        self.assertEqual(result['source'], {'commit': self.source, 'tree': self.source_tree})
        self.assertEqual(result['base'], {'commit': self.base, 'tree': self.base_tree})
        self.assertEqual(result['control'], {'commit': self.control,
                                             'tree': self.control_tree})
        self.assertNotIn('pr_number', result)

    def test_absent_or_unchanged_gap_does_not_authorize_commit(self):
        with self.assertRaisesRegex(poll.PollError, 'uniquely enumerated'):
            event.selected_commit([self.interval], 'openwrt/luci', self.control)
        interval = {**self.interval, 'state': 'unchanged'}
        with self.assertRaisesRegex(poll.PollError, 'fast-forward'):
            self.resolve(intervals=[interval])

    def test_tree_parent_and_checkout_controls(self):
        interval = {**self.interval, 'first_parent_commits': [
            {**self.interval['first_parent_commits'][0], 'tree': self.control_tree}]}
        with self.assertRaisesRegex(poll.PollError, 'source tree'):
            self.resolve(intervals=[interval])
        interval = {**self.interval, 'first_parent_commits': [
            {**self.interval['first_parent_commits'][0], 'first_parent': self.control}]}
        with self.assertRaisesRegex(poll.PollError, 'first-parent'):
            self.resolve(intervals=[interval])
        (self.source_checkout / 'source.uc').write_text('dirty\n')
        with self.assertRaisesRegex(poll.PollError, 'dirty'):
            self.resolve()

    def test_git_environment_cannot_redirect_named_checkout(self):
        (self.source_checkout / 'source.uc').write_text('dirty\n')
        with patch.dict(os.environ, GIT_DIR=str(self.origin / '.git'),
                        GIT_WORK_TREE=str(self.origin)):
            with self.assertRaisesRegex(poll.PollError, 'dirty'):
                self.resolve()

    def test_commit_object_bounds_and_parent_order(self):
        with patch.object(event, 'safe_git', side_effect=['1048577']):
            with self.assertRaisesRegex(poll.PollError, 'byte limit'):
                event.first_parent_from_object(self.source_checkout, self.source)
        with patch.object(event, 'safe_git', side_effect=['100', 'tree ' + self.source_tree]):
            with self.assertRaisesRegex(poll.PollError, 'header separator'):
                event.first_parent_from_object(self.source_checkout, self.source)
        merge = 'tree ' + self.source_tree + '\nparent ' + self.base + '\nparent ' + self.control + '\n\nmsg'
        with patch.object(event, 'safe_git', side_effect=['200', merge]):
            self.assertEqual(event.first_parent_from_object(self.source_checkout, self.source),
                             self.base)

    def test_receipt_cannot_be_written_inside_checkout(self):
        args = ['--previous', str(self.root / 'missing'), '--current', str(self.root / 'missing'),
                '--gap', str(self.root / 'missing'), '--repository', 'openwrt/luci',
                '--source-sha', self.source, '--source-checkout', str(self.source_checkout),
                '--control-sha', self.control, '--control-checkout', str(self.control_checkout),
                '--receipt', str(self.source_checkout / 'receipt.json')]
        self.assertEqual(event.main(args), 2)
        self.assertFalse((self.source_checkout / 'receipt.json').exists())

    def test_receipt_write_is_exclusive(self):
        path = self.root / 'receipt.json'
        path.write_text('keep me\n')
        with self.assertRaises(FileExistsError):
            event.write_receipt_exclusive(path, {'status': 'identities_resolved_only'})
        self.assertEqual(path.read_text(), 'keep me\n')

    def test_checkout_mutation_during_canonical_lookup_rejected(self):
        identities = {self.base: self.base_tree, self.source: self.source_tree,
                      self.control: self.control_tree}
        def mutate_on_control(_, sha):
            if sha == self.control:
                (self.source_checkout / 'source.uc').write_text('changed during fetch\n')
            return {'commit': sha, 'tree': identities[sha]}
        with patch.object(event, 'canonical_fetch', side_effect=mutate_on_control):
            with self.assertRaisesRegex(poll.PollError, 'dirty'):
                self.resolve()

    def test_canonical_object_mismatch_and_digest_fail(self):
        with patch.object(event, 'canonical_fetch',
                          return_value={'commit': self.base, 'tree': self.control_tree}):
            with self.assertRaisesRegex(poll.PollError, 'canonical base'):
                self.resolve()
        with self.assertRaisesRegex(poll.PollError, 'evidence digest'):
            event.resolve([self.interval], 'openwrt/luci', self.source,
                          self.source_checkout, self.control, self.control_checkout,
                          'bad', H, H)


if __name__ == '__main__':
    unittest.main()
