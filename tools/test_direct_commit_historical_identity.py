import unittest
from pathlib import Path
from unittest.mock import patch

from tools import direct_commit_historical_identity as historical
from tools import incoming_poll as poll


class HistoricalIdentityTests(unittest.TestCase):
    def test_resolves_pinned_objects_without_event_custody_fields(self):
        commits = {'introduced': 'a' * 40, 'absent_parent': 'b' * 40,
                   'fixed': 'c' * 40}
        trees = {'a' * 40: '1' * 40, 'b' * 40: '2' * 40,
                 'c' * 40: '3' * 40}
        identities = {commit: {'commit': commit, 'tree': tree}
                      for commit, tree in trees.items()}
        source, control = Path('/source'), Path('/control')
        with patch.object(historical.admission, 'frozen_oracle',
                          return_value={'commits': commits}), \
             patch.object(historical.event, 'checkout_identity',
                          side_effect=lambda checkout, url, commit: identities[commit]), \
             patch.object(historical.event, 'first_parent_from_object',
                          return_value=commits['absent_parent']), \
             patch.object(historical.event, 'safe_git',
                          return_value=trees[commits['absent_parent']]), \
             patch.object(historical.event, 'canonical_fetch',
                          side_effect=lambda repo, commit: identities[commit]):
            got = historical.resolve(source, control)
        self.assertEqual(got['schema'], 'historical-direct-commit-source-identity-v1')
        self.assertEqual(got['base'], identities[commits['absent_parent']])
        self.assertEqual(got['policy_ref_context'], 'master')
        self.assertNotIn('ref', got)
        self.assertNotIn('gap_sha256', got)
        self.assertNotIn('current_checkpoint_sha256', got)

    def test_rejects_non_parent_source(self):
        commits = {'introduced': 'a' * 40, 'absent_parent': 'b' * 40,
                   'fixed': 'c' * 40}
        with patch.object(historical.admission, 'frozen_oracle',
                          return_value={'commits': commits}), \
             patch.object(historical.event, 'checkout_identity',
                          side_effect=lambda checkout, url, commit:
                          {'commit': commit, 'tree': '1' * 40}), \
             patch.object(historical.event, 'first_parent_from_object',
                          return_value='d' * 40):
            with self.assertRaisesRegex(poll.PollError, 'first parent differs'):
                historical.resolve(Path('/source'), Path('/control'))


if __name__ == '__main__':
    unittest.main()
