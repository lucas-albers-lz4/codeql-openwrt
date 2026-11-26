import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import discovery_latest_predecessor as latest
from tools import incoming_poll as poll


class LatestPredecessorTests(unittest.TestCase):
    REPO = 'lucas-albers-lz4/codeql-openwrt'

    def setUp(self):
        self.run = {'id': 45790907027, 'run_attempt': 1,
                    'repository': {'full_name': self.REPO},
                    'path': latest.WORKFLOW, 'event': 'workflow_dispatch',
                    'head_branch': 'main', 'status': 'completed',
                    'conclusion': 'success', 'created_at': '2026-11-26T09:19:31Z'}
        self.response = {'total_count': 1, 'workflow_runs': [self.run]}

    def verify(self, response=None, genesis=False, prior='45790907027', attempt='1'):
        return latest.verify(self.response if response is None else response,
                             self.REPO, genesis, prior, attempt)

    def test_latest_successful_predecessor_and_first_genesis(self):
        self.assertEqual(self.verify()['status'], 'latest_predecessor_verified')
        self.assertEqual(self.verify({'total_count': 0, 'workflow_runs': []},
                                     genesis=True, prior='')['status'],
                         'genesis_allowed')

    def test_rejects_restart_or_stale_successor(self):
        with self.assertRaisesRegex(poll.PollError, 'genesis requires'):
            self.verify(genesis=True, prior='')
        with self.assertRaisesRegex(poll.PollError, 'latest successful'):
            self.verify(prior='45776032548')
        with self.assertRaisesRegex(poll.PollError, 'latest successful'):
            self.verify(attempt='2')
        with self.assertRaisesRegex(poll.PollError, 'successor requires'):
            self.verify({'total_count': 0, 'workflow_runs': []})
        changed = copy.deepcopy(self.response)
        changed['workflow_runs'][0]['run_attempt'] = 2
        with self.assertRaisesRegex(poll.PollError, 'rerun discovery history'):
            self.verify(changed)

    def test_rejects_wrong_workflow_repository_and_state(self):
        for key, value in (('path', 'other.yml'), ('head_branch', 'topic'),
                           ('status', 'in_progress'), ('event', 'pull_request')):
            changed = copy.deepcopy(self.response)
            changed['workflow_runs'][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(poll.PollError,
                                                                'invalid or rerun'):
                self.verify(changed)
        changed = copy.deepcopy(self.response)
        changed['workflow_runs'][0]['repository']['full_name'] = 'other/repo'
        with self.assertRaisesRegex(poll.PollError, 'invalid or rerun'):
            self.verify(changed)
        changed = copy.deepcopy(self.response)
        changed['workflow_runs'][0]['conclusion'] = 'failure'
        with self.assertRaisesRegex(poll.PollError, 'successor requires'):
            self.verify(changed)

    def test_failed_first_attempt_does_not_replace_last_success(self):
        failed = copy.deepcopy(self.run)
        failed.update(id=45791000000, conclusion='failure',
                      created_at='2026-11-26T10:00:00Z')
        response = {'total_count': 2, 'workflow_runs': [failed, self.run]}
        self.assertEqual(self.verify(response)['latest_run_id'], self.run['id'])
        failed['run_attempt'] = 2
        with self.assertRaisesRegex(poll.PollError, 'rerun discovery history'):
            self.verify(response)

    def test_rejects_malformed_api_and_symlink(self):
        for response in ({'total_count': True, 'workflow_runs': []},
                         {'total_count': 2, 'workflow_runs': []},
                         {'total_count': 0, 'workflow_runs': [self.run]}):
            with self.assertRaisesRegex(poll.PollError, 'invalid latest'):
                self.verify(response)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / 'api.json'
            raw.write_text(json.dumps(self.response))
            self.assertEqual(latest.read_api(raw), self.response)
            link = root / 'link.json'
            link.symlink_to(raw)
            with self.assertRaisesRegex(poll.PollError, 'unsafe latest'):
                latest.read_api(link)


if __name__ == '__main__':
    unittest.main()
