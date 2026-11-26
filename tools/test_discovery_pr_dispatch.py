import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.discovery_pr_dispatch import prepare
from tools.incoming_poll import PollError

A, B, C = 'a' * 40, 'b' * 40, 'c' * 40


def event():
    return {'repository': 'openwrt/openwrt', 'kind': 'pull_request', 'number': 17,
            'head_repository': 'example/openwrt', 'head_fork': True,
            'head_ref': 'change', 'base_ref': 'main', 'base_commit': B,
            'base': {'commit': B, 'tree': None},
            'source': {'commit': A, 'tree': None}}


def api():
    return {'number': 17, 'state': 'open',
            'base': {'sha': B, 'ref': 'main', 'repo': {'full_name': 'openwrt/openwrt'}},
            'head': {'sha': A, 'ref': 'change',
                     'repo': {'full_name': 'example/openwrt', 'fork': True}}}


def requests():
    result = []
    for repo in ('openwrt/openwrt', 'openwrt/luci'):
        tip = B
        rows = [api() | {'state': 'open'}] if repo == 'openwrt/openwrt' else []
        values = [
            (f'/repos/{repo}', {'id': 100 if repo == 'openwrt/openwrt' else 101,
                                'full_name': repo, 'default_branch': 'main'}),
            (f'/repos/{repo}/commits/main', {'sha': tip}),
            (f'/repos/{repo}/git/commits/{tip}', {'sha': tip, 'tree': {'sha': C}}),
            (f'/repos/{repo}/pulls?state=open&per_page=25&page=1', rows),
        ]
        for path, value in values:
            raw = json.dumps(value).encode()
            result.append({'path': path, 'status': 200,
                           'time': '2026-11-26T00:00:00Z', 'link': '',
                           'rate_remaining': '100',
                           'sha256': hashlib.sha256(raw).hexdigest(),
                           'body_base64': base64.b64encode(raw).decode()})
    return result


class DispatchInputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkpoint = self.root / 'decisions.json'
        self.response = self.root / 'pr.json'
        self.write_checkpoint()
        self.write_api()

    def write_checkpoint(self, rows=None):
        record = {'schema': 'incoming-poll-v3', 'status': 'complete',
                  'observed_at': '2026-11-26T00:00:00Z', 'capacity': 1,
                  'previous_sha256': None, 'genesis': True, 'requests': requests(),
                  'http_errors': [], 'limitations': [],
                  'decisions': rows if rows is not None else
                  [{'event': event(), 'decision': 'backlog',
                    'status': 'pending', 'reason': 'new'}]}
        self.checkpoint.write_text(json.dumps(record))

    def write_api(self, value=None):
        self.response.write_text(json.dumps(api() if value is None else value))

    def run_prepare(self):
        return prepare(self.checkpoint, self.response, 'openwrt/openwrt', 17, A)

    def test_exact_backlog_head_prepares_only(self):
        result = self.run_prepare()
        self.assertEqual((result['status'], result['upstream'], result['source_sha'],
                          result['control_sha'], result['discovery_decision']),
                         ('prepared_only', 'openwrt', A, B, 'backlog'))
        self.assertEqual(len(result['discovery_checkpoint_sha256']), 64)
        self.assertEqual(len(result['api_response_sha256']), 64)

    def test_moved_head_or_base_rejected(self):
        for side in ('head', 'base'):
            with self.subTest(side=side):
                changed = api(); changed[side]['sha'] = C
                self.write_api(changed)
                with self.assertRaises(PollError): self.run_prepare()

    def test_repository_and_branch_changes_rejected(self):
        for side, key, value in [('base', 'ref', 'other'),
                                 ('head', 'ref', 'other'),
                                 ('base', 'repo', {'full_name': 'other/repo'}),
                                 ('head', 'repo', {'full_name': 'example/openwrt', 'fork': False})]:
            with self.subTest(side=side, key=key):
                changed = api(); changed[side][key] = value
                self.write_api(changed)
                with self.assertRaises(PollError): self.run_prepare()

    def test_closed_or_absent_pr_rejected(self):
        changed = api(); changed['state'] = 'closed'; self.write_api(changed)
        with self.assertRaises(PollError): self.run_prepare()
        self.write_api()
        self.write_checkpoint([])
        with self.assertRaises(PollError): self.run_prepare()

    def test_decision_not_present_in_retained_requests_rejected(self):
        record = json.loads(self.checkpoint.read_text())
        record['requests'] = []
        self.checkpoint.write_text(json.dumps(record))
        with self.assertRaises(PollError): self.run_prepare()

    def test_duplicate_api_key_rejected(self):
        self.response.write_text('{"number":17,"number":17}')
        with self.assertRaises(PollError): self.run_prepare()

    def test_boolean_number_and_oversize_api_rejected(self):
        changed = api(); changed['number'] = True
        self.write_api(changed)
        with self.assertRaises(PollError): self.run_prepare()
        self.response.write_bytes(b' ' * 2_000_001)
        with self.assertRaises(PollError): self.run_prepare()

    def test_equal_head_and_control_candidate_rejected(self):
        same = event(); same['base_commit'] = A
        same['base'] = {'commit': A, 'tree': None}
        self.write_checkpoint([{'event': same, 'decision': 'backlog',
                                'status': 'pending', 'reason': 'new'}])
        changed = api(); changed['base']['sha'] = A
        self.write_api(changed)
        with patch('tools.discovery_pr_dispatch.replay_observed', return_value=[same]):
            with self.assertRaises(PollError): self.run_prepare()


if __name__ == '__main__':
    unittest.main()
