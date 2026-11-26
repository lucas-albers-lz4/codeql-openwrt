import unittest
import json
import io
from urllib.error import HTTPError
import tempfile
from pathlib import Path
from unittest.mock import patch
from tools import incoming_poll as p
from tools.test_default_branch_gap import GapTests  # Included in the hosted discovery contract.
from tools.test_default_branch_event import DirectCommitIdentityTests  # Read-only direct-commit contract.
from tools.test_direct_commit_admission import (DirectCommitAdmissionTests,
                                                FrozenAdmissionArtifactTests)  # Frozen admission input controls.
from tools.test_historical_openvpn_policy import HistoricalOpenvpnPolicyTests  # Versioned historical selector controls.

A = 'a' * 40
B = 'b' * 40
C = 'c' * 40

def event(sha=A, number=1):
    return {'repository': 'openwrt/openwrt', 'kind': 'pull_request', 'number': number,
            'head_repository': 'openwrt/openwrt', 'head_fork': False, 'head_ref': 'topic', 'base_ref': 'main', 'base_commit': B, 'base': {'commit': B, 'tree': None}, 'source': {'commit': sha, 'tree': None}}

def row(e):
    return {'event': e, 'status': 'pending', 'decision': 'backlog', 'reason': 'new'}

class PollTests(unittest.TestCase):
    def test_backlog_retained_and_retry_prioritized(self):
        previous = [row(event(A))]
        result = p.plan(previous, [event(B, 2)], 1)
        self.assertEqual([(x['decision'], x['reason']) for x in result], [('selected', 'retry'), ('backlog', 'new')])
        self.assertEqual(result[0]['event'], event(A))

    def test_completed_checkpoint_rejected(self):
        bad = row(event()); bad['status'] = 'completed'
        with self.assertRaises(p.PollError): p.plan([bad], [], 1)

    def test_duplicate_checkpoint_rejected(self):
        prior = row(event())
        with self.assertRaises(p.PollError): p.plan([prior, prior], [], 1)

    def test_head_or_base_change_not_dropped(self):
        updated = event(B)
        out = p.plan([row(event())], [updated], 0)
        self.assertEqual(len(out), 2)
        self.assertTrue(all(r['decision'] == 'backlog' for r in out))

    def test_page_errors_fail_closed(self):
        with self.assertRaises(p.PollError): p.pull_pages('openwrt/luci', lambda _: ([{}] * 25, ''), 2)
        link = '<https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=2>; rel="next"'
        with self.assertRaises(p.PollError): p.pull_pages('openwrt/luci', lambda _: ([{}] * 25, link), 1)
        with self.assertRaises(p.PollError): p.pull_pages('openwrt/luci', lambda _: ([], '<https://evil/>; rel="next"'), 2)

    def test_snapshot_defers_pr_trees_without_per_pr_gets(self):
        paths = []
        def get(path):
            paths.append(path)
            if '?' in path:
                return ([{'number': 7, 'state': 'open', 'base': {'repo': {'full_name': 'openwrt/luci'}, 'ref': 'master', 'sha': B}, 'head': {'repo': {'full_name': 'fork/luci', 'fork': True}, 'ref': 'change', 'sha': A}}], '')
            if '/git/commits/' in path:
                sha = path.rsplit('/', 1)[1]
                return ({'sha': sha, 'tree': {'sha': C}}, '')
            if '/commits/' in path: return ({'sha': B}, '')
            return ({'id': 123, 'full_name': 'openwrt/luci', 'default_branch': 'master'}, '')
        found = p.snapshot('openwrt/luci', get, 2)
        self.assertEqual(found[1]['source'], {'commit': A, 'tree': None})
        self.assertEqual(found[1]['base'], {'commit': B, 'tree': None})
        self.assertEqual([path for path in paths if '/git/commits/' in path], ['/repos/openwrt/luci/git/commits/' + B])

    def test_many_prs_selected_remain_discovery_only(self):
        pulls = [{'number': number, 'state': 'open', 'base': {'repo': {'full_name': 'openwrt/luci'}, 'ref': 'master', 'sha': B}, 'head': {'repo': {'full_name': 'fork/luci', 'fork': True}, 'ref': 'change', 'sha': A}} for number in range(1, 24)]
        paths = []
        def get(path):
            paths.append(path)
            if '?' in path: return (pulls, '')
            if '/git/commits/' in path: return ({'sha': B, 'tree': {'sha': C}}, '')
            if '/commits/' in path: return ({'sha': B}, '')
            return ({'id': 123, 'full_name': 'openwrt/luci', 'default_branch': 'master'}, '')
        found = p.snapshot('openwrt/luci', get, 2)
        selected = [d for d in p.plan([], found, 24) if d['event']['kind'] == 'pull_request']
        self.assertEqual(len(selected), 23)
        self.assertTrue(all(d['event']['source']['tree'] is None and d['event']['base']['tree'] is None for d in selected))
        self.assertEqual(len([path for path in paths if '/git/commits/' in path]), 1)

    def test_cross_repository_nonfork_is_recorded_not_scan_approved(self):
        def get(path):
            if '?' in path:
                return ([{'number': 24444, 'state': 'open', 'base': {'repo': {'full_name': 'openwrt/openwrt'}, 'ref': 'main', 'sha': B}, 'head': {'repo': {'full_name': 'brudalevante/openwrt', 'fork': False}, 'ref': 'topic', 'sha': A}}], '')
            if '/git/commits/' in path: return ({'sha': B, 'tree': {'sha': C}}, '')
            if '/commits/' in path: return ({'sha': B}, '')
            return ({'id': 123, 'full_name': 'openwrt/openwrt', 'default_branch': 'main'}, '')
        discovered = p.snapshot('openwrt/openwrt', get, 2)
        event = discovered[1]
        self.assertEqual((event['head_repository'], event['head_fork']), ('brudalevante/openwrt', False))
        self.assertIsNone(event['source']['tree'])
        self.assertEqual(len(p.plan([], discovered, 1)), 2)

    def test_snapshot_requires_tree_and_valid_base(self):
        def get(path):
            if '?' in path: return ([{'number': 7, 'state': 'open', 'base': {'repo': {'full_name': 'wrong'}, 'sha': B}, 'head': {'sha': A}}], '')
            if '/git/commits/' in path: return ({'sha': A, 'tree': {'sha': C}}, '')
            if '/commits/' in path: return ({'sha': A}, '')
            return ({'id': 123, 'full_name': 'openwrt/luci', 'default_branch': 'main'}, '')
        with self.assertRaises(p.PollError): p.snapshot('openwrt/luci', get, 1)

    def test_short_next_and_semantic_url(self):
        link = '<https://api.github.com/repos/openwrt/luci/pulls?page=2&per_page=25&state=open>; rel="next"'
        responses = iter([([1], link), ([2], '')])
        self.assertEqual(p.pull_pages('openwrt/luci', lambda _: next(responses), 2), [1, 2])

    def test_full_terminal_page_and_numeric_repo_link(self):
        responses = iter([([{}] * 25, ''), ([], '')])
        self.assertEqual(len(p.pull_pages('openwrt/luci', lambda _: next(responses), 2)), 25)
        link = '<https://api.github.com/repositories/123/pulls?state=open&per_page=25&page=2>; rel=next'
        responses = iter([([1], link), ([], '')])
        self.assertEqual(p.pull_pages('openwrt/luci', lambda _: next(responses), 2, 123), [1])
        with self.assertRaises(p.PollError): p.pull_pages('openwrt/luci', lambda _: ([1], link), 2, 124)

    def test_empty_terminal_probe_accepts_prev_but_not_next(self):
        prev = '<https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=1>; rel="prev", <https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=1>; rel="first"'
        responses = iter([([{}] * 25, ''), ([], prev)])
        self.assertEqual(len(p.pull_pages('openwrt/luci', lambda _: next(responses), 2)), 25)
        next_link = '<https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=3>; rel="NEXT"'
        responses = iter([([{}] * 25, ''), ([], next_link)])
        with self.assertRaises(p.PollError): p.pull_pages('openwrt/luci', lambda _: next(responses), 2)

    def test_next_relation_case_insensitive(self):
        link = '<https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=2>; rel="NEXT"'
        responses = iter([([1], link), ([2], '')])
        self.assertEqual(p.pull_pages('openwrt/luci', lambda _: next(responses), 2), [1, 2])

    def test_link_rel_tokens_and_unrelated_parameters(self):
        url = 'https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=2'
        link = '<https://example.test/prev>; title="before, here"; rel=prev, <' + url + '>; title="next page"; rel="next alternate"'
        responses = iter([([1], link), ([2], '')])
        self.assertEqual(p.pull_pages('openwrt/luci', lambda _: next(responses), 2), [1, 2])
        with self.assertRaises(p.PollError): p.link_values('<https://api.github.com>; rel="next\\"bad"')

    def test_next_link_rejects_query_and_origin_attacks(self):
        links = [
            '<https://evil.test/repos/openwrt/luci/pulls?state=open&per_page=25&page=2>; rel="next"',
            '<https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=2&page=3>; rel="next"',
            '<https://api.github.com/repos/openwrt/openwrt/pulls?state=open&per_page=25&page=2>; rel="next"',
            '<https://api.github.com/repos/openwrt/luci/pulls?state=open&per_page=25&page=2#x>; rel="next"',
        ]
        for link in links:
            with self.subTest(link=link), self.assertRaises(p.PollError):
                p.pull_pages('openwrt/luci', lambda _: ([], link), 2)

    def test_http_error_receipt_redacts_arbitrary_server_text(self):
        secret = 'ghp_test_secret'
        body = json.dumps({'message': 'Bad credentials', 'echo': secret}).encode()
        with patch.dict(p.os.environ, {'GITHUB_TOKEN': secret}), patch.object(p.OPENER, 'open', side_effect=lambda *args, **kwargs: (_ for _ in ()).throw(HTTPError('https://api.github.com/repos/openwrt/luci', 401, 'Unauthorized', {'X-GitHub-Request-Id': 'ABCD:123', 'X-RateLimit-Remaining': '7', 'Authorization': secret}, io.BytesIO(body)))), patch.object(p.time, 'sleep'):
            with self.assertRaises(p.PollError) as raised: p.fetch('/repos/openwrt/luci')
        detail = raised.exception.detail
        self.assertEqual(detail['status'], 401)
        self.assertEqual(detail['path'], '/repos/openwrt/luci')
        self.assertEqual(detail['safe_message'], 'Bad credentials')
        self.assertEqual(detail['headers']['X-GitHub-Request-Id'], 'ABCD:123')
        self.assertNotIn(secret, json.dumps(detail))
        self.assertNotIn('Authorization', detail['headers'])

    def test_http_error_oversize_and_untrusted_message(self):
        error = HTTPError('https://api.github.com', 401, 'Unauthorized', {}, io.BytesIO(b'x' * (p.MAX_ERROR_BODY + 1)))
        detail = p.http_failure('/repos/openwrt/luci', error)
        self.assertTrue(detail['body_truncated'])
        self.assertEqual(detail['body_prefix_bytes'], p.MAX_ERROR_BODY)
        self.assertEqual(detail['safe_message'], '[unrecognized or unavailable response omitted]')

    def test_transient_retry_success_and_exhaustion(self):
        class Response:
            status = 200
            headers = {'X-RateLimit-Remaining': '9'}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'{}'
        def error(): return HTTPError('https://api.github.com', 504, 'Gateway Timeout', {'X-GitHub-Request-Id': 'ABCD:123', 'X-RateLimit-Remaining': '9'}, io.BytesIO(b''))
        p.HTTP_ERRORS.clear(); p.REQUEST_LOG.clear()
        with patch.object(p.OPENER, 'open', side_effect=[error(), Response()]), patch.object(p.time, 'sleep') as sleep:
            self.assertEqual(p.fetch('/repos/openwrt/luci'), ({}, ''))
            sleep.assert_called_once_with(1)
        self.assertEqual([e['status'] for e in p.HTTP_ERRORS], [504])
        self.assertEqual(p.HTTP_ERRORS[0]['headers']['X-GitHub-Request-Id'], 'ABCD:123')
        p.HTTP_ERRORS.clear()
        with patch.object(p.OPENER, 'open', side_effect=[error(), error(), error()]), patch.object(p.time, 'sleep') as sleep:
            with self.assertRaises(p.PollError): p.fetch('/repos/openwrt/luci')
            self.assertEqual(sleep.call_count, 2)
        self.assertEqual(len(p.HTTP_ERRORS), 3)

    def test_rate_exhaustion_does_not_retry(self):
        err = HTTPError('https://api.github.com', 503, 'Unavailable', {'X-RateLimit-Remaining': '0'}, io.BytesIO(b''))
        with patch.object(p.OPENER, 'open', side_effect=err) as opened, patch.object(p.time, 'sleep') as sleep:
            with self.assertRaises(p.PollError): p.fetch('/repos/openwrt/luci')
            opened.assert_called_once(); sleep.assert_not_called()

    def test_non_string_error_message_keeps_failure_details(self):
        error = HTTPError('https://api.github.com', 504, 'Unavailable', {}, io.BytesIO(b'{"message": ["unexpected"]}'))
        detail = p.http_failure('/repos/openwrt/luci', error)
        self.assertEqual(detail['safe_message'], '[unrecognized or unavailable response omitted]')
        self.assertEqual(detail['status'], 504)

    def test_retry_after_seconds_or_date_does_not_retry(self):
        for value in ('10', 'Wed, 21 Oct 2037 07:28:00 GMT'):
            error = HTTPError('https://api.github.com', 503, 'Unavailable', {'Retry-After': value, 'X-RateLimit-Remaining': '10'}, io.BytesIO(b''))
            with self.subTest(value=value), patch.object(p.OPENER, 'open', side_effect=error) as opened, patch.object(p.time, 'sleep') as sleep:
                with self.assertRaises(p.PollError): p.fetch('/repos/openwrt/luci')
                opened.assert_called_once(); sleep.assert_not_called()

    def test_response_limit(self):
        class Response:
            status = 200
            headers = {'X-RateLimit-Remaining': '10'}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'x' * limit
        with patch.object(p.OPENER, 'open', return_value=Response()), patch.object(p, 'MAX_RESPONSE', 8):
            with self.assertRaises(p.PollError): p.fetch('/repos/openwrt/luci')

    def test_same_key_inconsistent_metadata_and_tree_rejected(self):
        changed = event(); changed['head_ref'] = 'other'
        with self.assertRaises(p.PollError): p.plan([row(event())], [changed], 1)
        changed = event(); changed['source']['tree'] = 'd' * 40
        with self.assertRaises(p.PollError): p.plan([row(event())], [changed], 1)

    def test_redirect_rejected(self):
        with self.assertRaises(p.PollError): p.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.test')

    def test_checkpoint_duplicate_keys_and_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'previous'
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaises(p.PollError): p.read_checkpoint(path)
            with patch.object(p, 'MAX_RECORD', 4):
                with self.assertRaises(p.PollError): p.read_checkpoint(path)

    def test_bound_fails_without_truncation(self):
        with patch.object(p, 'MAX_EVENTS', 1):
            with self.assertRaises(p.PollError): p.plan([row(event())], [event(B, 2)], 1)

    def test_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'decisions.json'
            p.atomic_write(target, {'status': 'complete'})
            self.assertEqual(json.loads(target.read_text()), {'status': 'complete'})
            self.assertFalse((Path(tmp) / '.decisions.json.tmp').exists())

if __name__ == '__main__': unittest.main()
