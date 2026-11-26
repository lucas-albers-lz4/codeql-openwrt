import base64
import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import default_branch_gap as gap
from tools import incoming_poll as poll


A, B, C, D, E = ('a' * 40, 'b' * 40, 'c' * 40, 'd' * 40, 'e' * 40)
TA, TB, TC, TD, TE = ('1' * 40, '2' * 40, '3' * 40, '4' * 40, '5' * 40)


def tip(sha, tree, repo='openwrt/luci'):
    return {'repository': repo, 'kind': 'default_branch', 'ref': 'master',
            'source': {'commit': sha, 'tree': tree}}


def commit(sha, tree, *parents):
    return {'sha': sha, 'commit': {'tree': {'sha': tree}},
            'parents': [{'sha': parent} for parent in parents]}


def compare(*commits):
    return {'status': 'ahead', 'ahead_by': len(commits), 'behind_by': 0,
            'total_commits': len(commits), 'base_commit': commit(A, TA),
            'merge_base_commit': {'sha': A}, 'commits': list(commits)}


def metadata_request(repo, repo_id):
    raw = json.dumps({'full_name': repo, 'id': repo_id}).encode()
    return {'path': '/repos/' + repo, 'body_base64': base64.b64encode(raw).decode()}


def checkpoint(events, luci_id=24997096):
    return {'decisions': [{'event': item} for item in events],
            'requests': [metadata_request('openwrt/openwrt', 12345),
                         metadata_request('openwrt/luci', luci_id)]}


class GapTests(unittest.TestCase):
    def test_two_step_fast_forward_preserves_order_and_trees(self):
        result = gap.first_parent_interval(tip(A, TA), tip(C, TC),
                                           compare(commit(B, TB, A), commit(C, TC, B)), '')
        self.assertEqual(result, [{'commit': B, 'tree': TB, 'first_parent': A},
                                  {'commit': C, 'tree': TC, 'first_parent': B}])

    def test_merge_uses_first_parent_path_and_ignores_side_branch_as_tip(self):
        result = gap.first_parent_interval(tip(A, TA), tip(D, TD),
                                           compare(commit(B, TB, A), commit(C, TC, A),
                                                   commit(D, TD, B, C)), '')
        self.assertEqual([row['commit'] for row in result], [B, D])

    def test_divergence_truncation_tree_and_cycle_fail_closed(self):
        good = compare(commit(B, TB, A), commit(C, TC, B))
        variants = []
        bad = copy.deepcopy(good); bad['status'] = 'diverged'; variants.append(bad)
        bad = copy.deepcopy(good); bad['total_commits'] = 101; variants.append(bad)
        bad = copy.deepcopy(good); bad['commits'].pop(); variants.append(bad)
        bad = copy.deepcopy(good); bad['base_commit']['commit']['tree']['sha'] = TE; variants.append(bad)
        bad = copy.deepcopy(good); bad['commits'][-1]['parents'] = [{'sha': C}]; variants.append(bad)
        bad = copy.deepcopy(good); bad['commits'][-1]['commit']['tree']['sha'] = TE; variants.append(bad)
        for data in variants:
            with self.subTest(data=data):
                with self.assertRaises(poll.PollError):
                    gap.first_parent_interval(tip(A, TA), tip(C, TC), data, '')
        with self.assertRaises(poll.PollError):
            gap.first_parent_interval(tip(A, TA), tip(C, TC), good, '<next>')
        next_link = ('<https://api.github.com/repos/openwrt/luci/compare/' +
                     A + '...' + C + '?per_page=100&page=2>; rel="next"')
        with self.assertRaises(poll.PollError):
            gap.first_parent_interval(tip(A, TA), tip(C, TC), good, next_link)

    def test_real_pinned_introduction_shape(self):
        old = tip('7f6ba9d46028635f0d5aa2e15fcab9ffd163a688',
                  '9859ba29f58ce0a756f40d86e3ae924f9c77a7c9')
        new = tip('5306e007656fe9a77aee2d2a94072d003b0b5a7d',
                  '46cb61d6204fd0763f3e34efd6f27783985b23b0')
        data = {'status': 'ahead', 'ahead_by': 1, 'behind_by': 0, 'total_commits': 1,
                'base_commit': commit(old['source']['commit'], old['source']['tree']),
                'merge_base_commit': {'sha': old['source']['commit']},
                'commits': [commit(new['source']['commit'], new['source']['tree'],
                                   old['source']['commit'])]}
        first_link = ('<https://api.github.com/repositories/24997096/compare/' +
                      old['source']['commit'] + '...' + new['source']['commit'] +
                      '?per_page=100&page=1>; rel="first"')
        self.assertEqual(gap.first_parent_interval(old, new, data, first_link, 24997096)[0]['commit'],
                         new['source']['commit'])
        with self.assertRaises(poll.PollError):
            gap.first_parent_interval(old, new, data, first_link, 24997097)

    def test_unchanged_tips_need_no_compare_and_prior_tip_must_be_retained(self):
        prior = [tip(A, TA, 'openwrt/openwrt'), tip(B, TB)]
        doc = checkpoint(prior)
        with patch.object(poll, 'replay_observed_doc', return_value=prior):
            result = gap.preflight(doc, checkpoint(prior), prior,
                                   lambda _: self.fail('unexpected API call'))
            self.assertEqual([x['state'] for x in result], ['unchanged', 'unchanged'])
            doc['decisions'] = [{'event': prior[0]}]
            with self.assertRaises(poll.PollError):
                gap.preflight(doc, checkpoint(prior), prior,
                              lambda _: self.fail('unexpected API call'))

    def test_same_commit_changed_tree_fails_before_compare(self):
        prior = [tip(A, TA, 'openwrt/openwrt'), tip(B, TB)]
        current = [tip(A, TA, 'openwrt/openwrt'), tip(B, TE)]
        doc = checkpoint(prior)
        with patch.object(poll, 'replay_observed_doc', return_value=prior):
            with self.assertRaises(poll.PollError):
                gap.preflight(doc, checkpoint(current), current,
                              lambda _: self.fail('unexpected API call'))

    def test_numeric_repository_id_must_match_even_for_unchanged_tip(self):
        prior = [tip(A, TA, 'openwrt/openwrt'), tip(B, TB)]
        with patch.object(poll, 'replay_observed_doc', return_value=prior):
            with self.assertRaisesRegex(poll.PollError, 'numeric identity'):
                gap.preflight(checkpoint(prior), checkpoint(prior, luci_id=24997097),
                              prior, lambda _: self.fail('unexpected API call'))
            changed = [prior[0], tip(C, TC)]
            with self.assertRaisesRegex(poll.PollError, 'numeric identity'):
                gap.preflight(checkpoint(prior), checkpoint(changed, luci_id=24997097),
                              changed, lambda _: self.fail('unexpected API call'))

    def test_retained_compare_replays_exact_interval_and_rejects_tamper(self):
        prior = [tip(A, TA, 'openwrt/openwrt'), tip(A, TA)]
        current = [tip(A, TA, 'openwrt/openwrt'), tip(B, TB)]
        prior_doc = checkpoint(prior)
        current_doc = checkpoint(current)
        data = compare(commit(B, TB, A))
        raw = json.dumps(data).encode()
        path = f'/repos/openwrt/luci/compare/{A}...{B}?per_page=100&page=1'
        request = {'path': path, 'status': 200, 'time': '2026-11-26T00:00:00Z',
                   'link': '', 'rate_remaining': '100',
                   'sha256': hashlib.sha256(raw).hexdigest(),
                   'body_base64': base64.b64encode(raw).decode()}
        with patch.object(poll, 'replay_observed_doc', return_value=prior):
            intervals = gap.preflight(prior_doc, current_doc, current, lambda _: (data, ''))
            record = {'schema': 'default-branch-gap-preflight-v1', 'status': 'complete',
                      'observed_at': '2026-11-26T00:00:00Z', 'previous_sha256': '0' * 64,
                      'current_sha256': '1' * 64, 'intervals': intervals,
                      'requests': [request], 'http_errors': [], 'limitations': []}
            self.assertEqual(gap.replay_record(record, prior_doc, current_doc, current), intervals)
            changed = copy.deepcopy(record); changed['intervals'][1]['first_parent_commits'] = []
            with self.assertRaises(poll.PollError):
                gap.replay_record(changed, prior_doc, current_doc, current)
            changed = copy.deepcopy(record); changed['requests'][0]['sha256'] = '2' * 64
            with self.assertRaises(poll.PollError):
                gap.replay_record(changed, prior_doc, current_doc, current)

    def test_gap_input_is_bounded_before_json_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'large.json'
            path.write_bytes(b' ' * 33)
            with patch.object(poll, 'MAX_RECORD', 32):
                with self.assertRaisesRegex(poll.PollError, 'byte limit'):
                    gap.load_gap(path)

    def test_deep_verify_input_takes_controlled_failure_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'deep.json'
            path.write_text('[]')
            args = ['--previous', str(Path(tmp) / 'previous'), '--current',
                    str(Path(tmp) / 'current'), '--verify-gap', str(path)]
            with patch.object(poll, 'verify_checkpoint_decisions',
                              return_value=({}, '1' * 64, [], '0' * 64, None)), \
                 patch.object(poll, 'load_checkpoint', return_value=({}, '0' * 64)), \
                 patch.object(gap, 'load_gap', side_effect=RecursionError), \
                 redirect_stderr(io.StringIO()):
                self.assertEqual(gap.main(args), 2)


if __name__ == '__main__':
    unittest.main()
