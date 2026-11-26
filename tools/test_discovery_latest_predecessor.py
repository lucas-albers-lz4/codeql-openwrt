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

    def verify(self, response=None, genesis=False, prior='45790907027', attempt='1',
               current_run='', current_event='workflow_dispatch', resolve_latest=False):
        return latest.verify(self.response if response is None else response,
                             self.REPO, genesis, prior, attempt, current_run,
                             current_event, resolve_latest)

    def test_latest_successful_predecessor_and_first_genesis(self):
        self.assertEqual(self.verify()['status'], 'latest_predecessor_verified')
        self.assertEqual(self.verify({'total_count': 0, 'workflow_runs': []},
                                     genesis=True, prior='', attempt='')['status'],
                         'genesis_allowed')

    def test_rejects_restart_or_stale_successor(self):
        with self.assertRaisesRegex(poll.PollError, 'genesis requires'):
            self.verify(genesis=True, prior='', attempt='')
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
                           ('event', 'pull_request')):
            changed = copy.deepcopy(self.response)
            changed['workflow_runs'][0][key] = value
            error = 'successor requires' if key == 'event' else 'invalid or rerun'
            with self.subTest(key=key), self.assertRaisesRegex(poll.PollError, error):
                self.verify(changed)
        changed = copy.deepcopy(self.response)
        changed['workflow_runs'][0]['status'] = 'in_progress'
        with self.assertRaisesRegex(poll.PollError, 'other discovery run is not terminal'):
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

    def test_current_manual_run_and_concurrent_or_rerun_history(self):
        current = copy.deepcopy(self.run)
        current.update(id=45833426577, status='in_progress', conclusion=None,
                       created_at='2026-11-26T13:52:28Z')
        response = {'total_count': 2, 'workflow_runs': [current, self.run]}
        self.assertEqual(latest.verify(response, self.REPO, False,
                                       '45790907027', '1', '45833426577',
                                       'workflow_dispatch')['status'],
                         'latest_predecessor_verified')
        with self.assertRaisesRegex(poll.PollError, 'current discovery run missing'):
            latest.verify(self.response, self.REPO, False,
                          '45790907027', '1', '45833426577')
        changed = copy.deepcopy(response)
        changed['workflow_runs'][1]['status'] = 'in_progress'
        changed['workflow_runs'][1]['conclusion'] = None
        with self.assertRaisesRegex(poll.PollError, 'other discovery run is not terminal'):
            latest.verify(changed, self.REPO, False,
                          '45790907027', '1', '45833426577')
        changed = copy.deepcopy(response)
        changed['workflow_runs'][1]['run_attempt'] = 2
        changed['workflow_runs'][1]['status'] = 'in_progress'
        changed['workflow_runs'][1]['conclusion'] = None
        with self.assertRaisesRegex(poll.PollError, 'rerun discovery history'):
            latest.verify(changed, self.REPO, False,
                          '45790907027', '1', '45833426577')

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

    def test_combined_event_filtered_history_replays_raw_responses(self):
        manual = copy.deepcopy(self.run)
        scheduled = copy.deepcopy(self.run)
        scheduled.update(id=45830000000, event='schedule',
                         created_at='2026-11-26T12:00:00Z')
        document = {
            'schema': 'incoming-discovery-history-api-v1',
            'workflow_dispatch': {'total_count': 1, 'workflow_runs': [manual]},
            'schedule': {'total_count': 1, 'workflow_runs': [scheduled]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.json'
            path.write_text(json.dumps(document))
            merged = latest.read_api(path)
        self.assertEqual(merged['total_count'], 2)
        self.assertEqual([run['event'] for run in merged['workflow_runs']],
                         ['workflow_dispatch', 'schedule'])
        with self.assertRaisesRegex(poll.PollError, 'different event'):
            document['schedule']['workflow_runs'][0]['event'] = 'workflow_dispatch'
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'history.json'
                path.write_text(json.dumps(document))
                latest.read_api(path)

    def test_scheduled_run_resolves_latest_mixed_manual_and_schedule_history(self):
        manual = copy.deepcopy(self.run)
        scheduled = copy.deepcopy(self.run)
        scheduled.update(id=45830000000, event='schedule',
                         created_at='2026-11-26T12:00:00Z')
        current = copy.deepcopy(self.run)
        current.update(id=45833426577, event='schedule', status='in_progress',
                       conclusion=None, created_at='2026-11-26T13:52:28Z')
        response = {'total_count': 3,
                    'workflow_runs': [current, scheduled, manual]}
        result = latest.verify(response, self.REPO, False, '', '',
                                '45833426577', 'schedule', True)
        self.assertEqual(result, {
            'status': 'latest_predecessor_resolved',
            'latest_run_id': scheduled['id'],
            'latest_run_attempt': 1,
            'latest_run_event': 'schedule',
        })

    def test_manual_successor_can_extend_latest_scheduled_run(self):
        scheduled = copy.deepcopy(self.run)
        scheduled.update(id=45830000000, event='schedule',
                         created_at='2026-11-26T12:00:00Z')
        current = copy.deepcopy(self.run)
        current.update(id=45833426577, status='in_progress', conclusion=None,
                       created_at='2026-11-26T13:52:28Z')
        response = {'total_count': 3,
                    'workflow_runs': [current, scheduled, self.run]}
        result = latest.verify(response, self.REPO, False,
                               str(scheduled['id']), '1', '45833426577',
                               'workflow_dispatch')
        self.assertEqual(result['latest_run_id'], scheduled['id'])
        self.assertEqual(result['latest_run_event'], 'schedule')

    def test_schedule_cannot_start_genesis_or_resolve_without_prior_success(self):
        current = copy.deepcopy(self.run)
        current.update(id=45833426577, event='schedule', status='in_progress',
                       conclusion=None, created_at='2026-11-26T13:52:28Z')
        current_only = {'total_count': 1, 'workflow_runs': [current]}
        with self.assertRaisesRegex(poll.PollError, 'scheduled successor'):
            latest.verify({'total_count': 0, 'workflow_runs': []}, self.REPO,
                          True, '', '', '45833426577', 'schedule', True)
        with self.assertRaisesRegex(poll.PollError, 'successor requires'):
            latest.verify(current_only, self.REPO,
                          False, '', '', '45833426577', 'schedule', True)
        with self.assertRaisesRegex(poll.PollError, 'scheduled successor'):
            latest.verify(self.response, self.REPO, False, '', '',
                          '45833426577', 'workflow_dispatch', True)

    def test_current_scheduled_run_must_be_in_api_history(self):
        current = copy.deepcopy(self.run)
        current.update(id=45833426577, event='schedule', status='in_progress',
                       conclusion=None, created_at='2026-11-26T13:52:28Z')
        response = {'total_count': 2, 'workflow_runs': [current, self.run]}
        self.assertEqual(latest.verify(response, self.REPO, False, '45790907027',
                                       '1', '45833426577', 'schedule')['status'],
                         'latest_predecessor_verified')
        current['event'] = 'pull_request'
        with self.assertRaisesRegex(poll.PollError, 'current discovery run event differs'):
            latest.verify(response, self.REPO, False, '45790907027', '1',
                          '45833426577', 'schedule')

    def test_ignores_unmanaged_event_rows_but_uses_both_chain_events(self):
        current = copy.deepcopy(self.run)
        current.update(id=45833426577, status='in_progress', conclusion=None,
                       created_at='2026-11-26T13:52:28Z')
        pull_request = copy.deepcopy(self.run)
        pull_request.update(id=45832000000, event='pull_request',
                            head_branch='main', created_at='2026-11-26T12:30:00Z')
        response = {'total_count': 3,
                    'workflow_runs': [current, pull_request, self.run]}
        self.assertEqual(latest.verify(response, self.REPO, False,
                                       '45790907027', '1', '45833426577',
                                       'workflow_dispatch')['latest_run_id'],
                         self.run['id'])

    def test_scheduled_discovery_stays_read_only_and_manual_scan_accepts_its_receipts(self):
        root = Path(__file__).resolve().parents[1]
        discovery = (root / '.github/workflows/incoming-discovery-manual.yml').read_text()
        scan = (root / '.github/workflows/default-branch-commit-scan.yml').read_text()
        self.assertIn("- cron: '17 7 * * *'", discovery)
        self.assertIn("github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'", discovery)
        self.assertIn("'scan_dispatched': False", discovery)
        self.assertNotIn('workflow_run:', discovery)
        self.assertNotIn('default-branch-commit-scan.yml', discovery)
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", scan)
        self.assertIn('(.event == "workflow_dispatch" or .event == "schedule")', scan)


if __name__ == '__main__':
    unittest.main()
