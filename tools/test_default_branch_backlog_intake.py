import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZIP_DEFLATED

from tools import default_branch_backlog_intake as intake
from tools import default_branch_gap as gap
from tools import incoming_poll as poll


REPO = intake.REPOSITORY
WORKFLOW = intake.WORKFLOW
HEAD = 'd66030c04f00d0ce9196876d74515641be8e42af'
REPO_IDS = {'openwrt/openwrt': 111, 'openwrt/luci': 222}


def sha(label):
    return hashlib.sha1(label.encode()).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def _record_request(requests, path, value, link=''):
    raw = json.dumps(value, separators=(',', ':')).encode()
    requests.append({
        'path': path, 'status': 200, 'time': '2026-11-26T00:00:00Z',
        'link': link, 'rate_remaining': '5000',
        'sha256': hashlib.sha256(raw).hexdigest(),
        'body_base64': base64.b64encode(raw).decode('ascii'),
    })


def event(repo, commit_sha, tree_sha, ref=None):
    if ref is None:
        ref = 'master' if repo == 'openwrt/luci' else 'main'
    return {'repository': repo, 'kind': 'default_branch', 'ref': ref,
            'source': {'commit': commit_sha, 'tree': tree_sha}}


def _snapshot_requests(tips):
    requests = []
    for repo in poll.REPOS:
        tip = tips[repo]
        repo_id = REPO_IDS[repo]
        branch = tip['ref']
        _record_request(requests, '/repos/' + repo,
                        {'full_name': repo, 'id': repo_id, 'default_branch': branch})
        _record_request(requests, f"/repos/{repo}/commits/{branch}",
                        {'sha': tip['source']['commit']})
        _record_request(requests,
                        f"/repos/{repo}/git/commits/{tip['source']['commit']}",
                        {'sha': tip['source']['commit'],
                         'tree': {'sha': tip['source']['tree']}})
        _record_request(requests, f'/repos/{repo}/pulls?state=open&per_page=25&page=1', [])
    return requests


def checkpoint(tips, previous_rows=None, previous_sha=None):
    observed = [tips[repo] for repo in poll.REPOS]
    previous_rows = previous_rows or []
    return {
        'schema': 'incoming-poll-v3', 'status': 'complete',
        'observed_at': '2026-11-26T00:00:00Z', 'capacity': 1,
        'previous_sha256': previous_sha, 'genesis': False,
        'requests': _snapshot_requests(tips), 'http_errors': [],
        'decisions': poll.plan(previous_rows, observed, 1),
        'limitations': ['synthetic offline fixture'],
    }


def _compare_commit(commit_sha, tree_sha, *parents):
    return {'sha': commit_sha, 'commit': {'tree': {'sha': tree_sha}},
            'parents': [{'sha': parent} for parent in parents]}


def gap_record(previous_doc, current_doc, commits, repository='openwrt/openwrt'):
    previous_sha = hashlib.sha256(json_bytes(previous_doc)).hexdigest()
    current_sha = hashlib.sha256(json_bytes(current_doc)).hexdigest()
    previous_observed = poll.replay_observed_doc(previous_doc)
    current_observed = poll.replay_observed_doc(current_doc)
    old_openwrt = next(item for item in previous_observed
                       if item['repository'] == repository)
    new_openwrt = next(item for item in current_observed
                       if item['repository'] == repository)
    request_rows = []
    compare_data = {
        'status': 'ahead', 'ahead_by': len(commits), 'behind_by': 0,
        'total_commits': len(commits),
        'base_commit': {'sha': old_openwrt['source']['commit'],
                        'commit': {'tree': {'sha': old_openwrt['source']['tree']}}},
        'merge_base_commit': {'sha': old_openwrt['source']['commit']},
        'commits': list(commits),
    }

    def get(path):
        raw = json.dumps(compare_data, separators=(',', ':')).encode()
        request_rows.append({
            'path': path, 'status': 200, 'time': '2026-11-26T00:00:01Z',
            'link': '', 'rate_remaining': '4999',
            'sha256': hashlib.sha256(raw).hexdigest(),
            'body_base64': base64.b64encode(raw).decode('ascii'),
        })
        return compare_data, ''

    intervals = gap.preflight(previous_doc, current_doc, current_observed, get)
    return {
        'schema': 'default-branch-gap-preflight-v1', 'status': 'complete',
        'observed_at': '2026-11-26T00:00:01Z',
        'previous_sha256': previous_sha, 'current_sha256': current_sha,
        'intervals': intervals, 'requests': request_rows, 'http_errors': [],
        'limitations': ['synthetic fixture; first-parent only'],
    }


class Fixture:
    def __init__(self, parent):
        self.parent = Path(parent)
        self.inputs = self.parent / 'inputs'
        self.inputs.mkdir(mode=0o700)
        self.private = self.parent / 'private'
        self.private.mkdir(mode=0o700)
        self.counter = 0

    def _run_doc(self, run_id, attempt, event_name='workflow_dispatch'):
        return {
            'id': run_id, 'run_attempt': attempt,
            'repository': {'id': 1454767376, 'full_name': REPO},
            'head_repository': {'id': 1454767376, 'full_name': REPO},
            'path': WORKFLOW, 'event': event_name, 'head_branch': 'main',
            'head_sha': HEAD, 'status': 'completed', 'conclusion': 'success',
        }

    def _artifact_api(self, run_doc, artifact_id, zip_raw):
        run_id = run_doc['id']
        attempt = run_doc['run_attempt']
        return {
            'id': artifact_id,
            'name': f'incoming-discovery-{run_id}-{attempt}',
            'expired': False, 'size_in_bytes': len(zip_raw),
            'digest': 'sha256:' + hashlib.sha256(zip_raw).hexdigest(),
            'workflow_run': {
                'id': run_id, 'repository_id': 1454767376,
                'head_repository_id': 1454767376, 'head_branch': 'main',
                'head_sha': run_doc['head_sha'],
            },
        }

    def bundle(self, run_id, attempt, doc, *, prior_run=None, prior_attempt=None,
               version=1, gap=None, bad_previous_run=None,
               bad_history_prior=None, bad_history_head=False,
               bad_combined_history=False):
        self.counter += 1
        decisions_raw = json_bytes(doc)
        run_doc = self._run_doc(run_id, attempt)
        input_doc = {
            'schema': intake.RUN_INPUT_V1,
            'consumer_sha': HEAD, 'run_id': str(run_id),
            'run_attempt': str(attempt), 'genesis': doc['genesis'],
            'previous_run_id': str(prior_run) if prior_run is not None else None,
            'previous_run_attempt': str(prior_attempt) if prior_attempt is not None else None,
            'previous_sha256': doc['previous_sha256'], 'capacity': 1,
        }
        members = {
            'run-input.json': json_bytes(input_doc),
            'decisions.json': decisions_raw,
            'decisions.sha256': (hashlib.sha256(decisions_raw).hexdigest() +
                                 '  discovery-output/decisions.json\n').encode(),
            'poll/decisions.json': decisions_raw,
        }
        if version == 2:
            predecessor_doc = self._run_doc(bad_previous_run or prior_run,
                                            prior_attempt or 1)
            predecessor_raw = json_bytes(predecessor_doc)
            history_predecessor = self._run_doc(bad_history_prior or prior_run,
                                                prior_attempt or 1)
            prior_history = dict(history_predecessor,
                                 created_at='2026-11-26T00:00:00Z')
            if bad_history_head:
                prior_history['head_sha'] = sha('contradictory-history-head')
            current_history = dict(run_doc, status='in_progress', conclusion=None,
                                   created_at='2026-11-26T01:00:00Z')
            history = json_bytes({'total_count': 2,
                                  'workflow_runs': [current_history, prior_history]})
            scheduled = json_bytes({'total_count': 0, 'workflow_runs': []})
            combined_manual = json.loads(history)
            if bad_combined_history:
                combined_manual['workflow_runs'][1]['head_sha'] = sha('combined-only-head')
            combined = json_bytes({'schema': 'incoming-discovery-history-api-v1',
                                   'workflow_dispatch': combined_manual,
                                   'schedule': json.loads(scheduled)})
            input_doc.update({
                'schema': intake.RUN_INPUT_V2,
                'event': run_doc['event'],
                'discovery_history_api_sha256': hashlib.sha256(combined).hexdigest(),
                'manual_run_history_api_sha256': hashlib.sha256(history).hexdigest(),
                'scheduled_run_history_api_sha256': hashlib.sha256(scheduled).hexdigest(),
                'predecessor_run_api_sha256': hashlib.sha256(predecessor_raw).hexdigest(),
                'previous_run_event': 'workflow_dispatch',
                'scan_dispatched': False,
            })
            members['run-input.json'] = json_bytes(input_doc)
            members['manual-run-history-api.json'] = history
            members['scheduled-run-history-api.json'] = scheduled
            members['discovery-history-api.json'] = combined
            members['predecessor-run-api.json'] = predecessor_raw
        if gap is not None:
            gap_raw = json_bytes(gap)
            members['gap/gap.json'] = gap_raw
            members['gap/gap.sha256'] = (hashlib.sha256(gap_raw).hexdigest() +
                                         '  discovery-output/gap/gap.json\n').encode()
        zip_buffer = self.inputs / f'{run_id}-{attempt}-{self.counter}.zip'
        with ZipFile(zip_buffer, 'w', ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        zip_raw = zip_buffer.read_bytes()
        artifact_id = run_id + 100000
        api_raw = json_bytes(self._artifact_api(run_doc, artifact_id, zip_raw))
        run_raw = json_bytes(run_doc)
        artifacts_path = self.inputs / f'{run_id}-{attempt}-{self.counter}-artifact.json'
        run_path = self.inputs / f'{run_id}-{attempt}-{self.counter}-run.json'
        artifacts_path.write_bytes(api_raw)
        run_path.write_bytes(run_raw)
        return {
            'zip': zip_buffer, 'run_api': run_path, 'artifacts_api': artifacts_path,
            'run_doc': run_doc, 'artifact_id': artifact_id,
            'decisions_sha256': hashlib.sha256(decisions_raw).hexdigest(),
        }

    def make_initial_pair(self, *, version=1):
        old_tip = event('openwrt/openwrt', sha('old-owrt'), sha('old-tree'))
        luci_tip = event('openwrt/luci', sha('luci-same'), sha('luci-tree'))
        previous = checkpoint({'openwrt/openwrt': old_tip, 'openwrt/luci': luci_tip},
                              previous_sha='f' * 64)
        previous_raw = json_bytes(previous)
        commits = []
        parent = old_tip['source']['commit']
        for index in range(1, 8):
            commit_sha = sha(f'openwrt-commit-{index}')
            tree_sha = sha(f'openwrt-tree-{index}')
            commits.append(_compare_commit(commit_sha, tree_sha, parent))
            parent = commit_sha
        new_tip = event('openwrt/openwrt', commits[-1]['sha'], commits[-1]['commit']['tree']['sha'])
        current = checkpoint({'openwrt/openwrt': new_tip, 'openwrt/luci': luci_tip},
                             previous['decisions'], hashlib.sha256(previous_raw).hexdigest())
        gap_doc = gap_record(previous, current, commits)
        prev_bundle = self.bundle(1001, 1, previous)
        current_bundle = self.bundle(1002, 1, current, prior_run=1001,
                                     prior_attempt=1, version=version, gap=gap_doc)
        return previous, current, gap_doc, prev_bundle, current_bundle, commits

    def make_empty_successor(self, previous, previous_bundle, run_id=1003):
        tips = {item['repository']: item for item in poll.replay_observed_doc(previous)}
        previous_raw = json_bytes(previous)
        current = checkpoint(tips, previous['decisions'], hashlib.sha256(previous_raw).hexdigest())
        gap_doc = gap_record(previous, current, [])
        current_bundle = self.bundle(run_id, 1, current, prior_run=previous_bundle['run_doc']['id'],
                                     prior_attempt=previous_bundle['run_doc']['run_attempt'],
                                     version=2, gap=gap_doc)
        return current, gap_doc, current_bundle

    def run_intake(self, previous_bundle, current_bundle, private=None):
        return intake.intake(
            private or self.private,
            previous_bundle['zip'], previous_bundle['run_api'],
            previous_bundle['artifacts_api'], current_bundle['zip'],
            current_bundle['run_api'], current_bundle['artifacts_api'])


class BacklogIntakeTests(unittest.TestCase):
    def setUp(self):
        run_root = Path(__file__).resolve().parents[1] / 'work'
        run_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(run_root, 0o700)
        self.tmp = tempfile.TemporaryDirectory(prefix='backlog-intake-', dir=run_root)
        self.fx = Fixture(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.fx.private / 'default-branch-backlog.sqlite3')
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def test_seven_rows_empty_successor_idempotence_and_receipt_chain(self):
        previous, current, _, prev_bundle, current_bundle, expected = self.fx.make_initial_pair()
        result = self.fx.run_intake(prev_bundle, current_bundle)
        self.assertEqual(result['status'], 'intake_recorded')
        self.assertEqual(result['commits_added'], 7)
        self.assertEqual(result['custody'], 'offline_retained_api_metadata')
        with self.db() as db:
            rows = db.execute('SELECT repository, ordinal, commit_sha, status FROM commit_backlog '
                              'ORDER BY ordinal').fetchall()
            self.assertEqual(len(rows), 7)
            self.assertEqual([row[1] for row in rows], list(range(1, 8)))
            self.assertEqual([row[2] for row in rows], [row['sha'] for row in expected])
            self.assertTrue(all(row[0] == 'openwrt/openwrt' and row[3] == 'pending'
                                for row in rows))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 1)
            cursor = db.execute('SELECT checkpoint_sha256, run_id, attempt FROM cursor').fetchone()
            self.assertEqual(cursor, (current_bundle['decisions_sha256'], 1002, 1))

        repeated = self.fx.run_intake(prev_bundle, current_bundle)
        self.assertEqual(repeated['status'], 'idempotent')
        self.assertEqual(repeated['receipt_hash'], result['receipt_hash'])
        with self.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 1)

        successor, _, next_bundle = self.fx.make_empty_successor(current, current_bundle)
        empty = self.fx.run_intake(current_bundle, next_bundle)
        self.assertEqual(empty['status'], 'intake_recorded')
        self.assertEqual(empty['commits_added'], 0)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0], 7)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commit_backlog WHERE status='pending'").fetchone()[0], 7)
            self.assertEqual(db.execute('SELECT checkpoint_sha256, run_id FROM cursor').fetchone(),
                             (next_bundle['decisions_sha256'], 1003))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 2)
            database, _ = intake._ensure_database(self.fx.private)
            connection = intake._connect(database)
            try:
                self.assertEqual(intake._verify_receipt_chain(connection)[0], 3)
            finally:
                connection.close()

    def test_digest_and_replayed_gap_tampering_rejected(self):
        _, _, gap_doc, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        changed_zip = self.fx.inputs / 'tampered.zip'
        changed = bytearray(current_bundle['zip'].read_bytes())
        changed[-8] ^= 0x01
        changed_zip.write_bytes(changed)
        altered_bundle = dict(current_bundle, zip=changed_zip)
        with self.assertRaisesRegex(intake.IntakeError, 'ZIP bytes differ'):
            self.fx.run_intake(prev_bundle, altered_bundle)
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

        altered_gap = json.loads(json_bytes(gap_doc))
        altered_gap['requests'][0]['sha256'] = '0' * 64
        previous, current, _, prev_bundle, _current_bundle, _ = self.fx.make_initial_pair()
        current_bundle = self.fx.bundle(
            1010, 1, current, prior_run=1001, prior_attempt=1, gap=altered_gap)
        with self.assertRaisesRegex((intake.IntakeError, poll.PollError), 'digest|retained'):
            self.fx.run_intake(prev_bundle, current_bundle)
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

    def test_wrong_predecessor_is_rejected(self):
        _, _, _, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        # Rebuild from the actual checkpoint and gap, with a wrong run-input
        # predecessor identity. A retained canonical run/API ZIP digest still
        # matches this intentionally inconsistent artifact.
        with ZipFile(current_bundle['zip']) as archive:
            checkpoint_doc = json.loads(archive.read('decisions.json'))
            gap_doc = json.loads(archive.read('gap/gap.json'))
        wrong = self.fx.bundle(1020, 1, checkpoint_doc, prior_run=9999,
                               prior_attempt=1, gap=gap_doc)
        with self.assertRaisesRegex(intake.IntakeError, 'does not link'):
            self.fx.run_intake(prev_bundle, wrong)
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())

    def test_v2_bundled_predecessor_api_must_match_supplied_run(self):
        previous, current, gap_doc, prev_bundle, _, _ = self.fx.make_initial_pair()
        bad = self.fx.bundle(1002, 1, current, prior_run=1001,
                             prior_attempt=1, version=2, gap=gap_doc,
                             bad_previous_run=9999)
        with self.assertRaisesRegex(intake.IntakeError,
                                    'v2 predecessor API identity differs'):
            self.fx.run_intake(prev_bundle, bad)
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())
        self.assertFalse((self.fx.private / 'archives').exists())

    def test_v2_history_must_select_supplied_predecessor(self):
        _, current, gap_doc, prev_bundle, _, _ = self.fx.make_initial_pair()
        bad = self.fx.bundle(1002, 1, current, prior_run=1001,
                             prior_attempt=1, version=2, gap=gap_doc,
                             bad_history_prior=9999)
        with self.assertRaisesRegex(poll.PollError,
                                    'predecessor is not the latest successful'):
            self.fx.run_intake(prev_bundle, bad)
        self.assertFalse((self.fx.private / 'default-branch-backlog.sqlite3').exists())
        self.assertFalse((self.fx.private / 'archives').exists())

    def test_v2_raw_and_combined_histories_must_be_identical(self):
        _, current, gap_doc, prev_bundle, _, _ = self.fx.make_initial_pair()
        bad = self.fx.bundle(1002, 1, current, prior_run=1001,
                             prior_attempt=1, version=2, gap=gap_doc,
                             bad_combined_history=True)
        with self.assertRaisesRegex(intake.IntakeError,
                                    'combined history differs from raw event responses'):
            self.fx.run_intake(prev_bundle, bad)
        self.assertFalse((self.fx.private / 'archives').exists())

    def test_v2_selected_history_head_must_match_predecessor_api(self):
        _, current, gap_doc, prev_bundle, _, _ = self.fx.make_initial_pair()
        bad = self.fx.bundle(1002, 1, current, prior_run=1001,
                             prior_attempt=1, version=2, gap=gap_doc,
                             bad_history_head=True)
        with self.assertRaisesRegex(intake.IntakeError,
                                    'selected history run differs from predecessor API'):
            self.fx.run_intake(prev_bundle, bad)
        self.assertFalse((self.fx.private / 'archives').exists())

    def test_v2_predecessor_and_v2_successor_histories_both_replay(self):
        _, current, _, previous_bundle, current_bundle, _ = \
            self.fx.make_initial_pair(version=2)
        first = self.fx.run_intake(previous_bundle, current_bundle)
        self.assertEqual(first['commits_added'], 7)
        _, _, next_bundle = self.fx.make_empty_successor(current, current_bundle)
        second = self.fx.run_intake(current_bundle, next_bundle)
        self.assertEqual(second['commits_added'], 0)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0], 7)

    def test_uri_delimiters_in_private_directory_bind_exact_database(self):
        _, _, _, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        special = self.fx.parent / 'private?name#part'
        special.mkdir(mode=0o700)
        result = self.fx.run_intake(prev_bundle, current_bundle, private=special)
        self.assertEqual(result['status'], 'intake_recorded')
        self.assertTrue((special / 'default-branch-backlog.sqlite3').is_file())
        self.assertFalse((self.fx.parent / 'private').joinpath(
            'default-branch-backlog.sqlite3').exists())

    def test_missing_prior_backlog_row_blocks_next_cursor_advance(self):
        previous, current, _, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        self.fx.run_intake(prev_bundle, current_bundle)
        with self.db() as db:
            db.execute('DELETE FROM commit_backlog WHERE ordinal=2')
        _, _, next_bundle = self.fx.make_empty_successor(current, current_bundle)
        with self.assertRaisesRegex(intake.IntakeError,
                                    'stored backlog rows differ from receipt'):
            self.fx.run_intake(current_bundle, next_bundle)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM intakes').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT run_id FROM cursor').fetchone()[0], 1002)

    def test_unexpected_trigger_blocks_existing_backlog(self):
        _, current, _, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        self.fx.run_intake(prev_bundle, current_bundle)
        with self.db() as db:
            db.execute('CREATE TRIGGER sqliteX_sabotage AFTER INSERT ON receipts '
                       'BEGIN DELETE FROM commit_backlog; END')
        _, _, next_bundle = self.fx.make_empty_successor(current, current_bundle)
        with self.assertRaisesRegex(intake.IntakeError,
                                    'unexpected table, view, index or trigger'):
            self.fx.run_intake(current_bundle, next_bundle)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT run_id FROM cursor').fetchone()[0], 1002)

    def test_post_write_reconciliation_rejects_mutating_trigger(self):
        _, _, _, prev_bundle, current_bundle, _ = self.fx.make_initial_pair()
        original_check = intake._initialize_or_check_schema

        def install_after_schema_check(connection):
            original_check(connection)
            connection.execute('CREATE TRIGGER sabotage AFTER INSERT ON receipts '
                               'BEGIN DELETE FROM commit_backlog; END')

        with patch.object(intake, '_initialize_or_check_schema',
                          side_effect=install_after_schema_check):
            with self.assertRaisesRegex(intake.IntakeError,
                                        'stored backlog rows differ from receipt'):
                self.fx.run_intake(prev_bundle, current_bundle)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM intakes').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commit_backlog').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM cursor').fetchone()[0], 0)

    def test_conflicting_duplicate_commit_rejected(self):
        previous, current, _, prev_bundle, current_bundle, commits = self.fx.make_initial_pair()
        self.fx.run_intake(prev_bundle, current_bundle)
        with self.db() as db:
            intake_id = db.execute('SELECT intake_id FROM intakes').fetchone()[0]
            # Force an identity collision for a future first-parent row with
            # conflicting tree/parent/origin metadata.
            db.execute('''INSERT INTO commit_backlog VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)''',
                       ('openwrt/openwrt', 'main', 1, sha('next-commit'), sha('wrong-tree'),
                        sha('wrong-parent'), intake_id, 'a' * 64, 'b' * 64, 'c' * 64))
            db.commit()
        tips = {item['repository']: item for item in poll.replay_observed_doc(current)}
        next_commit = _compare_commit(sha('next-commit'), sha('next-tree'),
                                      tips['openwrt/openwrt']['source']['commit'])
        tips['openwrt/openwrt'] = event('openwrt/openwrt', next_commit['sha'],
                                        next_commit['commit']['tree']['sha'])
        current_raw = json_bytes(current)
        successor = checkpoint(tips, current['decisions'],
                               hashlib.sha256(current_raw).hexdigest())
        gap_doc = gap_record(current, successor, [next_commit])
        successor_bundle = self.fx.bundle(1004, 1, successor, prior_run=1002,
                                          prior_attempt=1, gap=gap_doc)
        with self.assertRaisesRegex(intake.IntakeError, 'stored backlog rows differ'):
            self.fx.run_intake(current_bundle, successor_bundle)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM intakes').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT run_id FROM cursor').fetchone()[0], 1002)

    def test_sql_transaction_rolls_back_all_rows_cursor_and_receipt(self):
        _, _, _, prev_bundle, current_bundle, commits = self.fx.make_initial_pair()
        original_check = intake._initialize_or_check_schema

        def install_after_schema_check(connection):
            original_check(connection)
            connection.execute(f'''CREATE TRIGGER fail_second_backlog_row
                BEFORE INSERT ON commit_backlog
                WHEN NEW.commit_sha = '{commits[1]['sha']}'
                BEGIN SELECT RAISE(ABORT, 'injected row failure'); END''')

        with patch.object(intake, '_initialize_or_check_schema',
                          side_effect=install_after_schema_check):
            with self.assertRaisesRegex(intake.IntakeError, 'transaction failed'):
                self.fx.run_intake(prev_bundle, current_bundle)
        with self.db() as db:
            for table in ('intakes', 'commit_backlog', 'receipts', 'cursor'):
                self.assertEqual(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)

    def test_private_store_and_database_aliases_rejected(self):
        mode_bad = self.fx.parent / 'mode-bad'
        mode_bad.mkdir(mode=0o700)
        os.chmod(mode_bad, 0o755)
        with self.assertRaisesRegex(intake.IntakeError, 'mode 0700'):
            intake.private_root(mode_bad)

        database = self.fx.private / 'default-branch-backlog.sqlite3'
        database.write_bytes(b'not a database')
        os.chmod(database, 0o600)
        alias = self.fx.parent / 'db-hardlink'
        os.link(database, alias)
        with self.assertRaisesRegex(intake.IntakeError, 'singly linked'):
            intake._ensure_database(self.fx.private)

        database.unlink()
        target = self.fx.parent / 'target'
        target.write_bytes(b'outside')
        database.symlink_to(target)
        with self.assertRaisesRegex(intake.IntakeError, 'symlink'):
            intake._ensure_database(self.fx.private)


if __name__ == '__main__':
    unittest.main()
