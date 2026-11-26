import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from policy.tests import test_issuer_consumer_prerequisite as base_fixture
from tools.event_corpus_manifest import POLICY_SHA256
from tools.issuer_consumer_prerequisite import check_event_and_control


class PairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.scans = []
        for name in ('event-corpus', 'control-corpus'):
            directory = self.root / name
            directory.mkdir()
            fake = type('Temporary', (), {'name': str(directory), 'cleanup': lambda self: None})()
            fixture = base_fixture.ConsumerGraphTests('test_real_consumer_replay')
            with patch('policy.tests.test_issuer_consumer_prerequisite.tempfile.TemporaryDirectory', return_value=fake):
                fixture.setUp()
            self.scans.append(fixture)
        self.event, self.control = self.scans
        self.lock = self.event.lock
        self.write(self.root / 'lock.json', self.lock)
        self.incoming = {'schema': 'incoming-event-receipt-v1', 'status': 'identities_resolved_only',
                         'repository': 'luci', 'pr_number': 42,
                         'source': {'commit': 'e'*40, 'tree': '1'*40},
                         'control': {'commit': '2'*40, 'tree': '3'*40},
                         'base': {'commit': '4'*40, 'tree': '5'*40}}
        self.write(self.root / 'incoming.json', self.incoming)
        self.inventory = {'base_commit': '6'*40, 'base_tree': '7'*40, 'head_commit': '2'*40, 'head_tree': '3'*40}
        self.write(self.inputs / 'control-inventory.json', self.inventory)
        derived = dict(self.incoming, source=self.incoming['control'], base={'commit': '6'*40, 'tree': '7'*40})
        self.write(self.inputs / 'control-derived-receipt.json', derived)
        for fixture, identity, role, receipt in [(self.event, self.incoming['source'], None, self.root / 'incoming.json'),
                                                 (self.control, self.incoming['control'], 'clean_control', self.inputs / 'control-derived-receipt.json')]:
            fixture.manifest['event'] = {'repository': 'luci', 'pr_number': 42, 'head_commit': identity['commit'], 'head_tree': identity['tree'], 'identity_receipt_sha256': base_fixture.digest(receipt), 'policy_sha256': POLICY_SHA256, 'base_commit': (derived if role else self.incoming)['base']['commit'], 'base_tree': (derived if role else self.incoming)['base']['tree']}
            if role:
                fixture.manifest['event'].update(source_role=role, candidate_inventory_sha256=base_fixture.digest(self.inputs / 'control-inventory.json'))
                fixture.manifest['pins']['luci'] = identity['commit']
                fixture.manifest['selected'][0]['source_commit'] = identity['commit']
                fixture.manifest_path = self.inputs / 'control-manifest.json'
            self.write(fixture.manifest_path, fixture.manifest)
            fixture.write_graph()
        self.binding = {'schema': 'incoming-control-binding-v1', 'incoming_receipt_sha256': base_fixture.digest(self.root / 'incoming.json'), 'repository': 'luci', 'control': self.incoming['control'], 'policy_sha256': POLICY_SHA256, 'derived_receipt_sha256': base_fixture.digest(self.inputs / 'control-derived-receipt.json'), 'inventory_sha256': base_fixture.digest(self.inputs / 'control-inventory.json'), 'manifest_sha256': base_fixture.digest(self.inputs / 'control-manifest.json'), 'limitations': ['Derived receipt is an oracle adapter, not a PR membership claim.', 'A clean scan means zero results for this bounded source-staged corpus, not proof of safety.']}
        self.write(self.inputs / 'control-binding.json', self.binding)
        r3 = {'status': 'accepted', 'preflight': {'run_id': 'job/1', 'consumer_sha': '9'*40, 'lock_sha256': base_fixture.digest(self.root / 'lock.json')}, 'release': {'tag': 'v1', 'producer_commit': 'a'*40, 'asset_sha256': 'b'*64, 'isImmutable': True}, 'codeql': {'binary_sha256': 'd'*64}}
        self.write(self.root / 'receipt.json', r3)
        for fixture in self.scans:
            preflight = json.loads((fixture.root / 'preflight.json').read_text())
            preflight['r3_receipt_sha256'] = base_fixture.digest(self.root / 'receipt.json')
            self.write(fixture.root / 'preflight.json', preflight)
        self.assertion = {'schema': 'incoming-clean-control-assertion-v1', 'status': 'clean_scan', 'binding_sha256': base_fixture.digest(self.inputs / 'control-binding.json'), 'scan_receipt_sha256': base_fixture.digest(self.control.root / 'receipt.json'), 'triage_sha256': base_fixture.digest(self.control.root / 'out/triage.json'), 'result_count': 0}
        self.write(self.control.root / 'control-assertion.json', self.assertion)

    def write(self, path, obj):
        path.write_text(json.dumps(obj) + '\n')

    def verify(self):
        return check_event_and_control(self.root, self.event.manifest_path, self.event.manifest, self.inputs, self.control.manifest, self.root / 'incoming.json', self.root / 'lock.json', self.lock, 'job/1', '9'*40)

    def test_clean_distinct_control(self):
        self.assertEqual(self.verify()[1]['status'], 'clean_scan')

    def test_distinct_commit_with_identical_tree_is_not_a_control(self):
        bad = copy.deepcopy(self.incoming)
        bad['control']['tree'] = bad['source']['tree']
        self.write(self.root / 'incoming.json', bad)
        with self.assertRaisesRegex(RuntimeError, 'commits and trees must differ'):
            self.verify()

    def test_each_assertion_link(self):
        for field in ('binding_sha256', 'scan_receipt_sha256', 'triage_sha256', 'status', 'result_count'):
            with self.subTest(field=field):
                altered = dict(self.assertion, **{field: 'wrong'})
                self.write(self.control.root / 'control-assertion.json', altered)
                with self.assertRaisesRegex(RuntimeError, 'control assertion mismatch'):
                    self.verify()

    def test_swapped_binding_and_duplicate_keys(self):
        bad = copy.deepcopy(self.binding)
        bad['incoming_receipt_sha256'] = '0'*64
        self.write(self.inputs / 'control-binding.json', bad)
        with self.assertRaisesRegex(RuntimeError, 'control binding mismatch'):
            self.verify()
        (self.inputs / 'control-binding.json').write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(RuntimeError, 'duplicate JSON'):
            self.verify()

    def test_same_control_and_changed_run_or_lock(self):
        for mutate in ('same', 'run', 'lock'):
            with self.subTest(mutate=mutate):
                if mutate == 'same':
                    bad = dict(self.incoming, control=self.incoming['source'])
                    self.write(self.root / 'incoming.json', bad)
                elif mutate == 'run':
                    self.write(self.root / 'incoming.json', self.incoming)
                    pre = json.loads((self.control.root / 'preflight.json').read_text())
                    pre['run_id'] = 'other/2'
                    self.write(self.control.root / 'preflight.json', pre)
                else:
                    pre['run_id'] = 'job/1'
                    self.write(self.control.root / 'preflight.json', pre)
                    self.write(self.root / 'lock.json', dict(self.lock, extra=True))
                with self.assertRaises((ValueError, RuntimeError)):
                    self.verify()

    def test_different_r3_receipt_or_swapped_control_manifest(self):
        path = self.control.root / 'preflight.json'
        preflight = json.loads(path.read_text())
        preflight['r3_receipt_sha256'] = '0'*64
        self.write(path, preflight)
        with self.assertRaisesRegex(RuntimeError, 'scan R3 receipt mismatch'):
            self.verify()
        preflight['r3_receipt_sha256'] = base_fixture.digest(self.root / 'receipt.json')
        self.write(path, preflight)
        self.write(self.inputs / 'control-manifest.json', self.event.manifest)
        with self.assertRaisesRegex(RuntimeError, 'control manifest bytes differ'):
            self.verify()

    def test_assertion_symlink(self):
        assertion = self.control.root / 'control-assertion.json'
        assertion.unlink()
        assertion.symlink_to(self.event.root / 'receipt.json')
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            self.verify()

    def test_nonempty_control_and_failure_marker(self):
        self.control.sarif['runs'][0]['results'] = [{'ruleId': self.control.rule, 'level': 'warning', 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'a.uc', 'uriBaseId': '%SRCROOT%'}, 'region': {'startLine': 1, 'startColumn': 1, 'endColumn': 2}}}]}]
        self.control.write_graph()
        pre = json.loads((self.control.root / 'preflight.json').read_text())
        pre['r3_receipt_sha256'] = base_fixture.digest(self.root / 'receipt.json')
        self.write(self.control.root / 'preflight.json', pre)
        with self.assertRaisesRegex(RuntimeError, 'control produced findings'):
            self.verify()
        (self.inputs / 'control-failure.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'failure marker'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
