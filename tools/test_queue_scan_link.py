import hashlib
import hmac
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incoming_queue import apply_attested, encoded, open_queue
from incoming_queue_issued import issue_start
from issuer_artifact_freeze import INPUT_FILES, R3_OUT, SCAN_OUT
from queue_scan_link import LinkError, verify


class ScanLinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.database = self.root / 'queue.db'
        self.artifact = self.root / 'artifact'
        self.freeze = self.artifact / 'issuer-freeze-123-1'
        self.snapshot = self.freeze / 'snapshot'
        self.snapshot.mkdir(parents=True)
        self.head, self.base, self.consumer, self.tree = ('a'*40, 'b'*40, 'c'*40, 'd'*40)
        self.event_id = json.dumps(['openwrt/openwrt', 'pull_request', 17, self.head],
                                   separators=(',', ':'))
        self.reservation = {'schema': 'incoming-queue-manual-reservation-v1',
                            'status': 'reserved_only', 'queue_id': '', 'sequence': 2,
                            'observed_at': '2026-01-01T00:00:00Z', 'event_id': self.event_id,
                            'source': {'commit': self.head, 'tree': None}, 'control_sha': self.base}
        self.event = {'source': {'commit': self.head, 'tree': None}, 'base_commit': self.base}
        self.write_queue()
        self.run_api = self.root / 'run-api.json'
        self.run_api.write_bytes(encoded({'id': 123, 'run_attempt': 1,
            'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success',
            'head_sha': self.consumer, 'path': '.github/workflows/incoming-event-preflight.yml',
            'repository': {'full_name': 'lucas-albers-lz4/codeql-openwrt'},
            'created_at': '2026-01-01T00:01:00Z'}))
        self.files = {}
        for name in INPUT_FILES:
            self.files['inputs/' + name] = {}
        for role in ('event', 'control'):
            for name in SCAN_OUT:
                self.files[f'{role}/out/{name}'] = {}
            for name in ('preflight.json', 'receipt.json', 'commands.json'):
                self.files[f'{role}/{name}'] = {}
            self.files[f'{role}/commands/one.time'] = '0.1'
            self.files[f'{role}/stage/one.uc'] = 'let x = 1;'
        self.files['control/control-assertion.json'] = {}
        for name in ('preflight.json', 'receipt.json', 'commands.json'):
            self.files['r3/' + name] = {}
        self.files['r3/commands/one.time'] = '0.1'
        for case in ('openvpn-parent', 'openvpn-fixed'):
            for name in R3_OUT:
                self.files[f'r3/out/{case}/{name}'] = {}
        source = {'commit': self.head, 'tree': self.tree}
        receipt = {'repository': 'openwrt', 'pr_number': 17, 'source': source,
                   'base': {'commit': self.base}, 'control': {'commit': self.base}}
        self.files['inputs/incoming-event-receipt.json'] = receipt
        self.files['inputs/replayed-receipt.json'] = receipt
        self.files['inputs/scan-pull-api-response.json'] = {
            'head': {'sha': self.head}, 'base': {'sha': self.base}}
        self.files['inputs/consumer-graph.json'] = self.graph()
        event_info = {'head_commit': self.head, 'head_tree': self.tree,
                      'base_commit': self.base, 'base_tree': 'e'*40,
                      'repository': 'openwrt', 'pr_number': 17}
        self.files['inputs/incoming-event-receipt.json']['base']['tree'] = 'e'*40
        self.files['inputs/replayed-receipt.json']['base']['tree'] = 'e'*40
        self.files['inputs/event-corpus-manifest.json'] = {
            'event': event_info, 'pins': {'openwrt': self.head},
            'counts': {'selected': 1}}
        self.files['event/receipt.json'] = {
            'schema': 'ucode-event-corpus-linux-v1', 'status': 'clean_scan',
            'run_id': '123-1', 'consumer_sha': self.consumer, 'event': event_info,
            'source_pins': {'openwrt': self.head},
            'release_tag': 'v-test', 'producer_commit': 'f'*40,
            'selected_count': 1, 'successful_count': 1, 'extraction_error_count': 0}
        self.files['event/out/triage.json'] = {'status': 'clean_scan', 'run_id': '123-1',
                                                'result_count': 0, 'results_for_triage': []}
        self.files['control/control-assertion.json'] = {
            'schema': 'incoming-clean-control-assertion-v1',
            'status': 'clean_scan', 'result_count': 0}
        self.files['release-lock.json'] = {'release': {'tag': 'v-test', 'commit': 'f'*40}}
        control_event = {'head_commit': self.base, 'head_tree': 'e'*40,
                         'repository': 'openwrt', 'pr_number': 17}
        self.files['inputs/control-oracle/control-manifest.json'] = {
            'event': control_event, 'pins': {'openwrt': self.base},
            'counts': {'selected': 1}}
        self.files['inputs/control-oracle/control-derived-receipt.json'] = {
            'source': {'commit': self.base, 'tree': 'e'*40}}
        self.files['inputs/incoming-event-receipt.json']['control']['tree'] = 'e'*40
        self.files['inputs/replayed-receipt.json']['control']['tree'] = 'e'*40
        self.files['control/receipt.json'] = {
            'schema': 'ucode-event-corpus-linux-v1', 'status': 'clean_scan',
            'run_id': '123-1', 'consumer_sha': self.consumer, 'event': control_event,
            'source_pins': {'openwrt': self.base}, 'release_tag': 'v-test',
            'producer_commit': 'f'*40, 'selected_count': 1,
            'successful_count': 1, 'extraction_error_count': 0}
        self.files['control/out/triage.json'] = {
            'status': 'clean_scan', 'run_id': '123-1', 'result_count': 0}
        self.files['r3/receipt.json'] = {
            'schema': 'ucode-r3-linux-handoff-v1', 'status': 'accepted',
            'release': {'tag': 'v-test', 'producer_commit': 'f'*40},
            'preflight': {'run_id': '123-1', 'consumer_sha': self.consumer}}
        self.write_freeze()

    def graph(self):
        return {'schema': 'incoming-consumer-graph-workflow-v1', 'status': 'checked',
                'run_id': '123-1', 'consumer_sha': self.consumer,
                'event_status': 'clean_scan', 'control_status': 'clean_scan'}

    def write_queue(self):
        db = open_queue(self.database, create=True)
        self.reservation['queue_id'] = db.execute(
            "select value from metadata where key='queue_id'").fetchone()[0]
        raw = encoded(self.reservation)
        digest = hashlib.sha256(raw).hexdigest()
        db.execute('insert into history values (?,?,?)', (2, digest, raw))
        db.execute('insert into events values (?,?,?,?,?,?,?,?,?,?,?)',
                   (self.event_id, '["openwrt/openwrt","pull_request",17]', encoded(self.event),
                    '2026-01-01T00:00:00Z', 'reserved', 0, None, 'manual_reserved', 2, digest, None))
        db.commit()
        db.close()

    def write_freeze(self):
        manifest = encoded(self.files['inputs/event-corpus-manifest.json'])
        sarif = encoded(self.files['event/out/default-suite.sarif'])
        self.files['event/receipt.json']['manifest_sha256'] = hashlib.sha256(manifest).hexdigest()
        self.files['event/receipt.json']['sarif_sha256'] = hashlib.sha256(sarif).hexdigest()
        self.files['event/receipt.json']['coverage_sha256'] = hashlib.sha256(
            encoded(self.files['event/out/coverage-event.json'])).hexdigest()
        self.files['event/out/triage.json']['sarif_sha256'] = hashlib.sha256(sarif).hexdigest()
        self.files['event/receipt.json']['accepted_sha256'] = hashlib.sha256(
            encoded(self.files['event/out/triage.json'])).hexdigest()
        self.files['control/receipt.json']['manifest_sha256'] = hashlib.sha256(
            encoded(self.files['inputs/control-oracle/control-manifest.json'])).hexdigest()
        self.files['control/out/triage.json']['sarif_sha256'] = hashlib.sha256(
            encoded(self.files['control/out/default-suite.sarif'])).hexdigest()
        self.files['control/receipt.json']['sarif_sha256'] = self.files['control/out/triage.json']['sarif_sha256']
        self.files['control/control-assertion.json']['scan_receipt_sha256'] = hashlib.sha256(
            encoded(self.files['control/receipt.json'])).hexdigest()
        self.files['control/control-assertion.json']['triage_sha256'] = hashlib.sha256(
            encoded(self.files['control/out/triage.json'])).hexdigest()
        self.files['control/control-assertion.json']['binding_sha256'] = hashlib.sha256(
            encoded(self.files['inputs/control-oracle/control-binding.json'])).hexdigest()
        self.files['r3/receipt.json']['preflight']['lock_sha256'] = hashlib.sha256(
            encoded(self.files['release-lock.json'])).hexdigest()
        for rel, value in self.files.items():
            path = self.snapshot / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(encoded(value))
        self.freeze.joinpath('graph-recheck.json').write_bytes(encoded(self.graph()))
        def meta(rel):
            raw = (self.snapshot / rel).read_bytes()
            return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        def group(role):
            return {
                'root': {name: meta(f'{role}/{name}') for name in
                         (('preflight.json','receipt.json','commands.json','control-assertion.json')
                          if role=='control' else ('preflight.json','receipt.json','commands.json'))},
                'out': {name: meta(f'{role}/out/{name}') for name in SCAN_OUT},
                'commands': {'one.time': meta(f'{role}/commands/one.time')},
                'stage': {'one.uc': meta(f'{role}/stage/one.uc')},
            }
        inventory = {'schema': 'incoming-artifact-freeze-v1', 'status': 'frozen',
            'run_id': '123-1', 'consumer_commit': self.consumer,
            'source_identities': {role: {'stage_files': ['one.uc']} for role in ('event','control')},
            'release_lock': meta('release-lock.json'),
            'graph_recheck': {'bytes': len(encoded(self.graph())),
                              'sha256': hashlib.sha256(encoded(self.graph())).hexdigest()},
            'artifacts': {
                'inputs': {name: meta('inputs/'+name) for name in INPUT_FILES},
                'event': group('event'), 'control': group('control'),
                'r3': {
                    'root': {name: meta('r3/'+name) for name in ('preflight.json','receipt.json','commands.json')},
                    'commands': {'one.time': meta('r3/commands/one.time')},
                    **{case: {name: meta(f'r3/out/{case}/{name}') for name in R3_OUT}
                       for case in ('openvpn-parent','openvpn-fixed')},
                },
            }}
        inventory['source_identities']['event']['checkout'] = {
            'commit': self.head, 'tree': self.tree}
        (self.freeze / 'inventory.json').write_bytes(encoded(inventory))

    def verify(self, require_claim=False):
        return verify(self.database, self.artifact, self.run_api, '123', 1,
                      self.consumer, require_claim)

    def set_claim(self):
        db = open_queue(self.database)
        digest = db.execute('select digest from history where seq=2').fetchone()[0]
        db.close()
        self.files['inputs/reservation-claim.json'] = {
            'schema': 'incoming-reservation-claim-v1', 'status': 'claimed_unverified',
            'run_id': '123-1', 'queue_id': self.reservation['queue_id'],
            'reservation_sequence': 2, 'reservation_sha256': digest,
            'event_id': self.event_id, 'source_sha': self.head,
            'control_sha': self.base}
        self.files['inputs/dispatch-inputs.json'] = {
            'schema': 'incoming-dispatch-inputs-v1', 'status': 'claimed_unverified',
            'run_id': '123-1', 'upstream': 'openwrt', 'pr_number': 17,
            'source_sha': self.head, 'control_sha': self.base,
            'queue_id': self.reservation['queue_id'], 'reservation_sequence': 2,
            'reservation_sha256': digest}
        self.write_freeze()

    def test_exact_link_is_read_only(self):
        before = self.database.read_bytes()
        result = self.verify()
        self.assertEqual(result['status'], 'linked_only')
        self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse(self.database.with_name('queue.db-journal').exists())

    def start_queue(self, run_id='123-1'):
        db = open_queue(self.database)
        digest = db.execute('select digest from history where seq=2').fetchone()[0]
        job = {'workflow': '.github/workflows/incoming-event-preflight.yml',
               'job': 'released-event-scan', 'run_id': 123, 'attempt': 1}
        payload = {'kind': 'start', 'queue_id': self.reservation['queue_id'],
                   'event_id': self.event_id, 'reservation': 2,
                   'reservation_digest': digest, 'run_id': run_id, 'job': job}
        key = b'k' * 32
        mac = hmac.new(key, encoded(payload), hashlib.sha256).hexdigest()
        try:
            apply_attested(db, (2, digest), payload, mac, key,
                           '2026-01-01T00:01:30Z')
        finally:
            db.close()

    def test_exact_link_after_signed_start(self):
        self.set_claim()
        self.start_queue()
        before = self.database.read_bytes()
        result = self.verify(require_claim=True)
        self.assertEqual(result['queue_state'], 'started')
        self.assertEqual(result['reservation_sequence'], 2)
        self.assertEqual(self.database.read_bytes(), before)

    def test_wrong_started_run_rejected(self):
        self.set_claim()
        self.start_queue(run_id='999-1')
        with self.assertRaisesRegex(LinkError, 'matching recorded start'):
            self.verify(require_claim=True)

    def test_exact_link_after_issued_start(self):
        self.set_claim()
        db = open_queue(self.database)
        digest = db.execute('select digest from history where seq=2').fetchone()[0]
        payload = {'schema': 'incoming-issued-start-v1', 'kind': 'start',
                   'queue_id': self.reservation['queue_id'],
                   'event_id': self.event_id, 'reservation': 2,
                   'reservation_digest': digest, 'run_id': '123-1',
                   'job': {'workflow': '.github/workflows/incoming-event-preflight.yml',
                           'job': 'released-event-scan', 'run_id': 123,
                           'attempt': 1, 'id': 456,
                           'consumer_commit': self.consumer},
                   'source_sha': self.head, 'control_sha': self.base,
                   'policy_sha256': '1'*64,
                   'early_artifact': {'id': 789, 'sha256': '2'*64},
                   'observation_sha256': '3'*64,
                   'run_api_sha256': '4'*64, 'jobs_api_sha256': '5'*64,
                   'artifacts_api_sha256': '6'*64,
                   'recheck_run_api_sha256': '7'*64,
                   'recheck_jobs_api_sha256': '8'*64}
        try:
            issue_start(db, (2, digest), payload, b'k'*32,
                        '2026-01-01T00:01:30Z')
        finally:
            db.close()
        result = self.verify(require_claim=True)
        self.assertEqual(result['queue_state'], 'started')
        self.assertEqual(result['started_job_id'], 456)

    def test_same_job_claim_is_required_when_requested(self):
        with self.assertRaisesRegex(LinkError, 'claim missing'):
            self.verify(require_claim=True)
        self.set_claim()
        self.assertTrue(self.verify(require_claim=True)['claim_bound'])

    def test_wrong_same_job_claim_rejected(self):
        self.set_claim()
        self.files['inputs/reservation-claim.json']['reservation_sha256'] = '0'*64
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'reservation claim mismatch'):
            self.verify(require_claim=True)

    def test_wrong_pre_resolution_dispatch_rejected(self):
        self.set_claim()
        self.files['inputs/dispatch-inputs.json']['control_sha'] = 'e'*40
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'pre-resolution dispatch inputs'):
            self.verify(require_claim=True)

    def test_boolean_dispatch_sequence_rejected(self):
        self.set_claim()
        self.files['inputs/dispatch-inputs.json']['reservation_sequence'] = True
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'pre-resolution dispatch inputs'):
            self.verify(require_claim=True)

    def test_changed_snapshot_file_rejected(self):
        (self.snapshot / 'event/receipt.json').write_text('{}')
        with self.assertRaisesRegex(LinkError, 'snapshot hash mismatch'):
            self.verify()

    def test_changed_source_rejected_even_with_matching_freeze_hash(self):
        self.files['inputs/incoming-event-receipt.json']['source']['commit'] = 'e'*40
        self.files['inputs/replayed-receipt.json']['source']['commit'] = 'e'*40
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'PR source identity mismatch'):
            self.verify()

    def test_wrong_reservation_digest_rejected(self):
        db = open_queue(self.database)
        db.execute("update events set reservation_digest='0' where id=?", (self.event_id,))
        db.commit(); db.close()
        with self.assertRaisesRegex(LinkError, 'queue event is not held'):
            self.verify()

    def test_missing_snapshot_file_rejected(self):
        (self.snapshot / 'control/control-assertion.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_incomplete_freeze_inventory_rejected(self):
        path = self.freeze / 'inventory.json'
        data = json.loads(path.read_bytes())
        data['artifacts']['r3'] = {}
        path.write_bytes(encoded(data))
        with self.assertRaisesRegex(LinkError, 'incomplete R3 inventory'):
            self.verify()

    def test_run_before_reservation_rejected(self):
        data = json.loads(self.run_api.read_bytes())
        data['created_at'] = '2025-12-31T23:59:00Z'
        self.run_api.write_bytes(encoded(data))
        with self.assertRaisesRegex(LinkError, 'predates reservation'):
            self.verify()

    def test_wrong_run_identity_rejected(self):
        data = json.loads(self.run_api.read_bytes())
        data['run_attempt'] = 2
        self.run_api.write_bytes(encoded(data))
        with self.assertRaisesRegex(LinkError, 'run metadata does not match'):
            self.verify()

    def test_control_receipt_other_run_rejected_with_matching_freeze(self):
        self.files['control/receipt.json']['run_id'] = 'other-run'
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'clean-control identity'):
            self.verify()

    def test_r3_failure_rejected_with_matching_freeze(self):
        self.files['r3/receipt.json']['status'] = 'failed'
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'released R3 prerequisite'):
            self.verify()

    def test_intermediate_snapshot_symlink_rejected(self):
        original = self.snapshot / 'inputs'
        moved = self.root / 'moved-inputs'
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(LinkError, 'snapshot contains symlink'):
            self.verify()

    def test_changed_manifest_pr_rejected_even_with_matching_hashes(self):
        self.files['inputs/event-corpus-manifest.json']['event']['pr_number'] = 18
        self.files['event/receipt.json']['event']['pr_number'] = 18
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'source, manifest or SARIF binding'):
            self.verify()

    def test_graph_consumer_mismatch_rejected_even_with_matching_hashes(self):
        self.files['inputs/consumer-graph.json']['consumer_sha'] = 'e'*40
        self.write_freeze()
        with self.assertRaisesRegex(LinkError, 'same-run graph or scan mismatch'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
