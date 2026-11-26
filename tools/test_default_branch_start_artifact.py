import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import default_branch_start_artifact as early


RUN_ID = '900'
ATTEMPT = '2'
CONSUMER = 'f' * 40
REPOSITORY = 'lucas-albers-lz4/codeql-openwrt'


class DefaultBranchStartArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.inputs = self.parent / f'default-branch-inputs-{RUN_ID}-{ATTEMPT}'
        self.output = self.parent / f'default-branch-start-{RUN_ID}-{ATTEMPT}'
        self.inputs.mkdir(mode=0o700)
        (self.inputs / 'previous').mkdir()
        (self.inputs / 'current' / 'gap').mkdir(parents=True)
        inventory_raw = b'{"inventory":"source-first"}\n'
        self.source = {
            'identity.json': b'{"identity":"resolved"}\n',
            'manifest.json': (json.dumps({'event': {
                'candidate_inventory_sha256': hashlib.sha256(inventory_raw).hexdigest(),
            }}, sort_keys=True) + '\n').encode(),
            'inventory.json': inventory_raw,
            'previous/decisions.json': b'{"checkpoint":"previous"}\n',
            'current/decisions.json': b'{"checkpoint":"current"}\n',
            'current/gap/gap.json': b'{"gap":"linked"}\n',
        }
        for name, raw in self.source.items():
            path = self.inputs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.origin = {
            'previous_run_id': 101, 'previous_attempt': 3,
            'current_run_id': 202, 'current_attempt': 4,
        }
        self.api_raw = {
            'previous-run-api.json': self.run_api(101, 3),
            'current-run-api.json': self.run_api(202, 4),
        }
        for name, raw in self.api_raw.items():
            (self.inputs / name).write_bytes(raw)
        self.claim_value = {
            'schema': 'default-branch-reservation-claim-v1',
            'status': 'claimed_unverified',
            'asserted_reservation': {
                'queue_id': '0' * 32,
                'reservation_sequence': 7,
                'reservation_sha256': '8' * 64,
            },
            'derived_source': {'repository': 'openwrt/luci', 'commit_sha': 'a' * 40},
            'linked_discovery_origin': self.origin,
            'execution': {
                'workflow_run_id': int(RUN_ID),
                'workflow_run_attempt': int(ATTEMPT),
                'consumer_head': CONSUMER,
            },
            'linked_input_sha256': {
                'identity_receipt': self.sha('identity.json'),
                'manifest': self.sha('manifest.json'),
                'previous_checkpoint': self.sha('previous/decisions.json'),
                'current_checkpoint': self.sha('current/decisions.json'),
                'gap': self.sha('current/gap/gap.json'),
            },
        }
        self.write_claim()
        self.env = patch.dict(os.environ, {
            'GITHUB_RUN_ID': RUN_ID,
            'GITHUB_RUN_ATTEMPT': ATTEMPT,
            'GITHUB_SHA': CONSUMER,
            'GITHUB_REPOSITORY': REPOSITORY,
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def sha(self, name):
        return hashlib.sha256(self.source[name]).hexdigest()

    @staticmethod
    def run_api(run_id, attempt):
        return (json.dumps({
            'id': run_id,
            'run_attempt': attempt,
            'repository': {'full_name': REPOSITORY},
            'path': '.github/workflows/incoming-discovery-manual.yml',
            'event': 'schedule' if run_id == 101 else 'workflow_dispatch',
            'head_branch': 'main',
            'status': 'completed',
            'conclusion': 'success',
        }, sort_keys=True) + '\n').encode()

    def write_claim(self):
        raw = (json.dumps(self.claim_value, sort_keys=True, indent=2) + '\n').encode()
        (self.inputs / 'reservation-claim.json').write_bytes(raw)

    def test_claimed_positive_freezes_exact_bytes_and_per_file_hashes(self):
        self.assertEqual(early.freeze(self.inputs, self.output), 'claimed')
        expected = {
            'reservation-claim.json': (self.inputs / 'reservation-claim.json').read_bytes(),
            **self.source,
            **self.api_raw,
        }
        receipt = json.loads((self.output / 'receipt.json').read_bytes())
        self.assertEqual(receipt['schema'], 'mvp-default-branch-early-start-observation-v1')
        self.assertEqual(receipt['status'], 'retained_non_issuing')
        self.assertEqual(receipt['reservation_claim_status'], 'claimed_unverified')
        self.assertEqual(set(receipt['files']), set(expected))
        for name, raw in expected.items():
            frozen_path = self.output / name
            frozen = frozen_path.read_bytes()
            self.assertEqual(frozen, raw)
            self.assertEqual((frozen_path.stat().st_mode & 0o777), 0o600)
            self.assertEqual(receipt['files'][name], {
                'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        self.assertEqual((self.output.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((self.output / 'current').stat().st_mode & 0o777), 0o700)
        self.assertEqual((self.output / 'previous' / 'decisions.json').read_bytes(),
                         self.source['previous/decisions.json'])
        self.assertEqual((self.output / 'current' / 'gap' / 'gap.json').read_bytes(),
                         self.source['current/gap/gap.json'])

    def test_absent_claim_creates_no_early_artifact(self):
        self.claim_value['status'] = 'absent'
        self.claim_value['asserted_reservation'] = None
        self.write_claim()
        self.assertEqual(early.freeze(self.inputs, self.output), 'absent')
        self.assertFalse(self.output.exists())

    def test_partial_claim_does_not_create_an_artifact(self):
        del self.claim_value['asserted_reservation']['reservation_sha256']
        self.write_claim()
        with self.assertRaisesRegex(early.ArtifactError, 'incomplete'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_changed_claim_bound_source_fails_before_output(self):
        (self.inputs / 'current' / 'decisions.json').write_bytes(b'{"checkpoint":"mutated"}\n')
        with self.assertRaisesRegex(early.ArtifactError, 'claim-bound source bytes changed'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_changed_inventory_fails_manifest_digest_check(self):
        (self.inputs / 'inventory.json').write_bytes(b'{"inventory":"mutated"}\n')
        with self.assertRaisesRegex(early.ArtifactError,
                                   'candidate inventory bytes differ'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_symlink_source_is_rejected_before_output(self):
        path = self.inputs / 'previous' / 'decisions.json'
        target = self.parent / 'outside.json'
        target.write_bytes(self.source['previous/decisions.json'])
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(early.ArtifactError, 'unsafe or missing input file'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_hardlink_source_is_rejected_before_output(self):
        path = self.inputs / 'previous' / 'decisions.json'
        os.link(path, self.parent / 'alias.json')
        with self.assertRaisesRegex(early.ArtifactError, 'input file has aliases'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_fifo_source_is_rejected_without_blocking(self):
        path = self.inputs / 'previous' / 'decisions.json'
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(early.ArtifactError, 'not a regular file'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_run_api_mismatch_is_rejected_before_output(self):
        changed = json.loads(self.api_raw['current-run-api.json'])
        changed['run_attempt'] = 99
        (self.inputs / 'current-run-api.json').write_text(json.dumps(changed) + '\n')
        with self.assertRaisesRegex(early.ArtifactError, 'run API response differs'):
            early.freeze(self.inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir(mode=0o700)
        marker = self.output / 'keep.txt'
        marker.write_text('untouched')
        with self.assertRaisesRegex(early.ArtifactError, 'new and exclusive'):
            early.freeze(self.inputs, self.output)
        self.assertEqual(marker.read_text(), 'untouched')

    def test_workflow_contract_gates_early_upload_and_keeps_final_artifact(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    '.github/workflows/default-branch-commit-scan.yml').read_text()
        claim = workflow.index('Retain same-job default-branch reservation claim')
        prepare = workflow.index('Prepare early non-issuing default-branch observation')
        upload = workflow.index('Upload early non-issuing default-branch observation')
        release = workflow.index('Verify pinned immutable release in same job')
        scan = workflow.index('Scan full source-first corpus and pass actual SARIF to consumer')
        final = workflow.index('Retain linked inputs and released scan outputs')
        self.assertLess(claim, prepare)
        self.assertLess(prepare, upload)
        self.assertLess(upload, release)
        self.assertLess(release, scan)
        self.assertLess(scan, final)
        self.assertIn('tools.default_branch_start_artifact', workflow)
        self.assertIn("if: steps.early-start.outputs.claimed == 'true'", workflow)
        self.assertIn('default-branch-start-${{ github.run_id }}-${{ github.run_attempt }}', workflow)
        self.assertIn('tools.test_default_branch_start_artifact', workflow)
        final_block = workflow[final:]
        self.assertIn('if: always()', final_block)
        self.assertIn('default-branch-scan-${{ github.run_id }}-${{ github.run_attempt }}', final_block)
        self.assertIn('reservation-claim.json', final_block)


if __name__ == '__main__':
    unittest.main()
