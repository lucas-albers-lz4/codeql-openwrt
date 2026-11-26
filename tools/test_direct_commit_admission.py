import copy
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import direct_commit_admission as admission
from tools import incoming_event
from tools import incoming_poll as poll


class DirectCommitAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.git('init', '-q', str(self.repo))
        self.git('-C', str(self.repo), 'config', 'user.email', 'test@example.invalid')
        self.git('-C', str(self.repo), 'config', 'user.name', 'Test')
        self.git('-C', str(self.repo), 'remote', 'add', 'origin', incoming_event.REPOSITORIES['luci'])
        paths = {'package_recipe': 'protocols/luci-proto-openvpn/Makefile',
                 'shared_recipe': 'luci.mk',
                 'ucode_source': 'protocols/luci-proto-openvpn/root/usr/share/rpcd/ucode/luci.openvpn.uc'}
        (self.repo / 'luci.mk').write_text('cp -pR $(PKG_BUILD_DIR)/root/* $(1)/\n')
        self.git('-C', str(self.repo), 'add', '.')
        self.git('-C', str(self.repo), 'commit', '-qm', 'parent')
        parent = self.git('-C', str(self.repo), 'rev-parse', 'HEAD')
        for key in ('package_recipe', 'ucode_source'):
            (self.repo / paths[key]).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / paths['package_recipe']).write_text('include ../../luci.mk\nLUCI_DEPENDS:=+openvpn\n')
        (self.repo / paths['ucode_source']).write_text('let value = 1;\n')
        self.git('-C', str(self.repo), 'add', '.')
        self.git('-C', str(self.repo), 'commit', '-qm', 'introduce')
        source = self.git('-C', str(self.repo), 'rev-parse', 'HEAD')
        (self.repo / paths['ucode_source']).write_text('let value = 2;\n')
        self.git('-C', str(self.repo), 'commit', '-qam', 'fix')
        fixed = self.git('-C', str(self.repo), 'rev-parse', 'HEAD')
        self.source = self.root / 'source'
        self.control = self.root / 'control'
        for checkout, sha in ((self.source, source), (self.control, fixed)):
            self.git('clone', '-q', str(self.repo), str(checkout))
            self.git('-C', str(checkout), 'remote', 'set-url', 'origin',
                     incoming_event.REPOSITORIES['luci'])
            self.git('-C', str(checkout), 'checkout', '-q', sha)
        commits = {'absent_parent': parent, 'introduced': source, 'fixed': fixed}
        self.oracle = {'commits': commits, 'paths': paths,
                       'identities': {name: {kind: admission.object_at(
                           self.control if name == 'fixed' else self.source, sha, path)[0]
                           for kind, path in paths.items()} for name, sha in commits.items()},
                       'proposed_installed_path': 'usr/share/rpcd/ucode/luci.openvpn.uc',
                       'proposed_route': {'classification': 'plain', 'reason': 'rpcd_raw_mode_full_path'}}
        self.identity = {'schema': 'default-branch-event-identity-v1',
                         'status': 'identities_resolved_only', 'repository': 'openwrt/luci',
                         'ref': 'master', 'gap_sha256': 'a'*64,
                         'previous_checkpoint_sha256': 'b'*64,
                         'current_checkpoint_sha256': 'c'*64,
                         'source': self.commit_identity(source), 'base': self.commit_identity(parent),
                         'control': self.commit_identity(fixed)}
        self.frozen = patch.object(admission, 'frozen_oracle', return_value=self.oracle)
        self.frozen.start()
        self.addCleanup(self.frozen.stop)

    @staticmethod
    def git(*args):
        return subprocess.check_output(['git', *args], text=True).strip()

    def commit_identity(self, sha):
        return {'commit': sha, 'tree': self.git('-C', str(self.repo), 'rev-parse', sha + '^{tree}')}

    def verify(self, identity=None):
        return admission.verify(self.identity if identity is None else identity,
                                self.source, self.control)

    def test_source_first_admission_is_identity_only(self):
        got = self.verify()
        self.assertEqual(got['status'], 'source_policy_input_verified_only')
        self.assertNotIn('sarif', got)
        self.assertNotIn('gap_sha256', got)

    def test_historical_identity_has_no_synthetic_checkpoint_digests(self):
        identity = copy.deepcopy(self.identity)
        identity['schema'] = 'historical-direct-commit-source-identity-v1'
        identity['status'] = 'historical_objects_resolved_only'
        identity['policy_ref_context'] = identity.pop('ref')
        for key in ('gap_sha256', 'previous_checkpoint_sha256',
                    'current_checkpoint_sha256'):
            del identity[key]
        self.assertEqual(self.verify(identity)['status'],
                         'source_policy_input_verified_only')
        identity['gap_sha256'] = 'a' * 64
        with self.assertRaisesRegex(poll.PollError, 'receipt differs'):
            self.verify(identity)

    def test_source_receipt_and_oracle_tamper_fail(self):
        with self.assertRaisesRegex(poll.PollError, 'not an object'):
            self.verify([])
        changed = copy.deepcopy(self.identity)
        changed['base'] = None
        with self.assertRaisesRegex(poll.PollError, 'base commit differs'):
            self.verify(changed)
        changed = copy.deepcopy(self.identity)
        changed['source']['tree'] = '0' * 40
        with self.assertRaisesRegex(poll.PollError, 'checkout differs'):
            self.verify(changed)
        changed = copy.deepcopy(self.identity)
        changed['base']['tree'] = '0' * 40
        with self.assertRaisesRegex(poll.PollError, 'base tree differs'):
            self.verify(changed)
        self.oracle['identities']['introduced']['ucode_source']['sha256'] = '0' * 64
        with self.assertRaisesRegex(poll.PollError, 'ucode_source identity differs'):
            self.verify()

    def test_recipe_and_checkout_change_fail(self):
        self.oracle['identities']['introduced']['package_recipe']['sha256'] = '0' * 64
        with self.assertRaisesRegex(poll.PollError, 'package_recipe identity differs'):
            self.verify()
        self.oracle['identities']['introduced']['package_recipe']['sha256'] = hashlib.sha256(
            (self.source / self.oracle['paths']['package_recipe']).read_bytes()).hexdigest()
        (self.source / 'dirty').write_text('x')
        with self.assertRaisesRegex(poll.PollError, 'dirty'):
            self.verify()

    def test_large_blob_and_existing_output_fail(self):
        with patch.object(admission.event, 'safe_git', return_value=str(admission.MAX_BLOB + 1)):
            with self.assertRaisesRegex(poll.PollError, 'blob exceeds byte limit'):
                admission.object_at(self.source, self.identity['source']['commit'],
                                    self.oracle['paths']['ucode_source'])
        output = self.root / 'existing.json'
        output.write_text('keep')
        with self.assertRaises(FileExistsError):
            admission.event.write_receipt_exclusive(output, self.verify())
        self.assertEqual(output.read_text(), 'keep')


class FrozenAdmissionArtifactTests(unittest.TestCase):
    def test_committed_oracle_digest_and_source_identity(self):
        oracle = admission.frozen_oracle()
        self.assertEqual(hashlib.sha256(admission.ORACLE.read_bytes()).hexdigest(),
                         admission.ORACLE_SHA256)
        self.assertEqual(oracle['commits']['introduced'],
                         '5306e007656fe9a77aee2d2a94072d003b0b5a7d')
        self.assertEqual(oracle['identities']['introduced']['ucode_source']['sha256'],
                         '051c8162f826683333e11264615806df5ab08415676c0bd098921cb1b05af991')
        self.assertEqual(oracle['proposed_installed_path'],
                         'usr/share/rpcd/ucode/luci.openvpn.uc')

    def test_input_rejects_large_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            large = root / 'large'
            large.write_bytes(b'x' * 17)
            with self.assertRaisesRegex(poll.PollError, 'bounded'):
                admission.read_regular_bounded(large, 16)
            link = root / 'link'
            link.symlink_to(large)
            with self.assertRaises(OSError):
                admission.read_regular_bounded(link, 100)
            pipe = root / 'fifo'
            import os
            os.mkfifo(pipe)
            with self.assertRaisesRegex(poll.PollError, 'regular file'):
                admission.read_regular_bounded(pipe, 100)


if __name__ == '__main__':
    unittest.main()
