import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo

import operator_artifact_custody as custody


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.run_id = 123
        self.commit = 'a' * 40
        self.run = {'id': self.run_id, 'run_attempt': 1,
                    'repository': {'full_name': custody.REPO},
                    'path': custody.WORKFLOW, 'event': 'workflow_dispatch',
                    'head_sha': self.commit, 'status': 'completed', 'conclusion': 'success'}
        self.job = {'id': 456, 'name': 'released-event-scan', 'run_id': self.run_id,
                    'run_attempt': 1, 'head_sha': self.commit,
                    'status': 'completed', 'conclusion': 'success'}
        self.artifact = {'id': 789, 'name': 'released-event-123-1', 'expired': False,
                         'size_in_bytes': 20, 'workflow_run': {'id': self.run_id},
                         'digest': 'sha256:' + 'b' * 64}

    def verify(self):
        return custody.verify_api(self.run, {'total_count': 1, 'jobs': [self.job]},
                                  {'total_count': 1, 'artifacts': [self.artifact]},
                                  self.run_id, 1, self.commit)

    def test_exact_api_identity(self):
        self.assertEqual(self.verify()[0]['id'], 456)

    def test_wrong_job_or_incomplete_page_rejected(self):
        self.job['head_sha'] = 'c' * 40
        with self.assertRaises(custody.CustodyError):
            self.verify()
        self.job['head_sha'] = self.commit
        with self.assertRaises(custody.CustodyError):
            custody.verify_api(self.run, {'total_count': 2, 'jobs': [self.job]},
                               {'total_count': 1, 'artifacts': [self.artifact]},
                               self.run_id, 1, self.commit)

    def test_wrong_artifact_or_run_rejected(self):
        self.artifact['workflow_run']['id'] = 999
        with self.assertRaises(custody.CustodyError):
            self.verify()
        self.artifact['workflow_run']['id'] = self.run_id
        self.run['conclusion'] = 'failure'
        with self.assertRaises(custody.CustodyError):
            self.verify()

    def test_archive_accepts_regular_file_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = io.BytesIO()
            with ZipFile(archive, 'w') as z:
                item = ZipInfo('data/file.json')
                item.external_attr = 0o100644 << 16
                z.writestr(item, '{}')
            extracted = custody.unpack_checked(archive.getvalue(), root)
            self.assertEqual((extracted / 'data/file.json').read_bytes(), b'{}')
        for name in ('../escape', '/absolute', 'data/../escape', 'data\\escape'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = io.BytesIO()
                with ZipFile(archive, 'w') as z:
                    item = ZipInfo(name)
                    item.external_attr = 0o100644 << 16
                    z.writestr(item, 'x')
                with self.assertRaises(custody.CustodyError):
                    custody.unpack_checked(archive.getvalue(), Path(directory))

    def test_archive_symlink_and_duplicate_rejected(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as directory:
                archive = io.BytesIO()
                with ZipFile(archive, 'w') as z:
                    item = ZipInfo('x')
                    item.external_attr = (0o100644 if duplicate else 0o120777) << 16
                    z.writestr(item, 'x')
                    if duplicate:
                        z.writestr(item, 'y')
                with self.assertRaises(custody.CustodyError):
                    custody.unpack_checked(archive.getvalue(), Path(directory))

    def test_private_work_root_required(self):
        # Hosted Linux /tmp is sticky world-writable and is intentionally
        # rejected by private_root; place the positive fixture under cwd.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory).resolve()
            custody.private_root(root)
            root.chmod(0o777)
            with self.assertRaises(custody.CustodyError):
                custody.private_root(root)
            root.chmod(0o700)
            alias = root / 'alias'
            alias.symlink_to(root)
            with self.assertRaises(custody.CustodyError):
                custody.private_root(alias)

    def test_fetch_caps_stream_before_buffering(self):
        class Stream:
            def read(self, count):
                return b'x' * 8

        class Process:
            stdout = Stream()
            killed = False

            def poll(self):
                return None

            def kill(self):
                self.killed = True

            def wait(self):
                return 1

        process = Process()
        with tempfile.TemporaryDirectory() as directory, patch.object(
                custody.subprocess, 'Popen', return_value=process) as launcher:
            with self.assertRaises(custody.CustodyError):
                custody.fetch('test', Path(directory), 'api.json', limit=4)
            self.assertTrue(process.killed)
            self.assertEqual(launcher.call_args.args[0][:4],
                             ['gh', 'api', '--hostname', 'github.com'])


if __name__ == '__main__':
    unittest.main()
