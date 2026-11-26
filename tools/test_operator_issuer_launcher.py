import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import operator_issuer_launcher as launcher


class LauncherTests(unittest.TestCase):
    def test_private_source_uses_commit_not_dirty_checkout_or_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / 'checkout'
            checkout.mkdir()
            subprocess.run(['git', '-C', str(checkout), 'init', '-q'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'config', 'user.email',
                            'test@example.invalid'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'config', 'user.name',
                            'Test'], check=True)
            (checkout / '.gitignore').write_text('__pycache__/\n')
            (checkout / 'issuer.py').write_text('SAFE = True\n')
            subprocess.run(['git', '-C', str(checkout), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(checkout), 'commit', '-qm', 'approved'],
                           check=True)
            commit = subprocess.check_output(['git', '-C', str(checkout),
                                              'rev-parse', 'HEAD'], text=True).strip()
            (checkout / 'issuer.py').write_text('OPEN_KEY = True\n')
            cache = checkout / '__pycache__'
            cache.mkdir()
            (cache / 'issuer.cpython-312.pyc').write_bytes(b'bad bytecode')
            private = root / 'private'
            private.mkdir(mode=0o700)
            result = launcher.prepare(checkout, private, commit)
            self.assertEqual((result / 'issuer.py').read_text(), 'SAFE = True\n')
            self.assertFalse((result / '__pycache__').exists())

    def test_private_file_rejects_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            good = root / 'policy.json'
            fd = os.open(good, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(b'{}\n')
            self.assertEqual(launcher.private_file(good, root, max_bytes=4096), b'{}\n')
            link = root / 'link.json'
            link.symlink_to(good)
            with self.assertRaises(ValueError):
                launcher.private_file(link, root, max_bytes=4096)
            fifo = root / 'pipe.json'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                launcher.private_file(fifo, root, max_bytes=4096)

    def test_hostile_filter_and_replace_ref_do_not_change_materialized_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / 'checkout'
            checkout.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(checkout), *args],
                                               text=True).strip()
            git('init', '-q')
            git('config', 'user.email', 'test@example.invalid')
            git('config', 'user.name', 'Test')
            (checkout / 'issuer.py').write_text('SAFE = True\n')
            (checkout / '.gitattributes').write_text('issuer.py filter=attack\n')
            git('add', 'issuer.py', '.gitattributes')
            git('commit', '-qm', 'approved')
            approved = git('rev-parse', 'HEAD')
            (checkout / 'issuer.py').write_text('UNAPPROVED = True\n')
            git('add', 'issuer.py')
            git('commit', '-qm', 'unapproved')
            unapproved = git('rev-parse', 'HEAD')
            git('replace', approved, unapproved)
            sentinel = root / 'filter-ran'
            git('config', 'filter.attack.smudge', f'touch {sentinel}; cat')
            private = root / 'private'
            private.mkdir(mode=0o700)
            result = launcher.prepare(checkout, private, approved)
            self.assertEqual((result / 'issuer.py').read_text(), 'SAFE = True\n')
            self.assertFalse(sentinel.exists())


if __name__ == '__main__':
    unittest.main()
