import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kernel', HERE / 'kernel.py')
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)

class KernelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run = Path(self.tmp.name).resolve()
        self.root = self.run / 'linux'
        self.root.mkdir()
        for name in ('.config', '.modules', '.vermagic', 'modules.builtin', 'modules.builtin.modinfo', 'include/config/kernel.release', 'net/example.ko'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'x')
        (self.root / '.config').write_bytes(b'CONFIG_X86_64=y\n')
        (self.root / '.vermagic').write_bytes(b'0123456789abcdef0123456789abcdef\n')
        (self.root / 'include/config/kernel.release').write_bytes(b'6.12.116\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_directory_inventory(self):
        result = kernel.inventory(self.root, self.run)
        self.assertEqual(list(result['modules']), ['net/example.ko'])
        self.assertIn('modules.builtin', result['files'])

    def test_missing_and_alias_are_rejected(self):
        (self.root / 'modules.builtin').unlink()
        with self.assertRaises(FileNotFoundError):
            kernel.inventory(self.root, self.run)
        (self.root / 'modules.builtin').symlink_to(self.root / '.config')
        with self.assertRaisesRegex(ValueError, 'kernel path alias'):
            kernel.inventory(self.root, self.run)

    def test_wrong_kernel_config_and_release_rejected(self):
        (self.root / '.config').write_bytes(b'CONFIG_X86_64=n\n')
        with self.assertRaisesRegex(ValueError, 'kernel config is not x86_64'):
            kernel.inventory(self.root, self.run)
        (self.root / '.config').write_bytes(b'CONFIG_X86_64=y\n')
        (self.root / 'include/config/kernel.release').write_bytes(b'5.15.1\n')
        with self.assertRaisesRegex(ValueError, 'kernel release is not pinned 6.12.116'):
            kernel.inventory(self.root, self.run)
        with self.assertRaisesRegex(ValueError, 'unsafe kernel path'):
            kernel.regular(self.root, '/etc/passwd')

    def test_empty_package_warning_fails(self):
        with self.assertRaisesRegex(ValueError, 'selected kernel package generated empty'):
            kernel.reject_empty_package_diagnostic(b'WARNING: xyz is not available in the kernel config - generating empty package')
        with self.assertRaisesRegex(ValueError, 'required kernel module missing'):
            kernel.reject_empty_package_diagnostic(b"ERROR: module '/kernel/example.ko' is missing.")

if __name__ == '__main__':
    unittest.main()
