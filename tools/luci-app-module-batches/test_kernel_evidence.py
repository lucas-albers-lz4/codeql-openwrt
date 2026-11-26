import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('app_kernel_evidence', HERE / 'kernel-evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def archive_bytes(rows):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in rows:
            info = tarfile.TarInfo(name)
            info.mode, info.size = mode, len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def ipk_bytes(version, builtin=b'example.ko\n', package='kernel'):
    control = f'Package: {package}\nVersion: {version}\nArchitecture: x86_64\n'.encode()
    control_tar = archive_bytes([('control', control, 0o644)])
    data_tar = archive_bytes([
        (evidence.DATA_PREFIX + 'modules.builtin', builtin, 0o644),
        (evidence.DATA_PREFIX + 'modules.builtin.modinfo', b'modinfo\0data', 0o644),
    ])
    return archive_bytes([('debian-binary', b'2.0\n', 0o644),
                          ('control.tar.gz', control_tar, 0o644),
                          ('data.tar.gz', data_tar, 0o644)])


class KernelEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run = Path(self.tmp.name).resolve()
        self.ow = self.run / 'openwrt'
        self.kernel_root = self.ow / evidence.KERNEL_REL
        self.kernel_root.mkdir(parents=True)
        self.openwrt_config = b'CONFIG_TARGET_x86_64=y\n'
        self.ow.joinpath('.config').write_bytes(self.openwrt_config)
        (self.run / 'output').mkdir()
        self.magic = '0123456789abcdef0123456789abcdef'
        self.config = b'CONFIG_X86_64=y\n'
        self.builtin = b'kernel/net/example.ko\n'
        for rel, data in {
            '.config': self.config,
            '.modules': b'',
            '.vermagic': (self.magic + '\n').encode(),
            'modules.builtin': self.builtin,
            'modules.builtin.modinfo': b'module metadata\n',
            'include/config/kernel.release': b'6.12.116\n',
        }.items():
            path = self.kernel_root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.config_sha = hashlib.sha256(self.openwrt_config).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def add_kernel_package(self, *, version=None, builtin=b'example.ko\n', package='kernel', suffix=None):
        version = version or f'6.12.116~{self.magic}-r1'
        path = self.ow / 'bin/targets/x86/64/packages'
        path.mkdir(parents=True, exist_ok=True)
        name = f'kernel_{version}_x86_64.ipk' if suffix is None else f'kernel_{suffix}.ipk'
        result = path / name
        result.write_bytes(ipk_bytes(version, builtin, package))
        kv = self.ow / 'staging_dir/target-x86_64_musl/kernel.version'
        kv.parent.mkdir(parents=True, exist_ok=True)
        kv.write_text(version + '\n')
        return result

    def test_actual_kernel_ipk_identity_and_retained_evidence(self):
        captured = evidence.capture_kernel(self.run, self.config_sha)
        self.assertEqual(captured['kernel_release'], '6.12.116')
        self.add_kernel_package()
        evidence.snapshot_package_output(self.run)
        package = evidence.validate_package(self.run, self.config_sha)
        self.assertEqual(package['control']['Package'], 'kernel')
        self.assertEqual(package['control']['Architecture'], 'x86_64')
        self.assertEqual((self.run / 'output/kernel-evidence/kernel.ipk').read_bytes(),
                         (self.ow / package['ipk_path']).read_bytes())
        self.assertEqual(json.loads((self.run / 'output/kernel-package-inventory.json').read_text()), package)
        (self.ow / 'bin/targets/x86/64/packages/libc_1_x86_64.ipk').write_bytes(b'unrelated target package')
        self.assertTrue(evidence.recheck(self.run))

    def test_wrong_kernel_version_and_vermagic_fail_closed(self):
        (self.kernel_root / 'include/config/kernel.release').write_bytes(b'6.12.117\n')
        with self.assertRaisesRegex(ValueError, 'kernel release is not pinned 6.12.116'):
            evidence.capture_kernel(self.run, self.config_sha)

    def test_wrong_kernel_architecture_and_vermagic_fail_closed(self):
        (self.kernel_root / '.config').write_bytes(b'CONFIG_X86_64=n\n')
        with self.assertRaisesRegex(ValueError, 'kernel config is not x86_64'):
            evidence.capture_kernel(self.run, self.config_sha)
        (self.kernel_root / '.config').write_bytes(b'CONFIG_X86_64=y\n')
        (self.kernel_root / '.vermagic').write_bytes(b'unknown\n')
        with self.assertRaisesRegex(ValueError, 'kernel vermagic is missing or malformed'):
            evidence.capture_kernel(self.run, self.config_sha)

    def test_kernel_version_file_must_match_vermagic(self):
        evidence.capture_kernel(self.run, self.config_sha)
        self.add_kernel_package(version='6.12.116~unknown-r1')
        evidence.snapshot_package_output(self.run)
        with self.assertRaisesRegex(ValueError, 'staged kernel.version differs from kernel vermagic'):
            evidence.validate_package(self.run, self.config_sha)

    def test_kernel_version_snapshot_must_match_live_before_app_build(self):
        evidence.capture_kernel(self.run, self.config_sha)
        self.add_kernel_package()
        evidence.snapshot_package_output(self.run)
        (self.ow / 'staging_dir/target-x86_64_musl/kernel.version').write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'retained kernel.version differs from package-phase observation'):
            evidence.validate_package(self.run, self.config_sha)

    def test_kernel_package_control_mismatch_fail(self):
        evidence.capture_kernel(self.run, self.config_sha)
        self.add_kernel_package(package='wrong')
        evidence.snapshot_package_output(self.run)
        with self.assertRaisesRegex(ValueError, 'kernel IPK control identity differs'):
            evidence.validate_package(self.run, self.config_sha)

    def test_kernel_package_builtin_projection_mismatch_fail(self):
        evidence.capture_kernel(self.run, self.config_sha)
        self.add_kernel_package(builtin=b'wrong.ko\n')
        evidence.snapshot_package_output(self.run)
        with self.assertRaisesRegex(ValueError, 'modules.builtin projection differs'):
            evidence.validate_package(self.run, self.config_sha)

    def test_ambiguous_kernel_ipks_are_retained_then_rejected(self):
        evidence.capture_kernel(self.run, self.config_sha)
        self.add_kernel_package()
        self.add_kernel_package(suffix='duplicate')
        evidence.snapshot_package_output(self.run)
        with self.assertRaisesRegex(ValueError, 'kernel IPK output is missing or ambiguous'):
            evidence.validate_package(self.run, self.config_sha)
        retained = self.run / 'output/kernel-evidence/kernel-ipks'
        self.assertEqual(len(list(retained.glob('*.ipk'))), 2)

    def test_changed_kernel_inventory_or_package_output_fails_recheck(self):
        evidence.capture_kernel(self.run, self.config_sha)
        self.add_kernel_package()
        evidence.snapshot_package_output(self.run)
        evidence.validate_package(self.run, self.config_sha)
        (self.kernel_root / 'modules.builtin').write_bytes(b'changed\n')
        with self.assertRaisesRegex(ValueError, 'kernel build files changed'):
            evidence.recheck(self.run)

    def test_empty_and_missing_kernel_diagnostics_rejected(self):
        for text, message in (
            (b'WARNING: item is not available in the kernel config - generating empty package', 'selected kernel package generated empty'),
            (b"ERROR: module '/kernel/example.ko' is missing.", 'required kernel module missing'),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                evidence.kernel.reject_empty_package_diagnostic(text)


if __name__ == '__main__':
    unittest.main()
