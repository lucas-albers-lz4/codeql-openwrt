import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('statistics_package', HERE / 'package.py')
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)

class PackageTests(unittest.TestCase):
    def test_manifest_safe_ustar_and_size_cap(self):
        self.assertEqual(wrapper.package.MAX_TOTAL, 512 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / 'output'
            output.mkdir()
            data = b'kernel evidence\n'
            (output / 'kernel.ipk').write_bytes(data)
            (output / 'manifest.json').write_text(json.dumps({'process_group_quiescent': True, 'output_sha256': {'kernel.ipk': hashlib.sha256(data).hexdigest()}}))
            archive = root / 'bundle.tar'
            wrapper.package.create(output, archive)
            tar = shutil.which('gtar') or shutil.which('tar')
            if tar and b'GNU tar' in subprocess.check_output([tar, '--version']):
                dest = root / 'unpacked'
                dest.mkdir()
                subprocess.run([tar, '-xf', str(archive), '-C', str(dest)], cwd='/', check=True)
                self.assertEqual((dest / 'metadata/kernel.ipk').read_bytes(), data)
            with patch.object(wrapper.package, 'MAX_TOTAL', 1):
                with self.assertRaisesRegex(ValueError, 'output size limit exceeded'):
                    wrapper.package.collect(output)
            (output / 'alias').symlink_to(output / 'kernel.ipk')
            with self.assertRaisesRegex(ValueError, 'symlink in output'):
                wrapper.package.collect(output)

if __name__ == '__main__':
    unittest.main()
