import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verify', ROOT / 'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

class EvidenceTests(unittest.TestCase):
    def test_all_packages_and_real_controls(self):
        verify.inventory(ROOT)
        oracle = verify.obj(verify.file_bytes(ROOT, 'source-oracle.json'))
        self.assertEqual([verify.verify_package(ROOT, name, oracle) for name in verify.IPKS], [5, 7, 6])

    def test_wrong_control_is_rejected_at_package_boundary(self):
        verify.load_archive(ROOT)
        oracle = verify.obj(verify.file_bytes(ROOT, 'source-oracle.json'))
        with patch.object(verify, 'control_fields', return_value={'Package':'wrong','Version':'wrong','Architecture':'all'}):
            with self.assertRaisesRegex(ValueError, 'package control differs'):
                verify.verify_package(ROOT, 'luci-app-ddns', oracle)

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            verify.obj(b'{"key":1,"key":2}')

    def test_generated_input_mutation_rejected(self):
        oracle = verify.obj(verify.file_bytes(ROOT, 'source-oracle.json'))
        input_path = oracle['packages']['luci-app-advanced-reboot']['custom_prepare_projection']['merge_inputs_filename_order'][0]
        original = verify.file_bytes
        def changed(root, name):
            data = original(root, name)
            return data + b' ' if name == 'source/'+input_path else data
        with patch.object(verify, 'file_bytes', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'generated input bytes differ'):
                verify.verify_package(ROOT, 'luci-app-advanced-reboot', oracle)

    def test_serial_receipt_mutation_rejected(self):
        oracle = verify.obj(verify.file_bytes(ROOT, 'source-oracle.json'))
        original = verify.file_bytes
        def changed(root, name):
            data = original(root, name)
            return data + b' ' if name == 'raw/luci-app-ddns-after-luci-app-ddns.json' else data
        with patch.object(verify, 'file_bytes', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'serial receipt differs'):
                verify.verify_package(ROOT, 'luci-app-ddns', oracle)

if __name__ == '__main__':
    unittest.main()
