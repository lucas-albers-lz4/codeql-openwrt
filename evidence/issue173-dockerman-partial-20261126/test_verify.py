import importlib.util
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verify', ROOT/'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

class EvidenceTests(unittest.TestCase):
    def test_app_source_and_raw_packet(self):
        verify.inventory(ROOT)
        self.assertEqual(verify.verify_app(ROOT), 22)
    def test_wrong_control_rejected(self):
        verify.load_archive(ROOT)
        with patch.object(verify, 'control_fields', return_value={}):
            with self.assertRaisesRegex(ValueError, 'app control differs'):
                verify.verify_app(ROOT)
    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            verify.obj(b'{"x":1,"x":2}')
    def test_wrong_kmod_kernel_abi_rejected(self):
        controls = json.loads(verify.file_bytes(ROOT, 'provider-controls.json'))
        item = next(x for x in controls if '/kmod-veth_' in x['retained_path'])
        item['control'] = item['control'].replace('7df1a98339a37dfe41af7485d026e004', '0'*32)
        with self.assertRaisesRegex(ValueError, 'kmod kernel dependency differs'):
            verify.verify_controls(ROOT, controls)
    def test_missing_cycle_rejected_after_valid_log_digest(self):
        original = verify.file_bytes
        stderr = original(ROOT, 'raw/dockerman-compile.stderr')
        lines = stderr.splitlines(keepends=True)
        mutated = b''.join(line for line in lines if not line.startswith(b'make[1]: Circular package/feeds/packages/tini/'))
        receipt = json.loads(original(ROOT, 'raw/dockerman-compile.receipt.json'))
        receipt['stderr_sha256'] = hashlib.sha256(mutated).hexdigest()
        def changed(root, path):
            if path == 'raw/dockerman-compile.stderr': return mutated
            if path == 'raw/dockerman-compile.receipt.json': return json.dumps(receipt).encode()
            return original(root, path)
        verify.load_archive(ROOT)
        kernel = original(ROOT, 'raw/kernel-evidence/kernel.ipk')
        with patch.object(verify, 'file_bytes', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'cycle warnings differ'):
                verify.verify_kernel_and_logs(ROOT, kernel, None, None)

if __name__ == '__main__': unittest.main()
