import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('verify',ROOT/'verify.py');verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)
class EvidenceTests(unittest.TestCase):
    def test_real_package(self):
        verify.inventory(ROOT)
        self.assertEqual(verify.verify_app(ROOT),22)
    def test_stage_mutation_rejected(self):
        original=verify.file_bytes
        def changed(root,name):
            data=original(root,name)
            return data+b' ' if name=='raw/dockerman-stage/usr/share/rpcd/ucode/docker_rpc.uc' else data
        with patch.object(verify,'file_bytes',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'source or package member differs'):
                verify.verify_app(ROOT)
    def test_provider_abi_rejected(self):
        rows=json.loads(verify.file_bytes(ROOT,'provider-controls.json'))
        row=next(x for x in rows if '/kmod-veth_' in x['retained_path'])
        row['control']=row['control'].replace('7df1a98339a37dfe41af7485d026e004','0'*32)
        with self.assertRaisesRegex(ValueError,'kmod kernel dependency differs'):
            verify.verify_controls(ROOT,rows)
    def test_wrong_control_rejected(self):
        with patch.object(verify,'control_fields',return_value={}):
            with self.assertRaisesRegex(ValueError,'control differs'):
                verify.verify_app(ROOT)
    def test_extra_empty_warning_rejected(self):
        original=verify.file_bytes
        def changed(root,name):
            data=original(root,name)
            return data+b'WARNING: kmod-extra is not available in the kernel config - generating empty package\n' if name=='raw/dockerman-compile.stderr' else data
        with patch.object(verify,'file_bytes',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'kernel warnings differ'):
                verify.verify_kernel_and_diagnostics(ROOT)
    def test_extra_cycle_rejected(self):
        original=verify.file_bytes
        def changed(root,name):
            data=original(root,name)
            return data+b'make: Circular unexpected dependency dropped.\n' if name=='raw/dockerman-compile.stderr' else data
        with patch.object(verify,'file_bytes',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'cycle warnings differ'):
                verify.verify_kernel_and_diagnostics(ROOT)
if __name__=='__main__':unittest.main()
