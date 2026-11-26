import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('verify',ROOT/'verify.py')
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)

class EvidenceTests(unittest.TestCase):
    def test_actual_package(self):
        verify.inventory(ROOT)
        self.assertEqual(verify.verify_package(ROOT,verify.obj(verify.file_bytes(ROOT,'source-oracle.json'))),126)
    def test_wrong_control_rejected(self):
        verify.load_archive(ROOT)
        oracle=verify.obj(verify.file_bytes(ROOT,'source-oracle.json'))
        with patch.object(verify,'control_fields',return_value={}):
            with self.assertRaisesRegex(ValueError,'package control differs'):
                verify.verify_package(ROOT,oracle)
    def test_wrong_source_rejected(self):
        oracle=verify.obj(verify.file_bytes(ROOT,'source-oracle.json'))
        path=next(x['source_path'] for x in oracle['entries'] if x['package']=='luci-app-statistics' and x['projected_member'])
        original=verify.file_bytes
        def changed(root,name):
            data=original(root,name)
            return data+b' ' if name=='source/'+path else data
        with patch.object(verify,'file_bytes',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'source identity differs'):
                verify.verify_package(ROOT,oracle)
    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'):
            verify.obj(b'{"x":1,"x":2}')
    def test_warning_mutation_rejected(self):
        original=verify.file_bytes
        def changed(root,name):
            data=original(root,name)
            return data.replace(b'WARNING: kmod-drm-exec is not available in the kernel config - generating empty package',b'WARNING: kmod-other is not available in the kernel config - generating empty package') if name=='raw/statistics-compile.stderr' else data
        with patch.object(verify,'file_bytes',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'actual kernel warnings differ'):
                verify.verify_kernel(ROOT)
    def test_timing_metric_mutation_rejected(self):
        original=verify.file_bytes
        def changed(root,name):
            data=original(root,name)
            return data.replace(b'0.47 real',b'0.99 real') if name=='offline-timing/comparison.time-and-stderr' else data
        invocation=verify.obj(original(ROOT,'offline-timing/invocation.json'))
        import hashlib, json
        invocation['outputs']['comparison.time-and-stderr']=hashlib.sha256(changed(ROOT,'offline-timing/comparison.time-and-stderr')).hexdigest()
        def with_invocation(root,name):
            return json.dumps(invocation).encode() if name=='offline-timing/invocation.json' else changed(root,name)
        with patch.object(verify,'file_bytes',side_effect=with_invocation):
            with self.assertRaisesRegex(ValueError,'offline timing metrics differ'):
                verify.verify_timing(ROOT)
if __name__=='__main__':unittest.main()
