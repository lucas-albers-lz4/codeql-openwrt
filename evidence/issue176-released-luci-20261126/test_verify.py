import copy
import shutil
import tempfile
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import verify

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        profile = 'luci-app-adblock-fast'
        raw, inputs = verify.HERE / 'raw', verify.HERE / 'inputs'
        base = raw / 'r25-package/producer-runs' / profile
        output = base / 'output'
        lock = verify.load(inputs / 'r25-current-luci-package-lock.json')
        info = lock['packages'][profile]
        handoff = verify.load(raw / 'r25-package/receipt.json')
        index = verify.load(inputs / 'member-inventory.json')['packages']
        self.args = [profile, verify.load(inputs / 'luci-app-adblock-fast-oracle.json'),
                     index[info['package']['name']], verify.load(raw / 'r25-package/stage-receipts' / (profile + '.json')),
                     verify.load(base / 'receipt.json'), verify.load(output / 'coverage-manifest.json'),
                     verify.load(output / 'routing.json'), verify.load(output / 'success.json'),
                     verify.load(output / 'errors.json'), verify.load(output / 'default-suite.sarif'),
                     verify.load(output / 'resolved-suite.json'), verify.load(base / 'commands.json'),
                     handoff['packages'][profile], output]

    def test_actual_retained_profile(self):
        verify.verify_profile(*self.args)

    def test_subtree_symlink_and_manifest_fifo_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            shutil.copyfile(verify.HERE / 'raw-manifest.json', root / 'raw-manifest.json')
            (root / 'raw').symlink_to(verify.HERE / 'raw')
            with patch.object(verify, 'HERE', root):
                with self.assertRaisesRegex(ValueError, 'unsafe evidence subtree'):
                    verify.verify_inventory()
            (root / 'raw-manifest.json').unlink()
            os.mkfifo(root / 'raw-manifest.json')
            with patch.object(verify, 'HERE', root):
                with self.assertRaisesRegex(ValueError, 'unsafe raw manifest'):
                    verify.verify_inventory()

    def test_unexpected_route_rejected(self):
        args = copy.deepcopy(self.args)
        args[6]['decisions'][0]['reason'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'routing decision differs'):
            verify.verify_profile(*args)

    def test_missing_success_and_unexpected_error_rejected(self):
        args = copy.deepcopy(self.args)
        args[7]['#select']['tuples'].clear()
        with self.assertRaisesRegex(ValueError, 'successful file multiset differs'):
            verify.verify_profile(*args)
        args = copy.deepcopy(self.args)
        args[8]['#select']['tuples'].append(['unexpected'])
        with self.assertRaisesRegex(ValueError, 'extraction errors present'):
            verify.verify_profile(*args)

    def test_original_mode_and_unexpected_stdout_warning_rejected(self):
        args = copy.deepcopy(self.args)
        args[2]['observed_members'][0]['mode'] = '0755'
        with self.assertRaisesRegex(ValueError, 'original member mode, size or route differs'):
            verify.verify_profile(*args)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'output'
            shutil.copytree(self.args[-1], out)
            (out / 'success-query.stdout').write_text('WARNING: unexpected\n')
            args = copy.deepcopy(self.args)
            args[-1] = out
            with self.assertRaisesRegex(ValueError, 'phase warnings differ'):
                verify.verify_profile(*args)

    def test_unexpected_sarif_result_rejected(self):
        args = copy.deepcopy(self.args)
        args[9]['runs'][0]['results'].append({'ruleId':'unexpected'})
        with self.assertRaisesRegex(ValueError, 'SARIF results differ'):
            verify.verify_profile(*args)

if __name__ == '__main__':
    unittest.main()
