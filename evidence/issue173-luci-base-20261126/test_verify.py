import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import verify

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.root = verify.ROOT
        verify.load_archive(self.root)
        self.oracle = verify.obj((self.root/'source-first-oracle.json').read_bytes())
        self.receipt = verify.obj((self.root/'raw/byte-comparison.json').read_bytes())
        self.ipk = (self.root/'raw/luci-base.ipk').read_bytes()

    def test_actual_package(self):
        self.assertEqual(sum(verify.verify_package(self.root, self.oracle, self.receipt, self.ipk).values()), 21)

    def test_wrong_control_rejected(self):
        control, members, outer = verify.archive.read_ipk(self.ipk)
        control['control']['bytes'] = control['control']['bytes'].replace(b'Package: luci-base', b'Package: wrong')
        with patch.object(verify.archive, 'read_ipk', return_value=(control, members, outer)):
            with self.assertRaisesRegex(ValueError, 'package control differs'):
                verify.verify_package(self.root, self.oracle, self.receipt, self.ipk)

    def test_missing_control_and_stale_provider_receipt_rejected(self):
        receipt = copy.deepcopy(self.receipt)
        receipt['files'] = [r for r in receipt['files'] if r['installed_path'] != 'etc/init.d/ucitrack']
        with self.assertRaisesRegex(ValueError, 'receipt candidate count differs'):
            verify.verify_package(self.root, self.oracle, receipt, self.ipk)
        receipt = copy.deepcopy(self.receipt)
        row = next(r for r in receipt['files'] if r['installed_path'] == 'usr/share/rpcd/ucode/luci')
        row['source_sha256'] = '6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e'
        with self.assertRaisesRegex(ValueError, 'source/prepared receipt differs'):
            verify.verify_package(self.root, self.oracle, receipt, self.ipk)

    def test_header_substitution_mutation_rejected(self):
        control, members, outer = verify.archive.read_ipk(self.ipk)
        path = 'usr/share/ucode/luci/template/header.ut'
        members[path]['bytes'] = b'wrong substitution'
        receipt = copy.deepcopy(self.receipt)
        receipt['archive_data_members'] = verify.archive.receipts(members)
        with patch.object(verify.archive, 'read_ipk', return_value=(control, members, outer)):
            with self.assertRaisesRegex(ValueError, 'stage/IPK bytes differ'):
                verify.verify_package(self.root, self.oracle, receipt, self.ipk)

    def test_packet_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root/'alias').symlink_to(self.root/'raw/luci-base.ipk')
            with self.assertRaisesRegex(ValueError, 'packet path symlink'):
                verify.file_bytes(root, 'alias')

    def test_untrusted_parser_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            marker = root / 'executed'
            (root/'archive.py').write_text("open(" + repr(str(marker)) + ", 'w').write('bad')\n")
            with patch.object(verify, 'archive', None):
                with self.assertRaisesRegex(ValueError, 'archive parser digest differs'):
                    verify.load_archive(root)
            self.assertFalse(marker.exists())
            (root/'archive.py').unlink()
            (root/'archive.py').symlink_to(self.root/'archive.py')
            with self.assertRaisesRegex(ValueError, 'packet path symlink'):
                verify.load_archive(root)

if __name__ == '__main__':
    unittest.main()
