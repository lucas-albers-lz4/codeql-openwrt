import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import verify

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.root = verify.ROOT
        verify.load_archive(self.root)
        self.oracles = {name:verify.obj((self.root/(name+'-oracle.json')).read_bytes()) for name in ('app','service')}
        self.receipts = {name:verify.obj((self.root/'raw'/('app.json' if name == 'app' else 'service-before.json')).read_bytes()) for name in ('app','service')}
        self.ipks = {name:(self.root/'raw'/('luci-app-adblock-fast.ipk' if name == 'app' else 'adblock-fast.ipk')).read_bytes() for name in ('app','service')}

    def test_both_actual_packages(self):
        for name, count in (('app',9),('service',5)):
            self.assertEqual(verify.verify_package(self.root,name,self.oracles[name],self.receipts[name],self.ipks[name]),count)

    def test_wrong_control_rejected(self):
        control, members, outer = verify.archive.read_ipk(self.ipks['app'])
        control['control']['bytes'] = control['control']['bytes'].replace(b'Package: luci-app-adblock-fast',b'Package: wrong')
        with patch.object(verify.archive,'read_ipk',return_value=(control,members,outer)):
            with self.assertRaisesRegex(ValueError,'package control differs'):
                verify.verify_package(self.root,'app',self.oracles['app'],self.receipts['app'],self.ipks['app'])

    def test_missing_mapping_and_js_claim_rejected(self):
        receipt = copy.deepcopy(self.receipts['app'])
        receipt['source_mappings'].pop()
        with self.assertRaisesRegex(ValueError,'source mapping count differs'):
            verify.verify_package(self.root,'app',self.oracles['app'],receipt,self.ipks['app'])
        receipt = copy.deepcopy(self.receipts['app'])
        row = next(r for r in receipt['source_mappings'] if r['disposition'] == 'auxiliary_htdocs_js')
        row['transform_provenance'] = 'source_equal'
        with self.assertRaisesRegex(ValueError,'JS transformation boundary differs'):
            verify.verify_package(self.root,'app',self.oracles['app'],receipt,self.ipks['app'])

    def test_service_version_transform_mutation_rejected(self):
        control, members, outer = verify.archive.read_ipk(self.ipks['service'])
        path = 'lib/adblock-fast/adblock-fast.uc'
        members[path]['bytes'] = b'wrong version'
        receipt = copy.deepcopy(self.receipts['service'])
        receipt['data_members'] = verify.archive.receipts(members)
        row = next(r for r in receipt['source_mappings'] if r['path'] == path)
        row['staged_sha256'] = row['ipk_sha256'] = verify.sha(members[path]['bytes'])
        with patch.object(verify.archive,'read_ipk',return_value=(control,members,outer)):
            with self.assertRaisesRegex(ValueError,'service recipe projection differs'):
                verify.verify_package(self.root,'service',self.oracles['service'],receipt,self.ipks['service'])

    def test_parser_checked_before_first_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); marker = root/'executed'
            (root/'archive.py').write_text('open('+repr(str(marker))+", 'w').write('bad')\n")
            with patch.object(verify,'archive',None):
                with self.assertRaisesRegex(ValueError,'archive parser digest differs'):
                    verify.load_archive(root)
            self.assertFalse(marker.exists())

if __name__ == '__main__':
    unittest.main()
