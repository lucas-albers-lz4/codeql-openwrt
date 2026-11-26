"""Synthetic mutations against retained evidence; no build or extraction."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('portable_core', ROOT / 'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

class Tests(unittest.TestCase):
    def test_observed_packet(self):
        result = v.verify(ROOT)
        self.assertEqual((result['packages'], result['source_rows']), (3, 73))
        self.assertFalse(result['runtime_or_codeql_claim'])

    def test_missing_raw_file_and_nested_checksum_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'packet'
            shutil.copytree(ROOT, root)
            (root / 'raw/luci-mod-status.ipk').unlink()
            with self.assertRaisesRegex(ValueError, 'inventory'):
                v.verify(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'packet'
            shutil.copytree(ROOT, root)
            (root / 'raw/nested').mkdir()
            (root / 'raw/nested/SHA256SUMS').write_text('extra')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                v.verify(root)

    def test_hardlink_alias_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'packet'
            shutil.copytree(ROOT, root)
            os.link(root / 'raw/luci-mod-status.ipk', root / 'alias')
            with self.assertRaisesRegex(ValueError, 'hardlink'):
                v.verify(root)

    def test_source_byte_and_mode_mutations_rejected(self):
        oracle = v.obj(v.file_bytes(ROOT, 'source-oracle.json'))
        row = next(r for r in oracle['rows'] if r['classification'] == 'selected_markup_candidate')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'packet'
            shutil.copytree(ROOT, root)
            path = root / 'source' / row['source_path']
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'source identity differs'):
                v.validate_source(root, oracle)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'packet'
            shutil.copytree(ROOT, root)
            (root / 'source' / row['source_path']).chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'source mode differs'):
                v.validate_source(root, oracle)

    def test_stage_mapping_mismatch_rejected(self):
        oracle = v.obj(v.file_bytes(ROOT, 'source-oracle.json'))
        name = 'luci-mod-network'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'packet'
            shutil.copytree(ROOT, root)
            path = root / 'raw' / (name + '.json')
            receipt = v.obj(path.read_bytes())
            receipt['source_mappings'][0]['stage_sha256'] = '0' * 64
            data = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
            path.write_bytes(data)
            (root / 'raw' / (name + '-after.json')).write_bytes(data)
            with patch.dict(v.RECEIPTS, {name: v.sha(data)}):
                with self.assertRaisesRegex(ValueError, 'stage/IPK receipt differs'):
                    v.verify_package(root, name, oracle)

    def test_wrong_control_package_rejected(self):
        ipk = v.file_bytes(ROOT, 'raw/luci-mod-system.ipk')
        control, members, outer = v.archive.read_ipk(ipk)
        changed = copy.deepcopy(control)
        changed['control']['bytes'] = changed['control']['bytes'].replace(b'Package: luci-mod-system', b'Package: wrong')
        self.assertEqual(v.control_fields(changed)['Package'], 'wrong')
        oracle = v.obj(v.file_bytes(ROOT, 'source-oracle.json'))
        with patch.object(v.archive, 'read_ipk', return_value=(changed, members, outer)):
            with self.assertRaisesRegex(ValueError, 'package control differs'):
                v.verify_package(ROOT, 'luci-mod-system', oracle)
        changed['control']['bytes'] += b'\nPackage: duplicate\n'
        with self.assertRaisesRegex(ValueError, 'duplicate control'):
            v.control_fields(changed)

if __name__ == '__main__':
    unittest.main()
