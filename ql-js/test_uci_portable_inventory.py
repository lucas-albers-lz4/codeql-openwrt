"""Regression checks for the retained, portable UCI source-site inventory."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import uci_inventory

HERE = Path(__file__).resolve().parent
INVENTORY_SHA256 = '91bf4add23d23e0c852131e39107a779d596ce02bd7e625d47c65b4676e9b477'
MANIFEST_SHA256 = '3161274241e086d121fd5122e0dfe0c5fb5d97872710d79c87f86244be2b2627'
SOURCE_SHA256 = '341e1e41a21edc9114c5ec3eee9f76bc022ea4b89f6856d8b80854cf5b8c2a98'
FIELDS = ('path', 'start_line', 'start_column', 'end_line', 'end_column',
          'receiver', 'kind', 'property_known', 'property')


def validate(raw, manifest_raw):
    if hashlib.sha256(raw).hexdigest() != INVENTORY_SHA256:
        raise ValueError('inventory identity mismatch')
    if hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError('manifest identity mismatch')
    doc = uci_inventory._parse(raw)
    manifest = uci_inventory._parse(manifest_raw)
    if (not isinstance(doc, dict) or set(doc) != {'kind', 'version', 'source_manifest_sha256',
            'source_multiset_sha256', 'candidates', 'family', 'assessment'}
            or doc['family'] != 'rpc_surface' or doc['assessment'] != 'candidate'
            or doc['kind'] != 'uci-source-site-inventory'
            or type(doc['version']) is not int or doc['version'] != 1
            or doc['source_manifest_sha256'] != MANIFEST_SHA256 or doc['source_multiset_sha256'] != SOURCE_SHA256
            or not isinstance(doc['candidates'], list)):
        raise ValueError('invalid inventory schema')
    paths = {row['source'] for row in manifest}
    result = Counter()
    for row in doc['candidates']:
        if (not isinstance(row, dict) or set(row) != set(FIELDS) | {'count'}
                or not isinstance(row['path'], str) or row['path'] not in paths
                or row['receiver'] not in ('bare', 'L.uci')
                or row['kind'] not in ('dot', 'computed-index') or type(row['property_known']) is not bool
                or not isinstance(row['property'], str) or type(row['count']) is not int or row['count'] < 1
                or any(type(row[k]) is not int or row[k] < 1 for k in FIELDS[1:5])
                or (row['start_line'], row['start_column']) > (row['end_line'], row['end_column'])
                or (not row['property_known'] and row['property'] != '<unknown>')
                or (row['kind'] == 'dot' and (not row['property_known'] or not row['property']))):
            raise ValueError('invalid candidate')
        key = tuple(row[field] for field in FIELDS)
        if key in result:
            raise ValueError('duplicate candidate')
        result[key] = row['count']
    return result


class PortableInventoryTests(unittest.TestCase):
    def test_inventory_identity_counts_and_anchor(self):
        raw = (HERE / 'evidence/uci-corpus/inventory.json').read_bytes()
        manifest = (HERE / 'manifest.json').read_bytes()
        rows = validate(raw, manifest)
        self.assertEqual((len(rows), sum(rows.values())), (576, 576))
        self.assertEqual(sum(count for key, count in rows.items() if key[5] == 'L.uci'), 2)
        self.assertTrue(all(key[6] == 'dot' and key[7] for key in rows))
        self.assertIn(('modules/luci-mod-network/htdocs/luci-static/resources/view/network/dhcp.js',
                       616, 17, 616, 30, 'L.uci', 'dot', True, 'sections'), rows)

    def test_corruption_is_rejected(self):
        raw = (HERE / 'evidence/uci-corpus/inventory.json').read_bytes()
        manifest = (HERE / 'manifest.json').read_bytes()
        for changed in (raw.replace(b'"count": 1', b'"count": 2', 1), raw[:-1], raw + b' '):
            with self.subTest(changed=changed[-10:]), self.assertRaisesRegex(ValueError, 'identity'):
                validate(changed, manifest)
        with self.assertRaisesRegex(ValueError, 'manifest identity'):
            validate(raw, manifest + b' ')

    def test_semantic_validation_after_independent_digest_binding(self):
        manifest = (HERE / 'manifest.json').read_bytes()
        original = uci_inventory._parse((HERE / 'evidence/uci-corpus/inventory.json').read_bytes())
        def checked(raw):
            # Bind the synthetic test bytes, so rejection reaches the intended rule.
            with patch(__name__ + '.INVENTORY_SHA256', hashlib.sha256(raw).hexdigest()):
                return validate(raw, manifest)
        def encode(value):
            return json.dumps(value).encode()
        row = dict(original['candidates'][0], kind='computed-index', property='<unknown>')
        known, unknown = dict(row, property_known=True, count=2), dict(row, property_known=False, count=3)
        original['candidates'] = [known, unknown]
        result = checked(encode(original))
        self.assertEqual(sorted(result.values()), [2, 3])
        self.assertEqual({key[7] for key in result}, {True, False})
        for mutation in ('duplicate', 'sentinel', 'path', 'path_type', 'count', 'family'):
            doc = json.loads(encode(original))
            if mutation == 'duplicate':
                doc['candidates'].append(doc['candidates'][0].copy())
            elif mutation == 'sentinel':
                doc['candidates'][1]['property'] = 'other'
            elif mutation == 'path':
                doc['candidates'][0]['path'] = './foreign.js'
            elif mutation == 'path_type':
                doc['candidates'][0]['path'] = []
            elif mutation == 'count':
                doc['candidates'][0]['count'] = 0
            else:
                doc['family'] = 'other'
            reason = 'duplicate candidate' if mutation == 'duplicate' else 'invalid inventory schema' if mutation == 'family' else 'invalid candidate'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, reason):
                checked(encode(doc))
        raw = encode(original).replace(b'"family": "rpc_surface"', b'"family": "rpc_surface", "family": "rpc_surface"')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            checked(raw)


if __name__ == '__main__':
    unittest.main()
