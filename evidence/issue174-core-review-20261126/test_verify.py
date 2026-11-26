import copy
import json
import unittest
from pathlib import Path
import verify

class CrossPacketTests(unittest.TestCase):
    def setUp(self):
        self.spec = json.loads((verify.HERE / 'setlocaltime-and-request-args-expected.json').read_text())
        self.core = verify.ROOT / 'issue173-core-packages-20261126'
        self.oracle = json.loads((self.core / 'source-oracle.json').read_text())
        self.mapping = json.loads((verify.HERE / 'operation-map.json').read_text())
        self.query = json.loads((verify.ROOT / 'issue174-localtime-ipk-20261126/raw/retry-output/query.json').read_text())

    def test_original(self):
        verify.compare(self.mapping, self.query, self.spec)

    def test_missing_and_duplicated_rows_rejected(self):
        for change in ('missing', 'duplicate'):
            query = copy.deepcopy(self.query)
            rows = query['#select']['tuples']
            if change == 'missing':
                rows.pop()
            else:
                rows[-1] = copy.deepcopy(rows[0])
            with self.assertRaisesRegex(ValueError, 'query tuples differ'):
                verify.compare(self.mapping, query, self.spec)

    def test_acl_and_oracle_mutations_rejected(self):
        verify.compare_sources(self.mapping, self.oracle, self.core / 'source')
        mapping = copy.deepcopy(self.mapping)
        mapping['companion_acls']['status']['grant_lines'][0]['text'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'ACL grant differs'):
            verify.compare_sources(mapping, self.oracle, self.core / 'source')
        spec = copy.deepcopy(self.spec)
        spec['positive']['expected_message'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'source-first oracle tuples differ'):
            verify.compare(self.mapping, self.query, spec)

    def test_wrong_entity_and_uri_rejected(self):
        query = copy.deepcopy(self.query)
        query['#select']['tuples'][0][0]['label'] = 'CallExpression'
        with self.assertRaisesRegex(ValueError, 'unexpected entity label'):
            verify.compare(self.mapping, query, self.spec)
        query = copy.deepcopy(self.query)
        query['#select']['tuples'][0][0]['url']['uri'] = 'file:///other/stage/usr/share/rpcd/ucode/luci'
        with self.assertRaisesRegex(ValueError, 'unexpected query URI'):
            verify.compare(self.mapping, query, self.spec)

if __name__ == '__main__':
    unittest.main()
