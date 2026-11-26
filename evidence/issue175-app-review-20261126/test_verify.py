import copy
import json
from pathlib import Path
import unittest
import verify

class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = json.loads((verify.HERE / 'scope.json').read_text())
        self.inventory = json.loads((verify.EVIDENCE / 'issue172-luci-source-inventory-20261125/inventory.json').read_text())
        self.receipt = json.loads((verify.EVIDENCE / 'issue175-adblock-ipk-20261126/provenance/app-comparison.json').read_text())
        self.acl = json.loads((verify.EVIDENCE / 'issue175-adblock-ipk-20261126/package-context/luci-app-adblock-fast-acl.json').read_text())
        self.api_acl = json.loads((verify.HERE / 'adblock-fast-api.json').read_text())

    def test_scope_and_acl(self):
        verify.check_scope(self.scope, self.inventory, self.receipt)
        verify.check_acl(self.acl)
        verify.check_api_acl(self.api_acl)

    def test_missing_and_altered_member_rejected(self):
        scope = copy.deepcopy(self.scope)
        scope['app_regular_members'].pop()
        with self.assertRaisesRegex(ValueError, 'package member inventory differs'):
            verify.check_scope(scope, self.inventory, self.receipt)
        receipt = copy.deepcopy(self.receipt)
        row = next(r for r in receipt['data_members'] if r['type'] == 'file')
        row['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'IPK member mapping differs'):
            verify.check_scope(self.scope, self.inventory, receipt)

    def test_candidate_and_grant_mutations_rejected(self):
        scope = copy.deepcopy(self.scope)
        scope['source_candidates'][0]['disposition'] = 'selected source candidate'
        with self.assertRaisesRegex(ValueError, 'source candidate disposition differs'):
            verify.check_scope(scope, self.inventory, self.receipt)
        acl = copy.deepcopy(self.acl)
        acl['luci-app-adblock-fast']['write']['ubus']['luci.adblock-fast'].remove('setInitAction')
        with self.assertRaisesRegex(ValueError, 'declared ubus write grant differs'):
            verify.check_acl(acl)
        api_acl = copy.deepcopy(self.api_acl)
        api_acl['adblock-fast-api']['write']['ubus']['luci.adblock-fast'].remove('setInitAction')
        with self.assertRaisesRegex(ValueError, 'alternate ubus write grant differs'):
            verify.check_api_acl(api_acl)

if __name__ == '__main__':
    unittest.main()
