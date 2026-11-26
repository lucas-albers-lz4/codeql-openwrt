import unittest

from reservation_claim import ClaimError, claim


class ReservationClaimTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {'schema': 'incoming-event-receipt-v1',
                        'status': 'identities_resolved_only', 'repository': 'openwrt',
                        'pr_number': 17, 'source': {'commit': 'a'*40},
                        'control': {'commit': 'b'*40}}
        self.fields = {'queue_id': 'c'*32, 'reservation_sequence': '2',
                       'reservation_sha256': 'd'*64}

    def test_complete_claim_binds_resolved_pr(self):
        result = claim(self.fields, self.receipt, '123-1')
        self.assertEqual(result['status'], 'claimed_unverified')
        self.assertEqual(result['event_id'],
                         '["openwrt/openwrt","pull_request",17,"'+'a'*40+'"]')
        self.assertEqual(result['reservation_sequence'], 2)

    def test_absent_claim_is_explicit(self):
        result = claim(dict.fromkeys(self.fields, ''), self.receipt, '123-1')
        self.assertEqual(result['status'], 'absent')
        self.assertNotIn('queue_id', result)

    def test_partial_claim_rejected(self):
        fields = {**self.fields, 'reservation_sha256': ''}
        with self.assertRaisesRegex(ClaimError, 'incomplete'):
            claim(fields, self.receipt, '123-1')

    def test_invalid_claim_fields_rejected(self):
        for field, value in [('queue_id', 'wrong'), ('reservation_sequence', '-1'),
                             ('reservation_sha256', 'd'*63)]:
            with self.subTest(field=field), self.assertRaisesRegex(ClaimError, 'invalid reservation'):
                claim({**self.fields, field: value}, self.receipt, '123-1')

    def test_unresolved_source_rejected(self):
        with self.assertRaisesRegex(ClaimError, 'unresolved'):
            claim(self.fields, {**self.receipt, 'status': 'failed'}, '123-1')


if __name__ == '__main__':
    unittest.main()
