import unittest

from incoming_dispatch_record import record


class DispatchRecordTests(unittest.TestCase):
    def setUp(self):
        self.env = {'UPSTREAM': 'openwrt', 'PR_NUMBER': '17',
                    'SOURCE_SHA': 'a'*40, 'CONTROL_SHA': 'b'*40,
                    'QUEUE_ID': 'c'*32, 'RESERVATION_SEQUENCE': '2',
                    'RESERVATION_SHA256': 'd'*64,
                    'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '1'}

    def test_claim_retains_exact_inputs_and_run(self):
        value = record(self.env)
        self.assertEqual((value['status'], value['run_id'], value['pr_number']),
                         ('claimed_unverified', '101-1', 17))
        self.assertEqual(value['reservation_sha256'], 'd'*64)

    def test_absent_claim_is_explicit(self):
        env = {**self.env, 'QUEUE_ID': '', 'RESERVATION_SEQUENCE': '',
               'RESERVATION_SHA256': ''}
        value = record(env)
        self.assertEqual(value['status'], 'absent')
        self.assertNotIn('queue_id', value)

    def test_partial_claim_rejected(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            record({**self.env, 'RESERVATION_SHA256': ''})

    def test_invalid_identity_rejected(self):
        for key, value in [('UPSTREAM', 'other'), ('SOURCE_SHA', 'bad'),
                           ('GITHUB_RUN_ATTEMPT', '0')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'invalid'):
                record({**self.env, key: value})


if __name__ == '__main__':
    unittest.main()
