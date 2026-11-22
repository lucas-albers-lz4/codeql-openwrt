import unittest

from policy.v2_json import InputError, parse_json


class StrictJSONTests(unittest.TestCase):
    def test_valid_values_and_versions_keep_types(self):
        data = parse_json(b'{"version":2,"flag":true,"nested":[null,1.5]}')
        self.assertIs(type(data['version']), int)
        self.assertIs(type(data['flag']), bool)
        self.assertEqual(data['nested'], [None, 1.5])

    def test_duplicate_keys_at_any_depth_rejected(self):
        for raw in (b'{"version":2,"version":1}',
                    b'{"scope":{"caller":"a","caller":"b"}}',
                    b'[{"a":1,"\\u0061":2}]'):
            with self.subTest(raw=raw), self.assertRaisesRegex(InputError, 'duplicate'):
                parse_json(raw)

    def test_invalid_inputs_rejected(self):
        for raw in (b'{', b'{} trailing', b'\xff', b'\xef\xbb\xbf{}',
                    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e9999}',
                    '{}', None):
            with self.subTest(raw=raw), self.assertRaises(InputError):
                parse_json(raw)


if __name__ == '__main__':
    unittest.main()


class ParserLimitTests(unittest.TestCase):
    def test_decoder_recursion_error_is_normalized(self):
        from unittest.mock import patch
        with patch('policy.v2_json.json.loads', side_effect=RecursionError('depth')):
            with self.assertRaises(InputError):
                parse_json(b'[]')

    def test_integer_limit_is_input_error(self):
        with self.assertRaises(InputError):
            parse_json(b'9' * 10000)
