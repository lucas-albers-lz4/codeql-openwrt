import json
import pathlib
import subprocess
import tempfile
import unittest
from search import search

A = '/proc/sys/net/ipv6/conf/*/mtu'
B = '/proc/sys/net/ipv[46]/conf/*'
P = {'group': 'luci-mod-network-config', 'verb': 'read', 'scope': 'file', 'ubus_object': None}

class WitnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.exe = str(pathlib.Path(cls.temp.name) / 'check')
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(pathlib.Path(__file__).with_name('check.c')), '-o', cls.exe], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_fixture_provenance(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        fixture = json.loads((root / 'policy/fixtures/luci-mod-network.json').read_text())
        file_acl = fixture[P['group']][P['verb']][P['scope']]
        self.assertIn('read', file_acl[A])
        self.assertIn('read', file_acl[B])

    def test_pinned_pair_and_helper_recheck(self):
        result = search(P, A, P, B, self.exe)
        self.assertEqual(result['status'], 'witness')
        self.assertEqual(result['value'], '/proc/sys/net/ipv6/conf/eth0/mtu')
        self.assertEqual(subprocess.run([self.exe, A, B, result['value']]).returncode, 0)
        self.assertEqual(subprocess.run([self.exe, A, B, '/proc/sys/net/ipv5/conf/eth0/mtu']).returncode, 1)

    def test_provenance_and_unsupported_bracket(self):
        for key, value in [('group', 'other'), ('verb', 'write'), ('scope', 'ubus_object')]:
            self.assertEqual(search(P, A, {**P, key: value}, B, self.exe)['status'], 'scope_mismatch')
        u = {'group': 'g', 'verb': 'read', 'scope': 'ubus_function', 'ubus_object': 'luci'}
        self.assertEqual(search(u, 'a*', {**u, 'ubus_object': 'file'}, 'a*', self.exe)['status'], 'scope_mismatch')
        self.assertEqual(search(P, 'a[\\x]', P, 'a*', self.exe)['status'], 'inconclusive')

    def test_unexpected_fnmatch_result_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / 'stub.c'
            stub.write_text('int fake_fnmatch(const char *a, const char *b, int f) {(void)a; (void)b; (void)f; return 42;}\n')
            exe = str(pathlib.Path(d) / 'check')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Dfnmatch=fake_fnmatch', str(pathlib.Path(__file__).with_name('check.c')), str(stub), '-o', exe], check=True)
            self.assertEqual(subprocess.run([exe, 'a*', 'a*', 'abc']).returncode, 2)

    def test_invalid_verb_and_json(self):
        bad = {**P, 'verb': 'execute'}
        self.assertEqual(search(bad, A, bad, B, self.exe)['status'], 'scope_mismatch')
        proc = subprocess.run(['python3', str(pathlib.Path(__file__).with_name('search.py')), self.exe, '{', A, '{}', B], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('error: provenance must be valid JSON', proc.stderr)
        self.assertNotIn('Traceback', proc.stderr)

    def test_checker_decode_error_is_operational(self):
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / 'bad'
            bad.write_bytes(b'#!/bin/sh\nprintf \"\\377\" >&2\nexit 2\n')
            bad.chmod(0o755)
            with self.assertRaises(UnicodeDecodeError):
                search(P, 'a*', P, 'a*', str(bad))

    def test_checker_error_is_not_a_negative_match(self):
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / 'bad'
            bad.write_text('#!/bin/sh\nexit 2\n')
            bad.chmod(0o755)
            with self.assertRaises(RuntimeError):
                search(P, 'a*', P, 'a*', str(bad))

    def test_nonintersection_is_inconclusive(self):
        self.assertEqual(search(P, 'a*', P, 'b*', self.exe)['status'], 'inconclusive')

    def test_scope_and_bounds(self):
        self.assertEqual(search(P, A, {**P, 'scope': 'ubus_object'}, B, self.exe)['status'], 'scope_mismatch')
        self.assertEqual(search(P, A, P, B, self.exe, 0)['reason'], 'budget')
        self.assertEqual(search(P, 'a?', P, 'a*', self.exe)['status'], 'inconclusive')

if __name__ == '__main__': unittest.main()
