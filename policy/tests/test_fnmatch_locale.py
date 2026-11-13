"""C-locale byte matching agrees with the standalone C double."""

import locale
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import policy.oracle as oracle

from policy.oracle import FNM_NOESCAPE, Login, acl_match, libc_fnmatch, login_test_permission
from policy.tests.test_conformance import _compile_c_double


class TestFnmatchLocale(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.exe = _compile_c_double(Path(cls.temp.name) / "uh_ubus_policy")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def c_match(self, command, *args):
        result = subprocess.run([str(self.exe), command, *args], capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_c_locale_byte_parity(self):
        cases = [
            ("?", "é", False), ("??", "é", True),
            ("[!x]", "é", False), ("[!x][!x]", "é", True),
            ("?", "😀", False), ("????", "😀", True),
            ("[!x]", "😀", False), ("[!x][!x][!x][!x]", "😀", True),
            ("[!x]*", "é", True), ("[!x]*", "😀", True),
            ("é*", "éclair", True), ("é*", "eclair", False),
        ]
        original = locale.setlocale(locale.LC_ALL)
        try:
            locales = ["C"]
            for name in ("C.UTF-8", "C.utf8", "en_US.UTF-8"):
                try:
                    locale.setlocale(locale.LC_ALL, name)
                except locale.Error:
                    continue
                locales.append(name)
                break
            for name in locales:
                locale.setlocale(locale.LC_ALL, name)
                before = locale.setlocale(locale.LC_ALL)
                for pattern, value, expected in cases:
                    with self.subTest(locale=name, pattern=pattern, value=value):
                        self.assertEqual(self.c_match("group", pattern, value), expected)
                        self.assertEqual(libc_fnmatch(pattern, value, 0), expected)
                        self.assertEqual(login_test_permission(Login(username="test", read=[pattern]), "read", value), expected)
                        self.assertEqual(self.c_match("match", pattern, "*", value, "method"), expected)
                        self.assertEqual(acl_match(pattern, "*", value, "method"), expected)
                        self.assertEqual(locale.setlocale(locale.LC_ALL), before)
        finally:
            locale.setlocale(locale.LC_ALL, original)

    def test_escaping_and_negated_login(self):
        # Backslash escapes in login patterns, but is literal with FNM_NOESCAPE.
        self.assertTrue(self.c_match("group", r"\?", "?"))
        self.assertTrue(libc_fnmatch(r"\?", "?", 0))
        self.assertFalse(self.c_match("match", r"\?", "*", "?", "method"))
        self.assertFalse(acl_match(r"\?", "*", "?", "method"))
        self.assertTrue(libc_fnmatch(r"\?", r"\a", FNM_NOESCAPE))
        self.assertTrue(self.c_match("match", r"\?", "*", r"\a", "method"))
        login = Login(username="test", read=["*", "!??"])
        self.assertFalse(login_test_permission(login, "read", "é"))
        self.assertTrue(login_test_permission(login, "read", "😀"))

    def test_restores_explicit_thread_locale_on_success_and_exception(self):
        libc_fnmatch("*", "x", 0)  # Initialize the configured libc bindings.
        lib = oracle._LIBC
        thread_locale = None
        for name in (b"C.UTF-8", b"C.utf8", b"en_US.UTF-8"):
            thread_locale = lib.newlocale(1 << locale.LC_CTYPE, name, None)
            if thread_locale:
                break
        if not thread_locale:
            self.skipTest("no UTF-8 locale installed")
        previous = lib.uselocale(thread_locale)
        self.assertTrue(previous)
        try:
            self.assertFalse(libc_fnmatch("?", "é", 0))
            self.assertEqual(lib.uselocale(None), thread_locale)
            with patch.object(lib, "fnmatch", side_effect=RuntimeError("test failure")):
                with self.assertRaisesRegex(RuntimeError, "test failure"):
                    libc_fnmatch("*", "x", 0)
            self.assertEqual(lib.uselocale(None), thread_locale)
        finally:
            self.assertTrue(lib.uselocale(previous))
            lib.freelocale(thread_locale)

    def test_reject_embedded_nul(self):
        with self.assertRaises(ValueError):
            libc_fnmatch("*", "a\0b", 0)
