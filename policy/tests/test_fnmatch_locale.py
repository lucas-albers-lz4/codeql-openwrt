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

REPO = Path(__file__).resolve().parents[2]


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

    def test_fnmatch_truncates_embedded_nul(self):
        self.assertTrue(libc_fnmatch("*\0ignored", "a\0b", 0))
        self.assertFalse(libc_fnmatch("a\0*", "b\0a", 0))

    def test_acl_match_truncates_nul_in_literal_and_wildcard_inputs(self):
        cases = [
            # NUL terminates literal object and function patterns and values.
            ("luci\0*", "getVersion\0*", "luci\0suffix", "getVersion\0suffix", True),
            ("luci\0*", "getVersion", "lucX\0luci", "getVersion\0suffix", False),
            # NUL terminates wildcard patterns and values after the active prefix.
            ("luci*\0suffix", "get*\0suffix", "luci\0object", "getVersion\0value", True),
            ("luci*\0suffix", "get*", "other\0luci", "getVersion\0value", False),
            # A wildcard after NUL is not active; the resulting pattern is literal.
            ("luci\0*", "getVersion\0*", "luciX\0tail", "getVersion\0tail", False),
        ]

        for pattern_object, pattern_function, object_name, function_name, expected in cases:
            with self.subTest(
                pattern_object=pattern_object,
                pattern_function=pattern_function,
                object_name=object_name,
                function_name=function_name,
            ):
                self.assertEqual(
                    acl_match(pattern_object, pattern_function, object_name, function_name),
                    expected,
                )

        self.assertTrue(
            login_test_permission(
                Login(username="nul", read=["group\0ignored"]),
                "read",
                "group\0value",
            )
        )
        self.assertTrue(
            login_test_permission(
                Login(username="nul", read=["group*\0ignored"]),
                "read",
                "group\0value",
            )
        )

    def test_embedded_nul_acl_match_matches_c_reference(self):
        c_double = (REPO / "policy" / "c_double" / "uh_ubus_policy.c").as_posix()
        cases = [
            ("luci\0*", "getVersion\0*", "luci\0suffix", "getVersion\0suffix", True),
            ("luci\0*", "getVersion", "lucX\0luci", "getVersion\0suffix", False),
            ("luci*\0suffix", "get*\0suffix", "luci\0object", "getVersion\0value", True),
            ("luci*\0suffix", "get*", "other\0luci", "getVersion\0value", False),
            ("luci\0*", "getVersion\0*", "luciX\0tail", "getVersion\0tail", False),
        ]
        helper_source = r'''#define main uh_ubus_policy_cli_main
#include "__C_DOUBLE__"
#undef main

int main(void) {
    printf("%d\n", acl_match("luci\0*", "getVersion\0*", "luci\0suffix", "getVersion\0suffix"));
    printf("%d\n", acl_match("luci\0*", "getVersion", "lucX\0luci", "getVersion\0suffix"));
    printf("%d\n", acl_match("luci*\0suffix", "get*\0suffix", "luci\0object", "getVersion\0value"));
    printf("%d\n", acl_match("luci*\0suffix", "get*", "other\0luci", "getVersion\0value"));
    printf("%d\n", acl_match("luci\0*", "getVersion\0*", "luciX\0tail", "getVersion\0tail"));
    return 0;
}
'''.replace("__C_DOUBLE__", c_double)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "nul_acl_reference.c"
            executable = root / "nul_acl_reference"
            source.write_text(helper_source, encoding="utf-8")
            subprocess.run(
                [
                    "gcc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O0",
                    "-o",
                    str(executable),
                    str(source),
                ],
                cwd=REPO,
                check=True,
            )
            result = subprocess.run(
                [str(executable)], capture_output=True, text=True, check=True
            )

        c_results = [line == "1" for line in result.stdout.splitlines()]
        self.assertEqual(c_results, [expected for *_, expected in cases])
        for pattern_object, pattern_function, object_name, function_name, expected in cases:
            self.assertEqual(
                acl_match(pattern_object, pattern_function, object_name, function_name),
                expected,
            )
