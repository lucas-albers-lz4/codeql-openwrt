"""Compare login ACL decisions with pinned rpcd in the C locale."""

import ctypes
import subprocess
import tempfile
import unittest
from pathlib import Path

from policy.oracle import AclEntry, Login, Session, evaluate_call, login_test_permission, session_acls


class LoginNegationWhitespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        source = Path(__file__).with_name("rpcd_login_permission_ref.c")
        library = Path(cls.temp.name) / "rpcd_login_permission.so"
        subprocess.run(
            ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0",
             "-shared", "-fPIC", str(source), "-o", str(library)],
            check=True,
        )
        cls.reference = ctypes.CDLL(str(library)).reference_permission
        cls.reference.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                  ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t]
        cls.reference.restype = ctypes.c_int

    def native(self, login, perm, group):
        read = [] if login is None else login.read
        write = [] if login is None else login.write
        reads = (ctypes.c_char_p * len(read))(*(s.encode("utf-8") for s in read))
        writes = (ctypes.c_char_p * len(write))(*(s.encode("utf-8") for s in write))
        result = self.reference(login is None, perm.encode(), group.encode("utf-8"),
                                reads, len(read), writes, len(write))
        self.assertIn(result, (0, 1), "native reference setup failed")
        return bool(result)

    def test_negation_whitespace_matches_pinned_rpcd(self):
        cases = [
            ("positive", "example", ["*"], True),
            ("ordinary negation", "example", ["*", "!example"], False),
            *[("ASCII " + repr(c), "example", ["*", "!" + c + "example"], False)
              for c in " \t\n\r\v\f"],
            ("mixed ASCII", "example", ["*", "! \t\n\r\v\fexample"], False),
            ("empty negative", "example", ["*", "! \t"], True),
            *[(repr(c) + " plain group", "example", ["*", "!" + c + "example"], True)
              for c in ("\u00a0", "\u2003")],
            *[(repr(c) + " prefixed group", c + "example", ["*", "!" + c + "example"], False)
              for c in ("\u00a0", "\u2003")],
            ("ASCII then Unicode", "example", ["*", "! \t\u00a0example"], True),
            ("ASCII then Unicode match", "\u00a0example", ["*", "! \t\u00a0example"], False),
        ]
        for name, group, patterns, expected in cases:
            with self.subTest(case=name):
                login = Login(username="test", read=patterns)
                self.assertEqual(self.native(login, "read", group), expected)
                self.assertEqual(login_test_permission(login, "read", group), expected)

    def test_existing_read_write_default_and_nul_semantics(self):
        cases = [
            (None, "read", "unauthenticated", True),
            (None, "write", "other", False),
            (Login("test", read=[], write=["*"]), "read", "example", True),
            (Login("test", read=["*", "!example"], write=["*"]), "read", "example", False),
            (Login("test", read=[], write=["*", "!example"]), "read", "example", False),
            (Login("test", read=["*"]), "write", "example", False),
            (Login("test", read=["*", "!example\0ignored"]), "read", "example\0suffix", False),
            (Login("test", read=["*", "!\0example"]), "read", "example", True),
            (Login("test", read=["! \0example", "*\0ignored"]), "read", "example", True),
        ]
        for login, perm, group, expected in cases:
            with self.subTest(login=login, perm=perm, group=group):
                self.assertEqual(self.native(login, perm, group), expected)
                self.assertEqual(login_test_permission(login, perm, group), expected)

    def test_integrated_session_and_gate_follow_native_decision(self):
        sid = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        for whitespace in ("\u00a0", "\u2003"):
            login = Login("test", read=["*", "!" + whitespace + "example"])
            for group, expected in (("example", True), (whitespace + "example", False)):
                with self.subTest(whitespace=repr(whitespace), group=repr(group)):
                    self.assertEqual(self.native(login, "read", group), expected)
                    entry = AclEntry(group, "read", "ubus", "luci", "getFeatures", "synthetic")
                    acls = session_acls(login, [entry])
                    session = Session("test", sid, login, acls)
                    outcome = evaluate_call(sid=sid, object="luci", function="getFeatures",
                                            data={}, sessions={sid: session}).outcome
                    self.assertEqual(outcome, "allow" if expected else "deny")
                    self.assertEqual(entry in acls, expected)
