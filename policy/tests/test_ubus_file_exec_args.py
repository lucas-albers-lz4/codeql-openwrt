#!/usr/bin/env python3
"""Independent expectations from rpcd file.c d99f703, not Python/C parity."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from policy.oracle import AclEntry, C_DOUBLE_FLAGS, Session
from policy.tests.test_ubus_file_exec_cmdline import ORACLES, SID

REPO = Path(__file__).resolve().parents[2]


class TestRpcdArguments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binaries = {}
        for module, _ in ORACLES:
            name = module.__name__.rsplit('.', 1)[-1]
            binary = Path(cls.tmp.name) / name
            subprocess.run(['gcc', *C_DOUBLE_FLAGS, '-o', str(binary),
                            str(REPO / 'policy' / 'c_double' / (name + '.c'))], check=True)
            cls.binaries[name] = binary

    def test_upstream_arguments_and_acl_order(self):
        # A wildcard with a literal space matches only a built command line.
        cases = [
            ('absent', None, '', 'command_denied', 'executable_miss_and_null_params'),
            ('empty', [], '', 'command_denied', None),
            ('non-strings', [None, 1, False, {}, []], '', 'command_denied', None),
            ('empty-string', [''], ' ', 'allow', None),
            ('mixed', [7, 'one', None, '', False, 'two'], ' one  two', 'allow', None),
            ('253', ['x'] * 253, ' ' + ' '.join(['x'] * 253), 'allow', None),
            ('254', ['x'] * 254, ' ' + ' '.join(['x'] * 254), 'command_denied', 'too_many_args'),
            ('skipped-do-not-count', [None] * 254 + ['x'] * 253, ' ' + ' '.join(['x'] * 253), 'allow', None),
        ]
        for module, evaluate in ORACLES:
            command = next(iter(module.COMMANDS.values()))['fs_path']
            for case, params, suffix, fallback_outcome, reason in cases:
                for executable_acl in (False, True):
                    with self.subTest(oracle=module.__name__, case=case, executable_acl=executable_acl):
                        pattern = command if executable_acl else command + ' *'
                        session = Session('args-test', SID, None, [
                            AclEntry('test', 'write', 'ubus', 'file', 'exec', __file__),
                            AclEntry('test', 'write', 'file', pattern, 'exec', __file__),
                        ])
                        result = evaluate(sid=SID, command=command, params=params, sessions={SID: session})
                        self.assertEqual(result.cmdline, command + suffix)
                        self.assertEqual(result.outcome, 'allow' if executable_acl else fallback_outcome)
                        self.assertEqual(result.ubus_status, 0 if result.outcome == 'allow' else 6)
                        if executable_acl:
                            # This is an ACL decision, not child execution:
                            # rpcd's child separately exits 127 on string 254.
                            self.assertEqual(result.match_stage, 'executable')
                            self.assertFalse(any(s.get('stage') == 'cmdline' for s in result.steps))
                        elif reason:
                            self.assertEqual(result.steps[-1]['reason'], reason)
                            self.assertFalse(any(s.get('stage') == 'cmdline' for s in result.steps))
                        else:
                            self.assertEqual(result.steps[-2]['stage'], 'cmdline')
                            self.assertEqual(result.steps[-2]['object'], command + suffix)

    def test_fallback_limits_are_checked_in_order(self):
        for module, evaluate in ORACLES:
            command = next(iter(module.COMMANDS.values()))['fs_path']
            session = Session('args-test', SID, None, [
                AclEntry('test', 'write', 'ubus', 'file', 'exec', __file__),
                AclEntry('test', 'write', 'file', command + ' *', 'exec', __file__),
            ])
            cases = [
                (['é' * 510] + ['x'] * 254, 'cmdline_too_long'),
                (['x'] * 253 + ['é' * 510], 'too_many_args'),
            ]
            for params, reason in cases:
                with self.subTest(oracle=module.__name__, reason=reason):
                    result = evaluate(sid=SID, command=command, params=params,
                                      sessions={SID: session})
                    self.assertEqual(result.outcome, 'command_denied')
                    self.assertEqual(result.steps[-1]['reason'], reason)
                    self.assertFalse(any(s.get('stage') == 'cmdline' for s in result.steps))

    def test_typed_c_cmdline(self):
        cases = [
            ([], '/x', 0),
            (['n:1', 'n:false'], '/x', 0),
            (['s:'], '/x ', 0),
            (['n:1', 's:one', 's:', 'n:x', 's:two'], '/x one  two', 0),
            (['s:x'] * 253, '/x' + ' x' * 253, 0),
            (['s:x'] * 254, 'UBUS_PERMISSION_DENIED', 1),
            (['n:x'] * 254 + ['s:x'] * 253, '/x' + ' x' * 253, 0),
            (['s:' + 'é' * 510], '/x ' + 'é' * 510, 0),
            (['s:' + 'é' * 511], 'UBUS_PERMISSION_DENIED', 1),
        ]
        for name, binary in self.binaries.items():
            for args, expected, status in cases:
                with self.subTest(oracle=name, count=len(args), expected=expected[:30]):
                    proc = subprocess.run([str(binary), 'cmdline', '/x', *args], capture_output=True, text=True)
                    self.assertEqual(proc.returncode, status, proc.stderr)
                    self.assertEqual(proc.stdout, expected + '\n')

    def test_initial_executable_byte_limit(self):
        for name, binary in self.binaries.items():
            for length, status in ((1023, 0), (1024, 1)):
                with self.subTest(oracle=name, length=length):
                    executable = 'x' * length
                    proc = subprocess.run([str(binary), 'cmdline', executable], capture_output=True, text=True)
                    self.assertEqual(proc.returncode, status, proc.stderr)
                    self.assertEqual(proc.stdout, (executable if not status else 'UBUS_PERMISSION_DENIED') + '\n')
