#!/usr/bin/env python3
"""Shared file.exec cmdline parity against all five pinned C doubles."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from policy import (
    ubus_file_exec,
    ubus_file_exec_ifup,
    ubus_file_exec_kill,
    ubus_file_exec_list_backup,
    ubus_file_exec_mounts,
)
from policy.oracle import AclEntry, C_DOUBLE_FLAGS, Session
from policy.ubus_file_exec import UBUS_STATUS_OK, UBUS_STATUS_PERMISSION_DENIED

REPO = Path(__file__).resolve().parents[2]
CASES = REPO / "policy" / "fixtures" / "ubus_file_exec_cmdline_cases.json"
SID = "fefefefefefefefefefefefefefefefe"
ORACLES = (
    (ubus_file_exec, ubus_file_exec.evaluate_file_exec),
    (ubus_file_exec_ifup, ubus_file_exec_ifup.evaluate_ifup_exec),
    (ubus_file_exec_kill, ubus_file_exec_kill.evaluate_kill_exec),
    (ubus_file_exec_mounts, ubus_file_exec_mounts.evaluate_mounts_exec),
    (ubus_file_exec_list_backup, ubus_file_exec_list_backup.evaluate_list_backup_exec),
)


class TestCmdlineParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(CASES.read_text(encoding="utf-8"))
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.executables = {}
        for module, _evaluate in ORACLES:
            name = module.__name__.rsplit(".", 1)[-1]
            executable = Path(cls.tmp.name) / name
            subprocess.run(
                ["gcc", *C_DOUBLE_FLAGS, "-o", str(executable),
                 str(REPO / "policy" / "c_double" / f"{name}.c")],
                check=True,
                cwd=REPO,
            )
            cls.executables[name] = executable

    def _evaluate(self, module, evaluate, command, params, *, executable_acl=False):
        file_pattern = command if executable_acl else command + " *"
        sessions = {
            SID: Session(
                session_class="cmdline-parity-test",
                sid=SID,
                login=None,
                acls=[
                    AclEntry("test", "write", "ubus", "file", "exec", str(CASES)),
                    AclEntry("test", "write", "file", file_pattern, "exec", str(CASES)),
                ],
            )
        }
        result = evaluate(sid=SID, command=command, params=params, sessions=sessions)
        # The doubles take the filtered params as one space-joined CLI argument.
        c_params = "-" if result.params is None else " ".join(result.params)
        name = module.__name__.rsplit(".", 1)[-1]
        proc = subprocess.run(
            [str(self.executables[name]), "decide", SID, command, c_params,
             "file", "exec", command if executable_acl else "-",
             "exec" if executable_acl else "-", command + " *", "exec"],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(proc.stderr, "")
        self.assertIn(proc.returncode, (0, 1))
        return result, proc.stdout.strip()

    def _commands(self):
        for module, evaluate in ORACLES:
            self.assertEqual(module.RPCD_SHA, self.cases["rpcd"])
            for command in sorted({spec["fs_path"] for spec in module.COMMANDS.values()}):
                yield module, evaluate, command

    def _boundary_params(self, command, case):
        prefix = case["prefix_params"]
        # One separator follows the command and every prefix argument.
        remaining = case["cmdline_bytes"] - len(
            (command + " " + "".join(value + " " for value in prefix)).encode("utf-8")
        )
        count, padding = divmod(remaining, len(case["fill"].encode("utf-8")))
        params = [*prefix, case["fill"] * count + "a" * padding]
        self.assertEqual(
            len((command + " " + " ".join(params)).encode("utf-8")),
            case["cmdline_bytes"],
        )
        return params

    def test_cmdline_byte_boundaries(self) -> None:
        for module, evaluate, command in self._commands():
            for case in self.cases["boundary_cases"]:
                with self.subTest(oracle=module.__name__, command=command, case=case["id"]):
                    params = self._boundary_params(command, case)
                    result, c_decision = self._evaluate(module, evaluate, command, params)
                    self.assertEqual(c_decision, case["expected_c_decision"])
                    self.assertEqual(result.outcome, case["expected_outcome"])
                    self.assertEqual(len(result.cmdline.encode("utf-8")), case["cmdline_bytes"])
                    cmdline_checks = [step for step in result.steps if step.get("stage") == "cmdline"]
                    if case["expected_outcome"] == "allow":
                        self.assertEqual(result.ubus_status, UBUS_STATUS_OK)
                        self.assertEqual(result.match_stage, "cmdline")
                        self.assertEqual(len(cmdline_checks), 1)
                    else:
                        self.assertEqual(result.ubus_status, UBUS_STATUS_PERMISSION_DENIED)
                        self.assertIsNone(result.file_matched)
                        self.assertIsNone(result.match_stage)
                        self.assertEqual(result.steps[-1]["reason"], "cmdline_too_long")
                        self.assertEqual(cmdline_checks, [])

    def test_executable_acl_precedes_cmdline_cap(self) -> None:
        case = next(case for case in self.cases["boundary_cases"] if case["id"] == "ascii-1024-deny")
        for module, evaluate, command in self._commands():
            with self.subTest(oracle=module.__name__, command=command):
                params = self._boundary_params(command, case)
                result, c_decision = self._evaluate(
                    module, evaluate, command, params, executable_acl=True
                )
                self.assertEqual(c_decision, "ALLOW")
                self.assertEqual(result.outcome, "allow")
                self.assertEqual(result.ubus_status, UBUS_STATUS_OK)
                self.assertEqual(result.match_stage, "executable")
                self.assertFalse(any(step.get("stage") == "cmdline" for step in result.steps))

    def test_empty_params_cmdline(self) -> None:
        for module, evaluate, command in self._commands():
            for case in self.cases["empty_params_cases"]:
                with self.subTest(oracle=module.__name__, command=command, case=case["id"]):
                    result, c_decision = self._evaluate(module, evaluate, command, case["params"])
                    self.assertEqual(c_decision, case["expected_c_decision"])
                    self.assertEqual(result.outcome, case["expected_outcome"])
                    self.assertEqual(result.params, case["expected_params"])
                    self.assertEqual(result.cmdline, command + case["cmdline_suffix"])
                    if case["expected_outcome"] == "allow":
                        self.assertEqual(result.match_stage, "cmdline")
                    else:
                        self.assertEqual(result.steps[-1]["reason"], "executable_miss_and_null_params")


if __name__ == "__main__":
    unittest.main()
