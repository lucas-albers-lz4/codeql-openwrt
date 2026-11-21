from __future__ import annotations

import unittest
from types import SimpleNamespace

from run_baseline import classify_file_exec
from policy.oracle import ERROR_ACCESS
from policy.ubus_file_exec import UBUS_STATUS_PERMISSION_DENIED, UBUS_STATUS_OK


def result(**overrides):
    base = {
        "outcome": "command_denied",
        "ubus_matched": object(),
        "ubus_status": UBUS_STATUS_PERMISSION_DENIED,
        "jsonrpc_error": None,
        "file_matched": None,
        "match_stage": None,
        "steps": [],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class FileExecClassificationTests(unittest.TestCase):
    def test_failed_cmdline_acl_is_command_denial(self):
        outcome = classify_file_exec(
            result(
                steps=[
                    {"step": "rpc_file_access", "stage": "executable", "result": False},
                    {"step": "rpc_file_access", "stage": "cmdline", "result": False},
                ]
            )
        )
        self.assertEqual(outcome["http_gate"], "allow")
        self.assertEqual(outcome["command_gate"], "deny")
        self.assertEqual(outcome["relation_outcome"], "deny")

    def test_executable_miss_without_cmdline_check_is_unknown(self):
        outcome = classify_file_exec(
            result(steps=[{"step": "rpc_file_access", "stage": "executable", "result": False}])
        )
        self.assertEqual(outcome["http_gate"], "allow")
        self.assertEqual(outcome["command_gate"], "unknown")
        self.assertEqual(outcome["relation_outcome"], "unknown")

    def test_http_denial_leaves_command_stage_unknown_but_denies_relation(self):
        outcome = classify_file_exec(
            result(
                outcome="deny",
                ubus_matched=None,
                ubus_status=None,
                jsonrpc_error=ERROR_ACCESS,
                steps=[{"step": "uh_ubus_allowed", "result": False}],
            )
        )
        self.assertEqual(outcome["http_gate"], "deny")
        self.assertEqual(outcome["command_gate"], "unknown")
        self.assertEqual(outcome["relation_outcome"], "deny")

    def test_command_allow_requires_file_acl_match(self):
        outcome = classify_file_exec(
            result(
                outcome="allow",
                ubus_status=UBUS_STATUS_OK,
                file_matched=object(),
                match_stage="executable",
                steps=[{"step": "rpc_file_access", "stage": "executable", "result": True}],
            )
        )
        self.assertEqual(outcome["command_gate"], "allow")
        self.assertEqual(outcome["relation_outcome"], "allow")


if __name__ == "__main__":
    unittest.main()
