"""Raw file.exec data must retain JSON types across all evaluator wrappers."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.oracle import ERROR_PARSE
from policy.ubus_file_exec import UBUS_STATUS_INVALID_ARGUMENT


class TestFileExecData(unittest.TestCase):
    def test_raw_data_and_omitted_convenience_payload(self) -> None:
        for suffix, evaluator_name in (
            ("", "evaluate_file_exec"),
            ("_ifup", "evaluate_ifup_exec"),
            ("_kill", "evaluate_kill_exec"),
            ("_mounts", "evaluate_mounts_exec"),
            ("_list_backup", "evaluate_list_backup_exec"),
        ):
            module = importlib.import_module(f"policy.ubus_file_exec{suffix}")
            evaluate = getattr(module, evaluator_name)
            case = next(case for case in module.load_expected_cases()
                        if case["expected_outcome"] == "allow")
            kwargs = {key: case.get(key) for key in
                      ("session_class", "sid", "command", "params", "env")}
            with self.subTest(wrapper=suffix, data="omitted"):
                self.assertEqual(evaluate(**kwargs).outcome, "allow")
                self.assertEqual(module.evaluate_expected_case(case).outcome, "allow")
            for data in (None, [], "", 0, False):
                with self.subTest(wrapper=suffix, data=data):
                    for result in (evaluate(**kwargs, data=data),
                                   module.evaluate_expected_case({**case, "data": data})):
                        self.assertEqual(result.outcome, "jsonrpc_parse_error")
                        self.assertEqual(result.jsonrpc_error, ERROR_PARSE)
                        self.assertIsNone(result.ubus_status)
                        self.assertFalse(any(step["step"] == "uh_ubus_allowed"
                                             for step in result.steps))
            with self.subTest(wrapper=suffix, data={}):
                result = evaluate(**kwargs, data={})
                self.assertEqual(result.outcome, "invalid_argument")
                self.assertEqual(result.ubus_status, UBUS_STATUS_INVALID_ARGUMENT)
                # The case adapter must preserve an explicit empty table too, not
                # fall back to the omitted-payload convenience construction.
                adapter_result = module.evaluate_expected_case({**case, "data": {}})
                self.assertEqual(adapter_result.outcome, "invalid_argument")
                self.assertEqual(adapter_result.ubus_status, UBUS_STATUS_INVALID_ARGUMENT)
            with self.subTest(wrapper=suffix, data="explicit command table"):
                table = {"command": case["command"], "params": case["params"]}
                result = evaluate(**{**kwargs, "command": None}, data=table)
                self.assertEqual(result.outcome, "allow")
                # Precedence: a table-valued case payload wins over the case's own
                # command/params convenience fields, through the adapter as well.
                adapter_result = module.evaluate_expected_case(
                    {**case, "command": None, "data": table})
                self.assertEqual(adapter_result.outcome, "allow")


if __name__ == "__main__":
    unittest.main()
