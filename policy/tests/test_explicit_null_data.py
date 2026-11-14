#!/usr/bin/env python3
"""Keep omitted ubus data distinct from explicit JSON null in slice wrappers."""

from __future__ import annotations

from importlib import import_module
import subprocess
import tempfile
import unittest
from pathlib import Path

from policy.oracle import C_DOUBLE_FLAGS, ERROR_PARSE, ROOT_FIXTURE_SID

REPO = Path(__file__).resolve().parents[2]
C_SRC = REPO / "policy" / "c_double" / "uh_ubus_policy.c"


WRAPPERS = (
    ("ubus_hostapd_del_client", "evaluate_hostapd_del_client"),
    ("ubus_hostapd_wps_start", "evaluate_hostapd_wps_start"),
    ("ubus_hostapd_wps_cancel", "evaluate_hostapd_wps_cancel"),
    ("ubus_hostapd_wps_status", "evaluate_hostapd_wps_status"),
    ("ubus_luci_getbuiltinethernetports", "evaluate_luci_getbuiltinethernetports"),
    ("ubus_luci_getleds", "evaluate_luci_getleds"),
    ("ubus_luci_getmountpoints", "evaluate_luci_getmountpoints"),
    ("ubus_luci_getodhcp6cstats", "evaluate_luci_getodhcp6cstats"),
    ("ubus_luci_gettimezones", "evaluate_luci_gettimezones"),
    ("ubus_luci_getunixtime", "evaluate_luci_getunixtime"),
    ("ubus_luci_getversion", "evaluate_luci_getversion"),
    ("ubus_rc_init", "evaluate_rc_init"),
    ("ubus_rc_list", "evaluate_rc_list"),
    ("ubus_system_board", "evaluate_system_board"),
    ("ubus_system_info", "evaluate_system_info"),
    ("ubus_system_reboot", "evaluate_system_reboot"),
)


class TestExplicitNullData(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = Path(cls.tmp.name) / "uh_ubus_policy"
        subprocess.run(
            ["gcc", *C_DOUBLE_FLAGS, "-o", str(cls.exe), str(C_SRC)],
            check=True,
            cwd=REPO,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_all_legacy_wrappers_preserve_null_and_omitted_data(self) -> None:
        for module_name, function_name in WRAPPERS:
            with self.subTest(module=module_name):
                module = import_module(f"policy.{module_name}")
                fixture = next(
                    case
                    for case in module.load_expected_cases()
                    if case.get("id") == "null-data-parse-error"
                )
                self.assertIsNone(fixture["data"])
                self.assertEqual(fixture["expected_outcome"], "jsonrpc_parse_error")
                self.assertFalse(fixture["expect_grant"])
                self.assertEqual(
                    module.evaluate_expected_case(fixture).jsonrpc_error, ERROR_PARSE
                )

                evaluate = getattr(module, function_name)
                omitted = evaluate(sid=ROOT_FIXTURE_SID)
                explicit_null = evaluate(sid=ROOT_FIXTURE_SID, data=None)
                self.assertEqual(omitted.outcome, "allow")
                self.assertEqual(explicit_null.outcome, "jsonrpc_parse_error")
                self.assertEqual(explicit_null.jsonrpc_error, ERROR_PARSE)
                c_result = subprocess.run(
                    [
                        str(self.exe),
                        "parse",
                        "0",
                        ROOT_FIXTURE_SID,
                        module.UBUS_OBJECT,
                        module.UBUS_METHOD,
                        "null",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(c_result.stdout.strip(), "ERROR_PARSE")


if __name__ == "__main__":
    unittest.main()
