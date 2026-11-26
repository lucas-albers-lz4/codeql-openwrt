from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from tools import r25_package_stage as stage


def archive(entries: list[tuple[str, bytes | tuple[str, str]]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                info.type = tarfile.SYMTYPE
                info.linkname = value[1]
                tar.addfile(info)
            elif name in (".", "./"):
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
    return stream.getvalue()


def ipk(data_entries: list[tuple[str, bytes | tuple[str, str]]], *,
        package: str = "wifi-scripts", version: str = "1.0-r1",
        architecture: str = "all") -> bytes:
    control = archive([("./control", (
        f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
    ).encode())])
    data = archive([(".", b"")] + data_entries)
    return archive([("./debian-binary", b"2.0\n"),
                    ("./control.tar.gz", control), ("./data.tar.gz", data)])


class PackageStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        (self.workspace / "stages").mkdir()
        (self.workspace / "receipts").mkdir()
        self.ucode = b"#!/usr/bin/ucode\nreturn 1;\n"
        self.shell = b"#!/bin/sh\nexit 0\n"
        self.oracle = {
            "schema": "ucode-installed-stage-v1",
            "files": [
                {"expect_success": True, "path": "usr/bin/iwinfo",
                 "route": {"classification": "plain", "inconclusive_reason": None,
                           "reason": "ucode_shebang", "status": "plain_route_selected"},
                 "sha256": stage.digest(self.ucode)},
                {"expect_success": False, "path": "etc/hotplug.d/10-shell",
                 "route": {"classification": "excluded", "inconclusive_reason": None,
                           "reason": "no_ucode_route", "status": "excluded"},
                 "sha256": stage.digest(self.shell)},
            ],
        }
        self.oracle_bytes = json.dumps(self.oracle, sort_keys=True).encode()
        self.entries = [("./usr/bin/iwinfo", self.ucode),
                        ("./etc/hotplug.d/10-shell", self.shell)]
        self.package_bytes = ipk(self.entries)
        self.profile = {
            "package": {"name": "wifi-scripts", "version": "1.0-r1", "architecture": "all"},
            "ipk": {"filename": "fixture.ipk", "sha256": stage.digest(self.package_bytes),
                    "run_id": 1, "artifact_id": 2, "artifact_name": "fixture"},
            "oracle": {"path": "fixture-oracle.json", "sha256": stage.digest(self.oracle_bytes),
                       "regular_member_count": 2,
                       "route_counts": {"plain": 1, "markup": 0, "excluded": 1}},
        }

    def stage(self, raw=None, oracle=None, profile=None, *, stage_path=None, receipt_path=None):
        return stage.stage_package_bytes(
            "wifi-scripts-ucode-y", self.package_bytes if raw is None else raw,
            self.profile if profile is None else profile,
            self.oracle_bytes if oracle is None else oracle,
            self.workspace,
            self.workspace / "stages/test" if stage_path is None else stage_path,
            self.workspace / "receipts/test.json" if receipt_path is None else receipt_path,
            provenance={"producer_fixture_commit": "a" * 40},
        )

    def test_stages_exact_regular_members_and_records_route_positive_and_near_miss(self):
        receipt = self.stage()
        self.assertEqual(receipt["regular_member_count"], 2)
        self.assertEqual(receipt["selected_paths"], ["usr/bin/iwinfo"])
        self.assertEqual(receipt["excluded_paths"], ["etc/hotplug.d/10-shell"])
        self.assertEqual((self.workspace / "stages/test/usr/bin/iwinfo").read_bytes(), self.ucode)
        self.assertEqual((self.workspace / "stages/test/etc/hotplug.d/10-shell").read_bytes(), self.shell)
        self.assertEqual(json.loads((self.workspace / "receipts/test.json").read_text()), receipt)

    def test_checked_in_oracle_copies_and_zero_result_expectations_are_pinned(self):
        lock, _ = stage._load_lock(stage.LOCK_PATH)
        self.assertEqual(set(lock["packages"]), {"luci-base", "wifi-scripts-ucode-y"})
        expected_counts = {"luci-base": (76, {"plain": 10, "markup": 8, "excluded": 58}),
                           "wifi-scripts-ucode-y": (31, {"plain": 17, "markup": 0, "excluded": 14})}
        for package_id, profile in lock["packages"].items():
            raw = (stage.ROOT / profile["oracle"]["path"]).read_bytes()
            oracle, _ = stage.validate_oracle(raw, profile["oracle"]["sha256"], profile)
            count, routes = expected_counts[package_id]
            self.assertEqual(len(oracle["files"]), count)
            self.assertEqual(profile["oracle"]["route_counts"], routes)
            self.assertEqual(profile["expected_default_suite_result_count"], 0)
        wifi = json.loads((stage.ROOT / lock["packages"]["wifi-scripts-ucode-y"]["oracle"]["path"]).read_text())
        by_path = {row["path"]: row for row in wifi["files"]}
        self.assertEqual(by_path["lib/netifd/wireless/mac80211.sh"]["route"]["reason"],
                         "ucode_shebang")
        self.assertEqual(by_path["etc/hotplug.d/ieee80211/10-wifi-detect"]["route"]["classification"],
                         "excluded")

    def test_ipk_digest_is_checked_before_archive_processing_or_output(self):
        profile = json.loads(json.dumps(self.profile))
        profile["ipk"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "IPK digest"):
            self.stage(profile=profile)
        self.assertFalse((self.workspace / "stages/test").exists())

    def test_member_hash_mismatch_and_extra_member_fail_before_output(self):
        altered = ipk([( "./usr/bin/iwinfo", b"different"), self.entries[1]])
        profile = json.loads(json.dumps(self.profile))
        profile["ipk"]["sha256"] = stage.digest(altered)
        with self.assertRaisesRegex(ValueError, "member hash mismatch"):
            self.stage(raw=altered, profile=profile)
        self.assertFalse((self.workspace / "stages/test").exists())
        extra = ipk(self.entries + [("./usr/bin/extra.uc", b"return 1;\n")])
        profile["ipk"]["sha256"] = stage.digest(extra)
        with self.assertRaisesRegex(ValueError, "unexpected regular IPK member"):
            self.stage(raw=extra, profile=profile)
        self.assertFalse((self.workspace / "stages/test").exists())

    def test_missing_member_and_bad_package_control_fail(self):
        missing = ipk([self.entries[0]])
        profile = json.loads(json.dumps(self.profile))
        profile["ipk"]["sha256"] = stage.digest(missing)
        with self.assertRaisesRegex(ValueError, "regular-member inventory mismatch"):
            self.stage(raw=missing, profile=profile)
        bad_control = ipk(self.entries, version="0.0")
        profile["ipk"]["sha256"] = stage.digest(bad_control)
        with self.assertRaisesRegex(ValueError, "control identity mismatch"):
            self.stage(raw=bad_control, profile=profile)

    def test_duplicate_alias_and_traversal_paths_fail(self):
        duplicate = ipk(self.entries + [("usr/bin/iwinfo", self.ucode)])
        profile = json.loads(json.dumps(self.profile))
        profile["ipk"]["sha256"] = stage.digest(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate IPK data member"):
            self.stage(raw=duplicate, profile=profile)
        traversal = ipk(self.entries + [("../outside", b"x")])
        profile["ipk"]["sha256"] = stage.digest(traversal)
        with self.assertRaisesRegex(ValueError, "unsafe or noncanonical"):
            self.stage(raw=traversal, profile=profile)

    def test_archive_root_entries_count_toward_member_budget(self):
        data_tar = archive([("./", b"")] * (stage.MAX_ARCHIVE_MEMBERS + 1))
        with self.assertRaisesRegex(ValueError, "data archive exceeds member budget"):
            stage._regular_members(data_tar, {})

    def test_symlink_expected_member_is_rejected_without_writing(self):
        linked = ipk([("./usr/bin/iwinfo", ("symlink", "../secret")), self.entries[1]])
        profile = json.loads(json.dumps(self.profile))
        profile["ipk"]["sha256"] = stage.digest(linked)
        with self.assertRaisesRegex(ValueError, "nonregular IPK data member"):
            self.stage(raw=linked, profile=profile)
        self.assertFalse((self.workspace / "stages/test").exists())

    def test_output_aliases_and_preexisting_paths_are_rejected_before_writing(self):
        existing = self.workspace / "stages/test"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.stage()
        self.assertEqual(sentinel.read_text(), "keep")
        sentinel.unlink()
        existing.rmdir()

        (self.workspace / "receipts/test.json").write_text("keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.stage()
        self.assertFalse((self.workspace / "stages/test").exists())
        (self.workspace / "receipts/test.json").unlink()

        with self.assertRaisesRegex(ValueError, "must be disjoint"):
            self.stage(receipt_path=self.workspace / "stages/test/receipt.json")
        self.assertFalse((self.workspace / "stages/test").exists())

    def test_input_must_be_run_owned_regular_nonaliased_file(self):
        file = self.workspace / "input.ipk"
        file.write_bytes(self.package_bytes)
        self.assertEqual(stage._read_owned_ipk(file, self.workspace), self.package_bytes)
        link = self.workspace / "link.ipk"
        link.symlink_to(file)
        with self.assertRaisesRegex(ValueError, "symlink"):
            stage._read_owned_ipk(link, self.workspace)
        outside = Path(self.temp.name).parent / "not-owned.ipk"
        with self.assertRaisesRegex(ValueError, "inside the run-owned"):
            stage._read_owned_ipk(outside, self.workspace)
        hardlink = self.workspace / "hardlink.ipk"
        os.link(file, hardlink)
        with self.assertRaisesRegex(ValueError, "hard links"):
            stage._read_owned_ipk(hardlink, self.workspace)


if __name__ == "__main__":
    unittest.main()
