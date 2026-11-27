import copy
import gzip
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

import compare


def tar_bytes(entries, *, include_root=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        if include_root:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            root.mode = 0o755
            archive.addfile(root)
        for row in entries:
            name, body = row[:2]
            kind = row[2] if len(row) > 2 else "file"
            mode = row[3] if len(row) > 3 else (0o755 if kind == "directory" else 0o644)
            info = tarfile.TarInfo(name)
            info.mode = mode
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = body.decode()
                archive.addfile(info)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def ipk_bytes(data_tar, *, control=None, extra_outer=()):
    if control is None:
        control = (
            b"Package: adblock-fast\n"
            b"Version: 1.2.4-r4\n"
            b"Architecture: all\n"
        )
    control_tar = tar_bytes([("./control", control)], include_root=True)
    outer_rows = [
        ("./debian-binary", b"2.0\n"),
        ("./data.tar.gz", data_tar),
        ("./control.tar.gz", control_tar),
        *extra_outer,
    ]
    return tar_bytes(outer_rows)


class ArchiveTests(unittest.TestCase):
    def test_normalizes_leading_dot_slash_and_keeps_raw_names(self):
        data = tar_bytes([
            ("./lib/adblock-fast/a.uc", b"module {}\n", "file", 0o644),
            ("usr/lib/uvol/b.uc", b"module {}\n", "file", 0o600),
        ], include_root=True)
        entries, _ = compare.read_data_members(ipk_bytes(data))
        self.assertIn("lib/adblock-fast/a.uc", entries)
        self.assertEqual(entries["lib/adblock-fast/a.uc"]["raw_name"], "./lib/adblock-fast/a.uc")
        self.assertEqual(entries["usr/lib/uvol/b.uc"]["mode"], "0600")

    def test_accepts_one_root_directory(self):
        entries = compare.tar_entries(tar_bytes([], include_root=True), "test")
        self.assertEqual(entries[""]["kind"], "directory")

    def test_rejects_duplicate_after_dot_slash_normalization(self):
        data = tar_bytes([
            ("./lib/adblock-fast/a.uc", b"one"),
            ("lib/adblock-fast/a.uc", b"two"),
        ])
        with self.assertRaisesRegex(ValueError, "duplicate IPK data member"):
            compare.read_data_members(ipk_bytes(data))

    def test_rejects_duplicate_outer_member_after_normalization(self):
        duplicate = ("data.tar.gz", b"duplicate")
        with self.assertRaisesRegex(ValueError, "duplicate outer IPK member"):
            compare.ipk_parts(ipk_bytes(tar_bytes([]), extra_outer=[duplicate]))

    def test_rejects_absolute_and_parent_paths(self):
        for unsafe in ("/etc/passwd", "../escape.uc", "./../../escape.uc", "a//b.uc", "a/./b.uc"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaisesRegex(ValueError, "unsafe|absolute"):
                    compare.normalize_member(unsafe)

    def test_rejects_windows_separator(self):
        with self.assertRaisesRegex(ValueError, "unsafe"):
            compare.normalize_member(r"..\escape.uc")

    def test_rejects_nonregular_data_member(self):
        data = tar_bytes([("usr/lib/uvol/link.uc", b"target", "symlink")])
        with self.assertRaisesRegex(ValueError, "non-regular IPK data"):
            compare.read_data_members(ipk_bytes(data))

    def test_rejects_nonregular_outer_member(self):
        with self.assertRaisesRegex(ValueError, "non-regular outer IPK"):
            compare.ipk_parts(ipk_bytes(tar_bytes([]), extra_outer=[("link", b"target", "symlink")]))

    def test_rejects_oversized_archive_before_parse(self):
        with self.assertRaisesRegex(ValueError, "not a gzip|exceeds"):
            compare.ipk_parts(b"x" * (compare.MAX_IPK_BYTES + 1))

    def test_tar_total_limit_is_enforced_during_raw_header_scan(self):
        payload = b"x" * (5 * 1024 * 1024)
        data = tar_bytes([("one", payload), ("two", payload)])
        with self.assertRaisesRegex(ValueError, "total uncompressed file size limit"):
            compare.tar_entries(data, "bounded fixture", max_member_bytes=8 * 1024 * 1024,
                                max_total_bytes=8 * 1024 * 1024)

    def test_rejects_trailing_and_concatenated_gzip_members(self):
        data = tar_bytes([("one", b"payload")])
        for suffix in (b"trailing", gzip.compress(b"extra")):
            with self.subTest(suffix=suffix[:12]):
                with self.assertRaisesRegex(ValueError, "trailing or concatenated"):
                    compare.tar_entries(data + suffix, "gzip boundary fixture")

    def test_rejects_wrong_debian_binary(self):
        bad = tar_bytes([
            ("debian-binary", b"1.0\n"),
            ("data.tar.gz", tar_bytes([])),
            ("control.tar.gz", tar_bytes([("control", b"Package: x\n")]))
        ])
        with self.assertRaisesRegex(ValueError, "debian-binary"):
            compare.ipk_parts(bad)

    def test_rejects_unexpected_outer_member_set(self):
        with self.assertRaisesRegex(ValueError, "unexpected outer IPK members"):
            compare.ipk_parts(ipk_bytes(tar_bytes([]), extra_outer=[("extra", b"x")]))

    def test_rejects_duplicate_control_field(self):
        data = tar_bytes([("usr/sbin/uvol", b"#!/usr/bin/ucode -R\n")])
        malformed = (
            b"Package: adblock-fast\nVersion: 1.2.4-r4\n"
            b"Architecture: all\nPackage: other\n"
        )
        with self.assertRaisesRegex(ValueError, "duplicate IPK control field"):
            compare.control_fields(ipk_bytes(data, control=malformed))

    def test_rejects_missing_control_file(self):
        parts = [
            ("debian-binary", b"2.0\n"),
            ("data.tar.gz", tar_bytes([])),
            ("control.tar.gz", tar_bytes([("other", b"x")]))
        ]
        with self.assertRaisesRegex(ValueError, "regular IPK control file missing"):
            compare.control_fields(tar_bytes(parts))

    def test_returns_package_control_metadata(self):
        data = tar_bytes([])
        self.assertEqual(compare.control_fields(ipk_bytes(data)), {
            "Package": "adblock-fast", "Version": "1.2.4-r4", "Architecture": "all"
        })

    def test_retains_all_normalized_data_members(self):
        data = tar_bytes([
            ("./etc/config/example", b"x"),
            ("./usr/lib/example.uc", b"module {}\n"),
        ], include_root=True)
        entries, _ = compare.read_data_members(ipk_bytes(data))
        self.assertEqual(set(entries), {"etc/config/example", "usr/lib/example.uc"})
        self.assertEqual(entries["etc/config/example"]["kind"], "regular")


class OracleTests(unittest.TestCase):
    def test_oracle_has_seven_unique_members_and_three_mock_controls(self):
        oracle = json.loads(compare.ORACLE_PATH.read_text())
        selected = [row for package in oracle["packages"].values()
                    for row in package["ucode_members"]]
        controls = oracle["packages"]["adblock-fast"]["negative_controls"]
        self.assertEqual(len(selected), 7)
        self.assertEqual(len({row["member_path"] for row in selected}), 7)
        self.assertEqual(len(controls), 3)
        self.assertEqual(len({row["source_path"] for row in controls}), 3)
        self.assertEqual(oracle["packages"]["adblock-fast"]["version"], "1.2.4-r4")
        self.assertEqual(oracle["packages"]["uvol"]["version"], "1.0-r1")

    def test_source_first_rewrite_is_exactly_once(self):
        row = copy.deepcopy(compare.ORACLE["packages"]["adblock-fast"]["ucode_members"][0])
        source = b"header\n\tversion: 'dev-test',\nfooter\n"
        expected = b"header\n\tversion: '1.2.4-r4',\nfooter\n"
        row["expected_sha256"] = compare.sha256(expected)
        self.assertEqual(compare.expected_source_bytes(source, row), expected)
        with self.assertRaisesRegex(ValueError, "not uniquely applicable"):
            compare.expected_source_bytes(b"version missing\n", row)
        with self.assertRaisesRegex(ValueError, "not uniquely applicable"):
            compare.expected_source_bytes(source + source, row)

    def test_detects_ucode_extensions_and_extensionless_shebang(self):
        self.assertTrue(compare.is_ucode_looking("lib/example.uc", b"module {}"))
        self.assertTrue(compare.is_ucode_looking("usr/sbin/uvol", b"#!/usr/bin/ucode -R\n"))
        self.assertTrue(compare.is_ucode_looking("bin/custom", b"#!/usr/bin/env ucode\n"))
        self.assertTrue(compare.is_ucode_looking("usr/share/rpcd/ucode/provider", b"no shebang\n"))
        self.assertTrue(compare.is_ucode_looking("usr/lib/ucode/lib/module", b"no extension\n"))
        self.assertFalse(compare.is_ucode_looking("bin/custom", b"#!/bin/sh\n"))

    def test_mock_control_is_a_discriminating_near_miss(self):
        expected = {"lib/adblock-fast/adblock-fast.uc", "lib/adblock-fast/cli.uc"}
        entries = {
            path: {"kind": "regular", "bytes": b"module {}\n"}
            for path in expected
        }
        self.assertEqual(compare.require_ucode_member_set(entries, expected, "positive"), expected)
        entries["lib/adblock-fast/tests/lib/mocklib.uc"] = {
            "kind": "regular", "bytes": b"export const mock = true;\n"
        }
        with self.assertRaisesRegex(ValueError, "extra=.*mocklib.uc"):
            compare.require_ucode_member_set(entries, expected, "mock near miss")

    def test_source_mode_and_member_mode_are_separate_oracle_fields(self):
        rows = [row for package in compare.ORACLE["packages"].values()
                for row in package["ucode_members"]]
        self.assertTrue(all(row["source_mode"] == "100644" for row in rows))
        executable = [row for row in rows if row["member_path"] == "usr/sbin/uvol"]
        self.assertEqual(len(executable), 1)
        self.assertEqual(executable[0]["stage_mode"], "0755")
        self.assertEqual(executable[0]["member_mode"], "0755")
        self.assertEqual(executable[0]["source_mode"], "100644")

    def test_preparation_contracts_match_the_pinned_recipe_shapes(self):
        adblock_recipe = b"define Build/Configure\nendef\ndefine Build/Compile\nendef\n"
        uvol_recipe = (b"define Build/Prepare\nendef\ndefine Build/Configure\nendef\n"
                       b"define Build/Compile\nendef\n")
        self.assertEqual(compare.verify_empty_build_hooks(adblock_recipe, "adblock-fast"),
                         ["Configure", "Compile"])
        self.assertEqual(compare.verify_empty_build_hooks(uvol_recipe, "uvol"),
                         ["Prepare", "Configure", "Compile"])
        with self.assertRaisesRegex(ValueError, "unexpectedly overrides Build/Prepare"):
            compare.verify_empty_build_hooks(
                adblock_recipe + b"define Build/Prepare\ncp source output\nendef\n",
                "adblock-fast"
            )

    def test_pinned_build_directory_and_ipkg_all_layout(self):
        with tempfile.TemporaryDirectory() as td:
            openwrt = pathlib.Path(td) / "openwrt"
            adblock_stage = (openwrt / "build_dir/target-x86_64_musl"
                             / "adblock-fast-1.2.4/ipkg-all/adblock-fast")
            uvol_stage = (openwrt / "build_dir/target-x86_64_musl"
                          / "uvol-1.0/ipkg-all/uvol")
            adblock_stage.mkdir(parents=True)
            uvol_stage.mkdir(parents=True)
            compare.validate_stage_layout(openwrt, "adblock-fast", adblock_stage)
            compare.validate_stage_layout(openwrt, "uvol", uvol_stage)
            self.assertEqual(compare.package_build_version("adblock-fast"), "1.2.4")
            self.assertEqual(compare.package_build_version("uvol"), "1.0")

    def test_packaged_contents_log_binds_stage_and_ipk(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            openwrt = root / "openwrt"
            run = root / "run"
            stage = (openwrt / "build_dir/target-x86_64_musl"
                     / "uvol-1.0/ipkg-all/uvol")
            ipk = openwrt / "bin/packages/x86_64/packages/uvol_1.0-r1_all.ipk"
            log = run / "output/uvol-build.log"
            stage.mkdir(parents=True)
            ipk.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            ipk.write_bytes(b"ipk")
            log.write_text(f"Packaged contents of {stage} into {ipk}\n")
            got_stage, got_ipk, lines = compare.packaged_records(log, run, openwrt, "uvol")
            self.assertEqual(got_stage, stage.resolve())
            self.assertEqual(got_ipk, ipk.resolve())
            self.assertEqual(len(lines), 1)

    def test_install_log_binds_recipe_source_and_directory_destination(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            openwrt = root / "openwrt"
            run = root / "run"
            stage = (openwrt / "build_dir/target-x86_64_musl"
                     / "uvol-1.0/ipkg-all/uvol")
            destination = stage / "usr/lib/uvol"
            destination.mkdir(parents=True)
            log = run / "output/uvol-build.log"
            log.parent.mkdir(parents=True)
            target_file = destination / "blockdev_common.uc"
            log.write_text(
                f"install -m0644 ./files/blockdev_common.uc {destination}/\n"
                f"install -m0644 ./files/blockdev_common.uc {stage}/.pkgdir/uvol/usr/lib/uvol/\n"
            )
            matches = compare.stage_install_log_lines(
                log, run, openwrt, "./files/blockdev_common.uc", "directory", target_file
            )
            self.assertEqual(len(matches), 1)
            self.assertIn(str(destination) + "/", matches[0])

    def test_install_log_rejects_wrong_source_even_with_matching_destination(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            openwrt = root / "openwrt"
            run = root / "run"
            stage = (openwrt / "build_dir/target-x86_64_musl"
                     / "uvol-1.0/ipkg-all/uvol")
            destination = stage / "usr/lib/uvol"
            destination.mkdir(parents=True)
            log = run / "output/uvol-build.log"
            log.parent.mkdir(parents=True)
            log.write_text(f"install -m0644 ./files/other.uc {destination}/\n")
            with self.assertRaisesRegex(ValueError, "one source-to-IPK-stage install"):
                compare.stage_install_log_lines(
                    log, run, openwrt, "./files/blockdev_common.uc", "directory",
                    destination / "blockdev_common.uc"
                )

    def test_retained_stage_archive_preserves_mode_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            openwrt = root / "openwrt"
            run = root / "run"
            (run / "output").mkdir(parents=True)
            stage_root = (openwrt / "build_dir/target-x86_64_musl"
                          / "uvol-1.0/ipkg-all/uvol")
            file = stage_root / "usr/sbin/uvol"
            file.parent.mkdir(parents=True)
            file.write_bytes(b"#!/usr/bin/ucode -R\n")
            file.chmod(0o755)
            row = {
                "source_path": "utils/uvol/files/uvol",
                "member_path": "usr/sbin/uvol",
                "stage_path": file.relative_to(openwrt).as_posix(),
                "stage_sha256": compare.sha256(file.read_bytes()),
                "stage_mode": "0755",
            }
            result = {"uvol": {"staging_root": stage_root.relative_to(openwrt).as_posix(),
                               "stage_comparisons": [row]}}
            archive_record = compare.write_stage_archive(openwrt, run, result)
            archive_path = run / archive_record["path"]
            entries = compare.tar_entries(archive_path.read_bytes(), "retained stages")
            retained = entries["uvol/usr/sbin/uvol"]
            self.assertEqual(retained["bytes"], file.read_bytes())
            self.assertEqual(retained["mode"], "0755")
            self.assertEqual(archive_record["sha256"], compare.sha256(archive_path.read_bytes()))

    def test_renamed_mock_is_found_by_source_hash_and_content(self):
        source = b"export const mock = true;\n"
        digest = compare.sha256(source)
        entries = {"renamed/module.uc": {
            "kind": "regular", "sha256": digest,
        }}
        matches = compare.negative_control_matches(
            entries, {"renamed/module.uc": source}, source, digest
        )
        self.assertEqual(matches["sha256_matches"], ["renamed/module.uc"])
        self.assertEqual(matches["exact_content_matches"], ["renamed/module.uc"])


if __name__ == "__main__":
    unittest.main()
