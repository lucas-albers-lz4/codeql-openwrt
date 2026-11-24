import io
import pathlib
import tempfile
import tarfile
import unittest

import compare


def tar_bytes(entries, *, include_root=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        if include_root:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            tf.addfile(root)
        for name, body in entries:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def ipk_bytes(data_tar, *, extra=()):
    control = tar_bytes([("./control", b"Package: luci-base\nVersion: 26.284.22350~8125d12\nArchitecture: x86_64\n")], include_root=True)
    return tar_bytes([("./debian-binary", b"2.0\n"),
                      ("./data.tar.gz", data_tar),
                      ("./control.tar.gz", control), *extra])


class CompareTests(unittest.TestCase):
    def _write_build_inputs(self, root, config=None, feeds=None):
        (root / "feeds.conf").write_text(feeds or "src-link luci ../../luci\nsrc-link packages ../../packages\n")
        (root / ".config").write_text(config or (
            "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\n"
            "CONFIG_PACKAGE_luci-base=m\nCONFIG_USE_APK=n\n"))

    def test_build_inputs_requires_config_and_local_feed_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_build_inputs(root)
            result = compare.build_inputs(root)
            self.assertEqual(result["config"]["sha256"], compare.sha_file(root / ".config"))
            self.assertEqual(result["feeds"]["sha256"], compare.sha_file(root / "feeds.conf"))

    def test_build_inputs_accepts_canonical_disabled_kconfig_line(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_build_inputs(root, "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\n"
                                     "CONFIG_PACKAGE_luci-base=m\n# CONFIG_USE_APK is not set\n")
            compare.build_inputs(root)

    def test_build_inputs_rejects_apk_enabled_or_missing_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_build_inputs(root, "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\n"
                                     "CONFIG_PACKAGE_luci-base=m\nCONFIG_USE_APK=y\n")
            with self.assertRaisesRegex(ValueError, "disable CONFIG_USE_APK"):
                compare.build_inputs(root)

    def test_build_inputs_rejects_conflicting_config_assignment(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_build_inputs(root, "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\n"
                                     "CONFIG_PACKAGE_luci-base=m\nCONFIG_USE_APK=y\n"
                                     "# CONFIG_USE_APK is not set\n")
            with self.assertRaisesRegex(ValueError, "duplicate config assignment"):
                compare.build_inputs(root)

    def test_build_inputs_rejects_wrong_target_or_package_selection(self):
        for changed in (
            "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=n\nCONFIG_PACKAGE_luci-base=m\nCONFIG_USE_APK=n\n",
            "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=y\nCONFIG_USE_APK=n\n",
        ):
            with self.subTest(config=changed), tempfile.TemporaryDirectory() as td:
                root = pathlib.Path(td)
                self._write_build_inputs(root, changed)
                with self.assertRaisesRegex(ValueError, "missing required target/package"):
                    compare.build_inputs(root)

    def test_build_inputs_rejects_nonpinned_feed_wiring(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self._write_build_inputs(root, feeds="src-git luci moving-branch\nsrc-link packages ../packages\n")
            with self.assertRaisesRegex(ValueError, "feeds.conf must contain exactly"):
                compare.build_inputs(root)
            (root / ".config").unlink()
            with self.assertRaisesRegex(ValueError, "required OpenWrt"):
                compare.build_inputs(root)

    def test_paths_must_resolve_under_openwrt_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "openwrt"
            outside = pathlib.Path(td) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "build_dir").mkdir()
            self.assertEqual(compare.require_under(root / "build_dir", root, "prepared root"),
                             (root / "build_dir").resolve())
            with self.assertRaisesRegex(ValueError, "under OpenWrt checkout"):
                compare.require_under(outside, root, "IPK directory")

    def test_selected_file_cannot_be_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "openwrt"
            root.mkdir()
            regular = root / "regular.uc"
            regular.write_bytes(b"source")
            link = root / "selected.uc"
            link.symlink_to(regular)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                compare.read_regular_under(link, root, "selected")

    def test_feed_links_must_resolve_to_pinned_sources(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            openwrt, luci, packages, wrong = (root / name for name in ("openwrt", "luci", "packages", "wrong"))
            for directory in (openwrt, luci, packages, wrong):
                directory.mkdir()
            (openwrt / "feeds").mkdir()
            (openwrt / "feeds" / "luci").symlink_to("../../luci")
            (openwrt / "feeds" / "packages").symlink_to("../../packages")
            got = compare.require_feed_links(openwrt, luci, packages)
            self.assertEqual(got, {"luci": str(luci.resolve()), "packages": str(packages.resolve())})
            with self.assertRaisesRegex(ValueError, "expected pinned source"):
                compare.require_feed_links(openwrt, wrong, packages)

    def _header_ipk_member(self, header):
        body = tar_bytes([
            ("usr/share/ucode/luci/http.uc", b"http"),
            ("usr/share/ucode/luci/template/header.ut", header),
        ], include_root=True)
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "synthetic.ipk"
            p.write_bytes(ipk_bytes(body))
            return compare.ipk_data_members(p)["usr/share/ucode/luci/template/header.ut"]

    def test_accepts_correctly_transformed_header(self):
        source = b"version={# PKG_VERSION #}\n"
        prepared = source
        staged = b"version=23.05.7\n"
        ipk = self._header_ipk_member(staged)
        compare.validate_header_bytes(source, prepared, staged, ipk, "23.05.7")

    def test_rejects_wrong_transformed_header_in_valid_ipk(self):
        source = b"version={# PKG_VERSION #}\n"
        prepared = source
        staged = b"version=23.05.6\n"
        ipk = self._header_ipk_member(staged)
        with self.assertRaisesRegex(ValueError, "does not match.*substitution"):
            compare.validate_header_bytes(source, prepared, staged, ipk, "23.05.7")

    def test_reads_expected_ipk_members(self):
        body = tar_bytes([
            ("usr/share/ucode/luci/http.uc", b"http"),
            ("./usr/share/ucode/luci/template/header.ut", b"header"),
        ], include_root=True)
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(ipk_bytes(body))
            got = compare.ipk_data_members(p)
        self.assertEqual(got, {
            "usr/share/ucode/luci/http.uc": b"http",
            "usr/share/ucode/luci/template/header.ut": b"header",
        })

    def test_reads_pinned_outer_control_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(ipk_bytes(tar_bytes([])))
            self.assertEqual(compare.ipk_control_fields(p), {
                "Package": "luci-base", "Version": "26.284.22350~8125d12",
                "Architecture": "x86_64"})

    def test_rejects_duplicate_expected_data_member(self):
        name = "usr/share/ucode/luci/http.uc"
        body = tar_bytes([(name, b"first"), (name, b"second")])
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(ipk_bytes(body))
            with self.assertRaisesRegex(ValueError, "duplicate IPK data member"):
                compare.ipk_data_members(p)

    def test_rejects_missing_expected_member(self):
        body = tar_bytes([("usr/share/ucode/luci/http.uc", b"http")])
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(ipk_bytes(body))
            got = compare.ipk_data_members(p)
        with self.assertRaisesRegex(ValueError, "missing IPK member.*header.ut"):
            compare.require_ipk_files(got)

    def test_rejects_duplicate_outer_member(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(ipk_bytes(tar_bytes([]), extra=[("./data.tar.gz", b"duplicate")]))
            with self.assertRaisesRegex(ValueError, "duplicate outer IPK member"):
                compare.ipk_data_members(p)

    def test_rejects_malformed_archive(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(b"not an ipk")
            with self.assertRaisesRegex(ValueError, "not gzip-compressed outer tar"):
                compare.ipk_data_members(p)

    def test_rejects_unsafe_inner_member_alias(self):
        body = tar_bytes([("../../usr/share/ucode/luci/http.uc", b"forged")])
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "test.ipk"
            p.write_bytes(ipk_bytes(body))
            with self.assertRaisesRegex(ValueError, "unsafe IPK tar member"):
                compare.ipk_data_members(p)


if __name__ == "__main__":
    unittest.main()
