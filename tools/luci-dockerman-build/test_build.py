import gzip
import importlib.util
import io
import json
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

compare = load("dockerman_compare", HERE / "compare.py")
runner = load("dockerman_runner", HERE / "run.py")
package = load("dockerman_package", HERE / "package.py")
RECIPE_BYTES = b"LUCI_DEPENDS:=@(x86_64) +luci-base +docker +ttyd +dockerd +docker-compose +ucode-mod-socket\n"


def tar_gz(items):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in items:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.SYMTYPE
                info.linkname = "docker"
                info.mode = mode
                tar.addfile(info)
            else:
                info.size = len(data)
                info.mode = mode
                tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def fake_ipk(data_members, control_members):
    return tar_gz([("debian-binary", b"2.0\n", 0o644),
                   ("control.tar.gz", tar_gz(control_members), 0o644),
                   ("data.tar.gz", tar_gz(data_members), 0o644)])


class DockermanComparatorTests(unittest.TestCase):
    def test_version_projection_matches_pinned_findrev_timestamp(self):
        with patch.object(compare.subprocess, "check_output", return_value=b"1778767359 d5129a1\n"):
            self.assertEqual(compare.projected_version(Path("/pinned/luci")), compare.VERSION)

    def fixture(self, tmp):
        root = Path(tmp).resolve()
        luci, prepared, stage = root / "luci", root / "prepared", root / "stage"
        luci.mkdir(); prepared.mkdir(); stage.mkdir()
        rows = []
        expected_bytes = {}
        for index in range(22):
            ext = ".uc" if index < 3 else (".json" if index < 5 else ".js")
            if index == 0:
                source = "applications/luci-app-dockerman/root/usr/share/rpcd/ucode/docker_rpc.uc"
                member = "usr/share/rpcd/ucode/docker_rpc.uc"
                mode = "100755"
                projected_mode = "0755"
            elif index < 3:
                source = f"applications/luci-app-dockerman/ucode/test{index}.uc"
                member = f"usr/share/ucode/luci/test{index}.uc"
                mode = projected_mode = "100644"
                projected_mode = "0644"
            elif index < 5:
                source = f"applications/luci-app-dockerman/root/test{index}.json"
                member = f"usr/share/luci/test{index}.json"
                mode = "100644"; projected_mode = "0644"
            else:
                source = f"applications/luci-app-dockerman/htdocs/test{index}{ext}"
                member = f"www/test{index}{ext}"
                mode = "100644"; projected_mode = "0644"
            data = f"source-{index}".encode()
            expected_bytes[source] = data
            rows.append({"package": compare.PACKAGE, "source_path": source, "projected_member": member,
                         "git_mode": mode, "git_object": f"{index:040x}", "bytes": len(data),
                         "sha256": compare.digest(data), "source_mode_projected": projected_mode})
            rel = compare.expected_prepared(rows[-1])
            p = prepared / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data); p.chmod(int(mode, 8) & 0o7777)
            out = stage / member; out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(data); out.chmod(int(projected_mode, 8))
        (stage / "CONTROL").mkdir()
        control_bytes = b"Package: luci-app-dockerman\nVersion: " + compare.VERSION.encode() + b"\nArchitecture: all\n"
        (stage / "CONTROL/control").write_bytes(control_bytes)
        (stage / "CONTROL/control").chmod(0o644)
        controls = {"control": {"type": "file", "mode": 0o644,
                    "bytes": control_bytes, "size": len(control_bytes)}}
        members = {row["projected_member"]: {"type": "file", "mode": int(row["source_mode_projected"], 8),
                    "bytes": expected_bytes[row["source_path"]], "size": row["bytes"]} for row in rows}
        recipe = {"source_path": "applications/luci-app-dockerman/Makefile", "package": compare.PACKAGE,
                  "projected_member": None, "git_mode": "100644", "git_object": "f" * 40,
                  "bytes": len(RECIPE_BYTES), "sha256": compare.digest(RECIPE_BYTES)}
        oracle = {"entries": rows + [recipe], "luci_mk_sha256": compare.digest((compare.LUCI_SHA + "\n").encode())}
        return luci, prepared, stage, oracle, expected_bytes, controls, members

    def test_positive_exact_22_source_prepared_stage_ipk_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            luci, prepared, stage, oracle, expected, controls, members = self.fixture(tmp)
            fields = {"Package": compare.PACKAGE, "Version": compare.VERSION, "Architecture": "all"}
            with patch.object(compare, "load_oracle", return_value=oracle), \
                 patch.object(compare.subprocess, "check_output", return_value=(compare.LUCI_SHA + "\n").encode()), \
                 patch.object(compare, "projected_version", return_value=compare.VERSION), \
                 patch.object(compare, "pinned_blob", side_effect=lambda _luci, row: expected.get(row["source_path"], RECIPE_BYTES)), \
                 patch.object(compare.archive, "read_ipk", return_value=(controls, members, {"data.tar.gz": "digest"})):
                receipt = compare.compare(luci, prepared, stage, b"fixture IPK", b"CONFIG_LUCI_JSMIN=n\nCONFIG_LUCI_CSSTIDY=n\n")
            self.assertEqual(receipt["member_count"], 22)
            self.assertEqual(len(receipt["members"]), 22)
            self.assertEqual(sum(x["member"].endswith(".uc") for x in receipt["members"]), 3)

    def test_rejects_extra_ipk_member_even_with_valid_selected_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            luci, prepared, stage, oracle, expected, controls, members = self.fixture(tmp)
            members["usr/share/ucode/luci/unexpected.uc"] = {"type": "file", "mode": 0o644, "bytes": b"extra", "size": 5}
            fields = {"Package": compare.PACKAGE, "Version": compare.VERSION, "Architecture": "all"}
            with patch.object(compare, "load_oracle", return_value=oracle), \
                 patch.object(compare.subprocess, "check_output", return_value=(compare.LUCI_SHA + "\n").encode()), \
                 patch.object(compare, "projected_version", return_value=compare.VERSION), \
                 patch.object(compare, "pinned_blob", side_effect=lambda _luci, row: expected.get(row["source_path"], RECIPE_BYTES)), \
                 patch.object(compare.archive, "read_ipk", return_value=(controls, members, {})):
                with self.assertRaisesRegex(ValueError, "member set differs"):
                    compare.compare(luci, prepared, stage, b"fixture", b"CONFIG_LUCI_JSMIN=n\nCONFIG_LUCI_CSSTIDY=n\n")

    def test_rejects_selected_member_mode_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            luci, prepared, stage, oracle, expected, controls, members = self.fixture(tmp)
            members["usr/share/rpcd/ucode/docker_rpc.uc"]["mode"] = 0o644
            with patch.object(compare, "load_oracle", return_value=oracle), \
                 patch.object(compare.subprocess, "check_output", return_value=(compare.LUCI_SHA + "\n").encode()), \
                 patch.object(compare, "projected_version", return_value=compare.VERSION), \
                 patch.object(compare, "pinned_blob", side_effect=lambda _luci, row: expected.get(row["source_path"], RECIPE_BYTES)), \
                 patch.object(compare.archive, "read_ipk", return_value=(controls, members, {})):
                with self.assertRaisesRegex(ValueError, "bytes/modes differ"):
                    compare.compare(luci, prepared, stage, b"fixture", b"CONFIG_LUCI_JSMIN=n\nCONFIG_LUCI_CSSTIDY=n\n")

    def test_rejects_wrong_package_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            luci, prepared, stage, oracle, expected, controls, members = self.fixture(tmp)
            controls["control"]["bytes"] = b"Package: wrong\nVersion: " + compare.VERSION.encode() + b"\nArchitecture: all\n"
            with patch.object(compare, "load_oracle", return_value=oracle), \
                 patch.object(compare.subprocess, "check_output", return_value=(compare.LUCI_SHA + "\n").encode()), \
                 patch.object(compare, "projected_version", return_value=compare.VERSION), \
                 patch.object(compare, "pinned_blob", side_effect=lambda _luci, row: expected.get(row["source_path"], RECIPE_BYTES)), \
                 patch.object(compare.archive, "read_ipk", return_value=(controls, members, {})):
                with self.assertRaisesRegex(ValueError, "control identity differs"):
                    compare.compare(luci, prepared, stage, b"fixture", b"CONFIG_LUCI_JSMIN=n\nCONFIG_LUCI_CSSTIDY=n\n")

    def test_rejects_enabled_minifier_before_any_source_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            luci, prepared, stage, oracle, expected, _, _ = self.fixture(tmp)
            with patch.object(compare, "load_oracle", return_value=oracle), \
                 patch.object(compare.subprocess, "check_output", return_value=(compare.LUCI_SHA + "\n").encode()), \
                 patch.object(compare, "projected_version", return_value=compare.VERSION), \
                 patch.object(compare, "pinned_blob", side_effect=lambda _luci, row: expected.get(row["source_path"], RECIPE_BYTES)):
                with self.assertRaisesRegex(ValueError, "disabled transform"):
                    compare.compare(luci, prepared, stage, b"unused", b"CONFIG_LUCI_JSMIN=y\nCONFIG_LUCI_CSSTIDY=n\n")


class DockermanRunnerTests(unittest.TestCase):
    def test_only_the_six_pinned_directed_cycle_edges_are_observations(self):
        known = b"make[3]: Circular package/feeds/packages/containerd/compile <- package/feeds/packages/dockerd/compile dependency dropped.\n"
        rows = runner.cycle_observations((known,))
        self.assertEqual(rows[0]["edge"], ["containerd", "dockerd"])
        with self.assertRaisesRegex(ValueError, "unreviewed circular"):
            runner.cycle_observations((b"make: Circular package/feeds/packages/docker/compile <- package/feeds/packages/dockerd/compile dependency dropped.\n",))
        with self.assertRaisesRegex(ValueError, "unparsed or noncanonical circular"):
            runner.cycle_observations((b"Circular dependency warning without paths\n",))
        with self.assertRaisesRegex(ValueError, "unparsed or noncanonical circular"):
            runner.cycle_observations((b"make: Circular other/path/containerd/compile <- package/feeds/packages/dockerd/compile dependency dropped.\n",))

    def test_normal_phase_order_and_kernel_checks_are_sequential(self):
        phases, kernel = [], []
        runner.execute_phases(None, lambda _p, label, target, timeout: phases.append((label, target)), kernel.append)
        self.assertEqual([target for _, target in phases], [x[1] for x in runner.PHASES])
        self.assertEqual(kernel, ["capture", "snapshot-and-validate"])
        phases.clear(); kernel.clear()
        def fail(_p, label, target, timeout):
            phases.append(target)
            if label == "kernel-compile":
                raise RuntimeError("wrong kernel")
        with self.assertRaisesRegex(RuntimeError, "wrong kernel"):
            runner.execute_phases(None, fail, kernel.append)
        self.assertEqual(phases, ["tools/install", "toolchain/install", "target/linux/compile"])
        self.assertEqual(kernel, [])

    def test_failed_kernel_package_phase_retains_post_phase_snapshots_and_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / "output"; output.mkdir()
            calls = []
            probe = SimpleNamespace(root=root, out=output, quiescent=True)
            def invoke(label, argv, cwd, timeout):
                (output / (label + ".stdout")).write_bytes(b"partial stdout\n")
                (output / (label + ".stderr")).write_bytes(b"partial stderr\n")
                raise RuntimeError("make exit 2")
            probe.invoke = invoke
            def snapshot(_root):
                calls.append("kernel-output-snapshot")
                (output / "snapshot.json").write_text("{}\n")
            def frozen(_probe, label): calls.append(label)
            with patch.object(runner, "frozen_metadata", side_effect=frozen), \
                 patch.object(runner, "source_guard"), \
                 patch.object(runner.kernel_evidence, "snapshot_package_output", side_effect=snapshot):
                with self.assertRaisesRegex(RuntimeError, "retained build/validation failures"):
                    runner.phase(probe, "kernel-package-compile", "package/kernel/linux/compile", 1)
            failures = json.loads((output / "kernel-package-compile-validation-failures.json").read_text())
            self.assertIn("make exit 2", failures["make"])
            self.assertTrue((output / "snapshot.json").is_file())
            self.assertIn("kernel-package-compile-after", calls)

    def test_companion_control_inspection_does_not_parse_data_symlink(self):
        data = fake_ipk([("usr/bin/docker", b"binary", 0o755), ("usr/bin/docker-compose", None, 0o777)],
                        [("control", b"Package: docker-compose\nVersion: 5.1.4-r1\nArchitecture: x86_64\n", 0o644)])
        fields = runner.control_only(data)
        self.assertEqual(fields["Package"], "docker-compose")
        self.assertEqual(fields["Version"], "5.1.4-r1")

    def test_provider_control_must_match_exact_architecture_and_feed_version(self):
        good = {"Package": "ucode-mod-socket", "Version": "2026.07.09~b885dd0f-r3",
                "Architecture": "x86_64"}
        self.assertEqual(runner.validate_provider_control(
            "ucode-mod-socket", good, "2026.07.09~b885dd0f-r3", "x86_64"), good)
        for altered in ({**good, "Package": "other"}, {**good, "Architecture": "all"},
                        {**good, "Version": "2026.07.09~b885dd0fe1e974551fb1233ca5f3aa74d80b74d9-r3"}):
            with self.assertRaisesRegex(ValueError, "control identity differs"):
                runner.validate_provider_control("ucode-mod-socket", altered,
                                                 "2026.07.09~b885dd0f-r3", "x86_64")

    def test_provider_layout_uses_kmod_release_separate_from_virtual_kernel(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); ow = root / "openwrt"; output = root / "output"
            output.mkdir()
            package_root = ow / "bin/packages/x86_64/packages"; package_root.mkdir(parents=True)
            target_root = ow / "bin/targets/x86/64/packages"; target_root.mkdir(parents=True)
            go = ow / "staging_dir/hostpkg/lib/go-1.26/bin/go"; go.parent.mkdir(parents=True); go.write_bytes(b"go")
            magic = "a" * 32
            kernel_version = "6.12.116~" + magic + "-r1"
            def ipk(name, version, arch, package_override=None):
                package_field = package_override or name
                control = (f"Package: {package_field}\nVersion: {version}\nArchitecture: {arch}\n").encode()
                return fake_ipk([("usr/share/example", b"x", 0o644)], [("control", control, 0o644)])
            (package_root / "foo_1-r1_x86_64.ipk").write_bytes(ipk("foo", "1-r1", "x86_64"))
            (target_root / f"kernel_{kernel_version}_x86_64.ipk").write_bytes(
                ipk("kernel", kernel_version, "x86_64"))
            (target_root / "kmod-ipt-nat_6.12.116-r1_x86_64.ipk").write_bytes(
                ipk("kmod-ipt-nat", "6.12.116-r1", "x86_64"))
            probe = SimpleNamespace(root=root, out=output,
                                    invoke=lambda *_args, **_kwargs: b"go version go1.26.11 linux/amd64\n")
            with patch.object(runner, "EXPECTED_CONTROLS", {"foo": ("1-r1", "x86_64")}), \
                 patch.object(runner, "PROVIDER_DIRS", {"foo": "bin/packages/x86_64/packages"}), \
                 patch.object(runner, "KMODS", ("kmod-ipt-nat",)):
                good = runner.package_outputs(probe, {"version": kernel_version})
                self.assertEqual(good["ipks"]["kernel"]["control"]["Version"], kernel_version)
                self.assertEqual(good["ipks"]["kmod-ipt-nat"]["control"]["Version"], "6.12.116-r1")
                self.assertEqual(good["ipks"]["foo"]["path"], "bin/packages/x86_64/packages/foo_1-r1_x86_64.ipk")

            output_bad = root / "output-bad"; output_bad.mkdir()
            (package_root / "foo_1-r1_x86_64.ipk").write_bytes(ipk("foo", "1-r1", "x86_64", "other"))
            probe.out = output_bad
            with patch.object(runner, "EXPECTED_CONTROLS", {"foo": ("1-r1", "x86_64")}), \
                 patch.object(runner, "PROVIDER_DIRS", {"foo": "bin/packages/x86_64/packages"}), \
                 patch.object(runner, "KMODS", ("kmod-ipt-nat",)):
                with self.assertRaisesRegex(ValueError, "control identity differs"):
                    runner.package_outputs(probe, {"version": kernel_version})
            retained = output_bad / "provider-candidates/packages/foo_1-r1_x86_64.ipk"
            self.assertTrue(retained.is_file())
            self.assertEqual(compare.digest(retained.read_bytes()), compare.digest((package_root / retained.name).read_bytes()))

    def test_only_exact_source_scoped_display_helper_warnings_are_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = root / "output"; out.mkdir()
            kernel = root / "openwrt/build_dir/target-x86_64_musl/linux-x86_64/linux-6.12.116"
            kernel.mkdir(parents=True)
            (kernel / ".config").write_text("CONFIG_DRM=y\nCONFIG_DRM_I915=m\n")
            retained_kernel = out / "kernel-evidence"; retained_kernel.mkdir()
            kernel_config = b"CONFIG_DRM=y\nCONFIG_DRM_I915=m\n"
            (retained_kernel / ".config").write_bytes(kernel_config)
            (kernel / ".vermagic").write_bytes(b"a" * 32 + b"\n")
            (retained_kernel / ".vermagic").write_bytes(b"a" * 32 + b"\n")
            config = b"CONFIG_PACKAGE_kmod-drm-exec=y\nCONFIG_PACKAGE_kmod-drm-suballoc-helper=y\n"
            (out / "config-final").write_bytes(config)
            probe = SimpleNamespace(root=root, out=out)
            warnings = b"\n".join(runner.KNOWN_EMPTY_WARNINGS.values())
            with patch.object(runner, "CONFIG_SHA", runner.check.digest(config)), patch.object(runner, "write_json") as write:
                runner.validate_build_diagnostics(probe, "kernel-package-compile", b"", warnings)
                self.assertTrue(write.call_args.args[1]["source_scoped_exception_candidate"])
                self.assertEqual(write.call_args.args[1]["kernel_config_sha256"], runner.check.digest(kernel_config))
            with patch.object(runner, "CONFIG_SHA", runner.check.digest(config)):
                with self.assertRaisesRegex(ValueError, "outside the exact two"):
                    runner.validate_build_diagnostics(probe, "dockerman-compile", b"", warnings)
                with self.assertRaisesRegex(ValueError, "unreviewed empty-package"):
                    runner.validate_build_diagnostics(probe, "kernel-package-compile", b"", warnings + b"\nWARNING: kmod-other is not available in the kernel config - generating empty package")
                with self.assertRaisesRegex(ValueError, "must appear on stderr"):
                    runner.validate_build_diagnostics(probe, "kernel-package-compile", warnings, b"")
                with self.assertRaisesRegex(ValueError, "unreviewed empty-package"):
                    runner.validate_build_diagnostics(probe, "kernel-package-compile", b"", warnings + b" ")
                (kernel / ".config").write_text("CONFIG_DRM=y\nCONFIG_DRM_I915=m\nCONFIG_DRM_EXEC=m\n")
                (retained_kernel / ".config").write_bytes(b"CONFIG_DRM=y\nCONFIG_DRM_I915=m\nCONFIG_DRM_EXEC=m\n")
                with self.assertRaisesRegex(ValueError, "no longer explains"):
                    runner.validate_build_diagnostics(probe, "kernel-package-compile", b"", warnings)

    def test_selected_graph_scope_ignores_unrelated_global_rows_but_keeps_root_closure(self):
        raw = (b"$(curdir)/feeds/luci/luci-app-dockerman/compile += $(curdir)/feeds/luci/luci-app-dockerman/compile\n"
               b"$(curdir)/kernel/linux/compile += $(curdir)/kernel/linux/compile\n"
               b"$(curdir)/feeds/luci/luci-app-dockerman/compile += $(curdir)/feeds/packages/docker/compile\n"
               b"$(curdir)/feeds/packages/docker/compile += $(curdir)/feeds/packages/containerd/compile\n"
               b"$(curdir)/feeds/packages/containerd/compile += $(curdir)/feeds/packages/dockerd/compile\n"
               b"$(curdir)/feeds/packages/dockerd/compile += $(curdir)/feeds/packages/containerd/compile\n"
               b"package-$(CONFIG_PACKAGE_docker) += feeds/packages/docker\n"
               b"prereq-$(CONFIG_PACKAGE_docker) += feeds/packages/docker\n"
               b"$(curdir)/other/package/compile += $(curdir)/other/package/compile\n")
        config = b"CONFIG_PACKAGE_docker=y\n"
        projected = runner.graph_scope.scope(raw, config, roots=("feeds/luci/luci-app-dockerman", "kernel/linux"))
        self.assertEqual(projected.count(b"feeds/packages/docker/compile"), 2)
        self.assertNotIn(b"other/package", projected)
        with self.assertRaisesRegex(ValueError, "unknown graph directive"):
            runner.graph_scope.scope(raw + b"unknown graph row\n", config, roots=("feeds/luci/luci-app-dockerman", "kernel/linux"))


class DockermanEvidencePackageTests(unittest.TestCase):
    def test_streamed_bundle_preserves_raw_stage_mode_and_checks_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / "output"; output.mkdir()
            stage = output / "dockerman-stage/usr/share/rpcd/ucode/docker_rpc.uc"
            stage.parent.mkdir(parents=True)
            stage.write_bytes(b"raw staged Ucode")
            stage.chmod(0o755)
            digest = compare.digest(stage.read_bytes())
            manifest = {"process_group_quiescent": True, "output_capture_errors": [],
                        "output_sha256": {stage.relative_to(output).as_posix(): digest}}
            (output / "manifest.json").write_text(json.dumps(manifest) + "\n")
            archive = root / "evidence.tar"
            result = package.create(output, archive)
            self.assertGreater(result["archive_bytes"], result["output_bytes"])
            with tarfile.open(archive) as tar:
                member = tar.getmember("dockerman/dockerman-stage/usr/share/rpcd/ucode/docker_rpc.uc")
                self.assertEqual(member.mode & 0o777, 0o755)
                self.assertEqual(tar.extractfile(member).read(), b"raw staged Ucode")

    def test_bundle_rejects_output_that_does_not_match_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / "output"; output.mkdir()
            (output / "captured.log").write_bytes(b"changed")
            manifest = {"process_group_quiescent": True, "output_capture_errors": [],
                        "output_sha256": {"captured.log": compare.digest(b"original")}}
            (output / "manifest.json").write_text(json.dumps(manifest) + "\n")
            with self.assertRaisesRegex(ValueError, "digest changed"):
                package.create(output, root / "bad.tar")

    def test_bundle_detects_change_between_inventory_and_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / "output"; output.mkdir()
            item = output / "captured.log"
            item.write_bytes(b"original")
            manifest = {"process_group_quiescent": True, "output_capture_errors": [],
                        "output_sha256": {"captured.log": compare.digest(b"original")}}
            manifest_bytes = (json.dumps(manifest) + "\n").encode()
            (output / "manifest.json").write_bytes(manifest_bytes)
            original_inventory = package.inventory
            def raced_inventory(path):
                result = original_inventory(path)
                item.write_bytes(b"changed")
                return result
            with patch.object(package, "inventory", side_effect=raced_inventory):
                with self.assertRaisesRegex(ValueError, "changed while creating"):
                    package.create(output, root / "raced.tar")


if __name__ == "__main__":
    unittest.main()
