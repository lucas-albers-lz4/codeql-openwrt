"""Offline isolation and failure-reason tests; no network or real make."""

import json, os, subprocess, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
import sys, time
from unittest.mock import patch
import check, run

HERE = Path(__file__).resolve().parent


class GuardTests(unittest.TestCase):
    def test_config_positive_missing_and_duplicate(self):
        self.assertEqual(
            check.validate_config((check.SEED + "CONFIG_PACKAGE_golang1.26=m\n").encode())[
                "CONFIG_PACKAGE_golang1.26"
            ],
            "m",
        )
        with self.assertRaisesRegex(
            ValueError, "duplicate config symbol: CONFIG_PACKAGE_golang1.26"
        ):
            check.validate_config(
                (
                    check.SEED
                    + "CONFIG_PACKAGE_golang1.26=m\n# CONFIG_PACKAGE_golang1.26 is not set\n"
                ).encode()
            )
        with self.assertRaisesRegex(ValueError, "config symbol differs: CONFIG_TARGET_x86"):
            check.validate_config(check.SEED.replace("CONFIG_TARGET_x86=y\n", "").encode())
        with self.assertRaisesRegex(ValueError, "duplicate config symbol"):
            check.validate_config((check.SEED + "CONFIG_USE_APK=y\n").encode())

    def test_statistics_only_seed_and_config_isolation(self):
        expected = (
            "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=m\n"
            "# CONFIG_PACKAGE_luci-app-dockerman is not set\n"
            "CONFIG_PACKAGE_luci-app-statistics=m\nCONFIG_PER_FEED_REPO=y\n"
            "CONFIG_USE_APK=n\n# CONFIG_LUCI_JSMIN is not set\n"
            "# CONFIG_LUCI_CSSTIDY is not set\n"
        )
        self.assertEqual(check.STATISTICS_SEED, expected)
        self.assertEqual(check.profile_values("joint")[0], check.SEED)
        self.assertEqual(
            check.digest(check.SEED.encode()),
            "23aef585895752a6ba0d447be3e2898fd84982f0a7b2a3c6fddec28ce81bd059",
        )
        self.assertEqual(check.profile_values("statistics-only")[2], ("luci-app-statistics",))
        final = (expected + "CONFIG_HAVE_DOT_CONFIG=y\n").encode()
        selected = check.validate_final_config(final, "statistics-only")
        self.assertEqual(selected["CONFIG_PACKAGE_luci-app-dockerman"], "n")
        for change in (
            "CONFIG_PACKAGE_luci-app-dockerman=m",
            "CONFIG_PACKAGE_luci-app-dockerman=y",
            "",
        ):
            modified = expected.replace("# CONFIG_PACKAGE_luci-app-dockerman is not set", change)
            with self.assertRaisesRegex(
                ValueError, "config symbol differs: CONFIG_PACKAGE_luci-app-dockerman"
            ):
                check.validate_final_config(
                    (modified + "CONFIG_HAVE_DOT_CONFIG=y\n").encode(), "statistics-only"
                )
        with self.assertRaisesRegex(ValueError, "duplicate config symbol"):
            check.validate_final_config(
                final + b"CONFIG_PACKAGE_luci-app-dockerman=m\n", "statistics-only"
            )
        with self.assertRaisesRegex(ValueError, "unchanged seed"):
            check.validate_final_config(expected.encode(), "statistics-only")
        with self.assertRaisesRegex(ValueError, "unknown metadata profile"):
            check.profile_values("statistics;unexpected")

    def test_dockerman_only_seed_and_config_isolation(self):
        expected = (
            "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=m\n"
            "CONFIG_PACKAGE_luci-app-dockerman=m\n"
            "# CONFIG_PACKAGE_luci-app-statistics is not set\n"
            "CONFIG_PER_FEED_REPO=y\nCONFIG_USE_APK=n\n# CONFIG_LUCI_JSMIN is not set\n"
            "# CONFIG_LUCI_CSSTIDY is not set\n"
        )
        self.assertEqual(check.DOCKERMAN_SEED, expected)
        self.assertEqual(
            check.profile_values("dockerman-only")[2], ("luci-app-dockerman",)
        )
        final = (expected + "CONFIG_HAVE_DOT_CONFIG=y\n").encode()
        selected = check.validate_final_config(final, "dockerman-only")
        self.assertEqual(selected["CONFIG_PACKAGE_luci-app-statistics"], "n")
        for change in (
            "CONFIG_PACKAGE_luci-app-statistics=m",
            "CONFIG_PACKAGE_luci-app-statistics=y",
            "",
        ):
            modified = expected.replace(
                "# CONFIG_PACKAGE_luci-app-statistics is not set", change
            )
            with self.assertRaisesRegex(
                ValueError, "config symbol differs: CONFIG_PACKAGE_luci-app-statistics"
            ):
                check.validate_final_config(
                    (modified + "CONFIG_HAVE_DOT_CONFIG=y\n").encode(), "dockerman-only"
                )
        graph = (
            "package-$(CONFIG_PACKAGE_luci-app-dockerman) += feeds/luci/luci-app-dockerman\n"
            "$(curdir)/feeds/luci/luci-app-dockerman/compile += $(curdir)/feeds/packages/docker/compile\n"
        ).encode()
        check.validate_packagedeps(graph, "dockerman-only")
        with self.assertRaisesRegex(
            ValueError, "package graph declaration differs: luci-app-statistics"
        ):
            check.validate_packagedeps(graph, "joint")

    def test_statistics_graph_requires_only_selected_app(self):
        graph = (
            "package-$(CONFIG_PACKAGE_luci-app-statistics) += feeds/luci/luci-app-statistics\n"
            "$(curdir)/feeds/luci/luci-app-statistics/compile += $(curdir)/feeds/packages/collectd/compile\n"
        ).encode()
        check.validate_packagedeps(graph, "statistics-only")
        with self.assertRaisesRegex(
            ValueError, "package graph declaration differs: luci-app-dockerman"
        ):
            check.validate_packagedeps(graph, "joint")
        with self.assertRaisesRegex(ValueError, "package graph compile edge"):
            check.validate_packagedeps(
                graph.replace(b"/compile +=", b"/wrong +="), "statistics-only"
            )

    def test_diagnostics_keep_unknown_and_exact_recursion(self):
        known = json.loads((HERE / "known-diagnostics.json").read_text())
        pair = known["defconfig_recursive_pairs"][0]
        warning = known["defconfig_warnings"][0]
        row = check.diagnostics(
            "defconfig",
            (("\n".join([warning, *pair, "WARNING: synthetic unknown"]) + "\n").encode(), b""),
            known,
        )
        self.assertEqual(row["known_kconfig_recursive_pairs"], [pair])
        self.assertEqual(row["unreviewed_warnings"], ["WARNING: synthetic unknown"])
        self.assertEqual(row["disposition"], "review_required")
        bad = check.diagnostics(
            "defconfig",
            (b"tmp/.config-package.in:1:error: recursive dependency detected!\nnew symbol\n", b""),
            known,
        )
        self.assertTrue(bad["unexpected_errors"])
        duplicate = check.diagnostics(
            "defconfig", (("\n".join([*pair, *pair]) + "\n").encode(), b""), known
        )
        self.assertEqual(len(duplicate["known_kconfig_recursive_pairs"]), 1)
        self.assertEqual(len(duplicate["unexpected_errors"]), 1)

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            check.json_object(b'{"x":1,"x":2}')

    def test_fresh_root_and_feed_index_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve()
            root = check.fresh_root(p / "run")
            with self.assertRaisesRegex(ValueError, "absent and physical"):
                check.fresh_root(root)
            feeds = root / "feeds"
            (feeds / "luci.tmp").mkdir(parents=True)
            (feeds / "luci.tmp/.packageinfo").write_text("data")
            (feeds / "luci.index").symlink_to("luci.tmp/.packageinfo")
            self.assertEqual(check.validate_feed_index(root, "luci"), b"data")
            (feeds / "luci.index").unlink()
            (feeds / "luci.index").symlink_to("luci.tmp/../luci.tmp/.packageinfo")
            with self.assertRaisesRegex(ValueError, "feed index link"):
                check.validate_feed_index(root, "luci")

    def test_final_config_and_graph_generation_guards(self):
        with self.assertRaisesRegex(ValueError, "unchanged seed"):
            check.validate_final_config(check.SEED.encode())
        with self.assertRaisesRegex(ValueError, "completion marker"):
            check.validate_final_config((check.SEED + "# generated\n").encode())
        check.validate_final_config((check.SEED + "CONFIG_HAVE_DOT_CONFIG=y\n").encode())
        names = ("luci-app-dockerman", "luci-app-statistics")
        graph = "".join(
            f"package-$(CONFIG_PACKAGE_{n}) += feeds/luci/{n}\n"
            f"$(curdir)/feeds/luci/{n}/compile += $(curdir)/feeds/luci/luci-base/compile\n"
            for n in names
        )
        check.validate_packagedeps(graph.encode())
        with self.assertRaisesRegex(ValueError, "graph compile edge"):
            check.validate_packagedeps(
                graph.replace(
                    "$(curdir)/feeds/luci/luci-app-statistics/compile +=", "wrong +="
                ).encode()
            )

    def test_scoped_packageinfo_source_and_duplicates(self):
        expected = {
            "luci-app-dockerman": "package/feeds/luci/luci-app-dockerman/Makefile",
            "luci-app-statistics": "package/feeds/luci/luci-app-statistics/Makefile",
        }
        valid = "".join(
            "Source-Makefile: " + path + "\nPackage: " + name + "\n"
            for name, path in expected.items()
        ).encode()
        check.validate_packageinfo(valid, expected)
        with self.assertRaisesRegex(ValueError, "package metadata source differs"):
            check.validate_packageinfo(valid + valid, expected)
        with self.assertRaisesRegex(ValueError, "package metadata source differs"):
            check.validate_packageinfo(valid.replace(b"package/feeds/luci/", b"wrong/"), expected)

    def test_scan_dump_and_symlink_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            logs = root / "logs/a"
            logs.mkdir(parents=True)
            (logs / "dump.txt").write_text("scan failed")
            self.assertEqual(check.scan_dump_files(root), [("logs/a/dump.txt", b"scan failed")])
            (root / "logs/alias").symlink_to(logs)
            with self.assertRaisesRegex(ValueError, "symlink in scanner logs"):
                check.scan_dump_files(root)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "run"
        self.p = run.Probe(self.root, "1" * 40)

    def test_nonzero_phase_retains_exact_receipt(self):
        with patch.object(
            subprocess, "Popen", return_value=SimpleNamespace(pid=999, wait=lambda timeout=None: 7)
        ):
            with self.assertRaisesRegex(RuntimeError, "phase failed"):
                self.p.invoke("fake-phase", ["fake"], self.root)
        row = json.loads((self.p.out / "fake-phase.receipt.json").read_text())
        self.assertEqual(row["exit"], 7)
        self.assertEqual(row["argv"], ["fake"])
        self.assertNotIn("MAKEFLAGS", row["env"])

    def test_spawn_failure_retains_receipt(self):
        with patch.object(subprocess, "Popen", side_effect=OSError("synthetic spawn")):
            with self.assertRaisesRegex(RuntimeError, "phase failed"):
                self.p.invoke("fake-phase", ["fake"], self.root)
        self.assertIn(
            "synthetic spawn",
            json.loads((self.p.out / "fake-phase.receipt.json").read_text())["failure"],
        )

    def test_rejected_log_alias_is_never_read_for_diagnostics(self):
        actual = self.root / "actual"
        actual.write_text("ERROR: should not be parsed")

        def fake(argv, **kwargs):
            path = self.p.out / "defconfig.stdout"
            path.unlink()
            path.symlink_to(actual)
            return SimpleNamespace(pid=999, wait=lambda timeout=None: 0)

        with patch.object(subprocess, "Popen", side_effect=fake):
            with self.assertRaisesRegex(RuntimeError, "phase failed"):
                self.p.invoke("defconfig", ["make", "defconfig"], self.root)
        row = json.loads((self.p.out / "defconfig.receipt.json").read_text())
        self.assertIn("unsafe file", row["stdout_capture_error"])
        self.assertEqual(self.p.diags, [])

    def test_source_recipe_literal_error_is_not_runtime_diagnostic(self):
        def fake(argv, **kw):
            kw["stdout"].write(b"$(error ERROR: recipe literal, not execution)\n")
            return SimpleNamespace(pid=999, wait=lambda timeout=None: 0)

        with patch.object(subprocess, "Popen", side_effect=fake):
            self.p.invoke("scheduler-sources-0", ["git", "show", "blob"], self.root)
        self.assertEqual(self.p.phases[-1]["exit"], 0)
        self.assertEqual(self.p.diags, [])

    def test_nonzero_defconfig_retains_diagnostics(self):
        def fake(argv, **kw):
            kw["stderr"].write(b"WARNING: synthetic warning\nERROR: synthetic failure\n")
            return SimpleNamespace(pid=999, wait=lambda timeout=None: 2)

        with patch.object(subprocess, "Popen", side_effect=fake):
            with self.assertRaisesRegex(RuntimeError, "phase failed"):
                self.p.invoke("defconfig", ["make", "defconfig"], self.root)
        self.assertIn("WARNING: synthetic warning", self.p.diags[-1]["warnings"])
        self.assertIn("ERROR: synthetic failure", self.p.diags[-1]["unexpected_errors"])

    def test_partial_metadata_captured(self):
        ow = self.root / "openwrt"
        (ow / "tmp").mkdir(parents=True)
        (ow / ".config").write_text("partial")
        (ow / "tmp/.packagedeps").write_text("partial graph")
        self.p.capture_available()
        self.assertEqual((self.p.out / "config-final").read_text(), "partial")
        self.assertEqual((self.p.out / "tmp-.packagedeps").read_text(), "partial graph")

    def test_partial_capture_preserves_safe_files_when_one_unsafe(self):
        ow = self.root / "openwrt"
        (ow / "tmp").mkdir(parents=True)
        (ow / "tmp/.packageinfo").write_text("safe")
        (ow / ".config").symlink_to(ow / "tmp/.packageinfo")
        with self.assertRaisesRegex(ValueError, "metadata capture errors"):
            self.p.capture_available()
        self.assertEqual((self.p.out / "tmp-.packageinfo").read_text(), "safe")

    def test_timeout_terminates_synthetic_grandchild(self):
        marker = self.root / "grandchild-marker"
        started = self.root / "grandchild-started"
        child = (
            "import pathlib,time;pathlib.Path("
            + repr(str(started))
            + ").write_text('started');time.sleep(1.8);pathlib.Path("
            + repr(str(marker))
            + ").write_text('escaped')"
        )
        parent = (
            "import subprocess,sys,time,pathlib;subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]);p=pathlib.Path("
            + repr(str(started))
            + ");\nwhile not p.exists():time.sleep(0.01)\ntime.sleep(30)"
        )
        with self.assertRaisesRegex(RuntimeError, "phase failed"):
            self.p.invoke("timeout-test", [sys.executable, "-c", parent], self.root, timeout=1)
        self.assertTrue(started.exists(), "grandchild did not start before timeout")
        time.sleep(1.1)
        self.assertFalse(marker.exists())
        row = json.loads((self.p.out / "timeout-test.receipt.json").read_text())
        self.assertIn("terminated process group", row["failure"])

    def test_nonquiescent_failure_skips_raw_capture(self):
        self.p.quiescent = False
        result = {}
        with patch.object(self.p, "dumps") as dumps, patch.object(
            self.p, "capture_available"
        ) as capture:
            run.capture_failure_evidence(self.p, result)
        dumps.assert_not_called()
        capture.assert_not_called()
        self.assertIn("withheld", result["metadata_capture"])

    def test_orphan_group_after_success_withholds_output(self):
        marker = self.root / "orphan-marker"
        started = self.root / "orphan-started"
        child = (
            "import pathlib,time;pathlib.Path("
            + repr(str(started))
            + ").write_text('started');time.sleep(1.8);pathlib.Path("
            + repr(str(marker))
            + ").write_text('escaped')"
        )
        parent = (
            "import subprocess,sys,time,pathlib;subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]);p=pathlib.Path("
            + repr(str(started))
            + ");\nwhile not p.exists():time.sleep(0.01)\n"
        )
        with self.assertRaisesRegex(RuntimeError, "phase failed"):
            self.p.invoke("orphan-test", [sys.executable, "-c", parent], self.root, timeout=3)
        self.assertTrue(started.exists())
        self.assertFalse(self.p.quiescent)
        time.sleep(1.9)
        self.assertFalse(marker.exists())
        row = json.loads((self.p.out / "orphan-test.receipt.json").read_text())
        self.assertIn("process group", row["failure"])

    def test_simulated_sequence_has_only_defconfig_make(self):
        self.simulated_sequence("joint")

    def test_statistics_real_runner_path_and_selection(self):
        self.root = self.root.parent / "statistics-run"
        self.p = run.Probe(self.root, "1" * 40, "statistics-only")
        self.simulated_sequence("statistics-only")

    def test_dockerman_real_runner_path_and_selection(self):
        self.root = self.root.parent / "dockerman-run"
        self.p = run.Probe(self.root, "1" * 40, "dockerman-only")
        self.simulated_sequence("dockerman-only")

    def simulated_sequence(self, profile):
        calls = []
        ow = self.root / "openwrt"

        def invoke(label, argv, cwd, timeout=600):
            calls.append((label, argv))
            if label.startswith("clone-"):
                (self.root / label.removeprefix("clone-")).mkdir()
            if label == "feeds-update":
                feeds = ow / "feeds"
                feeds.mkdir()
                for n in ("luci", "packages"):
                    (feeds / n).symlink_to(self.root / n)
                    (feeds / (n + ".tmp")).mkdir()
                    (feeds / (n + ".tmp") / ".packageinfo").write_text(
                        "".join(
                            "Source-Makefile: feeds/"
                            + n
                            + ("/applications/" if n == "luci" else "/utils/")
                            + x
                            + "/Makefile\nPackage: "
                            + x
                            + "\n"
                            for x in (
                                self.p.selected_packages
                                if n == "luci"
                                else (
                                    "docker",
                                    "dockerd",
                                    "docker-compose",
                                    "ttyd",
                                    "collectd",
                                    "rrdtool1",
                                    "containerd",
                                )
                            )
                        )
                    )
                    (feeds / (n + ".index")).symlink_to(n + ".tmp/.packageinfo")
            if label == "feeds-install":
                base = ow / "package/feeds/luci"
                base.mkdir(parents=True)
                src = self.root / "luci/applications"
                src.mkdir()
                for n in self.p.selected_packages:
                    (src / n).mkdir()
                    (base / n).symlink_to(src / n)
            if label == "defconfig":
                tmp = ow / "tmp"
                tmp.mkdir()
                (ow / ".config").write_text(self.p.seed + "CONFIG_HAVE_DOT_CONFIG=y\n")
                (tmp / ".config-package.in").write_text("synthetic metadata")
                (tmp / ".packagedeps").write_text(
                    "".join(
                        f"package-$(CONFIG_PACKAGE_{n}) += feeds/luci/{n}\n"
                        f"$(curdir)/feeds/luci/{n}/compile += $(curdir)/feeds/luci/luci-base/compile\n"
                        for n in self.p.selected_packages
                    )
                )
                (tmp / ".packageinfo").write_text(
                    "".join(
                        "Source-Makefile: package/feeds/luci/"
                        + x
                        + "/Makefile\nPackage: "
                        + x
                        + "\n"
                        for x in self.p.selected_packages
                    )
                )
            return b""

        with patch.object(run.platform, "system", return_value="Linux"), patch.object(
            run.platform, "machine", return_value="x86_64"
        ), patch.object(run.shutil, "which", return_value=sys.executable), patch.object(
            self.p, "invoke", side_effect=invoke
        ), patch.object(
            self.p, "sources", return_value={}
        ), patch.object(
            self.p, "consumer_identity", return_value={}
        ), patch.object(
            self.p, "source_evidence"
        ), patch.object(
            self.p, "dumps"
        ):
            result = self.p.run()
        self.assertEqual(result["status"], "metadata_collected_review_required")
        self.assertEqual((self.p.out / "config-input").read_text(), self.p.seed)
        if profile == "joint":
            self.assertEqual(
                set(result),
                {
                    "status",
                    "source_before",
                    "source_after",
                    "consumer_before",
                    "consumer_after",
                    "selected_config_index",
                    "diagnostics",
                    "scope",
                },
            )
            self.assertNotIn("profile", result)
            self.assertNotIn("selected_app_packages", result)
        else:
            self.assertEqual(result["profile"], profile)
            self.assertEqual(result["selected_app_packages"], list(self.p.selected_packages))
            disabled = (
                "CONFIG_PACKAGE_luci-app-dockerman"
                if profile == "statistics-only"
                else "CONFIG_PACKAGE_luci-app-statistics"
            )
            self.assertEqual(result["selected_config_index"][disabled], "n")
        self.assertEqual(
            [argv for _, argv in calls if argv[0] == "make"],
            [["make", "--version"], ["make", "defconfig"]],
        )
        self.assertTrue(all("NO_DEPS" not in x and x != "-n" for _, argv in calls for x in argv))

    def test_unknown_profile_never_creates_root(self):
        target = self.root.parent / "unknown-profile"
        with self.assertRaisesRegex(ValueError, "unknown metadata profile"):
            run.Probe(target, "1" * 40, "other")
        self.assertFalse(target.exists())

    def test_profile_workflow_paths_and_alias_rejection(self):
        script = HERE / "profile-path.sh"
        temp = self.root.parent
        result = subprocess.run(
            ["bash", str(script), "joint", str(temp)], capture_output=True, text=True, check=True
        )
        self.assertEqual(
            result.stdout.splitlines(),
            [
                f"root={temp}/issue173-app-metadata",
                f"archive={temp}/issue173-app-metadata-evidence.tar",
                "suffix=",
            ],
        )
        result = subprocess.run(
            ["bash", str(script), "statistics-only", str(temp)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            result.stdout.splitlines(),
            [
                f"root={temp}/issue173-app-metadata-statistics-only",
                f"archive={temp}/issue173-app-metadata-statistics-only-evidence.tar",
                "suffix=-statistics-only",
            ],
        )
        result = subprocess.run(
            ["bash", str(script), "dockerman-only", str(temp)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            result.stdout.splitlines(),
            [
                f"root={temp}/issue173-app-metadata-dockerman-only",
                f"archive={temp}/issue173-app-metadata-dockerman-only-evidence.tar",
                "suffix=-dockerman-only",
            ],
        )
        result = subprocess.run(
            ["bash", str(script), "other", str(temp)], capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        for char in ("\n", "\r"):
            unsafe = temp / ("unsafe" + char + "path")
            unsafe.mkdir()
            result = subprocess.run(
                ["bash", str(script), "joint", str(unsafe)], capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("runner temp must be a physical absolute directory", result.stderr)
        alias = temp / "alias"
        alias.symlink_to(temp)
        result = subprocess.run(
            ["bash", str(script), "joint", str(alias)], capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_failure_receipt_distinguishes_requested_packages(self):
        for profile in ("joint", "statistics-only", "dockerman-only"):
            target = self.root.parent / ("failure-" + profile)
            argv = ["run.py", "--root", str(target), "--consumer-commit", "1" * 40, "--profile", profile]
            with patch.object(sys, "argv", argv), patch.object(
                run.Probe, "run", side_effect=ValueError("synthetic preflight failure")
            ), patch.object(run, "capture_failure_evidence"):
                with self.assertRaisesRegex(SystemExit, "metadata probe failed"):
                    run.main()
            manifest = json.loads((target / "output" / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            if profile == "joint":
                self.assertNotIn("profile", manifest)
                self.assertNotIn("requested_app_packages", manifest)
            else:
                self.assertEqual(manifest["profile"], profile)
                expected = (
                    ["luci-app-statistics"]
                    if profile == "statistics-only"
                    else ["luci-app-dockerman"]
                )
                self.assertEqual(manifest["requested_app_packages"], expected)
                self.assertNotIn("selected_app_packages", manifest)
    def test_config_present_during_feeds_stops(self):
        ow = self.root / "openwrt"
        ow.mkdir()
        (ow / ".config").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "config appeared"):
            self.p.no_config()


if __name__ == "__main__":
    unittest.main()
