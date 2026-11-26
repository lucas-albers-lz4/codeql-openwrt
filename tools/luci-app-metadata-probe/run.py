#!/usr/bin/env python3
"""Capture pinned feed/defconfig metadata only; never invoke build targets."""

import argparse, datetime, json, os, platform, shutil, signal, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check

REPO = HERE.parent.parent
PINS = {
    "openwrt": (
        "https://git.openwrt.org/openwrt/openwrt.git",
        "4e9642517b48bae612ff10fb72fb9199e559500e",
    ),
    "luci": (
        "https://git.openwrt.org/project/luci.git",
        "cb87fe60e1e2e052af36a93647f2264577829e0a",
    ),
    "packages": (
        "https://git.openwrt.org/feed/packages.git",
        "07e0d16305d2b5903b37ad7913e33e18795f81a4",
    ),
}
FILES = {
    "source-oracle.json": "a5ab0a2b8f0099073a040b57ec4be3324a874d2f67ec3951a62a18cfa886cf4f",
    "inventory.py": "963056113899b5eb411614d9bbd541ae7185e047e39a5cb325d4c60209aa944e",
    "companion-recipes.json": "de1282aa000606b2230462a6b27a152f887b3c4806eecfdd9398614308d2c97e",
    "scheduler-sources.json": "ddfc97fe6b4b119c7c0ebf776d9daf3a781fdb0f97b626ce47f72db339182b7a",
    "known-diagnostics.json": "e0bb8b76ec386934ea85d510f9bf99693b095347238eb498bd2d447f83eee153",
}
BASELINE_SHA = "91fcf7f84e2934a1df21c7438f898fb5cd097eb9f6cfde3bc80239369c0d7cbc"
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


class Probe:
    def __init__(self, root, consumer_commit, profile="joint"):
        check.need(
            len(consumer_commit) == 40 and all(c in "0123456789abcdef" for c in consumer_commit),
            "invalid consumer commit",
        )
        self.seed, _, self.selected_packages = check.profile_values(profile)
        self.profile = profile
        self.consumer_commit = consumer_commit
        self.root = check.fresh_root(root)
        for name in ("output", "home", "tmp"):
            (self.root / name).mkdir()
        self.out = self.root / "output"
        self.phases = []
        self.diags = []
        self.quiescent = True
        self.env = {
            "PATH": PATH,
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "LC_ALL": "C",
            "TZ": "UTC",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
        self.known = check.json_object((HERE / "known-diagnostics.json").read_bytes())

    def invoke(self, label, argv, cwd, timeout=600):
        check.need(
            label and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label),
            "unsafe phase label",
        )
        out = self.out / (label + ".stdout")
        err = self.out / (label + ".stderr")
        started = utc()
        start = time.monotonic()
        code = None
        failure = None
        proc = None
        try:
            with out.open("xb") as so, err.open("xb") as se:
                try:
                    proc = subprocess.Popen(
                        argv, cwd=cwd, env=self.env, stdout=so, stderr=se, start_new_session=True
                    )
                    try:
                        code = proc.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        failure = "phase timeout; terminated process group"
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            code = proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(proc.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            try:
                                code = proc.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                failure = "phase timeout; process did not exit after SIGKILL"
                                self.quiescent = False
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if group_exists(proc.pid):
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        self.quiescent = False
                        failure = failure or "phase left a process group after exit"
                except OSError as e:
                    if proc is not None:
                        self.quiescent = False
                    failure = repr(e)
        except OSError as e:
            failure = repr(e)
        row = {
            "label": label,
            "argv": argv,
            "cwd": str(cwd),
            "env": self.env,
            "exit": code,
            "started_utc": started,
            "finished_utc": utc(),
            "elapsed_seconds": time.monotonic() - start,
            "peak_rss_bytes": None,
            "rss_note": "not measured",
            "failure": failure,
        }
        captured = {}
        for name, p in (("stdout", out), ("stderr", err)):
            try:
                check.need(self.quiescent, "process group may still be active")
                captured[name] = check.physical_file(p, self.out)
                row[name + "_sha256"] = check.digest(captured[name])
            except Exception as e:
                row[name + "_sha256"] = None
                row[name + "_capture_error"] = repr(e)
                failure = failure or repr(e)
                row["failure"] = failure
        with (self.out / (label + ".receipt.json")).open("x") as f:
            json.dump(row, f, indent=2, sort_keys=True)
            f.write("\n")
        self.phases.append(row)
        if (
            label in ("feeds-update", "feeds-install", "defconfig")
            and "stdout" in captured
            and "stderr" in captured
        ):
            diag = check.diagnostics(label, (captured["stdout"], captured["stderr"]), self.known)
            self.diags.append({"phase": label, **diag})
        else:
            diag = {"unexpected_errors": []}
        if failure or code != 0:
            raise RuntimeError("phase failed: " + label)
        if diag["unexpected_errors"]:
            raise RuntimeError("unexpected error in phase: " + label)
        return captured["stdout"]

    def git(self, label, repo, *args):
        return self.invoke(label, ["git", "-C", str(repo), *args], self.root)

    def consumer_identity(self, suffix):
        head = self.git("consumer-head-" + suffix, REPO, "rev-parse", "HEAD", "HEAD^{tree}")
        values = head.decode().splitlines()
        check.need(
            len(values) == 2 and values[0] == self.consumer_commit,
            "consumer checkout revision differs",
        )
        status = self.git(
            "consumer-status-" + suffix, REPO, "status", "--porcelain=v1", "--untracked-files=all"
        )
        check.need(not status, "consumer checkout changed")
        return {"commit": values[0], "tree": values[1], "status": "clean"}

    def no_config(self):
        p = self.root / "openwrt/.config"
        check.need(not p.exists() and not p.is_symlink(), "config appeared during feeds setup")

    def sources(self, suffix):
        result = {}
        for name, (_, commit) in PINS.items():
            repo = self.root / name
            head = (
                self.git(name + "-head-" + suffix, repo, "rev-parse", "HEAD", "HEAD^{tree}")
                .decode()
                .splitlines()
            )
            check.need(len(head) == 2 and head[0] == commit, "source revision differs: " + name)
            status = self.git(
                name + "-status-" + suffix,
                repo,
                "status",
                "--porcelain=v1",
                (
                    "--untracked-files=all"
                    if name != "openwrt" or suffix == "before"
                    else "--untracked-files=no"
                ),
            )
            check.need(not status, "source checkout changed: " + name)
            result[name] = {
                "commit": head[0],
                "tree": head[1],
                "status": "clean" if name != "openwrt" or suffix == "before" else "tracked-clean",
            }
        return result

    def dumps(self):
        files = check.scan_dump_files(self.root / "openwrt")
        for name, data in files:
            dest = self.out / "scanner-dumps" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                check.need(check.physical_file(dest, self.out) == data, "scanner dump changed")
            else:
                with dest.open("xb") as f:
                    f.write(data)
        check.need(not files, "scanner dump files present")

    def capture_available(self):
        ow = self.root / "openwrt"
        errors = []
        for name in (".config", "tmp/.packageinfo", "tmp/.packagedeps", "tmp/.config-package.in"):
            path = ow / name
            if not path.exists() and not path.is_symlink():
                continue
            try:
                data = check.physical_file(path, ow, True)
                dest = self.out / (
                    "config-final" if name == ".config" else name.replace("/", "-").lstrip(".")
                )
                if dest.exists():
                    check.need(
                        check.physical_file(dest, self.out) == data,
                        "captured metadata changed: " + name,
                    )
                else:
                    with dest.open("xb") as f:
                        f.write(data)
            except Exception as e:
                errors.append(name + ": " + repr(e))
        if errors:
            raise ValueError("metadata capture errors: " + "; ".join(errors))

    def source_evidence(self):
        for manifest in ("companion-recipes.json", "scheduler-sources.json"):
            for i, row in enumerate(check.json_object((HERE / manifest).read_bytes())["entries"]):
                repo = self.root / ("packages" if row["repo"] == "openwrt/packages" else "openwrt")
                data = self.git(
                    manifest.split(".")[0] + "-" + str(i),
                    repo,
                    "show",
                    row["commit"] + ":" + row["source_path"],
                )
                check.need(
                    check.digest(data) == row["sha256"],
                    "source recipe differs: " + row["source_path"],
                )
        baseline = REPO / "evidence/issue172-luci-source-inventory-20261125/inventory.json"
        check.need(check.digest(baseline.read_bytes()) == BASELINE_SHA, "#172 baseline differs")
        target = self.out / "source-oracle-observed.json"
        self.invoke(
            "source-oracle",
            [
                sys.executable,
                "-I",
                "-B",
                str(HERE / "inventory.py"),
                "--luci",
                str(self.root / "luci"),
                "--inventory172",
                str(baseline),
                "--output",
                str(target),
            ],
            self.root,
        )
        check.need(
            check.digest(check.physical_file(target, self.out, True))
            == FILES["source-oracle.json"],
            "source oracle differs",
        )

    def run(self):
        for name, h in FILES.items():
            check.need(check.digest((HERE / name).read_bytes()) == h, "tool input differs: " + name)
        check.need(
            platform.system() == "Linux" and platform.machine() == "x86_64",
            "Linux x86_64 host required",
        )
        executables = {}
        for name in ("git", "make", "cc", "c++", "perl", "python3", "uname", "df", "free"):
            resolved = shutil.which(name, path=PATH)
            check.need(resolved is not None, "host executable missing: " + name)
            executables[name] = str(Path(resolved).resolve(strict=True))
        with (self.out / "host-executable-paths.json").open("x") as f:
            json.dump(executables, f, indent=2, sort_keys=True)
            f.write("\n")
        self.invoke("host-uname", ["uname", "-a"], self.root)
        self.invoke("host-git", ["git", "--version"], self.root)
        self.invoke("host-make", ["make", "--version"], self.root)
        self.invoke("host-cc", ["cc", "--version"], self.root)
        self.invoke("host-cxx", ["c++", "--version"], self.root)
        self.invoke("host-perl", ["perl", "-v"], self.root)
        self.invoke("host-python", [sys.executable, "--version"], self.root)
        self.invoke("host-df", ["df", "-Pk", str(self.root)], self.root)
        self.invoke("host-memory", ["free", "-b"], self.root)
        for name, (url, commit) in PINS.items():
            self.invoke(
                "clone-" + name,
                ["git", "clone", "--no-checkout", url, str(self.root / name)],
                self.root,
                1200,
            )
            self.git("checkout-" + name, self.root / name, "checkout", "--detach", commit)
        consumer_before = self.consumer_identity("before")
        before = self.sources("before")
        self.source_evidence()
        ow = self.root / "openwrt"
        self.no_config()
        feed_config = b"src-link luci ../../luci\nsrc-link packages ../../packages\n"
        with (ow / "feeds.conf").open("xb") as f:
            f.write(feed_config)
        with (self.out / "feeds.conf").open("xb") as f:
            f.write(feed_config)
        self.invoke("feeds-update", ["./scripts/feeds", "update", "luci", "packages"], ow)
        self.no_config()
        self.dumps()
        for n in ("luci", "packages"):
            check.validate_link(ow / "feeds" / n, self.root / n)
            data = check.validate_feed_index(ow, n)
            if n == "luci":
                check.validate_packageinfo(
                    data,
                    {
                        x: "feeds/luci/applications/" + x + "/Makefile"
                        for x in self.selected_packages
                    },
                )
            else:
                check.validate_packageinfo(
                    data,
                    {
                        x: "feeds/packages/utils/" + x + "/Makefile"
                        for x in (
                            (
                                "docker",
                                "dockerd",
                                "docker-compose",
                                "ttyd",
                                "collectd",
                                "rrdtool1",
                                "containerd",
                            )
                            if self.profile in ("joint", "dockerman-only")
                            else ("collectd", "rrdtool1")
                        )
                    },
                )
            with (self.out / ("feed-" + n + ".packageinfo")).open("xb") as f:
                f.write(data)
        self.invoke("feeds-install", ["./scripts/feeds", "install", "-a"], ow)
        self.no_config()
        self.dumps()
        for n in ("luci", "packages"):
            check.validate_link(ow / "feeds" / n, self.root / n)
        for n in self.selected_packages:
            check.validate_link(ow / "package/feeds/luci" / n, self.root / "luci/applications" / n)
        for n in ("s", "fs"):
            self.invoke("feeds-list-" + n, ["./scripts/feeds", "list", "-" + n], ow)
        self.no_config()
        for name in ("tmp/.packageinfo", "tmp/.packagedeps"):
            path = ow / name
            if path.exists() or path.is_symlink():
                data = check.physical_file(path, ow, True)
                with (self.out / ("pre-defconfig-" + path.name.lstrip("."))).open("xb") as f:
                    f.write(data)
        seed = self.seed.encode()
        with (ow / ".config").open("xb") as f:
            f.write(seed)
        with (self.out / "config-input").open("xb") as f:
            f.write(seed)
        self.invoke("defconfig", ["make", "defconfig"], ow)
        self.dumps()
        self.capture_available()
        captured = {}
        for name in (
            "config-final",
            "tmp-.packageinfo",
            "tmp-.packagedeps",
            "tmp-.config-package.in",
        ):
            captured[name] = check.physical_file(self.out / name, self.out, True)
        choices = check.validate_final_config(captured["config-final"], self.profile)
        check.validate_packagedeps(captured["tmp-.packagedeps"], self.profile)
        check.validate_packageinfo(
            captured["tmp-.packageinfo"],
            {x: "package/feeds/luci/" + x + "/Makefile" for x in self.selected_packages},
        )
        after = self.sources("after")
        consumer_after = self.consumer_identity("after")
        for n in ("luci", "packages"):
            check.validate_link(ow / "feeds" / n, self.root / n)
            check.validate_feed_index(ow, n)
        for n in self.selected_packages:
            check.validate_link(ow / "package/feeds/luci" / n, self.root / "luci/applications" / n)
        result = {
            "status": "metadata_collected_review_required",
            "source_before": before,
            "source_after": after,
            "consumer_before": consumer_before,
            "consumer_after": consumer_after,
            "selected_config_index": choices,
            "diagnostics": self.diags,
            "scope": "raw metadata only; host prereq/Kconfig and pinned recipe DUMP scans may compile/run; no tools/toolchain, target/kernel, package or image build, package membership or dependency-closure approval",
        }
        if self.profile != "joint":
            result["profile"] = self.profile
            result["selected_app_packages"] = list(self.selected_packages)
        return result

    def finish(self, result):
        files = {}
        errors = []
        if not self.quiescent:
            errors.append("process group may still be active; output withheld")
        for path in sorted(self.out.rglob("*")):
            if not self.quiescent:
                break
            name = path.relative_to(self.out).as_posix()
            try:
                check.need(not path.is_symlink(), "symlink in evidence output")
                if path.is_file():
                    files[name] = check.digest(check.physical_file(path, self.out))
                else:
                    check.need(path.is_dir(), "special evidence output")
            except Exception as exc:
                errors.append(name + ": " + repr(exc))
        if errors:
            result["status"] = "failed"
            result["output_capture_errors"] = errors
        result.update(
            {
                "phase_receipts": self.phases,
                "output_sha256": files,
                "env": self.env,
                "umask": "0022",
                "process_group_quiescent": self.quiescent,
            }
        )
        with (self.out / "manifest.json").open("x") as file:
            json.dump(result, file, indent=2, sort_keys=True)
            file.write("\n")
        return not errors


def capture_failure_evidence(probe, result):
    if not probe.quiescent:
        result["metadata_capture"] = "withheld: process group may still be active"
        return
    try:
        probe.dumps()
    except Exception as exc:
        result["scanner_capture"] = repr(exc)
    try:
        probe.capture_available()
    except Exception as exc:
        result["metadata_capture"] = repr(exc)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--consumer-commit", required=True)
    p.add_argument("--profile", choices=check.PROFILES, default="joint")
    a = p.parse_args()
    os.umask(0o022)
    probe = Probe(a.root, a.consumer_commit, a.profile)
    failure = None
    try:
        result = probe.run()
    except Exception as e:
        failure = repr(e)
        result = {
            "status": "failed",
            "failure": failure,
            "config_evidence": "partial_or_unvalidated",
            "diagnostics": probe.diags,
            "scope": "partial metadata only; host prereq/Kconfig and pinned recipe DUMP scans may compile/run; no target/toolchain/package build approval",
        }
        if probe.profile != "joint":
            result["profile"] = probe.profile
            result["requested_app_packages"] = list(probe.selected_packages)
        capture_failure_evidence(probe, result)
    output_ok = probe.finish(result)
    if failure or not output_ok:
        raise SystemExit(
            "metadata probe failed; local partial output is available only when safely captured"
        )
    print("metadata collected; independent graph and diagnostics review required")


if __name__ == "__main__":
    main()
