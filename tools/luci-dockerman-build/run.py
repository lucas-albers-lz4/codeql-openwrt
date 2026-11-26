#!/usr/bin/env python3
"""Reviewed-candidate normal dependency Dockerman build; never run implicitly."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "tools/luci-app-metadata-probe"))
import run as metadata
import check
sys.path.insert(0, str(HERE))
import compare
KERNEL_HELPER = REPO / "tools/luci-app-module-batches/kernel-evidence.py"
sys.path.insert(0, str(REPO / "tools/luci-statistics-batch"))
import kernel as kernel_checks
sys.path.insert(0, str(REPO / "tools/luci-statistics-batch"))
import graph_scope
kernel_spec = importlib.util.spec_from_file_location("dockerman_kernel_evidence", KERNEL_HELPER)
kernel_evidence = importlib.util.module_from_spec(kernel_spec)
kernel_spec.loader.exec_module(kernel_evidence)
stats_spec = importlib.util.spec_from_file_location(
    "dockerman_statistics_runner", REPO / "tools/luci-statistics-batch/run.py")
statistics_runner = importlib.util.module_from_spec(stats_spec)
stats_spec.loader.exec_module(statistics_runner)
CONFIG_SHA = "4678b8d328391f97ba85b19020cbdcc077cccc528dc79553b99625627f25ae17"
GRAPH_SCOPE_SHA = "dbd149322c47f4ee8e75aa8cc3a8e0caf51b5c425561866fe26da8fdaced2ddc"
PACKAGE_VERSION = "26.134.50559~d5129a1"
KMOD_PACKAGE_VERSION = "6.12.116-r1"
PHASES = (
    ("tools-install", "tools/install", 1800),
    ("toolchain-install", "toolchain/install", 2700),
    ("kernel-compile", "target/linux/compile", 2700),
    ("kernel-package-compile", "package/kernel/linux/compile", 1500),
    ("dockerman-compile", "package/feeds/luci/luci-app-dockerman/compile", 10500),
)
KNOWN_CYCLE_EDGES = {
    ("dockerd", "containerd"), ("containerd", "dockerd"),
    ("dockerd", "tini"), ("tini", "dockerd"),
    ("containerd", "runc"), ("runc", "dockerd"),
}
GRAPH_ROOTS = ("feeds/luci/luci-app-dockerman", "kernel/linux")
EXPECTED_CONTROLS = {
    "luci-app-dockerman": (PACKAGE_VERSION, "all"),
    "luci-base": ("26.317.52279~1c75ea4", "x86_64"),
    "docker": ("29.6.1-r1", "x86_64"),
    "dockerd": ("29.6.1-r1", "x86_64"),
    "docker-compose": ("5.1.4-r1", "x86_64"),
    "ttyd": ("1.7.7-r1", "x86_64"),
    "ucode-mod-socket": ("2026.07.09~b885dd0f-r3", "x86_64"),
    "containerd": ("2.2.5-r1", "x86_64"),
    "runc": ("1.3.6-r1", "x86_64"),
    "tini": ("0.19.0-r4", "x86_64"),
}
KMODS = ("kmod-ipt-nat", "kmod-ipt-physdev", "kmod-nf-ipvs", "kmod-veth", "kmod-ipt-nat6")
PROVIDER_DIRS = {
    "luci-app-dockerman": "bin/packages/x86_64/luci",
    "luci-base": "bin/packages/x86_64/luci",
    "docker": "bin/packages/x86_64/packages", "dockerd": "bin/packages/x86_64/packages",
    "docker-compose": "bin/packages/x86_64/packages", "ttyd": "bin/packages/x86_64/packages",
    "containerd": "bin/packages/x86_64/packages", "runc": "bin/packages/x86_64/packages",
    "tini": "bin/packages/x86_64/packages", "ucode-mod-socket": "bin/packages/x86_64/base",
}
KNOWN_EMPTY_WARNINGS = {
    "kmod-drm-exec": b"WARNING: kmod-drm-exec is not available in the kernel config - generating empty package",
    "kmod-drm-suballoc-helper": b"WARNING: kmod-drm-suballoc-helper is not available in the kernel config - generating empty package",
}
TAGS = {
    "docker-cli": ("https://github.com/docker/cli.git", "v29.6.1",
                   "54ef6288d2fdf057c6eb58419d9a8f8587f532e4",
                   "8900f1d330cb39e93e16d780a26bff1d7e07ba03"),
    "moby": ("https://github.com/moby/moby.git", "docker-v29.6.1",
             "5259f1f37f10f37594a18eab40604e3e91622fe9",
             "8ec5ab355a34b2a0e2b3238d67bdefe77fefa982"),
}


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def host_preflight(out, root):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("build host must be Linux x86_64")
    mem = Path("/proc/meminfo").read_text()
    match = re.search(r"^MemTotal:\s+(\d+) kB$", mem, re.M)
    memory = int(match.group(1)) * 1024 if match else 0
    free = shutil.disk_usage(root.parent).free
    cpus = os.cpu_count() or 0
    if memory < 15 * 1024**3 or free < 60 * 1024**3 or cpus < 2:
        raise ValueError("host requires >=15 GiB RAM, >=60 GiB free disk and >=2 CPUs")
    write_json(out / "host-preflight.json", {"platform": platform.platform(), "machine": platform.machine(),
        "memory_total_bytes": memory, "disk_free_bytes": free, "cpu_count": cpus,
        "limits": {"memory_min_bytes": 15 * 1024**3, "disk_min_bytes": 60 * 1024**3,
                   "job_timeout_minutes": 360, "phase_timeouts_seconds": dict((x[0], x[2]) for x in PHASES)}})


def cycle_observations(streams):
    rows = []
    pattern = re.compile(r"^make(?:\[\d+\])?: Circular package/feeds/packages/([A-Za-z0-9+_.-]+)/compile <- package/feeds/packages/([A-Za-z0-9+_.-]+)/compile dependency dropped\.$")
    for line in b"\n".join(streams).decode("utf-8", "replace").splitlines():
        if "circular" not in line.lower():
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError("unparsed or noncanonical circular dependency warning: " + line)
        edge = match.groups()
        if edge not in KNOWN_CYCLE_EDGES:
            raise ValueError("unreviewed circular dependency warning: " + line)
        rows.append({"line": line, "edge": list(edge), "disposition": "observed known source-graph cycle warning"})
    return rows


def frozen_metadata(probe, label):
    ow = probe.root / "openwrt"
    config = check.physical_file(ow / ".config", ow, True)
    graph = check.physical_file(ow / "tmp/.packagedeps", ow, True)
    raw_sha = check.digest(graph)
    for name, data in (("config", config), ("packagedeps", graph)):
        with (probe.out / ("frozen-" + label + "-" + name)).open("xb") as stream:
            stream.write(data)
    raw_pin_path = probe.out / "initial-packagedeps-sha256"
    if not raw_pin_path.exists():
        with raw_pin_path.open("x", encoding="ascii") as stream:
            stream.write(raw_sha + "\n")
    elif raw_pin_path.read_text().strip() != raw_sha:
        raise ValueError("full .packagedeps bytes changed during this run")
    if check.digest(config) != CONFIG_SHA:
        raise ValueError("frozen Dockerman config differs")
    check.validate_final_config(config, "dockerman-only")
    projected = graph_scope.scope(graph, config, roots=GRAPH_ROOTS)
    if check.digest(projected) != GRAPH_SCOPE_SHA:
        raise ValueError("Dockerman+kernel selected dependency graph scope differs")
    return raw_sha


def source_guard(probe, label):
    expected = getattr(probe, "source_lock", None)
    if not isinstance(expected, dict):
        raise ValueError("source tree lock is unavailable")
    for name, facts in expected.items():
        repo = probe.root / name
        head = probe.git("source-head-" + label + "-" + name, repo, "rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
        if head != [metadata.PINS[name][1], facts["tree"]]:
            raise ValueError("pinned source commit/tree changed: " + name)
        flag = "--untracked-files=no" if name == "openwrt" else "--untracked-files=all"
        status = probe.git("source-status-" + label + "-" + name, repo, "status", "--porcelain=v1", flag)
        if status:
            raise ValueError("source checkout changed: " + name)
    ow = probe.root / "openwrt"
    check.validate_link(ow / "feeds/luci", probe.root / "luci")
    check.validate_link(ow / "feeds/packages", probe.root / "packages")
    check.validate_link(ow / "package/feeds/luci/luci-app-dockerman",
                        probe.root / "luci/applications/luci-app-dockerman")
    check.validate_link(ow / "package/feeds/luci/luci-base", probe.root / "luci/modules/luci-base")
    for package_name in ("docker", "dockerd", "docker-compose", "ttyd", "containerd", "runc", "tini"):
        check.validate_link(ow / "package/feeds/packages" / package_name,
                            probe.root / "packages/utils" / package_name)


def validate_build_diagnostics(probe, label, stdout, stderr):
    data = stdout + b"\n" + stderr
    needle = b"is not available in the kernel config - generating empty package"
    stdout_lines = [line for line in stdout.splitlines() if needle in line]
    lines = [line for line in stderr.splitlines() if needle in line]
    if stdout_lines:
        raise ValueError("empty-package diagnostics must appear on stderr")
    names = []
    for line in lines:
        matched = [name for name, expected in KNOWN_EMPTY_WARNINGS.items() if line == expected]
        if len(matched) != 1:
            raise ValueError("unreviewed empty-package diagnostic: " + line.decode("utf-8", "replace"))
        names.append(matched[0])
    candidate = False
    if lines:
        if label != "kernel-package-compile" or sorted(names) != sorted(KNOWN_EMPTY_WARNINGS):
            raise ValueError("empty-package diagnostic outside the exact two reviewed kernel helpers")
        config = check.physical_file(probe.out / "config-final", probe.out, True)
        if check.digest(config) != CONFIG_SHA:
            raise ValueError("empty-package source-scope exception requires exact Dockerman config")
        config_lines = set(config.decode().splitlines())
        for package in KNOWN_EMPTY_WARNINGS:
            if f"CONFIG_PACKAGE_{package}=y" not in config_lines:
                raise ValueError("reviewed empty helper is not selected by the pinned profile: " + package)
        kernel_root = probe.root / "openwrt/build_dir/target-x86_64_musl/linux-x86_64/linux-6.12.116"
        kernel_config = check.physical_file(kernel_root / ".config", kernel_root, True)
        retained_kernel_config = check.physical_file(probe.out / "kernel-evidence/.config", probe.out, True)
        if retained_kernel_config != kernel_config:
            raise ValueError("retained kernel config differs from live kernel config")
        kernel_lines = kernel_config.decode().splitlines()
        symbols = {"kmod-drm-exec": "CONFIG_DRM_EXEC", "kmod-drm-suballoc-helper": "CONFIG_DRM_SUBALLOC_HELPER"}
        for package, symbol in symbols.items():
            found = [line for line in kernel_lines if line.startswith(symbol + "=") or line == f"# {symbol} is not set"]
            if found not in ([], [f"# {symbol} is not set"]):
                raise ValueError("kernel config no longer explains reviewed empty helper: " + package)
        for symbol, expected in (("CONFIG_DRM", "CONFIG_DRM=y"), ("CONFIG_DRM_I915", "CONFIG_DRM_I915=m")):
            found = [line for line in kernel_lines if line.startswith(symbol + "=") or line == f"# {symbol} is not set"]
            if found != [expected]:
                raise ValueError("pinned DRM/i915 kernel context differs: " + symbol)
        live_magic = check.physical_file(kernel_root / ".vermagic", kernel_root, True)
        retained_magic = check.physical_file(probe.out / "kernel-evidence/.vermagic", probe.out, True)
        if live_magic != retained_magic:
            raise ValueError("retained kernel vermagic differs from live kernel vermagic")
        candidate = True
    scrubbed = b"\n".join(line for line in data.splitlines() if line.strip() not in lines)
    kernel_checks.reject_empty_package_diagnostic(scrubbed)
    write_json(probe.out / (label + "-diagnostic-disposition.json"), {
        "phase": label, "raw_empty_package_lines": [x.decode("utf-8", "replace") for x in lines],
        "source_scoped_exception_candidate": candidate,
        "kernel_config_sha256": check.digest(kernel_config) if candidate else None,
        "kernel_vermagic_sha256": check.digest(live_magic) if candidate else None,
        "disposition": "candidate only; kernel IPK validation and package-recipe dependency comparison remain required" if candidate else "no empty package diagnostics observed"})


def phase(probe, label, target, timeout):
    frozen_metadata(probe, label + "-before")
    source_guard(probe, "before-" + label)
    argv = ["/usr/bin/time", "-v", "-o", str(probe.out / (label + ".time")), "make", "-j2", target, "V=s"]
    failure = None
    try:
        probe.invoke(label, argv, probe.root / "openwrt", timeout=timeout)
    except Exception as exc:
        failure = exc
    if not probe.quiescent:
        raise failure or RuntimeError("phase process group is not quiescent; do not inspect live outputs")
    stdout = check.physical_file(probe.out / (label + ".stdout"), probe.out)
    stderr = check.physical_file(probe.out / (label + ".stderr"), probe.out)
    custody_error = None
    try:
        if label == "kernel-compile":
            kernel_evidence.capture_kernel(probe.root, CONFIG_SHA)
        elif label == "kernel-package-compile":
            kernel_evidence.snapshot_package_output(probe.root)
    except Exception as exc:
        custody_error = exc
    after_error = None
    try:
        frozen_metadata(probe, label + "-after")
        source_guard(probe, "after-" + label)
    except Exception as exc:
        after_error = exc
    diagnostic_error = None
    try:
        validate_build_diagnostics(probe, label, stdout, stderr)
    except Exception as exc:
        diagnostic_error = exc
    cycle_error = None
    if label in ("kernel-compile", "kernel-package-compile", "dockerman-compile"):
        try:
            write_json(probe.out / (label + "-cycle-warnings.json"), cycle_observations((stdout, stderr)))
        except Exception as exc:
            cycle_error = exc
    failures = {key: repr(exc) for key, exc in (
        ("make", failure), ("custody", custody_error), ("post_phase", after_error),
        ("diagnostics", diagnostic_error), ("cycle_parser", cycle_error)) if exc is not None}
    if failures:
        write_json(probe.out / (label + "-validation-failures.json"), failures)
        raise RuntimeError("phase had retained build/validation failures: " + json.dumps(failures, sort_keys=True))


def remote_tag_preflight(probe):
    observations = {}
    for label, (url, tag, obj, peeled) in TAGS.items():
        output = probe.invoke("tag-preflight-" + label,
            ["git", "ls-remote", "--tags", url, "refs/tags/" + tag, "refs/tags/" + tag + "^{}"], probe.root, timeout=180)
        rows = [line.split() for line in output.decode().splitlines() if line.strip()]
        mapping = {parts[1]: parts[0] for parts in rows if len(parts) == 2}
        if mapping != {"refs/tags/" + tag: obj, "refs/tags/" + tag + "^{}": peeled}:
            raise ValueError("upstream release tag object or peeled commit differs: " + label)
        observations[label] = {"url": url, "tag": tag, "tag_object": obj, "peeled_commit": peeled,
                               "raw_sha256": check.digest(output)}
    write_json(probe.out / "upstream-tag-pins.json", observations)


def control_only(data):
    # Keep companion data archive semantics out of this control-identity check.
    outer = compare.archive.members(data)
    if set(outer) != {"debian-binary", "control.tar.gz", "data.tar.gz"}:
        raise ValueError("unexpected IPK outer members")
    if outer["debian-binary"]["bytes"] != b"2.0\n":
        raise ValueError("unexpected IPK format")
    control = compare.archive.members(outer["control.tar.gz"]["bytes"])
    return compare.base.control_from_rows(control)


def validate_provider_control(name, fields, version, architecture):
    expected = {"Package": name, "Version": version, "Architecture": architecture}
    if fields != expected:
        raise ValueError("required provider IPK control identity differs: " + name)
    return expected


def retain_provider_candidates(probe):
    """Copy selected provider IPK candidates before any identity verdict."""
    ow = probe.root / "openwrt"
    names = set(EXPECTED_CONTROLS) | {"kernel", *KMODS}
    roots = {
        "luci": ow / "bin/packages/x86_64/luci",
        "packages": ow / "bin/packages/x86_64/packages",
        "base": ow / "bin/packages/x86_64/base",
        "target": ow / "bin/targets/x86/64/packages",
    }
    output = probe.out / "provider-candidates"
    output.mkdir(mode=0o755)
    records = []
    for repo, root in roots.items():
        if not root.exists() and not root.is_symlink():
            continue
        if root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError("provider IPK directory is aliased: " + str(root))
        for source in sorted(root.glob("*.ipk")):
            if source.name.split("_", 1)[0] not in names:
                continue
            data, mode = compare.physical_file(source)
            destination = output / repo / source.name
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(data)
            destination.chmod(mode)
            records.append({"path": str(source.relative_to(ow)),
                            "retained_path": destination.relative_to(probe.out).as_posix(),
                            "sha256": check.digest(data), "size": len(data), "mode": format(mode, "04o")})
    write_json(probe.out / "provider-candidates.json", {"members": records})
    return records


def package_outputs(probe, kernel_receipt):
    ow = probe.root / "openwrt"
    retained_candidates = {row["path"]: row for row in retain_provider_candidates(probe)}
    roots = [ow / "bin/packages/x86_64/luci", ow / "bin/packages/x86_64/packages",
             ow / "bin/packages/x86_64/base", ow / "bin/targets/x86/64/packages"]
    inventory = []
    candidates = {name: [] for name in (*EXPECTED_CONTROLS, "kernel", *KMODS)}
    for root in roots:
        if not root.exists() and not root.is_symlink():
            continue
        if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
            raise ValueError("provider IPK scan root is aliased: " + str(root))
        for path in sorted(root.glob("*.ipk")):
            data = check.physical_file(path, ow, True)
            row = {"path": path.relative_to(ow).as_posix(), "sha256": check.digest(data), "size": len(data)}
            inventory.append(row)
            stem = path.name.split("_", 1)[0]
            if stem in candidates:
                fields = control_only(data)
                candidates[stem].append((path, data, fields))
    required = dict(EXPECTED_CONTROLS)
    magic = kernel_receipt["version"].split("~", 1)[1].split("-r1", 1)[0]
    kernel_version = "6.12.116~" + magic + "-r1"
    required["kernel"] = (kernel_version, "x86_64")
    for name in KMODS:
        required[name] = (KMOD_PACKAGE_VERSION, "x86_64")
    rows = {}
    for name, (version, arch) in required.items():
        matches = candidates.get(name, [])
        if len(matches) != 1:
            raise ValueError("required provider IPK is missing or ambiguous: " + name)
        if len(matches) != 1:
            raise ValueError("required provider IPK missing or ambiguous: " + name)
        path, data, fields = matches[0]
        validate_provider_control(name, fields, version, arch)
        expected_directory = ("bin/targets/x86/64/packages" if name == "kernel" or name.startswith("kmod-")
                              else PROVIDER_DIRS[name])
        if path.parent.relative_to(ow).as_posix() != expected_directory:
            raise ValueError("provider IPK appeared in an unexpected feed/target directory: " + name)
        expected_filename = f"{name}_{version}_{arch}.ipk"
        if path.name != expected_filename:
            raise ValueError("provider IPK filename differs from its exact control identity: " + name)
        retained = retained_candidates.get(path.relative_to(ow).as_posix())
        if retained is None or retained["sha256"] != check.digest(data):
            raise ValueError("validated provider bytes were not retained: " + name)
        rows[name] = {"path": path.relative_to(ow).as_posix(), "control": fields,
                      "sha256": check.digest(data), "size": len(data),
                      "mode": retained["mode"], "retained_path": retained["retained_path"],
                      "data_members": "not parsed for dependency IPKs; package main archive is validated separately"}
    go = ow / "staging_dir/hostpkg/lib/go-1.26/bin/go"
    if not go.is_file() or go.is_symlink() or go.resolve(strict=True) != go:
        raise ValueError("normal Dockerman target did not provide the expected Go host tool")
    version_output = probe.invoke("go-version", [str(go), "version"], ow)
    if version_output.strip() != b"go version go1.26.11 linux/amd64":
        raise ValueError("Go host tool version differs")
    return {"schema": "issue173-dockerman-provider-inventory-v1", "ipks": rows,
            "all_seen_ipks": inventory,
            "provider_candidate_manifest": "provider-candidates.json",
            "provider_candidate_manifest_sha256": check.digest((probe.out / "provider-candidates.json").read_bytes()),
            "go_binary": str(go.relative_to(ow)),
            "go_version": version_output.decode().strip()}


def execute_phases(probe, run_phase, kernel_action):
    """Preserve the ordinary prerequisite order; stop immediately on any failure."""
    for label, target, timeout in PHASES:
        run_phase(probe, label, target, timeout)
        if label == "kernel-compile":
            kernel_action("capture")
        elif label == "kernel-package-compile":
            kernel_action("snapshot-and-validate")


def capture_selected_prepared(prepared, output):
    rows = [r for r in compare.load_oracle()["entries"] if r["package"] == "luci-app-dockerman" and r["projected_member"]]
    target = output / "dockerman-prepared"
    target.mkdir(mode=0o755)
    inventory = []
    for row in rows:
        rel = compare.expected_prepared(row)
        source = Path(prepared) / rel
        if not source.exists() and not source.is_symlink():
            inventory.append({"source_path": row["source_path"], "prepared_path": rel, "status": "missing"})
            continue
        data, mode = compare.physical_file(source)
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(data)
        dest.chmod(mode)
        inventory.append({"source_path": row["source_path"], "prepared_path": rel,
                          "sha256": check.digest(data), "size": len(data), "mode": format(mode, "04o"),
                          "status": "captured"})
    write_json(output / "dockerman-prepared-inventory.json", {"members": inventory})
    return target


def capture_stage(stage, output):
    stage = Path(stage)
    destination = output / "dockerman-stage"
    destination.mkdir(mode=0o755)
    inventory = []
    for source in sorted(stage.rglob("*")):
        if source.is_symlink():
            raise ValueError("symlink in Dockerman stage: " + str(source))
        rel = source.relative_to(stage)
        dest = destination / rel
        if source.is_dir():
            dest.mkdir(mode=source.stat().st_mode & 0o7777, parents=True, exist_ok=True)
        elif source.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            data, mode = compare.physical_file(source)
            with dest.open("xb") as stream:
                stream.write(data)
            dest.chmod(mode)
            inventory.append({"path": rel.as_posix(), "sha256": check.digest(data),
                              "size": len(data), "mode": format(mode, "04o")})
        else:
            raise ValueError("special object in Dockerman stage: " + str(source))
    write_json(output / "dockerman-stage-inventory.json", {"members": inventory})
    return destination


def build(probe):
    host_preflight(probe.out, probe.root)
    for name, expected in (("source-oracle", compare.ORACLE_SHA256),):
        if check.digest((HERE.parent / "luci-app-metadata-probe/source-oracle.json").read_bytes()) != expected:
            raise ValueError(name + " input digest differs")
    metadata_result = probe.run()
    if metadata_result.get("profile") != "dockerman-only":
        raise ValueError("metadata setup did not select Dockerman-only profile")
    probe.source_lock = metadata_result["source_before"]
    write_json(probe.out / "metadata-probe-result.json", metadata_result)
    frozen_metadata(probe, "initial-build")
    probe.invoke("dockerman-source-preflight",
                 [sys.executable, "-I", "-B", str(HERE / "compare.py"), "--preflight",
                  "--luci", str(probe.root / "luci")], probe.root, timeout=300)
    remote_tag_preflight(probe)
    source_guard(probe, "pre-build")
    def kernel_action(action):
        if action == "capture":
            # phase() snapshots this state before diagnostic interpretation,
            # including a failed kernel compile attempt.
            return
        else:
            kernel_evidence.validate_package(probe.root, CONFIG_SHA)
    execute_phases(probe, phase, kernel_action)
    kernel_evidence.recheck(probe.root)
    ipk_dir = probe.root / "openwrt/bin/packages/x86_64/luci"
    built_ipk = ipk_dir / ("luci-app-dockerman_" + PACKAGE_VERSION + "_all.ipk")
    if not ipk_dir.is_dir() or ipk_dir.is_symlink() or sorted(ipk_dir.glob("luci-app-dockerman_*.ipk")) != [built_ipk]:
        raise ValueError("Dockerman selected IPK path is missing or ambiguous")
    ipk = check.physical_file(built_ipk, probe.root / "openwrt", True)
    retained = probe.out / "luci-app-dockerman.ipk"
    with retained.open("xb") as stream:
        stream.write(ipk)
    prepared = probe.root / "openwrt/build_dir/target-x86_64_musl/luci-app-dockerman"
    stage = prepared / "ipkg-all/luci-app-dockerman"
    if prepared.is_symlink() or stage.is_symlink() or not prepared.is_dir() or not stage.is_dir():
        raise ValueError("Dockerman prepared/stage directories are missing or aliased")
    if prepared.resolve(strict=True) != prepared or stage.resolve(strict=True) != stage:
        raise ValueError("Dockerman prepared/stage path is not physical")
    prepared_copy = capture_selected_prepared(prepared, probe.out)
    stage_copy = capture_stage(stage, probe.out)
    go_receipt = package_outputs(probe, json.loads((probe.out / "kernel-package-inventory.json").read_text()))
    result = compare.compare(probe.root / "luci", prepared, stage, ipk,
                             (probe.root / "openwrt/.config").read_bytes())
    # Recompare the portable retained copies so the receipt binds the exact files
    # that the evidence artifact will carry, including hidden CONTROL metadata.
    compare.compare(probe.root / "luci", prepared_copy, stage_copy, ipk,
                    (probe.root / "openwrt/.config").read_bytes())
    with (probe.out / "dockerman-package-comparison.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n")
    with (probe.out / "dockerman-provider-inventory.json").open("x", encoding="utf-8") as stream:
        json.dump(go_receipt, stream, indent=2, sort_keys=True); stream.write("\n")
    diagnostic_path = probe.out / "kernel-package-compile-diagnostic-disposition.json"
    if diagnostic_path.exists():
        diagnostic = check.json_object(diagnostic_path.read_bytes())
        if diagnostic.get("source_scoped_exception_candidate") is True:
            kernel_package = check.json_object((probe.out / "kernel-package-inventory.json").read_bytes())
            comparison = check.json_object((probe.out / "dockerman-package-comparison.json").read_bytes())
            if set(comparison["declared_runtime_dependencies"]) != compare.DIRECT_DEPS:
                raise ValueError("source-scoped helper diagnostic cannot be finalized with a changed app dependency set")
            write_json(probe.out / "kernel-diagnostic-scope-final-disposition.json", {
                "raw_warning_receipt": diagnostic_path.name,
                "raw_warning_receipt_sha256": check.digest(diagnostic_path.read_bytes()),
                "warning_lines": diagnostic["raw_empty_package_lines"],
                "config_sha256": CONFIG_SHA,
                "kernel_package_inventory": "kernel-package-inventory.json",
                "kernel_package_inventory_sha256": check.digest((probe.out / "kernel-package-inventory.json").read_bytes()),
                "kernel_version": kernel_package["version"],
                "kernel_config_sha256": diagnostic["kernel_config_sha256"],
                "kernel_vermagic_sha256": diagnostic["kernel_vermagic_sha256"],
                "dockerman_comparison": "dockerman-package-comparison.json",
                "dockerman_comparison_sha256": check.digest((probe.out / "dockerman-package-comparison.json").read_bytes()),
                "direct_app_dependencies": comparison["declared_runtime_dependencies"],
                "disposition": "both helper warnings were retained; pinned kernel/IPK validation passed and selected Dockerman recipe declares no direct DRM dependency; this is not complete kernel-module coverage"})
    return {"status": "dockerman_package_compared_review_required", "profile": "dockerman-only",
            "selected_package": "luci-app-dockerman", "comparison_sha256": check.digest((probe.out / "dockerman-package-comparison.json").read_bytes()),
            "ipk_sha256": check.digest(ipk), "config_sha256": CONFIG_SHA,
            "raw_graph_sha256": (probe.out / "initial-packagedeps-sha256").read_text().strip(),
            "selected_graph_scope_sha256": GRAPH_SCOPE_SHA,
            "source_pins": {name: pair[1] for name, pair in metadata.PINS.items()},
            "metadata_run_id": 45780167961, "metadata_artifact_id": 15097324501,
            "expected_cycle_edges": sorted([list(x) for x in KNOWN_CYCLE_EDGES]),
            "scope": "normal dependency build observation and exact main-IPK source comparison; not complete dependency closure, runtime behavior or security coverage"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="fresh absent physical absolute run root")
    parser.add_argument("--consumer-commit", required=True)
    parser.add_argument("--prereq-root", type=Path)
    args = parser.parse_args()
    os.umask(0o022)
    probe = metadata.Probe(args.root, args.consumer_commit, "dockerman-only")
    failure = None
    try:
        if args.prereq_root is not None:
            statistics_runner.capture_prerequisites(probe, args.prereq_root)
        result = build(probe)
    except Exception as exc:
        failure = repr(exc)
        result = {"status": "failed", "failure": failure, "profile": "dockerman-only",
                  "scope": "partial build evidence only; inspect retained phases and diagnostics"}
        if probe.quiescent and probe.out.exists() and not (probe.out / "provider-candidates.json").exists():
            try:
                retain_provider_candidates(probe)
            except Exception as retain_exc:
                result["provider_candidate_retention_error"] = repr(retain_exc)
        metadata.capture_failure_evidence(probe, result)
    output_ok = probe.finish(result)
    if failure or not output_ok:
        raise SystemExit("Dockerman build failed; safe partial evidence remains in the run output")
    print("Dockerman source comparison recorded; independent package and build audit required")


if __name__ == "__main__":
    main()
