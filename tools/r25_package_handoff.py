#!/usr/bin/env python3
"""Download pinned package artifacts and run the released R2.5 entry point."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

from tools.r25_package_stage import (MAX_IPK_BYTES, ROOT, _check_workspace_path,
                                     _load_lock, digest, need, stage_locked_package,
                                     validate_oracle)
from tools.r3_linux_handoff import pinned as validate_release_lock


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARTIFACT_ZIP_BYTES = MAX_IPK_BYTES + 1024 * 1024
MAX_ARTIFACT_MEMBERS = 64
MAX_ARTIFACT_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARTIFACT_STDERR_BYTES = 1024 * 1024
EXPECTED_COUNTS = {
    "luci-base": {"files": 76, "plain": 10, "markup": 8, "excluded": 58, "successful": 18},
    "wifi-scripts-ucode-y": {"files": 31, "plain": 17, "markup": 0, "excluded": 14, "successful": 17},
}


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_exclusive_text(path: Path, text: str) -> None:
    """Publish an already-sanitized log atomically without replacing a file."""
    need(not path.exists() and not path.is_symlink(), f"log output already exists: {path}")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=f".{path.name}.", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def require_real_dir(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    need(absolute.exists() and absolute.is_dir() and not absolute.is_symlink(),
         f"expected an existing real directory: {absolute}")
    need(absolute.resolve(strict=True) == absolute, f"directory path traverses an alias: {absolute}")
    return absolute


def make_new_dir(path: Path, parent: Path) -> Path:
    parent = require_real_dir(parent)
    absolute = Path(os.path.abspath(path))
    need(absolute.parent == parent, f"new R2.5 output must be a direct child of {parent}")
    need(not absolute.exists() and not absolute.is_symlink(), f"R2.5 output already exists: {absolute}")
    absolute.mkdir(mode=0o700)
    need(not absolute.is_symlink() and absolute.is_dir(), "R2.5 output is not a real directory")
    return absolute


def clean_environment(*, include_gh: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    env.pop("ACTIONS_RUNTIME_TOKEN", None)
    env.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
    if include_gh:
        token = os.environ.get("GH_TOKEN")
        need(bool(token), "GH_TOKEN is required to read the pinned package artifacts")
        env["GH_TOKEN"] = token
        env["GH_PROMPT_DISABLED"] = "1"
    return env


def run_checked(label: str, argv: list[str], cwd: Path, env: dict[str, str],
                log_root: Path, records: list[dict]) -> str:
    need(re.fullmatch(r"[a-z0-9-]+", label) is not None, "unsafe command label")
    stdout_path, stderr_path = log_root / f"{label}.stdout", log_root / f"{label}.stderr"
    started = time.monotonic()
    result = subprocess.run(argv, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    elapsed = round(time.monotonic() - started, 3)
    secret = os.environ.get("GH_TOKEN")
    stdout = result.stdout.replace(secret, "[redacted]") if secret else result.stdout
    stderr = result.stderr.replace(secret, "[redacted]") if secret else result.stderr
    stdout_path.write_text(stdout)
    stderr_path.write_text(stderr)
    record = {"label": label, "argv": argv, "exit_status": result.returncode,
              "elapsed_seconds": elapsed,
              "stdout_sha256": sha_file(stdout_path), "stderr_sha256": sha_file(stderr_path),
              "stdout": stdout_path.relative_to(log_root.parent).as_posix(),
              "stderr": stderr_path.relative_to(log_root.parent).as_posix()}
    records.append(record)
    write_json(log_root.parent / "commands.json", records)
    if result.returncode:
        raise RuntimeError(f"{label} failed with {result.returncode}; see {stderr_path}")
    return result.stdout


def run_binary_download(label: str, argv: list[str], cwd: Path, env: dict[str, str],
                        archive_path: Path, log_root: Path,
                        records: list[dict]) -> dict:
    """Stream a bounded binary API response into a new run-owned file."""
    need(re.fullmatch(r"[a-z0-9-]+", label) is not None, "unsafe command label")
    need(not archive_path.exists() and not archive_path.is_symlink(),
         f"artifact archive output already exists: {archive_path}")
    stderr_path = log_root / f"{label}.stderr"
    need(not stderr_path.exists() and not stderr_path.is_symlink(),
         f"artifact download stderr output already exists: {stderr_path}")
    started = time.monotonic()
    deadline = started + 300
    timed_out = False
    too_large = False
    received = 0
    hasher = hashlib.sha256()
    process = None
    selector = selectors.DefaultSelector()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    archive_fd = os.open(archive_path, flags, 0o600)
    stderr_temp = None
    try:
        stderr_temp = tempfile.TemporaryFile(mode="w+b")
        with os.fdopen(archive_fd, "wb", closefd=False) as archive_file:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                       stderr=stderr_temp, text=False)
            assert process.stdout is not None
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    if process.poll() is None:
                        process.kill()
                    break
                ready = selector.select(timeout=min(1.0, max(0.0, remaining)))
                if not ready:
                    continue
                for key, _ in ready:
                    block = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if not too_large and received + len(block) <= MAX_ARTIFACT_ZIP_BYTES:
                        archive_file.write(block)
                        hasher.update(block)
                    else:
                        too_large = True
                        if process.poll() is None:
                            process.kill()
                    received += len(block)
            remaining = deadline - time.monotonic()
            if remaining <= 0 and process.poll() is None:
                timed_out = True
                process.kill()
            try:
                returncode = process.wait(timeout=max(0.01, remaining))
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                returncode = process.wait(timeout=5)
            archive_file.flush()
        stderr_temp.seek(0)
        error_bytes = stderr_temp.read(MAX_ARTIFACT_STDERR_BYTES + 1)
    except Exception:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        archive_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        raise
    finally:
        if process is not None and process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        os.close(archive_fd)
        if stderr_temp is not None:
            stderr_temp.close()
        selector.close()
    elapsed = round(time.monotonic() - started, 3)
    size = archive_path.stat().st_size
    archive_sha256 = hasher.hexdigest()
    stderr_truncated = len(error_bytes) > MAX_ARTIFACT_STDERR_BYTES
    if stderr_truncated:
        error_bytes = error_bytes[:MAX_ARTIFACT_STDERR_BYTES]
    error_text = error_bytes.decode("utf-8", "replace")
    for secret in (env.get("GH_TOKEN"), env.get("GITHUB_TOKEN")):
        if secret:
            error_text = error_text.replace(secret, "[redacted]")
    if stderr_truncated:
        error_text += f"\n[stderr truncated at {MAX_ARTIFACT_STDERR_BYTES} bytes]\n"
    write_exclusive_text(stderr_path, error_text)
    record = {"label": label, "argv": argv, "exit_status": returncode,
              "elapsed_seconds": elapsed, "archive_bytes": size,
              "response_bytes_observed": received,
              "archive_sha256": archive_sha256,
              "archive_path": archive_path.relative_to(log_root.parent).as_posix()
              if not timed_out and not too_large and returncode == 0 else None,
              "stderr_sha256": sha_file(stderr_path),
              "stderr": stderr_path.relative_to(log_root.parent).as_posix(),
              "stderr_truncated": stderr_truncated,
              "timed_out": timed_out, "response_too_large": too_large}
    records.append(record)
    write_json(log_root.parent / "commands.json", records)
    if timed_out:
        archive_path.unlink(missing_ok=True)
        raise ValueError(f"{label} exceeded the 300 second timeout")
    if too_large:
        archive_path.unlink(missing_ok=True)
        raise ValueError(f"{label} response exceeds artifact ZIP byte budget")
    if returncode:
        archive_path.unlink(missing_ok=True)
        raise RuntimeError(f"{label} failed with {returncode}; see {stderr_path}")
    need(size == received and sha_file(archive_path) == archive_sha256,
         "retained artifact ZIP differs from streamed response")
    return {"archive_sha256": archive_sha256, "archive_bytes": size,
            "command_label": label}


def extract_pinned_ipk(archive_path: Path, filename: str, expected_sha256: str,
                       output_path: Path, workspace: Path) -> dict:
    """Validate one artifact ZIP member before writing the pinned IPK."""
    workspace = require_real_dir(workspace)
    archive_path = _check_workspace_path(archive_path, workspace, must_exist=True)
    output_path = _check_workspace_path(output_path, workspace, must_exist=False)
    need(0 < archive_path.stat().st_size <= MAX_ARTIFACT_ZIP_BYTES,
         "artifact ZIP is empty or exceeds byte budget")
    need(HEX64.fullmatch(expected_sha256 or "") is not None,
         "invalid expected IPK SHA-256")

    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        need(0 < len(infos) <= MAX_ARTIFACT_MEMBERS,
             "artifact ZIP member count is invalid or exceeds budget")
        seen_names = set()
        total_uncompressed = 0
        ipk_infos = []
        for member in infos:
            member_name = member.filename
            member_path = PurePosixPath(member_name)
            need(isinstance(member_name, str) and bool(member_name) and
                 not member_path.is_absolute() and member_path.as_posix() == member_name and
                 "\\" not in member_name and
                 all(part not in ("", ".", "..") for part in member_name.split("/")),
                 f"artifact ZIP contains an unsafe member path: {member_name!r}")
            need(member_name not in seen_names,
                 f"duplicate artifact ZIP member path: {member_name}")
            seen_names.add(member_name)
            mode = (member.external_attr >> 16) & 0xFFFF
            need(stat.S_IFMT(mode) in (0, stat.S_IFREG),
                 f"artifact ZIP member is not a regular file: {member_name}")
            need(not member.is_dir() and not (member.flag_bits & 0x1),
                 f"artifact ZIP member is a directory or encrypted: {member_name}")
            need(member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                 f"artifact ZIP compression method is unsupported: {member_name}")
            need(0 <= member.file_size <= MAX_ARTIFACT_MEMBER_BYTES and
                 0 <= member.compress_size <= MAX_ARTIFACT_ZIP_BYTES,
                 f"artifact ZIP member size is invalid or exceeds budget: {member_name}")
            total_uncompressed += member.file_size
            need(total_uncompressed <= MAX_ARTIFACT_TOTAL_BYTES,
                 "artifact ZIP total uncompressed size exceeds budget")
            if member.file_size:
                need(member.compress_size > 0 and
                     member.file_size <= member.compress_size * 100,
                     f"artifact ZIP member compression ratio exceeds budget: {member_name}")
            if member_name == filename:
                ipk_infos.append(member)
        need(len(ipk_infos) == 1,
             "pinned package artifact must contain exactly one expected IPK member")
        info = ipk_infos[0]
        need(0 < info.file_size <= MAX_IPK_BYTES,
             "pinned IPK member size is invalid or exceeds budget")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(output_path, flags, 0o600)
        total = 0
        hasher = hashlib.sha256()
        try:
            with os.fdopen(fd, "wb", closefd=False) as output, archive.open(info, "r") as source:
                while True:
                    block = source.read(64 * 1024)
                    if not block:
                        break
                    total += len(block)
                    need(total <= info.file_size and total <= MAX_IPK_BYTES,
                         "artifact ZIP member expands beyond its declared or allowed size")
                    hasher.update(block)
                    output.write(block)
                output.flush()
            need(total == info.file_size, "artifact ZIP member size differs from its header")
            ipk_sha256 = hasher.hexdigest()
            need(ipk_sha256 == expected_sha256,
                 "downloaded IPK digest differs from independent package pin")
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
        finally:
            os.close(fd)
    return {"ipk_sha256": ipk_sha256, "ipk_bytes": total,
            "member_name": filename, "archive_member_count": len(infos),
            "archive_declared_uncompressed_bytes": total_uncompressed,
            "other_ipk_members": sorted(member.filename for member in infos
                                         if member.filename.endswith(".ipk") and
                                         member.filename != filename)}


def download_pinned_artifact(repo: str, package_id: str, profile: dict, root: Path,
                             log_root: Path, records: list[dict]) -> tuple[Path, dict]:
    artifact = profile["ipk"]
    run_id, artifact_id = artifact["run_id"], artifact["artifact_id"]
    need(type(run_id) is int and type(artifact_id) is int and run_id > 0 and artifact_id > 0,
         f"invalid package artifact pin: {package_id}")
    api_path = f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    metadata = json.loads(run_checked(f"{package_id}-artifact-list",
                                      ["gh", "api", api_path], ROOT,
                                      clean_environment(include_gh=True), log_root, records))
    artifacts = metadata.get("artifacts")
    need(isinstance(artifacts, list), f"artifact listing malformed: {package_id}")
    matches = [item for item in artifacts if item.get("id") == artifact_id and
               item.get("name") == artifact["artifact_name"]]
    need(len(matches) == 1 and matches[0].get("expired") is False,
         f"pinned package artifact missing, changed or expired: {package_id}")
    workflow_run = matches[0].get("workflow_run")
    if isinstance(workflow_run, dict) and workflow_run.get("id") is not None:
        need(workflow_run["id"] == run_id, f"artifact belongs to another run: {package_id}")
    reported_size = matches[0].get("size_in_bytes")
    if type(reported_size) is int:
        need(0 < reported_size <= MAX_ARTIFACT_ZIP_BYTES,
             f"pinned package artifact exceeds the archive byte budget: {package_id}")
    expected_archive_sha = artifact.get("archive_sha256")
    need(HEX64.fullmatch(expected_archive_sha or "") is not None,
         f"reviewed artifact ZIP digest is missing: {package_id}")
    api_digest = matches[0].get("digest")
    if isinstance(api_digest, str) and api_digest:
        need(api_digest == f"sha256:{expected_archive_sha}",
             f"GitHub artifact metadata differs from reviewed ZIP digest: {package_id}")
    download_dir = make_new_dir(root / package_id, root)
    archive_path = download_dir / "artifact.zip"
    archive_info = run_binary_download(
        f"{package_id}-artifact-download",
        ["gh", "api", "-H", "Accept: application/vnd.github+json",
         f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"], ROOT,
        clean_environment(include_gh=True), archive_path, log_root, records)
    need(archive_info["archive_sha256"] == expected_archive_sha,
         f"downloaded artifact archive differs from consumer lock: {package_id}")
    if isinstance(api_digest, str) and api_digest:
        need(api_digest == f"sha256:{archive_info['archive_sha256']}",
             f"downloaded artifact archive differs from GitHub digest: {package_id}")
    ipk = download_dir / artifact["filename"]
    extracted = extract_pinned_ipk(archive_path, artifact["filename"], artifact["sha256"],
                                   ipk, download_dir)
    return ipk, {**archive_info, **extracted, "api_digest": api_digest}


def verify_bundle_inputs(r3_root: Path, release_lock: dict,
                         package_lock: dict) -> tuple[Path, Path, Path]:
    release = release_lock["release"]
    bundle = r3_root / "bundle/codeql-ucode-linux"
    manifest_path = bundle / "bundle-manifest.json"
    need(manifest_path.is_file() and not manifest_path.is_symlink(), "released bundle manifest missing")
    need(sha_file(manifest_path) == release["manifest_sha256"],
         "R2.5 bundle manifest digest differs from release lock")
    manifest = json.loads(manifest_path.read_text())
    need(manifest.get("artifact_kind") == "versioned-release" and
         manifest.get("producer_commit") == release["commit"] and
         manifest.get("release_tag") == release["tag"], "R2.5 bundle provenance mismatch")
    runner_rel = "runner/run-installed-stage.py"
    runner = bundle / runner_rel
    entries = [entry for entry in manifest.get("files", [])
               if isinstance(entry, dict) and entry.get("path") == runner_rel]
    need(len(entries) == 1 and runner.is_file() and not runner.is_symlink(),
         "released R2.5 runner is absent or duplicated in bundle manifest")
    need(sha_file(runner) == entries[0].get("sha256") and
         runner.stat().st_size == entries[0].get("bytes") and
         stat.S_IMODE(runner.stat().st_mode) == entries[0].get("mode"),
         "released R2.5 runner differs from bundle manifest")
    runner_pin = package_lock.get("producer", {}).get("runner", {}).get("sha256")
    need(HEX64.fullmatch(runner_pin or "") is not None and sha_file(runner) == runner_pin,
         "released R2.5 runner differs from consumer package-lock source pin")
    codeql_archive = r3_root / "downloads/codeql-linux64.zip"
    codeql = r3_root / "cli/codeql/codeql"
    need(codeql_archive.is_file() and not codeql_archive.is_symlink(), "pinned CodeQL archive missing")
    need(codeql.is_file() and not codeql.is_symlink(), "pinned CodeQL executable missing")
    need(sha_file(codeql_archive) == release_lock["codeql"]["sha256"],
         "CodeQL archive differs from consumer lock")
    need(sha_file(codeql) == release["codeql_binary_sha256"],
         "CodeQL executable differs from release lock")
    return bundle, codeql, codeql_archive


def verify_coverage(package_id: str, profile: dict, oracle: dict,
                    run_root: Path, release_lock: dict, *,
                    profile_set: str = "historical") -> dict:
    coverage_path = run_root / "output/coverage-manifest.json"
    receipt_path = run_root / "receipt.json"
    sarif_path = run_root / "output/default-suite.sarif"
    routing_path = run_root / "output/routing.json"
    for path in (coverage_path, receipt_path, sarif_path, routing_path):
        need(path.is_file() and not path.is_symlink(), f"producer output missing or nonregular: {path.name}")
    coverage = json.loads(coverage_path.read_text())
    receipt = json.loads(receipt_path.read_text())
    if profile_set == "historical":
        need(package_id in EXPECTED_COUNTS,
             f"historical profile is not independently expected: {package_id}")
        want_profile = EXPECTED_COUNTS[package_id]
    elif profile_set == "current-luci":
        route_counts = profile.get("oracle", {}).get("route_counts", {})
        want_profile = {"files": profile.get("oracle", {}).get("regular_member_count"),
                        "plain": route_counts.get("plain"), "markup": route_counts.get("markup"),
                        "excluded": route_counts.get("excluded"),
                        "successful": route_counts.get("plain", 0) + route_counts.get("markup", 0)}
    else:
        raise ValueError(f"unsupported package profile set: {profile_set}")
    need(coverage.get("schema") == "ucode-installed-stage-coverage-v1",
         f"unexpected coverage schema: {package_id}")
    need(coverage.get("bundle_manifest_sha256") == release_lock["release"]["manifest_sha256"] and
         coverage.get("producer_commit") == release_lock["release"]["commit"] and
         coverage.get("release_tag") == release_lock["release"]["tag"] and
         coverage.get("codeql_archive_sha256") == release_lock["codeql"]["sha256"],
         f"producer coverage identity mismatch: {package_id}")
    need(coverage.get("oracle_sha256") == profile["oracle"]["sha256"],
         f"producer used a different package oracle: {package_id}")
    files = coverage.get("files")
    need(isinstance(files, list) and len(files) == want_profile["files"],
         f"producer coverage file count mismatch: {package_id}")
    expected = {entry["path"]: entry for entry in oracle["files"]}
    stage_root = run_root.parents[1] / "stages" / package_id
    need(stage_root.is_dir() and not stage_root.is_symlink() and
         stage_root.resolve(strict=True) == stage_root,
         f"producer modified the package stage root: {package_id}")
    actual_stage = set()
    for path in stage_root.rglob("*"):
        mode = path.lstat().st_mode
        need(not stat.S_ISLNK(mode) and (stat.S_ISDIR(mode) or stat.S_ISREG(mode)),
             f"producer changed stage to contain a symlink or special file: {package_id}")
        if stat.S_ISREG(mode):
            need(path.stat().st_nlink == 1, f"staged package file has a hardlink alias: {package_id}")
            rel = path.relative_to(stage_root).as_posix()
            actual_stage.add(rel)
            need(rel in expected and sha_file(path) == expected[rel]["sha256"],
                 f"staged package bytes changed during producer execution: {package_id}/{rel}")
    need(actual_stage == set(expected), f"post-run stage inventory changed: {package_id}")
    by_path = {}
    for row in files:
        need(isinstance(row, dict) and row.get("path") not in by_path,
             f"duplicate or malformed producer coverage identity: {package_id}")
        by_path[row["path"]] = row
    need(set(by_path) == set(expected), f"producer coverage path multiset mismatch: {package_id}")
    route_counts = Counter()
    success_total = 0
    for name, entry in expected.items():
        row = by_path[name]
        need(row.get("sha256") == entry["sha256"] and row.get("route") == entry["route"],
             f"producer file identity or route differs from source oracle: {package_id}/{name}")
        need(row.get("successful_count") == int(entry["expect_success"]) and
             row.get("extraction_error_count") == 0,
             f"producer diagnostic multiplicity/error mismatch: {package_id}/{name}")
        route_counts[entry["route"]["classification"]] += 1
        success_total += row["successful_count"]
    need(all(route_counts.get(key, 0) == value for key, value in
         (("plain", want_profile["plain"]), ("markup", want_profile["markup"]),
          ("excluded", want_profile["excluded"]))),
         f"source route count mismatch: {package_id}")
    need(success_total == want_profile["successful"],
         f"producer successful-file count mismatch: {package_id}")
    sarif = json.loads(sarif_path.read_text())
    sarif_summary = coverage.get("sarif")
    sarif_results = sarif.get("runs", [{}])[0].get("results") if sarif.get("runs") else None
    need(sarif.get("version") == "2.1.0" and len(sarif.get("runs", [])) == 1 and
         isinstance(sarif_results, list) and
         isinstance(sarif_summary, dict) and sarif_summary.get("sha256") == sha_file(sarif_path) and
         sarif_summary.get("result_count") == len(sarif_results),
         f"producer SARIF bytes and coverage summary differ: {package_id}")
    expected_rules = set(release_lock["release"]["expected_rules"])
    rule_ids = sarif_summary.get("rule_ids")
    descriptors = sarif["runs"][0].get("tool", {}).get("driver", {}).get("rules")
    descriptor_ids = [row.get("id") for row in descriptors] if isinstance(descriptors, list) else None
    need(isinstance(rule_ids, list) and len(rule_ids) == len(set(rule_ids)) and
         set(rule_ids) <= expected_rules and isinstance(descriptor_ids, list) and
         len(descriptor_ids) == len(set(descriptor_ids)) and
         Counter(descriptor_ids) == Counter(rule_ids),
         f"producer SARIF declares an unpinned rule: {package_id}")
    need(sarif_summary.get("result_count") == profile.get("expected_default_suite_result_count"),
         f"unexpected default-suite package SARIF result; review required: {package_id}")
    need(receipt.get("bundle_manifest_sha256") == coverage["bundle_manifest_sha256"] and
         receipt.get("producer_commit") == coverage["producer_commit"] and
         receipt.get("release_tag") == coverage["release_tag"] and
         receipt.get("codeql_version") == coverage.get("codeql_version") and
         isinstance(coverage.get("codeql_version"), str) and
         coverage["codeql_version"].splitlines()[0] ==
         f"CodeQL command-line toolchain release {release_lock['codeql']['version']}." and
         receipt.get("codeql_archive_sha256") == release_lock["codeql"]["sha256"] and
         receipt.get("oracle_sha256") == profile["oracle"]["sha256"] and
         receipt.get("sarif", {}).get("sha256") == sarif_summary["sha256"] and
         receipt.get("sarif", {}).get("result_count") == profile.get("expected_default_suite_result_count") and
         receipt.get("extraction_errors") == [] and
         receipt.get("routing_sha256") == coverage.get("routing_sha256") == sha_file(routing_path) and
         receipt.get("coverage_manifest_sha256") == sha_file(coverage_path) and
         receipt.get("stage_files") == {name: entry["sha256"] for name, entry in expected.items()},
         f"producer receipt and coverage identities differ: {package_id}")
    successful = Counter(receipt.get("successful_files", {}))
    expected_successful = Counter({name: 1 for name, entry in expected.items()
                                   if entry["expect_success"]})
    need(successful == expected_successful,
         f"producer receipt successful-file multiset differs from oracle: {package_id}")
    resolved_queries = coverage.get("resolved_queries")
    need(isinstance(resolved_queries, list) and set(resolved_queries) == {
        "DirectRpcShellWord.ql", "ExtractionErrors.ql", "SuccessfullyExtractedFiles.ql"
    } and receipt.get("resolved_queries") == resolved_queries,
         f"producer resolved-query identity differs from reviewed default suite: {package_id}")
    commands = coverage.get("commands")
    need(isinstance(commands, list) and commands and
         all(command.get("exit_status") == 0 for command in commands),
         f"producer command statuses are incomplete or nonzero: {package_id}")
    routing = json.loads(routing_path.read_text())
    decisions = routing.get("decisions")
    need(isinstance(decisions, list) and len(decisions) == want_profile["files"] and
         routing.get("input_count") == want_profile["files"] and
         routing.get("duplicate_input_count") == 0,
         f"routing identity count mismatch: {package_id}")
    observed_routes = Counter()
    for decision in decisions:
        name = decision.get("installed_path")
        need(name in expected and decision.get("path") is not None,
             f"unexpected routed package path: {package_id}/{name}")
        need(decision["path"] == str(stage_root / name),
             f"routing decision resolved to a different staged file: {package_id}/{name}")
        for key, value in expected[name]["route"].items():
            need(decision.get(key) == value, f"route decision differs from oracle: {package_id}/{name}")
        observed_routes[name] += 1
    need(observed_routes == Counter(expected.keys()), f"routing multiset differs from oracle: {package_id}")
    return {"package_id": package_id, "coverage_manifest_sha256": sha_file(coverage_path),
            "producer_receipt_sha256": sha_file(receipt_path),
            "routing_sha256": sha_file(routing_path), "sarif_sha256": sha_file(sarif_path),
            "file_count": len(files), "successful_file_count": success_total,
            "route_counts": dict(route_counts), "sarif_result_count": sarif_summary["result_count"]}


def run_package_lane(r3_root: Path, run_id: str,
                     release_lock_path: Path, package_lock_path: Path, *,
                     profile_set: str = "historical", after_stage=None) -> dict:
    release_lock = json.loads(release_lock_path.read_text())
    validate_release_lock(release_lock)
    consumer_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    consumer_dirty = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).strip()
    need(HEX40.fullmatch(consumer_sha) is not None and not consumer_dirty,
         "consumer source checkout must be clean for released package handoff")
    package_lock, package_lock_raw = _load_lock(package_lock_path, profile_set=profile_set)
    oracle_data = {}
    for package_id, profile in package_lock["packages"].items():
        oracle_path = ROOT / profile["oracle"]["path"]
        raw_oracle = oracle_path.read_bytes()
        oracle_data[package_id], _ = validate_oracle(
            raw_oracle, profile["oracle"]["sha256"], profile)
    r3_root = require_real_dir(r3_root)
    bundle, codeql, codeql_archive = verify_bundle_inputs(r3_root, release_lock, package_lock)
    root = make_new_dir(r3_root / "r25-package", r3_root)
    for name in ("incoming", "stages", "stage-receipts", "producer-runs", "commands"):
        (root / name).mkdir(mode=0o700)
    records: list[dict] = []
    input_repo = package_lock["artifact_repository"]
    summaries = {}
    for package_id, profile in package_lock["packages"].items():
        ipk_path, artifact_archive = download_pinned_artifact(
            input_repo, package_id, profile, root / "incoming", root / "commands", records)
        need(ipk_path.parent == root / "incoming" / package_id,
             f"download path differs from package input root: {package_id}")
        stage = root / "stages" / package_id
        stage_receipt = root / "stage-receipts" / f"{package_id}.json"
        stage_started = time.monotonic()
        try:
            staged = stage_locked_package(package_id, ipk_path, root, stage, stage_receipt,
                                          lock_path=package_lock_path, profile_set=profile_set)
        except Exception as error:
            records.append({"label": f"{package_id}-consumer-stage", "exit_status": 1,
                            "elapsed_seconds": round(time.monotonic() - stage_started, 3),
                            "operation": "tools.r25_package_stage.stage_locked_package",
                            "error": str(error)})
            write_json(root / "commands.json", records)
            raise
        records.append({"label": f"{package_id}-consumer-stage", "exit_status": 0,
                        "elapsed_seconds": round(time.monotonic() - stage_started, 3),
                        "operation": "tools.r25_package_stage.stage_locked_package",
                        "stage_receipt_sha256": sha_file(stage_receipt)})
        write_json(root / "commands.json", records)
        if after_stage is not None:
            preserve_started = time.monotonic()
            try:
                after_stage(package_id, stage, stage_receipt, staged)
            except Exception as error:
                records.append({"label": f"{package_id}-stage-preservation", "exit_status": 1,
                                "elapsed_seconds": round(time.monotonic() - preserve_started, 3),
                                "operation": "current-luci-hidden-stage-preservation",
                                "error": str(error)})
                write_json(root / "commands.json", records)
                raise
            records.append({"label": f"{package_id}-stage-preservation", "exit_status": 0,
                            "elapsed_seconds": round(time.monotonic() - preserve_started, 3),
                            "operation": "current-luci-hidden-stage-preservation"})
            write_json(root / "commands.json", records)
        oracle_path = ROOT / profile["oracle"]["path"]
        output = root / "producer-runs" / package_id
        command = [sys.executable, "-B", bundle / "runner/run-installed-stage.py",
                   "--bundle", bundle,
                   "--bundle-sha256", release_lock["release"]["manifest_sha256"],
                   "--codeql", codeql, "--codeql-archive", codeql_archive,
                   "--stage", stage, "--oracle", oracle_path, "--output", output]
        clean_env = clean_environment()
        time_report = root / "commands" / f"{package_id}-producer.time"
        if Path("/usr/bin/time").is_file():
            wrapped = ["/usr/bin/time", "-v", "-o", str(time_report), *map(str, command)]
        else:
            wrapped = list(map(str, command))
        started = time.monotonic()
        result = subprocess.run(wrapped, cwd=ROOT, env=clean_env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        elapsed = round(time.monotonic() - started, 3)
        out_file = root / "commands" / f"{package_id}-producer.stdout"
        err_file = root / "commands" / f"{package_id}-producer.stderr"
        out_file.write_text(result.stdout)
        err_file.write_text(result.stderr)
        runner_record = {"label": f"{package_id}-producer", "argv": list(map(str, command)),
                         "exit_status": result.returncode, "elapsed_seconds": elapsed,
                         "stdout": out_file.relative_to(root).as_posix(),
                         "stderr": err_file.relative_to(root).as_posix(),
                         "peak_rss_kb": None,
                         "time_report": time_report.relative_to(root).as_posix() if time_report.exists() else None}
        if time_report.exists():
            match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)",
                              time_report.read_text(errors="replace"))
            runner_record["peak_rss_kb"] = int(match.group(1)) if match else None
        records.append(runner_record)
        write_json(root / "commands.json", records)
        if result.returncode:
            raise RuntimeError(f"released producer package run failed for {package_id}; see {err_file}")
        verification_started = time.monotonic()
        try:
            summaries[package_id] = verify_coverage(package_id, profile, oracle_data[package_id],
                                                    output, release_lock, profile_set=profile_set)
        except Exception as error:
            records.append({"label": f"{package_id}-consumer-acceptance", "exit_status": 1,
                            "elapsed_seconds": round(time.monotonic() - verification_started, 3),
                            "operation": "tools.r25_package_handoff.verify_coverage",
                            "error": str(error)})
            write_json(root / "commands.json", records)
            raise
        records.append({"label": f"{package_id}-consumer-acceptance", "exit_status": 0,
                        "elapsed_seconds": round(time.monotonic() - verification_started, 3),
                        "operation": "tools.r25_package_handoff.verify_coverage"})
        write_json(root / "commands.json", records)
        summaries[package_id]["stage_receipt_sha256"] = digest(
            stage_receipt.read_bytes())
        summaries[package_id]["ipk_sha256"] = staged["ipk_sha256"]
        summaries[package_id]["artifact_archive"] = artifact_archive

    receipt = {
        "schema": "openwrt-r25-package-handoff-v1",
        "run_id": run_id,
        "consumer_sha": consumer_sha,
        "consumer_dirty": False,
        "producer_release": {"tag": release_lock["release"]["tag"],
                             "commit": release_lock["release"]["commit"],
                             "manifest_sha256": release_lock["release"]["manifest_sha256"]},
        "codeql": {"archive_sha256": release_lock["codeql"]["sha256"],
                   "binary_sha256": release_lock["release"]["codeql_binary_sha256"]},
        "package_lock_sha256": digest(package_lock_raw),
        "packages": summaries,
        "commands": records,
    }
    write_json(root / "receipt.json", receipt)
    write_json(root / "commands.json", records)
    return receipt


def main() -> int:
    if len(sys.argv) != 5:
        raise SystemExit("usage: r25_package_handoff.py RELEASE_LOCK PACKAGE_LOCK EXISTING_R3_RUN_ROOT RUN_ID")
    release_lock_path, package_lock_path = Path(sys.argv[1]), Path(sys.argv[2])
    r3_root = Path(sys.argv[3])
    run_id = sys.argv[4]
    try:
        receipt = run_package_lane(r3_root, run_id, release_lock_path, package_lock_path)
    except Exception as error:
        print(f"R2.5 released package handoff failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
