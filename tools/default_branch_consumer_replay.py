#!/usr/bin/env python3
"""Replay the pinned event-SARIF consumer against a retained final artifact.

This is a read-only offline replay. It checks the final ZIP with the bounded
final-proof reader, binds its nine frozen inputs to the supplied early ZIP,
rederives the selected source bytes/routes from pinned Git objects, materializes
only selected files in private scratch, and invokes the actual
``tools/sarif_accept.py --event-triage`` consumer from the manifest-pinned
consumer revision. Equality reproduces the archived triage packet; it does not
authenticate the hosted run, artifact uploader, a queue action, or completion.
"""
from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from tools import default_branch_final_proof as final_proof
from tools import default_branch_live_observation as live_observation
from tools import default_branch_source_truth as source_truth


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "mvp-default-branch-consumer-replay-v1"
RUN_PREFIX = re.compile(r"default-branch-inputs-([1-9][0-9]*)-([1-9][0-9]*)/\Z")
TUPLE_FIELDS = (
    "rule_id", "uri", "start_line", "start_column", "end_line",
    "end_column", "level",
)
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_PROCESS_OUTPUT = 4 * 1024 * 1024
CONSUMER_TIMEOUT_SECONDS = 60


class ReplayError(ValueError):
    """A supplied artifact, pin, or consumer replay failed its contract."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    """Read a bounded regular file without following a final symlink."""
    try:
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            need(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
            need(before.st_size <= limit, f"{label} exceeds byte limit")
            raw = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
        need(len(raw) <= limit and len(raw) == before.st_size == after.st_size and
             (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and
             before.st_mtime_ns == after.st_mtime_ns,
             f"{label} changed or exceeded byte limit while being read")
        return raw
    except ReplayError:
        raise
    except OSError as exc:
        raise ReplayError(f"cannot read {label}: {exc}") from exc


def _parse_object(raw: bytes, label: str) -> dict[str, Any]:
    need(len(raw) <= MAX_JSON_BYTES, f"{label} exceeds JSON byte limit")
    stack: list[int] = []
    in_string = False
    escaped = False
    pairs = {ord("}"): ord("{"), ord("]"): ord("[")}
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
        elif byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            stack.append(byte)
            need(len(stack) <= MAX_JSON_DEPTH,
                 f"{label} exceeds JSON nesting limit")
        elif byte in pairs:
            need(stack and stack.pop() == pairs[byte],
                 f"{label} has mismatched JSON nesting")
    need(not in_string and not stack, f"{label} has incomplete JSON nesting")
    try:
        return final_proof.parse_object(raw, label)
    except (final_proof.FinalProofError, RecursionError) as exc:
        raise ReplayError(str(exc)) from exc


def _repo_info(root: Path, label: str) -> dict[str, Any]:
    try:
        need(not root.is_symlink(), f"{label} checkout root is a symlink")
        resolved = root.resolve(strict=True)
        need(resolved.is_dir(), f"{label} checkout root is not a directory")
        top = Path(source_truth._git_text(resolved, "rev-parse", "--show-toplevel")).resolve()
        need(top == resolved, f"{label} path is not the checkout root")
        head = source_truth._git_text(resolved, "rev-parse", "--verify", "HEAD^{commit}")
        tree = source_truth._git_text(resolved, "rev-parse", "--verify", "HEAD^{tree}")
    except (source_truth.SourceTruthError, OSError) as exc:
        raise ReplayError(f"cannot inspect {label} checkout: {exc}") from exc
    return {
        "path": str(resolved), "head": head, "tree": tree,
        "dirty_state": "not_checked_by_object_only_replay",
    }


def _derive_run_identity(final_names: set[str]) -> tuple[int, int]:
    identities: set[tuple[int, int]] = set()
    for name in final_names:
        first, sep, rest = name.partition("/")
        if not sep:
            continue
        match = RUN_PREFIX.fullmatch(first + "/")
        if match:
            identities.add((int(match.group(1)), int(match.group(2))))
    need(len(identities) == 1, "final artifact does not name exactly one run/attempt")
    run_id, attempt = next(iter(identities))
    need(run_id <= 2**63 - 1 and attempt <= 2**31 - 1,
         "final artifact run/attempt exceeds supported range")
    return run_id, attempt


def _early_inputs(raw: bytes, run_id: int, attempt: int,
                  consumer_commit: str) -> dict[str, bytes]:
    try:
        members = final_proof._read_zip(raw, "early artifact")
    except final_proof.FinalProofError as exc:
        raise ReplayError(str(exc)) from exc
    expected = set(final_proof.FROZEN_INPUTS) | {"receipt.json"}
    need(set(members) == expected,
         "early ZIP does not contain exactly the nine frozen inputs and receipt")
    try:
        live_observation._verify_receipt_files(
            members, run_id, attempt, {"consumer_commit": consumer_commit})
    except (live_observation.LiveObservationError, KeyError, TypeError,
            ValueError, RecursionError) as exc:
        raise ReplayError(f"early frozen-input receipt failed: {exc}") from exc
    return members


def _validate_installed_path(value: Any) -> str:
    need(isinstance(value, str) and value and "\x00" not in value and
         "\\" not in value and not value.startswith("/"),
         "selected installed path is unsafe")
    parts = value.split("/")
    need(all(part not in ("", ".", "..") for part in parts) and
         str(PurePosixPath(value)) == value,
         "selected installed path is noncanonical")
    return value


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _write_exclusive(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    """Create a new regular file in run-owned scratch; never replace a path."""
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _new_output_path(path: Path, input_roots: list[Path]) -> Path:
    need(path.name not in ("", ".", ".."), "output path has no filename")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReplayError(f"output parent is unavailable: {exc}") from exc
    need(parent.is_dir() and not parent.is_symlink(),
         "output parent is not a real directory")
    target = parent / path.name
    need(not target.exists() and not target.is_symlink(),
         "output path already exists")
    for input_root in input_roots:
        root = input_root.resolve(strict=True)
        need(not target.is_relative_to(root),
             "output path must be outside every input checkout")
    return target


def _write_scratch_tree(root: Path, relative: str, data: bytes) -> Path:
    safe = _validate_installed_path(relative)
    current = root
    for part in safe.split("/")[:-1]:
        current = current / part
        if current.exists():
            need(current.is_dir() and not current.is_symlink(),
                 "scratch path component is not a real directory")
        else:
            _mkdir_private(current)
    target = current / safe.split("/")[-1]
    _write_exclusive(target, data)
    return target


def _materialize_selected_sources(manifest: dict[str, Any],
                                  checkouts: dict[str, Path],
                                  stage_root: Path) -> dict[str, str]:
    selected = manifest.get("selected")
    pins = manifest.get("pins")
    need(type(selected) is list and selected and type(pins) is dict,
         "source manifest selection or pin map is malformed")
    seen_installed: set[str] = set()
    source_hashes: dict[str, str] = {}
    by_repo: dict[str, list[dict[str, Any]]] = {name: [] for name in source_truth.REPOSITORIES}
    for row in selected:
        need(type(row) is dict and row.get("repo") in by_repo,
             "selected source row has an unknown repository")
        by_repo[row["repo"]].append(row)

    for repo, rows in by_repo.items():
        paths = [source_truth._validate_source_path(row.get("source_path")) for row in rows]
        try:
            entries = source_truth._tree_entries(checkouts[repo], pins[repo], paths)
            blobs = source_truth._read_blobs(
                checkouts[repo], [entries[path]["git_blob"] for path in paths])
        except (source_truth.SourceTruthError, KeyError, TypeError) as exc:
            raise ReplayError(f"cannot materialize pinned {repo} source bytes: {exc}") from exc
        for row in rows:
            source_path = row["source_path"]
            entry = entries[source_path]
            installed = _validate_installed_path(row.get("proposed_installed_path"))
            need(installed not in seen_installed,
                 f"duplicate selected installed path: {installed}")
            seen_installed.add(installed)
            need(entry.get("mode") in ("100644", "100755") and
                 entry.get("git_blob") == row.get("git_blob"),
                 f"pinned Git tree identity differs: {repo}:{source_path}")
            data = blobs[entry["git_blob"]]
            sha = digest(data)
            need(sha == row.get("source_sha256"),
                 f"pinned source SHA-256 differs: {repo}:{source_path}")
            _write_scratch_tree(stage_root, installed, data)
            source_hashes[installed] = sha
    need(len(source_hashes) == len(selected),
         "selected source materialization multiplicity differs")
    return dict(sorted(source_hashes.items()))


def _drain_bounded(stream, output: bytearray, cap: int,
                   overflow: list[str], label: str,
                   process: subprocess.Popen) -> None:
    while True:
        block = stream.read(64 * 1024)
        if not block:
            return
        if len(output) + len(block) > cap:
            overflow.append(label)
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                pass
            return
        output.extend(block)


def _invoke_consumer(consumer_script: Path, scratch: Path,
                     *, run_id: int, attempt: int) -> dict[str, Any]:
    payload = scratch / "payload"
    out = payload / "out"
    stage = payload / "stage"
    for path in (payload, out, stage, scratch / "home", scratch / "tmp"):
        need(path.is_dir() and not path.is_symlink(),
             "consumer replay scratch directory is missing or aliased")
    command = [
        sys.executable, "-I", "-S", "-B", str(consumer_script),
        "--sarif", str(out / "default-suite.sarif"),
        "--manifest", str(out / "event-triage-input.json"),
        "--receipt", str(out / "producer-receipt.json"),
        "--source-root", str(stage), "--event-triage",
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(scratch / "home"), "TMPDIR": str(scratch / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        "LC_ALL": "C", "LANG": "C",
    }
    stdout_buf, stderr_buf = bytearray(), bytearray()
    overflow: list[str] = []
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            command, cwd=str(scratch), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=(os.name != "nt"),
        )
    except OSError as exc:
        raise ReplayError(f"cannot start pinned SARIF consumer: {exc}") from exc
    assert proc.stdout is not None and proc.stderr is not None
    stdout_thread = threading.Thread(
        target=_drain_bounded,
        args=(proc.stdout, stdout_buf, MAX_PROCESS_OUTPUT, overflow, "stdout", proc),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_drain_bounded,
        args=(proc.stderr, stderr_buf, MAX_PROCESS_OUTPUT, overflow, "stderr", proc),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        returncode = proc.wait(timeout=CONSUMER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        if os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
        else:
            proc.kill()
        proc.wait()
        raise ReplayError("pinned SARIF consumer exceeded the time limit") from exc
    finally:
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        proc.stdout.close()
        proc.stderr.close()
    wall_seconds = time.monotonic() - started
    need(not overflow, "pinned SARIF consumer output exceeded byte limit")
    return {
        "argv": command, "cwd": str(scratch), "exit": returncode,
        "wall_seconds": round(wall_seconds, 6),
        "python_version": sys.version,
        "environment": {
            "HOME": env["HOME"], "TMPDIR": env["TMPDIR"],
            "PYTHONNOUSERSITE": env["PYTHONNOUSERSITE"],
            "PYTHONDONTWRITEBYTECODE": env["PYTHONDONTWRITEBYTECODE"],
        },
        "stdout": bytes(stdout_buf), "stderr": bytes(stderr_buf),
        "run_id": run_id, "attempt": attempt,
    }


def _tuple_counter(packet: dict[str, Any], label: str) -> Counter:
    rows = packet.get("results_for_triage")
    need(type(rows) is list, f"{label} triage rows are malformed")
    tuples = []
    for row in rows:
        need(type(row) is dict and set(row) == set(TUPLE_FIELDS),
             f"{label} triage tuple shape differs")
        need(all(type(row.get(key)) is int and row[key] >= 1 for key in (
            "start_line", "start_column", "end_line", "end_column")) and
             all(type(row.get(key)) is str and row[key] for key in (
                 "rule_id", "uri", "level")),
             f"{label} triage tuple field type differs")
        tuples.append(tuple(row[key] for key in TUPLE_FIELDS))
    need(type(packet.get("result_count")) is int and
         packet["result_count"] == len(tuples),
         f"{label} triage result count differs from tuple multiplicity")
    expected_status = "triage_required" if tuples else "clean_scan"
    need(packet.get("status") == expected_status,
         f"{label} triage status differs from result multiplicity")
    return Counter(tuples)


def _assert_output_equal(actual_raw: bytes, hosted_raw: bytes,
                         sarif_raw: bytes, triage_input: dict[str, Any],
                         expected_paths: Counter, run_token: str) -> dict[str, Any]:
    need(actual_raw == hosted_raw,
         "replayed consumer stdout bytes differ from hosted triage bytes")
    actual = _parse_object(actual_raw, "replayed consumer output")
    hosted = _parse_object(hosted_raw, "archived hosted triage output")
    try:
        final_proof._verify_consumer_results(
            sarif_raw, hosted, triage_input, expected_paths, run_token)
    except final_proof.FinalProofError as exc:
        raise ReplayError(f"archived hosted output/SARIF contract failed: {exc}") from exc
    actual_tuples = _tuple_counter(actual, "replayed")
    hosted_tuples = _tuple_counter(hosted, "hosted")
    need(actual == hosted, "replayed consumer JSON differs from hosted triage output")
    need(actual_tuples == hosted_tuples,
         "replayed consumer tuple multiplicity differs from hosted triage output")
    need(actual.get("status") == hosted.get("status") and
         actual.get("result_count") == hosted.get("result_count"),
         "replayed consumer status or result count differs from hosted triage output")
    return {
        "status": actual["status"], "result_count": actual["result_count"],
        "tuple_rows": len(actual.get("results_for_triage", [])),
        "tuple_unique": len(actual_tuples),
        "tuple_multiplicity": [
            {"tuple": list(row), "count": count}
            for row, count in sorted(hosted_tuples.items())
        ],
    }


def _validate_consumer_checkout(consumer_root: Path, expected_commit: str,
                                implementation_root: Path) -> dict[str, Any]:
    need(source_truth.HEX40.fullmatch(expected_commit) is not None,
         "manifest-pinned consumer commit is malformed")
    actual = _repo_info(consumer_root, "consumer")
    need(actual["head"] == expected_commit,
         "consumer checkout HEAD differs from frozen manifest consumer commit")
    identities = {}
    blobs = {}
    for relative in ("tools/sarif_accept.py", "docs/current-corpus-source-v0.6.json"):
        try:
            local = source_truth._git(consumer_root, "show", f"{expected_commit}:{relative}")
            pinned = source_truth._git(implementation_root, "show", f"HEAD:{relative}")
        except (ReplayError, source_truth.SourceTruthError) as exc:
            raise ReplayError(f"cannot read pinned consumer/policy bytes: {exc}") from exc
        need(local == pinned,
             f"manifest-pinned consumer file differs from implementation base: {relative}")
        identities[relative] = digest(local)
        blobs[relative] = local
    return {**actual, "files": identities, "blobs": blobs}


def replay(final_zip_path: Path, early_zip_path: Path,
           checkout_roots: dict[str, Path], consumer_root: Path,
           work_root: Path, *, expected_consumer_base: str | None = None) -> dict[str, Any]:
    """Replay the actual pinned consumer using exact supplied artifact bytes."""
    total_started = time.monotonic()
    need(set(checkout_roots) == set(source_truth.REPOSITORIES),
         "exactly the pinned luci/openwrt/packages source checkouts are required")
    need(not work_root.is_symlink(), "run work root is a symlink")
    work_root = work_root.resolve(strict=True)
    need(work_root.is_dir(), "run work root is not a directory")
    artifact_started = time.monotonic()
    final_raw = _read_regular(final_zip_path, final_proof.MAX_INPUT, "final ZIP")
    early_raw = _read_regular(early_zip_path, final_proof.MAX_INPUT, "early ZIP")
    try:
        raw_names = set(final_proof._raw_zip_names(final_raw, "final artifact"))
        run_id, attempt = _derive_run_identity(raw_names)
        inputs, r3 = final_proof._final_members(final_raw, run_id, attempt)
    except final_proof.FinalProofError as exc:
        raise ReplayError(f"final artifact ZIP failed: {exc}") from exc

    for name in sorted(final_proof.FROZEN_INPUTS):
        _parse_object(inputs[name], "frozen input " + name)
    manifest = _parse_object(inputs["manifest.json"], "source-first manifest")
    event = manifest.get("event")
    need(type(event) is dict and isinstance(event.get("consumer_commit"), str),
         "source manifest lacks consumer commit identity")
    need(event.get("candidate_inventory_sha256") == digest(inputs["inventory.json"]),
         "frozen candidate inventory digest differs from source manifest")
    consumer_root = consumer_root.resolve(strict=True)
    consumer_info = _validate_consumer_checkout(consumer_root, event["consumer_commit"], ROOT)
    if expected_consumer_base is not None:
        need(_repo_info(ROOT, "implementation")["head"] ==
             expected_consumer_base,
             "implementation checkout HEAD differs from requested base")

    early_members = _early_inputs(early_raw, run_id, attempt, event["consumer_commit"])
    try:
        final_proof._compare_frozen_inputs(inputs, early_members)
    except final_proof.FinalProofError as exc:
        raise ReplayError(f"early/final frozen input comparison failed: {exc}") from exc

    corpus = "default-branch-corpus/"
    required = {
        corpus + "validated-default-branch-manifest.json",
        corpus + "out/coverage-default-branch.json",
        corpus + "out/default-suite.sarif", corpus + "out/event-triage-input.json",
        corpus + "out/producer-receipt.json", corpus + "out/routing.json",
        corpus + "out/triage.json", corpus + "receipt.json",
        corpus + "commands.json",
    }
    need(required <= set(r3), "final R3 artifact lacks consumer replay members")
    try:
        command_rows = final_proof._verify_final_inventory(r3, manifest)
        final_proof._verify_command_receipt(command_rows, r3, manifest, run_id, attempt)
    except final_proof.FinalProofError as exc:
        raise ReplayError(f"final R3 inventory/command receipt failed: {exc}") from exc
    manifest_raw = inputs["manifest.json"]
    need(r3[corpus + "validated-default-branch-manifest.json"] == manifest_raw,
         "validated R3 manifest differs from frozen source manifest")

    coverage_raw = r3[corpus + "out/coverage-default-branch.json"]
    routing_raw = r3[corpus + "out/routing.json"]
    sarif_raw = r3[corpus + "out/default-suite.sarif"]
    triage_input_raw = r3[corpus + "out/event-triage-input.json"]
    producer_raw = r3[corpus + "out/producer-receipt.json"]
    hosted_raw = r3[corpus + "out/triage.json"]
    corpus_receipt_raw = r3[corpus + "receipt.json"]
    coverage = _parse_object(coverage_raw, "coverage receipt")
    routing = _parse_object(routing_raw, "route receipt")
    triage_input = _parse_object(triage_input_raw, "consumer triage input")
    producer = _parse_object(producer_raw, "producer receipt")
    hosted = _parse_object(hosted_raw, "hosted triage output")
    corpus_receipt = _parse_object(corpus_receipt_raw, "corpus receipt")
    _parse_object(sarif_raw, "SARIF")
    run_token = f"{run_id}-{attempt}"
    need(producer.get("run_id") == run_token and hosted.get("run_id") == run_token and
         corpus_receipt.get("run_id") == run_token,
         "producer, hosted triage, or corpus receipt run identity differs")
    need(corpus_receipt.get("sarif_sha256") == digest(sarif_raw) and
         corpus_receipt.get("accepted_sha256") == digest(hosted_raw) and
         corpus_receipt.get("status") == hosted.get("status") and
         corpus_receipt.get("consumer_sha") == event["consumer_commit"],
         "corpus receipt digest or status differs from archived consumer outputs")
    need(producer.get("consumer_sha") == event["consumer_commit"] and
         producer.get("route_sha256") == digest(routing_raw) and
         producer.get("sarif_sha256") == digest(sarif_raw),
         "producer receipt consumer/route/SARIF identity differs")
    artifact_validation_seconds = time.monotonic() - artifact_started

    root_info = {}
    roots: dict[str, Path] = {}
    for repo in source_truth.REPOSITORIES:
        supplied = checkout_roots[repo]
        info = _repo_info(supplied, repo)
        need(info["head"] == manifest.get("pins", {}).get(repo),
             f"{repo} checkout HEAD differs from frozen source pin")
        root_info[repo] = info
        roots[repo] = Path(info["path"])

    input_roots = [ROOT.resolve(), consumer_root, *roots.values()]
    for input_root in input_roots:
        need(not work_root.is_relative_to(input_root) and
             not input_root.is_relative_to(work_root),
             "run work root must be disjoint from all input checkouts")

    run_dir = Path(tempfile.mkdtemp(prefix=f"consumer-replay-{run_token}-", dir=work_root))
    run_dir.chmod(0o700)
    scratch = run_dir / "scratch"
    _mkdir_private(scratch)
    home = scratch / "home"
    tmp = scratch / "tmp"
    payload = scratch / "payload"
    out = payload / "out"
    stage = payload / "stage"
    for path in (home, tmp, payload, out, stage):
        _mkdir_private(path)
    payload_files = {
        "default-suite.sarif": sarif_raw,
        "event-triage-input.json": triage_input_raw,
        "producer-receipt.json": producer_raw,
        "manifest.json": manifest_raw,
        "coverage.json": coverage_raw,
        "routing.json": routing_raw,
    }
    for name, raw in payload_files.items():
        _write_exclusive(out / name, raw)

    consumer_script = scratch / "consumer" / "tools" / "sarif_accept.py"
    _mkdir_private(scratch / "consumer")
    _mkdir_private(scratch / "consumer" / "tools")
    _write_exclusive(consumer_script, consumer_info["blobs"]["tools/sarif_accept.py"])

    source_truth_started = time.monotonic()
    try:
        source_result = source_truth.verify(
            out / "manifest.json", out / "coverage.json", out / "routing.json", roots)
    except (source_truth.SourceTruthError, OSError, ValueError, TypeError,
            KeyError, RecursionError) as exc:
        raise ReplayError(f"bounded source/policy verification failed: {exc}") from exc
    # Exit 3 from the source verifier represents source-signal candidates
    # outside this frozen denominator. Its selected/excluded byte and route
    # checks remain useful; preserve that partial boundary in the receipt.
    source_status = ("partial_outside_frozen_denominator"
                     if not source_result.get("tracked_candidate_signals_accounted_for")
                     else "bounded_selected_excluded_match")
    source_truth_seconds = time.monotonic() - source_truth_started
    materialize_started = time.monotonic()
    source_hashes = _materialize_selected_sources(manifest, roots, stage)
    source_materialization_seconds = time.monotonic() - materialize_started

    # Keep a copy of the hosted output beside the exact consumer inputs for
    # human-readable inspection. It is not passed as a consumer input.
    _write_exclusive(out / "hosted-triage.json", hosted_raw)
    invocation = _invoke_consumer(
        consumer_script, scratch, run_id=run_id, attempt=attempt)
    stdout = invocation.pop("stdout")
    stderr = invocation.pop("stderr")
    _write_exclusive(run_dir / "consumer.stdout.json", stdout)
    _write_exclusive(run_dir / "consumer.stderr.txt", stderr)
    need(invocation["exit"] == 0,
         f"actual sarif_accept.py exited {invocation['exit']}: " +
         stderr.decode("utf-8", "replace")[:500])
    expected_paths = Counter(row["proposed_installed_path"] for row in manifest["selected"])
    comparison = _assert_output_equal(
        stdout, hosted_raw, sarif_raw, triage_input, expected_paths, run_token)
    consumer_tool_sha = consumer_info["files"]["tools/sarif_accept.py"]
    policy_sha = consumer_info["files"]["docs/current-corpus-source-v0.6.json"]
    need(policy_sha == source_result["frozen_policy_sha256"],
         "consumer policy bytes differ from source verifier's exact pinned policy")
    return {
        "schema": SCHEMA,
        "status": "replayed_hosted_triage_equal",
        "scope": "offline replay of supplied retained bytes; not authenticated execution or completion",
        "run_id": run_id, "attempt": attempt,
        "final_zip": {"bytes": len(final_raw), "sha256": digest(final_raw)},
        "early_zip": {"bytes": len(early_raw), "sha256": digest(early_raw)},
        "frozen_input_count": len(final_proof.FROZEN_INPUTS),
        "frozen_inputs_byte_equal_early_final": True,
        "frozen_inputs": {
            name: {"bytes": len(inputs[name]), "sha256": digest(inputs[name])}
            for name in sorted(final_proof.FROZEN_INPUTS)
        },
        "consumer": {
            "commit": consumer_info["head"], "tree": consumer_info["tree"],
            "dirty_state": consumer_info["dirty_state"],
            "sarif_accept_sha256": consumer_tool_sha,
            "policy_sha256": policy_sha,
        },
        "implementation": _repo_info(ROOT, "implementation"),
        "source_checkouts": root_info,
        "source_truth": {
            "status": source_status,
            "source_verifier_status": source_result["status"],
            "selected_and_excluded_git_bytes_rederived": source_result[
                "selected_and_excluded_git_bytes_rederived"],
            "source_route_recomputed_from_git_blob_bytes": source_result[
                "source_route_recomputed_from_git_blob_bytes"],
            "frozen_policy_sha256": source_result["frozen_policy_sha256"],
            "canonical_git_provenance_verified": False,
            "source_candidates_outside_frozen_denominator": source_result[
                "source_candidates_outside_frozen_denominator"],
        },
        "selected_source_stage": {
            "count": len(source_hashes), "installed_path_sha256": source_hashes,
        },
        "command": {
            "argv": invocation["argv"], "cwd": invocation["cwd"],
            "exit": invocation["exit"], "wall_seconds": invocation["wall_seconds"],
            "python_version": invocation["python_version"],
            "environment": invocation["environment"],
            "isolated_flags": ["-I", "-S", "-B"],
            "stdout_sha256": digest(stdout), "stdout_bytes": len(stdout),
            "stderr_sha256": digest(stderr), "stderr_bytes": len(stderr),
            "timeout_seconds": CONSUMER_TIMEOUT_SECONDS,
        },
        "hosted_output": {
            "sha256": digest(hosted_raw), "bytes": len(hosted_raw),
        },
        "replayed_output": {
            "sha256": digest(stdout), "bytes": len(stdout),
        },
        "comparison": comparison,
        "phase_times_seconds": {
            "artifact_and_input_validation": round(artifact_validation_seconds, 6),
            "source_truth": round(source_truth_seconds, 6),
            "selected_source_materialization": round(source_materialization_seconds, 6),
            "actual_consumer": invocation["wall_seconds"],
            "total": round(time.monotonic() - total_started, 6),
        },
        "scratch_path": str(run_dir),
        "limitations": [
            "The replay verifies supplied ZIP bytes and pinned Git objects; it does not authenticate GitHub API capture or the artifact uploader.",
            "The consumer output equality proves reproducibility for these supplied bytes, not that the hosted command executed or was fresh.",
            "The source checkout roots are supplied local repositories; canonical Git provenance is not verified by this replay.",
            "A partial outside-denominator source census remains partial even when selected bytes/routes and consumer output match.",
            "No key, queue, network, database, CodeQL query, package installation, or completion issuer is used.",
        ],
    }


def _write_receipt(path: Path, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(path, raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-zip", type=Path, required=True)
    parser.add_argument("--early-zip", type=Path, required=True)
    parser.add_argument("--consumer-checkout", type=Path, required=True)
    parser.add_argument("--luci-checkout", type=Path, required=True)
    parser.add_argument("--openwrt-checkout", type=Path, required=True)
    parser.add_argument("--packages-checkout", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-consumer-base", required=False)
    args = parser.parse_args(argv)
    roots = {
        "luci": args.luci_checkout,
        "openwrt": args.openwrt_checkout,
        "packages": args.packages_checkout,
    }
    try:
        output_path = _new_output_path(args.output, [
            ROOT, args.consumer_checkout, *roots.values(),
        ])
        result = replay(
            args.final_zip, args.early_zip, roots, args.consumer_checkout,
            args.work_root, expected_consumer_base=args.expected_consumer_base,
        )
        _write_receipt(output_path, result)
    except (ReplayError, final_proof.FinalProofError, OSError, ValueError,
            TypeError, KeyError, RecursionError) as exc:
        print("default-branch consumer replay rejected: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"], "run_id": result["run_id"],
        "attempt": result["attempt"], "triage_status": result["comparison"]["status"],
        "result_count": result["comparison"]["result_count"],
        "source_truth_status": result["source_truth"]["status"],
        "receipt": str(output_path),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
