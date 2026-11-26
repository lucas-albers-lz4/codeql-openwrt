#!/usr/bin/env python3
"""Acquire fixed canonical source pins and run the default-branch source oracle.

This is a local, bounded preflight for an isolated codeql-openwrt checkout
inside the ledger's ignored work/ directory. It does not authenticate a scan,
start, queue action, issuer, installed package, or runtime result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from math import ceil
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from tools import event_corpus_manifest as route_oracle
from tools import full_tree_candidates as selector


ROOT = Path(__file__).resolve().parents[1]
POLICY_RELATIVE = Path("docs/current-corpus-source-v0.6.json")
POLICY_SHA256 = "9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490"
SOURCE_TRUTH_SHA256 = "345a6acae3e6b9c01c45622a43bd8edba13f3f345f56f9e2af18efe90ef8c74b"
POLICY_BASE_COMMIT = "bce40f6a15c273778061e8fceced7b9e0f58d99b"
POLICY_BASE_TREE = "aad77be60ad2931cfc99f6eb49afd7d72843325e"
REPOSITORY_URLS = {
    "luci": "https://github.com/openwrt/luci.git",
    "openwrt": "https://github.com/openwrt/openwrt.git",
    "packages": "https://github.com/openwrt/packages.git",
}
APPROVED_FALLBACK_REFS = {
    "luci": "refs/heads/master",
    "openwrt": "refs/heads/main",
    "packages": "refs/heads/master",
}
API_ROOT = "https://api.github.com/repos/openwrt/openwrt"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
RUN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
MAX_INPUT_JSON_BYTES = 8 * 1024 * 1024
MAX_API_COMMIT_BYTES = 1024 * 1024
MAX_API_TREE_BYTES = 32 * 1024 * 1024
MAX_API_TREE_ENTRIES = 100_000
MAX_CAPTURE_BYTES = 256 * 1024
MAX_GIT_FILE_BYTES = 1_500_000_000
MAX_REPO_OBJECT_BYTES = 1_500_000_000
MAX_TOTAL_OBJECT_BYTES = 4_000_000_000
MAX_REPO_WORKTREE_BYTES = 2_000_000_000
MAX_TOTAL_WORKTREE_BYTES = 4_000_000_000
MAX_TREE_LIST_BYTES = 64 * 1024 * 1024
MAX_FALLBACK_DEPTH = 2048
MAX_FETCH_SECONDS = 600
MAX_COMMAND_SECONDS = 45
MAX_ORACLE_SECONDS = 600
MAX_TOTAL_SECONDS = 2400
MIN_FREE_DISK_BYTES = 12_000_000_000
BASE_COMMIT = "8ae2fb4bae82eb770287ed388235b96dd04e0454"
BASE_REMOTE = "https://github.com/lucas-albers-lz4/codeql-openwrt.git"
EXIT_REJECTED = 2
EXIT_SOURCE_PARTIAL = 3
EXIT_POLICY_BASE_UNRESOLVED = 4


class PreflightError(ValueError):
    """A pin, input, boundary, or observed command failed validation."""


_ACTIVE_DEADLINE: float | None = None
_COMMAND_LOG: list[dict[str, Any]] = []
_API_REQUEST_LOG: list[dict[str, Any]] = []
_ACTIVE_RUN_ROOT: Path | None = None
_API_AUTH_SOURCE: str | None = None


def _effective_timeout(requested: int) -> int:
    if _ACTIVE_DEADLINE is None:
        return requested
    remaining = _ACTIVE_DEADLINE - time.monotonic()
    if remaining <= 0:
        raise PreflightError("total preflight time budget exceeded")
    return min(requested, max(1, ceil(remaining)))


class NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so an API bearer token is never sent to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str, limit: int = MAX_INPUT_JSON_BYTES
               ) -> tuple[bytes, dict[str, Any]]:
    try:
        if path.is_symlink():
            raise PreflightError(f"{label} input is a symlink")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise PreflightError(f"{label} input is not a regular file")
            if info.st_size > limit:
                raise PreflightError(f"{label} input exceeds {limit} bytes")
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise PreflightError(f"{label} input exceeds {limit} bytes")
        parsed = json.loads(raw, object_pairs_hook=_unique_object)
    except PreflightError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreflightError(f"cannot read {label} JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PreflightError(f"{label} JSON must be an object")
    return raw, parsed


def _sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX40.fullmatch(value):
        raise PreflightError(f"invalid {label}; expected a full lowercase Git SHA-1")
    return value


def derive_pins(policy: dict[str, Any], manifest: dict[str, Any]
                ) -> tuple[dict[str, str], dict[str, str]]:
    """Validate the frozen policy/event relation and return source/control pins."""
    if policy.get("schema") != "mvp-bounded-corpus-v0.6":
        raise PreflightError("unsupported frozen corpus policy")
    policy_pins = policy.get("pins")
    manifest_pins = manifest.get("pins")
    repositories = set(REPOSITORY_URLS)
    if not isinstance(policy_pins, dict) or set(policy_pins) != repositories:
        raise PreflightError("frozen policy must pin exactly luci/openwrt/packages")
    if not isinstance(manifest_pins, dict) or set(manifest_pins) != repositories:
        raise PreflightError("manifest must pin exactly luci/openwrt/packages")
    frozen = {repo: _sha40(policy_pins[repo], f"policy {repo} pin")
              for repo in sorted(repositories)}
    event = manifest.get("event")
    if not isinstance(event, dict):
        raise PreflightError("manifest event identity is missing")
    event_repo = event.get("repository")
    if event_repo != "openwrt":
        raise PreflightError("this bounded completion preflight requires an OpenWrt event")
    event_head = _sha40(event.get("head_commit"), "event head commit")
    event_tree = _sha40(event.get("head_tree"), "event head tree")
    first_parent = _sha40(event.get("first_parent_commit"), "event first parent")
    base_commit = _sha40(event.get("base_commit"), "event base commit")
    base_tree = _sha40(event.get("base_tree"), "event base tree")
    control_commit = _sha40(event.get("control_commit"), "event control commit")
    policy_base = _sha40(event.get("policy_base_commit"), "event policy base commit")
    if manifest.get("schema") != "mvp-default-branch-commit-corpus-v1":
        raise PreflightError("unsupported default-branch manifest schema")
    if event.get("kind") != "default_branch_commit" or event.get("source_role") != \
            "incoming_default_branch_first_parent":
        raise PreflightError("manifest is not a first-parent default-branch event")
    if base_commit != first_parent:
        raise PreflightError("event base differs from its first parent")
    if control_commit == event_head:
        raise PreflightError("event control must be distinct from the source commit")
    if policy_base != frozen[event_repo]:
        raise PreflightError("event policy base differs from the frozen policy")
    expected = dict(frozen)
    expected[event_repo] = event_head
    actual = {repo: _sha40(manifest_pins[repo], f"manifest {repo} pin")
              for repo in sorted(repositories)}
    if actual != expected:
        raise PreflightError("manifest source pins differ from frozen policy plus event head")
    if event.get("base_tree") != base_tree or event.get("head_tree") != event_tree:
        raise PreflightError("event tree identity is malformed")
    if event.get("route_oracle_script_sha256") != hashlib.sha256(
            Path(route_oracle.__file__).read_bytes()).hexdigest():
        raise PreflightError("route oracle script digest differs from the manifest")
    if event.get("selector_script_sha256") != hashlib.sha256(
            Path(selector.__file__).read_bytes()).hexdigest():
        raise PreflightError("selector script digest differs from the manifest")
    if event.get("policy_sha256") != POLICY_SHA256:
        raise PreflightError("manifest does not bind the frozen v0.6 policy digest")
    controls = {"event_base": base_commit, "event_control": control_commit}
    return expected, controls


def _checked_tree_document(document: dict[str, Any], expected_tree: str
                           ) -> tuple[dict[str, tuple[str, str, str]], int]:
    """Check a recursive Git Trees API body and reconstruct each Git tree OID."""
    if document.get("sha") != expected_tree or document.get("truncated") is not False:
        raise PreflightError("Git Trees API SHA differs or response is truncated")
    rows = document.get("tree")
    if not isinstance(rows, list) or len(rows) > MAX_API_TREE_ENTRIES:
        raise PreflightError("Git Trees API entry list is missing or too large")
    by_parent: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    paths: dict[str, tuple[str, str, str]] = {}
    tree_oids: dict[str, str] = {"": expected_tree}
    seen_paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise PreflightError("Git Trees API entry is malformed")
        path = row.get("path")
        if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
            raise PreflightError("Git Trees API path is invalid")
        parts = path.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise PreflightError("Git Trees API path is unsafe")
        oid = row.get("sha")
        kind = row.get("type")
        mode = row.get("mode")
        if not isinstance(oid, str) or not HEX40.fullmatch(oid):
            raise PreflightError("Git Trees API object ID is invalid")
        valid_mode_types = {"040000": "tree", "100644": "blob", "100755": "blob",
                            "120000": "blob", "160000": "commit"}
        if not isinstance(mode, str) or mode not in valid_mode_types or \
                valid_mode_types[mode] != kind:
            raise PreflightError("Git Trees API mode or type is invalid")
        if path in seen_paths:
            raise PreflightError(f"duplicate Git Trees API path: {path}")
        seen_paths.add(path)
        if kind == "tree":
            if path in tree_oids:
                raise PreflightError(f"duplicate Git Trees API tree path: {path}")
            tree_oids[path] = oid
        else:
            paths[path] = (mode, kind, oid)
        parent, _, name = path.rpartition("/")
        by_parent.setdefault(parent, []).append((name, row))
    for tree_path in tree_oids:
        by_parent.setdefault(tree_path, [])
    for parent in by_parent:
        if parent and tree_oids.get(parent) is None:
            raise PreflightError(f"Git Trees API omits parent tree: {parent}")
    reconstructed = 0
    for parent in sorted(by_parent, key=lambda item: (item.count("/"), item), reverse=True):
        payload = bytearray()
        children = by_parent[parent]
        children.sort(key=lambda pair: (pair[0] + ("/" if pair[1]["type"] == "tree" else ""))
                      .encode("utf-8"))
        for name, row in children:
            mode = row["mode"].lstrip("0") or "0"
            payload.extend(mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0")
            payload.extend(bytes.fromhex(row["sha"]))
        body = bytes(payload)
        actual = hashlib.sha1(b"tree " + str(len(body)).encode("ascii") + b"\0" + body,
                              usedforsecurity=False).hexdigest()
        expected = tree_oids[parent]
        if actual != expected:
            raise PreflightError(f"Git tree object hash differs: {parent or '<root>'}")
        reconstructed += 1
    return paths, reconstructed


def _changed_paths(base: dict[str, tuple[str, str, str]],
                   head: dict[str, tuple[str, str, str]]) -> list[str]:
    return sorted(path for path in base.keys() | head.keys()
                  if base.get(path) != head.get(path))


def _write_exclusive(path: Path, data: bytes, mode: int = 0o400) -> None:
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _mkdir_private(path: Path) -> None:
    os.mkdir(path, 0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise PreflightError(f"run directory is not private: {path.name}")


def _make_read_only(root: Path) -> None:
    """Remove write bits without following symlinks or changing executable bits."""
    for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                os.chmod(path, stat.S_IMODE(info.st_mode) & 0o555, follow_symlinks=False)
        for name in dirs:
            path = current_path / name
            info = os.lstat(path)
            if stat.S_ISDIR(info.st_mode):
                os.chmod(path, stat.S_IMODE(info.st_mode) & 0o555, follow_symlinks=False)
        os.chmod(current_path, stat.S_IMODE(os.lstat(current_path).st_mode) & 0o555,
                 follow_symlinks=False)


def _is_read_only(root: Path) -> bool:
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                continue
            if info.st_mode & 0o222:
                return False
        if os.lstat(current).st_mode & 0o222:
            return False
    return True


def _file_size_limiter(limit: int):
    def apply_limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    return apply_limit


def _capture_command(argv: list[str], *, env: dict[str, str], timeout: int,
                     output_limit: int = MAX_CAPTURE_BYTES, cwd: Path | None = None,
                     file_size_limit: bool = True,
                     file_size_cap: int = MAX_GIT_FILE_BYTES,
                     stdin_data: bytes | None = None) -> dict[str, Any]:
    """Run fixed argv with bounded time and captured output; never invoke a shell."""
    start = time.monotonic()
    initial_timeout = _effective_timeout(timeout)
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            preexec_fn=_file_size_limiter(file_size_cap) if file_size_limit else None)
    except OSError as exc:
        raise PreflightError(f"cannot execute {Path(argv[0]).name}: {exc}") from exc
    assert process.stdout is not None and process.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    overflow: list[str] = []

    def drain(name: str, stream: Any) -> None:
        while True:
            remaining = output_limit + 1 - len(output[name])
            chunk = stream.read(min(64 * 1024, max(1, remaining)))
            if not chunk:
                return
            output[name].extend(chunk)
            if len(output[name]) > output_limit:
                overflow.append(name)
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                return

    readers = [threading.Thread(target=drain, args=(name, stream), daemon=True)
               for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for reader in readers:
        reader.start()
    if stdin_data is not None:
        assert process.stdin is not None
        try:
            process.stdin.write(stdin_data)
            process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()
    try:
        try:
            wait_timeout = min(initial_timeout, _effective_timeout(timeout))
        except PreflightError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            raise
        code = process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.wait()
        raise PreflightError(f"{Path(argv[0]).name} exceeded {timeout}s time limit") from exc
    finally:
        for reader in readers:
            reader.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
    elapsed = time.monotonic() - start
    if overflow:
        raise PreflightError(f"{Path(argv[0]).name} {overflow[0]} exceeded byte limit")
    return {"argv": argv, "exit_code": code, "elapsed_seconds": round(elapsed, 6),
            "stdout": bytes(output["stdout"]), "stderr": bytes(output["stderr"])}


def _run_git(root: Path, args: list[str], *, home: Path, tmp: Path,
             timeout: int = MAX_COMMAND_SECONDS, output_limit: int = MAX_CAPTURE_BYTES,
             check: bool = True, file_size_cap: int = MAX_GIT_FILE_BYTES
             ) -> dict[str, Any]:
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(home),
        "TMPDIR": str(tmp), "LANG": "C", "LC_ALL": "C",
        "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_LFS_SKIP_SMUDGE": "1", "GIT_PAGER": "cat",
    }
    argv = ["git", "-C", str(root), "-c", "protocol.version=2",
            "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-c", "http.followRedirects=false",
            *args]
    started = time.monotonic()
    try:
        result = _capture_command(argv, env=env, timeout=timeout, output_limit=output_limit,
                                  file_size_cap=file_size_cap)
    except PreflightError as exc:
        _COMMAND_LOG.append({"argv": argv, "exit_code": None,
                             "elapsed_seconds": round(time.monotonic() - started, 6),
                             "failure": str(exc)[:1000]})
        raise
    command_record = {
        "argv": argv, "exit_code": result["exit_code"],
        "elapsed_seconds": round(result["elapsed_seconds"], 6),
        "stdout_bytes": len(result["stdout"]),
        "stdout_sha256": hashlib.sha256(result["stdout"]).hexdigest(),
        "stderr_bytes": len(result["stderr"]),
        "stderr_sha256": hashlib.sha256(result["stderr"]).hexdigest(),
        "stderr_excerpt": result["stderr"].decode("utf-8", "replace").strip()[:1000],
    }
    _COMMAND_LOG.append(command_record)
    if check and result["exit_code"] != 0:
        detail = result["stderr"].decode("utf-8", "replace").strip()[:2000]
        raise PreflightError(f"git {' '.join(args[:2])} failed ({result['exit_code']}): {detail}")
    return result


def _git_text(root: Path, args: list[str], *, home: Path, tmp: Path,
              timeout: int = MAX_COMMAND_SECONDS) -> tuple[str, dict[str, Any]]:
    result = _run_git(root, args, home=home, tmp=tmp, timeout=timeout,
                      output_limit=64 * 1024)
    try:
        value = result["stdout"].decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise PreflightError("Git returned non-UTF-8 identity output") from exc
    return value, {key: val for key, val in result.items() if key not in ("stdout", "stderr")}


def _api_token() -> str:
    global _API_AUTH_SOURCE
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if os.environ.get("GH_TOKEN"):
        _API_AUTH_SOURCE = "GH_TOKEN environment variable"
    elif os.environ.get("GITHUB_TOKEN"):
        _API_AUTH_SOURCE = "GITHUB_TOKEN environment variable"
    if not token:
        gh = shutil.which("gh")
        if not gh:
            raise PreflightError("authenticated GitHub API requires GH_TOKEN or gh auth")
        auth_env = {"PATH": os.environ.get("PATH", os.defpath),
                    "HOME": os.environ.get("HOME", str(Path.home())),
                    "GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"}
        result = _capture_command([gh, "auth", "token", "--hostname", "github.com"],
                                  env=auth_env, timeout=10, output_limit=8192,
                                  file_size_limit=False)
        if result["exit_code"] != 0:
            raise PreflightError("gh auth could not provide a GitHub API token")
        token = result["stdout"].decode("ascii", "strict").strip()
        _API_AUTH_SOURCE = "gh auth token"
    if not isinstance(token, str) or not (20 <= len(token) <= 4096) or \
            any(ch.isspace() for ch in token):
        raise PreflightError("GitHub API token format is invalid")
    return token


def _api_get(url: str, token: str, *, limit: int, timeout: int = 30,
             home: Path, tmp: Path) -> tuple[bytes, dict[str, Any]]:
    if not (re.fullmatch(re.escape(API_ROOT) + r"/git/commits/[0-9a-f]{40}", url) or
            re.fullmatch(re.escape(API_ROOT) + r"/git/trees/[0-9a-f]{40}\?recursive=1", url)):
        raise PreflightError("API URL is outside the fixed OpenWrt commit/tree endpoints")
    effective = _effective_timeout(timeout)
    command_timeout = min(effective, timeout) + 1
    command = [sys.executable, "-B", "-m", "tools.canonical_source_preflight",
               "--api-worker", url, str(limit), str(timeout)]
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home),
           "TMPDIR": str(tmp), "LANG": "C", "LC_ALL": "C",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": str(home / "pycache"),
           "GH_PROMPT_DISABLED": "1"}
    started = time.monotonic()
    try:
        result = _capture_command(command, env=env, timeout=command_timeout,
                                  output_limit=limit + 1, file_size_limit=False,
                                  stdin_data=token.encode("ascii"), cwd=ROOT)
    except PreflightError as exc:
        _API_REQUEST_LOG.append({"argv": command, "url": url, "exit_code": None,
                                 "failure": str(exc)[:1000]})
        raise
    if result["exit_code"] != 0:
        detail = result["stderr"].decode("utf-8", "replace").strip()[:1000]
        _API_REQUEST_LOG.append({"argv": command, "url": url,
                                 "exit_code": result["exit_code"],
                                 "elapsed_seconds": round(result["elapsed_seconds"], 6),
                                 "stderr_excerpt": detail})
        if result["exit_code"] == 3:
            raise PreflightError("GitHub API response exceeds byte limit")
        raise PreflightError(f"GitHub API worker rejected response: {detail or result['exit_code']}")
    raw = result["stdout"]
    metadata = _api_json(result["stderr"], "API worker metadata")
    if metadata.get("url") != url or metadata.get("redirects_followed") != 0:
        raise PreflightError("GitHub API worker metadata differs")
    metadata.update({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "elapsed_seconds": round(time.monotonic() - started, 6)})
    _API_REQUEST_LOG.append({"argv": command, "url": url, "exit_code": 0,
                             "elapsed_seconds": round(result["elapsed_seconds"], 6),
                             "response_bytes": len(raw),
                             "response_sha256": metadata["sha256"]})
    return raw, metadata


def _api_worker_main(argv: list[str]) -> int:
    """Internal supervised HTTP worker; bearer token arrives only on stdin."""
    try:
        if len(argv) != 3:
            raise PreflightError("invalid internal API worker arguments")
        url, raw_limit, raw_timeout = argv
        if not (re.fullmatch(re.escape(API_ROOT) + r"/git/commits/[0-9a-f]{40}", url) or
                re.fullmatch(re.escape(API_ROOT) + r"/git/trees/[0-9a-f]{40}\?recursive=1", url)):
            raise PreflightError("internal API URL is outside fixed Git endpoints")
        limit, timeout = int(raw_limit), int(raw_timeout)
        if not (1 <= limit <= MAX_API_TREE_BYTES and 1 <= timeout <= 30):
            raise PreflightError("internal API worker bounds are invalid")
        token_raw = sys.stdin.buffer.read(4097)
        if len(token_raw) > 4096:
            raise PreflightError("internal API token exceeds bound")
        token = token_raw.decode("ascii", "strict").strip()
        if not (20 <= len(token) <= 4096) or any(ch.isspace() for ch in token):
            raise PreflightError("internal API token is invalid")
        request = Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "codeql-openwrt-canonical-source-preflight/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }, method="GET")
        opener = build_opener(ProxyHandler({}), NoRedirectHandler())
        request_deadline = time.monotonic() + timeout
        if _ACTIVE_DEADLINE is not None:
            request_deadline = min(request_deadline, _ACTIVE_DEADLINE)
        open_timeout = request_deadline - time.monotonic()
        if open_timeout <= 0:
            raise TimeoutError("API request deadline expired before connection")
        with opener.open(request, timeout=open_timeout) as response:
            raw, metadata = _read_api_response(response, url, limit, request_deadline)
            if len(raw) > limit:
                print("{\"error\":\"response_exceeds_limit\"}", file=sys.stderr)
                return 3
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        sys.stderr.write(json.dumps(metadata, sort_keys=True) + "\n")
        return 0
    except HTTPError as exc:
        reason = "redirect_rejected" if 300 <= exc.code < 400 else f"http_{exc.code}"
    except (URLError, TimeoutError, OSError) as exc:
        reason = "network_error_" + type(exc).__name__
    except (PreflightError, ValueError, UnicodeError) as exc:
        reason = "rejected_" + str(exc)[:240]
    sys.stderr.write(json.dumps({"error": reason}, sort_keys=True) + "\n")
    return 2


def _read_api_response(response: Any, url: str, limit: int,
                       request_deadline: float) -> tuple[bytes, dict[str, Any]]:
    """Read one framed HTTP response without redirects or unbounded slow-drip IO."""
    if response.geturl() != url or response.status != 200:
        raise PreflightError("API redirect or non-200 response rejected")
    length = response.headers.get("Content-Length")
    declared_length = None
    if length is not None:
        try:
            declared_length = int(length)
        except ValueError as exc:
            raise PreflightError("API Content-Length is malformed") from exc
        if declared_length < 0:
            raise PreflightError("API Content-Length is negative")
        if declared_length > limit:
            raise PreflightError("GitHub API response exceeds byte limit")
    raw = bytearray()
    while len(raw) <= limit:
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            raise PreflightError("API request exceeded absolute worker deadline")
        raw_layer = getattr(response.fp, "raw", None)
        sock = getattr(raw_layer, "_sock", None)
        if sock is not None:
            sock.settimeout(remaining)
        amount = min(64 * 1024, limit + 1 - len(raw))
        chunk = response.read1(amount)
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > limit:
        raise PreflightError("GitHub API response exceeds byte limit")
    if declared_length is not None and len(raw) != declared_length:
        raise PreflightError("API body length differs from Content-Length")
    metadata = {
        "url": url, "status": response.status,
        "content_type": response.headers.get("Content-Type"),
        "date": response.headers.get("Date"),
        "request_id": response.headers.get("X-GitHub-Request-Id"),
        "redirects_followed": 0,
    }
    return bytes(raw), metadata


def _api_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PreflightError(f"invalid {label} API JSON") from exc
    if not isinstance(document, dict):
        raise PreflightError(f"{label} API JSON is not an object")
    return document


def _canonical_tree_pair(policy_base: str, event_head: str, *, api_dir: Path,
                         token: str, policy: dict[str, Any],
                         direct_git_fetch: dict[str, Any], home: Path, tmp: Path
                         ) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Verify the API-only base/head tree delta and frozen recipe-path policy."""
    if policy_base != POLICY_BASE_COMMIT:
        raise PreflightError("frozen OpenWrt policy base differs from the reviewed v0.6 pin")
    raw_responses: dict[str, bytes] = {}
    receipts: dict[str, Any] = {}
    commits: dict[str, dict[str, Any]] = {}
    trees: dict[str, dict[str, Any]] = {}
    oids = {"base": policy_base, "head": event_head}
    for label, commit_oid in oids.items():
        raw, receipt = _api_get(f"{API_ROOT}/git/commits/{commit_oid}", token,
                                limit=MAX_API_COMMIT_BYTES, home=home, tmp=tmp)
        _write_exclusive(api_dir / f"{label}-commit.json", raw)
        raw_responses[f"{label}_commit"] = raw
        receipts[f"{label}_commit"] = receipt
        commit_doc = _api_json(raw, f"{label} commit")
        if commit_doc.get("sha") != commit_oid:
            raise PreflightError(f"GitHub commit API returned a different {label} SHA")
        tree = commit_doc.get("tree")
        if not isinstance(tree, dict):
            raise PreflightError(f"GitHub commit API omits {label} tree")
        tree_oid = _sha40(tree.get("sha"), f"{label} tree")
        commits[label] = {"commit": commit_doc, "tree_sha": tree_oid}
        raw, receipt = _api_get(f"{API_ROOT}/git/trees/{tree_oid}?recursive=1", token,
                                limit=MAX_API_TREE_BYTES, home=home, tmp=tmp)
        _write_exclusive(api_dir / f"{label}-tree.json", raw)
        raw_responses[f"{label}_tree"] = raw
        receipts[f"{label}_tree"] = receipt
        trees[label] = _api_json(raw, f"{label} tree")
    base_entries, base_tree_count = _checked_tree_document(
        trees["base"], commits["base"]["tree_sha"])
    if commits["base"]["tree_sha"] != POLICY_BASE_TREE:
        raise PreflightError("canonical API policy-base tree differs from reviewed identity")
    head_entries, head_tree_count = _checked_tree_document(
        trees["head"], commits["head"]["tree_sha"])
    changed = _changed_paths(base_entries, head_entries)
    relevant = route_oracle.relevant_recipe_changes(policy, "openwrt", changed)
    no_recipe_drift = not relevant
    result = {
        "status": ("canonical_api_tree_delta_verified" if no_recipe_drift
                   else "recipe_delta_requires_review"),
        "repository": "openwrt/openwrt",
        "transport": "authenticated GitHub REST Git Commit and recursive Trees APIs",
        "base_commit": policy_base,
        "base_tree": commits["base"]["tree_sha"],
        "head_commit": event_head,
        "head_tree": commits["head"]["tree_sha"],
        "commit_response_sha256": {
            key: hashlib.sha256(raw_responses[f"{key}_commit"]).hexdigest()
            for key in ("base", "head")},
        "tree_response_sha256": {
            key: hashlib.sha256(raw_responses[f"{key}_tree"]).hexdigest()
            for key in ("base", "head")},
        "api_responses": receipts,
        "base_non_tree_entry_count": len(base_entries),
        "head_non_tree_entry_count": len(head_entries),
        "base_recomputed_tree_object_count": base_tree_count,
        "head_recomputed_tree_object_count": head_tree_count,
        "changed_path_count": len(changed),
        "changed_paths_sha256": hashlib.sha256(
            ("\n".join(changed) + "\n").encode("utf-8")).hexdigest(),
        "relevant_recipe_changes": relevant,
        "recipe_delta_clear_under_frozen_policy": not relevant,
        "policy_base_git_commit_object_acquired":
            direct_git_fetch.get("status") == "direct_sha_fetch_verified",
        "direct_git_fetch": direct_git_fetch,
        "canonical_api_tree_delta_verified": True,
        "api_redirects_followed": False,
        "limits": [
            "This API check establishes canonical GitHub commit/tree identities, not advertised branch reachability; the separate direct-SHA Git fetch result is recorded independently.",
            "Recursive Trees responses must be complete and each listed tree hash is recomputed; no source blob bytes are fetched by this API delta step.",
            "This recipe-path delta is checked against frozen v0.6 path policy; it does not prove package build effects or installed bytes.",
        ],
    }
    return result, raw_responses


def _object_store_size(root: Path, *, home: Path, tmp: Path) -> int:
    raw, _ = _git_text(root, ["count-objects", "-v"], home=home, tmp=tmp)
    values = {}
    for line in raw.splitlines():
        name, separator, number = line.partition(":")
        if separator:
            try:
                values[name.strip()] = int(number.strip())
            except ValueError:
                continue
    return values.get("size", 0) * 1024 + values.get("size-pack", 0) * 1024


def _tree_blob_size(root: Path, commit: str, *, home: Path, tmp: Path) -> tuple[int, int]:
    """Bound checkout expansion before materializing a pinned source tree."""
    result = _run_git(root, ["ls-tree", "-r", "-l", "-z", "--full-tree", commit],
                      home=home, tmp=tmp, output_limit=MAX_TREE_LIST_BYTES)
    total = 0
    count = 0
    for record in result["stdout"].split(b"\0"):
        if not record:
            continue
        try:
            header, _path = record.split(b"\t", 1)
            mode, kind, oid, raw_size = header.decode("ascii").split()
        except (ValueError, UnicodeError) as exc:
            raise PreflightError("malformed tracked-tree size record") from exc
        if kind == "commit" and mode == "160000":
            continue
        if kind != "blob" or not HEX40.fullmatch(oid):
            raise PreflightError("tracked source tree has unexpected object type")
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise PreflightError("tracked blob size is not numeric") from exc
        if size < 0:
            raise PreflightError("tracked blob size is negative")
        count += 1
        total += size
        if total > MAX_REPO_WORKTREE_BYTES:
            raise PreflightError("tracked source bytes exceed per-repository checkout budget")
    return total, count


def _worktree_size(root: Path) -> int:
    total = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        if Path(current) == root:
            dirs[:] = [name for name in dirs if name != ".git"]
        for name in files:
            path = Path(current) / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PreflightError("source checkout contains non-regular or aliased file")
            total += info.st_size
            if total > MAX_REPO_WORKTREE_BYTES:
                raise PreflightError("materialized source tree exceeds checkout byte budget")
    return total


def _direct_fetch_only(root: Path, repo_name: str, oid: str, *, home: Path,
                       tmp: Path) -> dict[str, Any]:
    """Try one exact canonical Git fetch without a branch or local-cache fallback."""
    before = _object_store_size(root, home=home, tmp=tmp)
    remaining = MAX_REPO_OBJECT_BYTES - before
    if remaining <= 0:
        raise PreflightError(f"{repo_name} object store is already at its byte limit")
    try:
        fetched = _run_git(root, ["fetch", "--quiet", "--no-tags", "--depth=1",
                                  "origin", oid], home=home, tmp=tmp,
                           timeout=MAX_FETCH_SECONDS, check=False,
                           file_size_cap=min(MAX_GIT_FILE_BYTES, remaining))
    except PreflightError as exc:
        return {"status": "direct_sha_fetch_failed", "requested_oid": oid,
                "failure": str(exc)[:1000], "local_cache_used": False}
    if fetched["exit_code"] != 0:
        return {"status": "direct_sha_fetch_failed", "requested_oid": oid,
                "argv": fetched["argv"], "exit_code": fetched["exit_code"],
                "elapsed_seconds": round(fetched["elapsed_seconds"], 6),
                "stderr_excerpt": fetched["stderr"].decode("utf-8", "replace").strip()[:1000],
                "local_cache_used": False}
    fetch_head = _git_text(root, ["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
                           home=home, tmp=tmp)[0]
    if fetch_head != oid:
        raise PreflightError("policy-base FETCH_HEAD differs from exact requested commit")
    tree = _git_text(root, ["rev-parse", "--verify", f"{oid}^{{tree}}"],
                     home=home, tmp=tmp)[0]
    if tree != POLICY_BASE_TREE:
        raise PreflightError("direct Git policy-base tree differs from reviewed identity")
    store = _object_store_size(root, home=home, tmp=tmp)
    if store > MAX_REPO_OBJECT_BYTES:
        raise PreflightError("OpenWrt object store exceeds budget after policy-base fetch")
    return {"status": "direct_sha_fetch_verified", "requested_oid": oid,
            "fetch_head": fetch_head, "tree": tree,
            "argv": fetched["argv"], "exit_code": fetched["exit_code"],
            "elapsed_seconds": round(fetched["elapsed_seconds"], 6),
            "object_store_bytes_after_fetch": store, "local_cache_used": False}


def _fetch_object(root: Path, repo_name: str, oid: str, *, home: Path,
                  tmp: Path) -> dict[str, Any]:
    """Try direct SHA fetch; then one fixed, shallow advertised-ref fallback."""
    before = _object_store_size(root, home=home, tmp=tmp)
    remaining = MAX_REPO_OBJECT_BYTES - before
    if remaining <= 0:
        raise PreflightError(f"{repo_name} object store is already at its byte limit")
    try:
        direct = _run_git(root, ["fetch", "--quiet", "--no-tags", "--depth=1",
                                 "origin", oid], home=home, tmp=tmp,
                          timeout=MAX_FETCH_SECONDS, check=False,
                          file_size_cap=min(MAX_GIT_FILE_BYTES, remaining))
        direct_attempt = {"method": "direct_sha_fetch", "argv": direct["argv"],
                          "exit_code": direct["exit_code"],
                          "elapsed_seconds": round(direct["elapsed_seconds"], 6),
                          "stderr_excerpt": direct["stderr"].decode(
                              "utf-8", "replace").strip()[:1000]}
    except PreflightError as exc:
        direct = None
        direct_attempt = {"method": "direct_sha_fetch", "exit_code": None,
                          "failure": str(exc)[:1000]}
    if direct is not None and direct["exit_code"] == 0:
        fetched_oid = _git_text(root, ["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
                                home=home, tmp=tmp)[0]
        if fetched_oid != oid:
            raise PreflightError("direct Git FETCH_HEAD differs from exact requested commit")
        store = _object_store_size(root, home=home, tmp=tmp)
        if store > MAX_REPO_OBJECT_BYTES:
            raise PreflightError(f"{repo_name} object store exceeds byte budget")
        return {"method": "direct_sha_fetch", "requested_oid": oid,
                "fetch_head": fetched_oid, "fallback_used": False,
                "branch_reachability_proven": False,
                "object_store_bytes_after_fetch": store,
                "attempts": [direct_attempt]}
    ref = APPROVED_FALLBACK_REFS[repo_name]
    remote_ref = "refs/remotes/origin/preflight" + ref.removeprefix("refs/heads")
    before_fallback = _object_store_size(root, home=home, tmp=tmp)
    remaining = MAX_REPO_OBJECT_BYTES - before_fallback
    if remaining <= 0:
        raise PreflightError(f"{repo_name} object store has no fallback byte budget")
    fallback = _run_git(root, ["fetch", "--quiet", "--no-tags",
                               f"--depth={MAX_FALLBACK_DEPTH}", "origin",
                               f"{ref}:{remote_ref}"], home=home, tmp=tmp,
                        timeout=MAX_FETCH_SECONDS, check=False,
                        file_size_cap=min(MAX_GIT_FILE_BYTES, remaining))
    if fallback["exit_code"] != 0:
        detail = fallback["stderr"].decode("utf-8", "replace").strip()[:1000]
        raise PreflightError(f"fixed advertised-ref fallback failed for {repo_name}: {detail}")
    fallback_head = _git_text(root, ["rev-parse", "--verify", f"{remote_ref}^{{commit}}"],
                              home=home, tmp=tmp)[0]
    reachable = _run_git(root, ["merge-base", "--is-ancestor", oid, remote_ref],
                         home=home, tmp=tmp, timeout=MAX_COMMAND_SECONDS,
                         output_limit=32 * 1024, check=False)
    if reachable["exit_code"] != 0:
        raise PreflightError(f"exact {repo_name} pin is not proven reachable from bounded {ref}")
    after_fallback = _object_store_size(root, home=home, tmp=tmp)
    if after_fallback > MAX_REPO_OBJECT_BYTES:
        raise PreflightError(f"{repo_name} object store exceeds byte budget after fallback")
    return {"method": "approved_advertised_ref_fallback", "requested_oid": oid,
            "fallback_ref": ref, "fallback_depth": MAX_FALLBACK_DEPTH,
            "fallback_tip": fallback_head,
            "branch_reachability_proven": True,
            "object_store_bytes_after_fetch": after_fallback,
            "fallback_used": True,
            "attempts": [direct_attempt,
                {"method": "approved_advertised_ref", "exit_code": 0,
                 "argv": fallback["argv"],
                 "elapsed_seconds": round(fallback["elapsed_seconds"], 6),
                 "ancestor_check_exit_code": 0},
            ]}


def _acquire_repository(repo_name: str, commit: str, checkout: Path, *,
                        home: Path, tmp: Path, expected_tree: str | None = None,
                        extra_objects: dict[str, str] | None = None,
                        direct_only_objects: dict[str, str] | None = None) -> dict[str, Any]:
    _mkdir_private(checkout)
    _run_git(checkout, ["init", "--quiet", "--template="], home=home, tmp=tmp)
    _run_git(checkout, ["remote", "add", "origin", REPOSITORY_URLS[repo_name]],
             home=home, tmp=tmp)
    source_fetch = _fetch_object(checkout, repo_name, commit, home=home, tmp=tmp)
    extra_fetches = {}
    fetched_oids = {commit: "source_commit"}
    for label, oid in (extra_objects or {}).items():
        if oid in fetched_oids:
            extra_fetches[label] = {"method": "already_fetched_exact_object",
                                    "requested_oid": oid,
                                    "shared_with": fetched_oids[oid]}
        else:
            extra_fetches[label] = _fetch_object(checkout, repo_name, oid,
                                                 home=home, tmp=tmp)
            fetched_oids[oid] = label
    direct_only_fetches = {}
    for label, oid in (direct_only_objects or {}).items():
        if oid in fetched_oids:
            direct_only_fetches[label] = {"status": "already_fetched_exact_object",
                                          "requested_oid": oid,
                                          "shared_with": fetched_oids[oid]}
        else:
            direct_only_fetches[label] = _direct_fetch_only(
                checkout, repo_name, oid, home=home, tmp=tmp)
            if direct_only_fetches[label].get("status") == "direct_sha_fetch_verified":
                fetched_oids[oid] = label
    tree_bytes, tracked_blob_count = _tree_blob_size(checkout, commit, home=home, tmp=tmp)
    head_result = _run_git(checkout, ["-c", "core.hooksPath=/dev/null",
                                      "checkout", "--quiet", "--detach", commit],
                            home=home, tmp=tmp)
    head = _git_text(checkout, ["rev-parse", "--verify", "HEAD^{commit}"], home=home, tmp=tmp)[0]
    tree = _git_text(checkout, ["rev-parse", "--verify", f"{commit}^{{tree}}"], home=home, tmp=tmp)[0]
    top = Path(_git_text(checkout, ["rev-parse", "--show-toplevel"], home=home, tmp=tmp)[0]).resolve()
    origin = _git_text(checkout, ["remote", "get-url", "origin"], home=home, tmp=tmp)[0]
    status = _git_text(checkout, ["status", "--porcelain=v1", "--untracked-files=all"],
                       home=home, tmp=tmp)[0]
    if head != commit or top != checkout.resolve() or origin != REPOSITORY_URLS[repo_name] or status:
        raise PreflightError(f"{repo_name} checkout is not exact, clean, and fixed-remote")
    git_dir = Path(_git_text(checkout, ["rev-parse", "--git-dir"], home=home, tmp=tmp)[0])
    if not git_dir.is_absolute():
        git_dir = checkout / git_dir
    for alternate in (git_dir / "objects/info/alternates",
                      git_dir / "objects/info/http-alternates"):
        if alternate.exists() or alternate.is_symlink():
            raise PreflightError(f"{repo_name} checkout uses an object alternate")
    partial_clone = _run_git(checkout, ["config", "--local", "--get", "extensions.partialClone"],
                             home=home, tmp=tmp, check=False)
    promisor = _run_git(checkout, ["config", "--local", "--get", "remote.origin.promisor"],
                        home=home, tmp=tmp, check=False)
    replacements = _run_git(checkout, ["for-each-ref", "--format=%(refname)", "refs/replace"],
                            home=home, tmp=tmp)
    if partial_clone["exit_code"] == 0 or promisor["exit_code"] == 0 or replacements["stdout"]:
        raise PreflightError(f"{repo_name} checkout has partial/promisor/replacement object configuration")
    if expected_tree and tree != expected_tree:
        raise PreflightError(f"{repo_name} tree differs from frozen event identity")
    verified_objects = {}
    for label, oid in (extra_objects or {}).items():
        object_commit = _git_text(checkout, ["rev-parse", "--verify", f"{oid}^{{commit}}"],
                                  home=home, tmp=tmp)[0]
        object_tree = _git_text(checkout, ["rev-parse", "--verify", f"{oid}^{{tree}}"],
                                home=home, tmp=tmp)[0]
        if object_commit != oid:
            raise PreflightError(f"{repo_name} {label} commit object differs")
        verified_objects[label] = {"commit": object_commit, "tree": object_tree}
    parent_receipt = None
    if repo_name == "openwrt":
        commit_text = _run_git(checkout, ["cat-file", "commit", commit], home=home, tmp=tmp,
                               output_limit=64 * 1024)["stdout"].decode("utf-8", "strict")
        headers = commit_text.split("\n\n", 1)[0]
        parents = [line[7:] for line in headers.splitlines() if line.startswith("parent ")]
        parent_receipt = {"parents": parents}
    before = _object_store_size(checkout, home=home, tmp=tmp)
    if before > MAX_REPO_OBJECT_BYTES:
        raise PreflightError(f"{repo_name} object store exceeds {MAX_REPO_OBJECT_BYTES} bytes")
    materialized_bytes = _worktree_size(checkout)
    if materialized_bytes > MAX_REPO_WORKTREE_BYTES:
        raise PreflightError(f"{repo_name} materialized tree exceeds byte budget")
    _make_read_only(checkout)
    if not _is_read_only(checkout):
        raise PreflightError(f"{repo_name} checkout could not be made read-only")
    return {
        "canonical_url": REPOSITORY_URLS[repo_name], "commit": head, "tree": tree,
        "origin_url_exact": True, "worktree_clean": True, "detached_head": True,
        "worktree_and_git_directory_read_only": True,
        "object_alternates_absent": True,
        "partial_clone_and_promisor_absent": True,
        "replacement_refs_absent": True,
        "object_store_bytes": before, "tracked_blob_count": tracked_blob_count,
        "tracked_blob_bytes_for_checkout": tree_bytes,
        "materialized_worktree_bytes": materialized_bytes,
        "commit_fetch": source_fetch,
        "additional_fetches": extra_fetches, "additional_objects": verified_objects,
        "direct_only_fetches": direct_only_fetches,
        "commit_parent_records": parent_receipt,
    }


def _allowed_run_root(value: Path) -> tuple[Path, Path]:
    work_root = ROOT.parent.resolve(strict=True)
    if work_root.name != "work" or not (work_root.parent / "AGENTS.md").is_file():
        raise PreflightError("consumer checkout is not a direct child of ledger work/")
    if value.is_absolute():
        if any(part in (".", "..") for part in value.parts):
            raise PreflightError("run root path traversal is not allowed")
        requested = value
    else:
        if any(part in (".", "..") for part in value.parts):
            raise PreflightError("run root path traversal is not allowed")
        requested = work_root / value
    if requested.parent.resolve(strict=True) != work_root:
        raise PreflightError("run root must be a unique direct child of ledger work/")
    if not RUN_NAME.fullmatch(requested.name):
        raise PreflightError("run root name contains unsupported characters")
    if requested.exists() or requested.is_symlink():
        raise PreflightError("run root already exists; refusing reuse or replacement")
    return requested, work_root


def _launcher_cache_receipt(work_root: Path) -> dict[str, Any]:
    supplied = os.environ.get("PYTHONPYCACHEPREFIX")
    if not supplied:
        raise PreflightError("launcher requires a fresh PYTHONPYCACHEPREFIX under ledger work/")
    raw_path = Path(supplied)
    if raw_path.is_symlink():
        raise PreflightError("launcher bytecode-cache path is a symlink")
    try:
        cache = raw_path.resolve(strict=True)
        info = os.lstat(cache)
    except OSError as exc:
        raise PreflightError("launcher bytecode-cache directory must already exist") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077 or cache.parent != work_root or
            not cache.name.startswith("canonical-source-launcher-cache-") or
            any(cache.iterdir())):
        raise PreflightError("launcher bytecode-cache directory must be a private, empty work/ child")
    return {"path": str(cache), "owner_uid": info.st_uid,
            "mode": oct(stat.S_IMODE(info.st_mode)), "empty_at_start": True}


def _snapshot_inputs(run_root: Path, inputs: dict[str, tuple[bytes, dict[str, Any]]]
                     ) -> dict[str, Path]:
    input_dir = run_root / "inputs"
    _mkdir_private(input_dir)
    paths = {}
    for name, (raw, _doc) in inputs.items():
        path = input_dir / f"{name}.json"
        _write_exclusive(path, raw)
        paths[name] = path
    return paths


def _verify_input_bindings(policy_raw: bytes, policy: dict[str, Any],
                           manifest: dict[str, Any], coverage: dict[str, Any],
                           routing: dict[str, Any], manifest_raw: bytes) -> None:
    digest = hashlib.sha256(policy_raw).hexdigest()
    if digest != POLICY_SHA256 or digest != selector.EXPECTED_MANIFESTS["mvp-bounded-corpus-v0.6"]:
        raise PreflightError("frozen policy bytes do not match the approved v0.6 digest")
    if coverage.get("schema") != "ucode-default-branch-corpus-coverage-v1":
        raise PreflightError("unsupported default-branch coverage schema")
    if coverage.get("source_manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest():
        raise PreflightError("coverage does not bind the exact supplied manifest bytes")
    if not isinstance(routing.get("decisions"), list):
        raise PreflightError("routing document has no decisions list")
    if not isinstance(manifest.get("selected"), list) or not isinstance(manifest.get("excluded"), list):
        raise PreflightError("manifest selected/excluded rows are missing")


def _base_checkout_receipt(home: Path, tmp: Path) -> dict[str, Any]:
    head = _git_text(ROOT, ["rev-parse", "--verify", "HEAD^{commit}"], home=home, tmp=tmp)[0]
    tree = _git_text(ROOT, ["rev-parse", "--verify", "HEAD^{tree}"], home=home, tmp=tmp)[0]
    origin = _git_text(ROOT, ["remote", "get-url", "origin"], home=home, tmp=tmp)[0]
    status = _run_git(ROOT, ["status", "--porcelain=v1", "--untracked-files=all"],
                      home=home, tmp=tmp)["stdout"].decode("utf-8", "strict").splitlines()
    dirty_paths = [line[3:] for line in status if len(line) >= 4]
    allowed = {"tools/canonical_source_preflight.py",
               "tools/test_canonical_source_preflight.py",
               "docs/canonical-source-acquisition-preflight.md",
               ".github/workflows/default-branch-commit-scan.yml"}
    ancestor = _run_git(ROOT, ["merge-base", "--is-ancestor", BASE_COMMIT, "HEAD"],
                        home=home, tmp=tmp, check=False)
    if ancestor["exit_code"] != 0 or origin != BASE_REMOTE:
        raise PreflightError("implementation checkout is not descended from the fixed canonical base")
    if any(path not in allowed for path in dirty_paths):
        raise PreflightError("implementation checkout has changes outside the reviewed candidate files")
    source_truth_sha = hashlib.sha256((ROOT / "tools/default_branch_source_truth.py").read_bytes()).hexdigest()
    if source_truth_sha != SOURCE_TRUTH_SHA256:
        raise PreflightError("existing source verifier differs from the reviewed base bytes")
    git_version = _run_git(ROOT, ["--version"], home=home, tmp=tmp)
    return {"base_commit": BASE_COMMIT, "commit": head, "tree": tree, "origin_url": origin,
            "dirty_paths": sorted(dirty_paths), "source_verifier_sha256": source_truth_sha,
            "source_verifier_base_bytes_verified": True,
            "git_version": git_version["stdout"].decode("utf-8", "strict").strip(),
            "candidate_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def _run_oracle(snapshot_paths: dict[str, Path], checkouts: dict[str, Path],
                run_root: Path, home: Path, tmp: Path, *, timeout: int
                ) -> tuple[int, bytes, bytes, float, list[str]]:
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(home),
        "TMPDIR": str(tmp), "LANG": "C", "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ALLOW_PROTOCOL": "file",
        "GIT_PAGER": "cat", "PYTHONPYCACHEPREFIX": str(run_root / "pycache"),
    }
    argv = [sys.executable, "-B", "-m", "tools.default_branch_source_truth",
            "--manifest", str(snapshot_paths["manifest"]),
            "--coverage", str(snapshot_paths["coverage"]),
            "--routing", str(snapshot_paths["routing"]),
            "--luci-checkout", str(checkouts["luci"]),
            "--openwrt-checkout", str(checkouts["openwrt"]),
            "--packages-checkout", str(checkouts["packages"])]
    result = _capture_command(argv, env=env, timeout=timeout,
                              output_limit=MAX_INPUT_JSON_BYTES, cwd=ROOT,
                              file_size_limit=False)
    stdout = result["stdout"]
    if result["stderr"]:
        _write_exclusive(run_root / "source-oracle.stderr.txt", result["stderr"], mode=0o400)
    if result["exit_code"] not in (0, 2, 3):
        raise PreflightError(f"source verifier returned unexpected exit {result['exit_code']}")
    if result["exit_code"] in (0, 3):
        _write_exclusive(run_root / "source-oracle.json", stdout, mode=0o400)
        try:
            oracle = json.loads(stdout, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise PreflightError("source verifier did not produce valid JSON") from exc
        if not isinstance(oracle, dict):
            raise PreflightError("source verifier receipt is not a JSON object")
    return result["exit_code"], stdout, result["stderr"], result["elapsed_seconds"], argv


def _save_receipt(run_root: Path, receipt: dict[str, Any]) -> Path:
    path = run_root / "preflight-receipt.json"
    raw = (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    _write_exclusive(path, raw, mode=0o400)
    return path


def _final_status(policy_base_status: str, api_delta_verified: bool,
                  oracle_code: int) -> tuple[str, int]:
    if oracle_code == 2:
        return "source_oracle_rejected", EXIT_REJECTED
    if not api_delta_verified:
        return "policy_base_provenance_unresolved", EXIT_POLICY_BASE_UNRESOLVED
    if policy_base_status == "recipe_delta_requires_review":
        return "policy_base_recipe_delta_requires_review", EXIT_POLICY_BASE_UNRESOLVED
    if oracle_code == 3:
        return "canonical_source_verified_source_oracle_partial", EXIT_SOURCE_PARTIAL
    if oracle_code == 0 and policy_base_status == "canonical_api_tree_delta_verified":
        return "canonical_source_and_source_oracle_verified", 0
    return "source_oracle_rejected", EXIT_REJECTED


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    global _ACTIVE_DEADLINE, _COMMAND_LOG, _API_REQUEST_LOG, _ACTIVE_RUN_ROOT, _API_AUTH_SOURCE
    _COMMAND_LOG = []
    _API_REQUEST_LOG = []
    _ACTIVE_RUN_ROOT = None
    _API_AUTH_SOURCE = None
    run_root, work_root = _allowed_run_root(args.run_root)
    launcher_cache = _launcher_cache_receipt(work_root)
    disk = shutil.disk_usage(work_root)
    if disk.free < MIN_FREE_DISK_BYTES:
        raise PreflightError(f"less than {MIN_FREE_DISK_BYTES} bytes free under work/")
    input_paths = {"policy": args.policy or ROOT / POLICY_RELATIVE,
                   "manifest": args.manifest, "coverage": args.coverage,
                   "routing": args.routing}
    loaded = {name: _read_json(path, name) for name, path in input_paths.items()}
    policy_raw, policy = loaded["policy"]
    manifest_raw, manifest = loaded["manifest"]
    coverage_raw, coverage = loaded["coverage"]
    routing_raw, routing = loaded["routing"]
    _verify_input_bindings(policy_raw, policy, manifest, coverage, routing, manifest_raw)
    if coverage.get("source_pins") != manifest.get("pins") or coverage.get("event") != manifest.get("event"):
        raise PreflightError("coverage pins/event differ from the exact manifest")
    pins, controls = derive_pins(policy, manifest)
    os.mkdir(run_root, 0o700)
    if not stat.S_ISDIR(os.lstat(run_root).st_mode) or os.lstat(run_root).st_mode & 0o077:
        raise PreflightError("run root creation failed private-directory check")
    _ACTIVE_RUN_ROOT = run_root
    started = time.monotonic()
    _ACTIVE_DEADLINE = started + MAX_TOTAL_SECONDS
    for name in ("home", "tmp", "source", "api", "pycache"):
        _mkdir_private(run_root / name)
    home, tmp = run_root / "home", run_root / "tmp"
    _mkdir_private(home / "pycache")
    snapshots = _snapshot_inputs(run_root, loaded)
    base_checkout = _base_checkout_receipt(home, tmp)
    receipt: dict[str, Any] = {
        "schema": "canonical-source-acquisition-preflight-v1",
        "status": "running",
        "base_checkout": BASE_COMMIT,
        "implementation_checkout": base_checkout,
        "run_root": str(run_root), "work_root": str(work_root),
        "launcher_bytecode_cache": launcher_cache,
        "started_unix_seconds": int(time.time()),
        "resource_preflight": {"free_disk_bytes_at_start": disk.free,
                               "minimum_free_disk_bytes": MIN_FREE_DISK_BYTES,
                               "max_total_object_store_bytes": MAX_TOTAL_OBJECT_BYTES,
                               "max_repo_object_store_bytes": MAX_REPO_OBJECT_BYTES,
                               "max_total_worktree_bytes": MAX_TOTAL_WORKTREE_BYTES,
                               "max_repo_worktree_bytes": MAX_REPO_WORKTREE_BYTES,
                               "max_git_file_bytes": MAX_GIT_FILE_BYTES,
                               "max_tree_list_bytes": MAX_TREE_LIST_BYTES,
                               "max_fallback_depth": MAX_FALLBACK_DEPTH,
                               "max_fetch_seconds": MAX_FETCH_SECONDS,
                               "max_total_seconds": MAX_TOTAL_SECONDS,
                               "peak_rss_bytes": None,
                               "peak_rss_limit_reason": "not measured by this subprocess wrapper"},
        "policy": {"sha256": hashlib.sha256(policy_raw).hexdigest(),
                   "source": str(input_paths["policy"]),
                   "schema": policy.get("schema")},
        "inputs": {name: {"source_path": str(input_paths[name]),
                          "snapshot_path": str(snapshots[name]),
                          "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                   for name, (raw, _doc) in loaded.items()},
        "source_pins": pins,
        "event_objects": controls,
        "fixed_remotes": REPOSITORY_URLS,
        "fallback_refs": APPROVED_FALLBACK_REFS,
        "runtime": {"python_executable": sys.executable,
                    "python_version": sys.version.split()[0]},
        "canonical_source_checkouts": {},
        "policy_base_provenance": {"status": "unresolved",
                                   "policy_base_commit": manifest["event"]["policy_base_commit"],
                                   "local_cache_used": False},
        "source_oracle": None,
        "elapsed_seconds": None,
        "limits": [
            "The three source remotes and API repository are fixed in code; caller URLs and Git config are ignored.",
            "Git commands run with no shell, HTTPS-only protocol, no credential helper, no prompts, hooks or LFS smudge, capped output, file size and wall time.",
            "Every source pin is fetched directly by SHA or by one approved shallow ref with an exact reachability check.",
            "The canonical API base-to-head tree delta is always checked; if the policy-base SHA fetch fails, its commit object provenance remains API-only, with no local cache or caller artifact fallback.",
            "The manifest and artifact coverage/routing are supplied unsigned observations; this preflight rechecks their internal/source identity but does not authenticate a live start or scan.",
            "The source verifier can report packages-feed candidate signals outside the selected/excluded denominator; that is a partial scope result, not fetch failure.",
            "This run does not read signing keys, queue databases, issuer state, scan databases or credentials other than an in-memory GitHub API bearer token.",
        ],
    }
    total_objects = 0
    total_worktree = 0
    try:
        event = manifest["event"]
        repo_checkouts = {}
        for repo_name in sorted(REPOSITORY_URLS):
            checkout = run_root / "source" / repo_name
            repo_checkouts[repo_name] = checkout
            extras = {}
            expected_tree = None
            if repo_name == event["repository"]:
                expected_tree = event["head_tree"]
                extras = {"event_base": event["base_commit"],
                          "event_control": event["control_commit"]}
            direct_only = ({"policy_base": event["policy_base_commit"]}
                           if repo_name == "openwrt" else {})
            repo_receipt = _acquire_repository(repo_name, pins[repo_name], checkout,
                                               home=home, tmp=tmp,
                                               expected_tree=expected_tree,
                                               extra_objects=extras,
                                               direct_only_objects=direct_only)
            receipt["canonical_source_checkouts"][repo_name] = repo_receipt
            total_objects += repo_receipt["object_store_bytes"]
            if total_objects > MAX_TOTAL_OBJECT_BYTES:
                raise PreflightError("total source object stores exceed byte budget")
            total_worktree += repo_receipt["materialized_worktree_bytes"]
            if total_worktree > MAX_TOTAL_WORKTREE_BYTES:
                raise PreflightError("total materialized source trees exceed byte budget")
        openwrt_info = receipt["canonical_source_checkouts"].get("openwrt")
        if event["repository"] == "openwrt":
            parent_rows = openwrt_info["commit_parent_records"]["parents"]
            if not parent_rows or parent_rows[0] != event["first_parent_commit"]:
                raise PreflightError("canonical event commit first parent differs from manifest")
            for label, oid in controls.items():
                if openwrt_info["additional_objects"].get(label, {}).get("commit") != oid:
                    raise PreflightError(f"canonical event {label} object was not verified")
            if openwrt_info["additional_objects"]["event_base"]["tree"] != event["base_tree"]:
                raise PreflightError("canonical event first-parent tree differs from manifest")
        receipt["canonical_source_checkouts_total_object_bytes"] = total_objects
        receipt["canonical_source_checkouts_total_worktree_bytes"] = total_worktree
        policy_base_git = openwrt_info["direct_only_fetches"].get("policy_base", {})
        try:
            token = _api_token()
            delta, _raw_api = _canonical_tree_pair(
                event["policy_base_commit"], event["head_commit"],
                api_dir=run_root / "api", token=token, policy=policy,
                direct_git_fetch=policy_base_git, home=home, tmp=tmp)
            if delta["head_tree"] != openwrt_info["tree"]:
                raise PreflightError("canonical API event tree differs from fetched source commit tree")
            if delta["base_tree"] != POLICY_BASE_TREE:
                raise PreflightError("canonical API base tree differs from reviewed policy-base tree")
            if policy_base_git.get("status") == "direct_sha_fetch_verified" and \
                    policy_base_git.get("tree") != delta["base_tree"]:
                raise PreflightError("canonical API base tree differs from direct Git policy-base object")
            receipt["policy_base_provenance"] = delta
        except PreflightError as exc:
            receipt["policy_base_provenance"] = {
                "status": "unresolved", "policy_base_commit": event["policy_base_commit"],
                "local_cache_used": False,
                "failure": str(exc),
                "direct_git_fetch": policy_base_git,
                "canonical_api_tree_delta_verified": False,
                "policy_base_git_commit_object_acquired":
                    policy_base_git.get("status") == "direct_sha_fetch_verified",
            }
        oracle_code, oracle_raw, oracle_stderr, oracle_elapsed, oracle_argv = _run_oracle(
            snapshots, repo_checkouts, run_root, home, tmp, timeout=MAX_ORACLE_SECONDS)
        oracle = json.loads(oracle_raw, object_pairs_hook=_unique_object) if oracle_raw else {}
        for repo_name, checkout in repo_checkouts.items():
            clean = _git_text(checkout, ["status", "--porcelain=v1", "--untracked-files=all"],
                              home=home, tmp=tmp)[0] == ""
            if not clean or not _is_read_only(checkout):
                raise PreflightError(f"{repo_name} checkout changed during source verification")
            receipt["canonical_source_checkouts"][repo_name]["clean_after_oracle"] = clean
        receipt["source_oracle"] = {
            "receipt_path": str(run_root / "source-oracle.json"),
            "sha256": hashlib.sha256(oracle_raw).hexdigest() if oracle_raw else None,
            "bytes": len(oracle_raw), "exit_code": oracle_code,
            "elapsed_seconds": oracle_elapsed,
            "argv": oracle_argv,
            "stderr": oracle_stderr.decode("utf-8", "replace")[:2000],
            "status": oracle.get("status"),
            "selected": oracle.get("selected"), "excluded": oracle.get("excluded"),
            "route_classes": oracle.get("route_classes"),
            "tracked_candidate_signals_accounted_for": oracle.get(
                "tracked_candidate_signals_accounted_for"),
            "outside_frozen_denominator_count": len(
                oracle.get("source_candidates_outside_frozen_denominator", [])),
            "canonical_git_provenance_verified_by_verifier": oracle.get(
                "canonical_git_provenance_verified"),
        }
        receipt["status"], result = _final_status(
            receipt["policy_base_provenance"].get("status", "unresolved"),
            receipt["policy_base_provenance"].get("canonical_api_tree_delta_verified") is True,
            oracle_code)
    except (PreflightError, OSError, ValueError, KeyError, TypeError,
            UnicodeError, subprocess.SubprocessError) as exc:
        receipt["status"] = "preflight_rejected"
        receipt["failure"] = f"{type(exc).__name__}: {exc}"
        result = EXIT_REJECTED
    receipt["elapsed_seconds"] = round(time.monotonic() - started, 6)
    receipt["git_commands"] = _COMMAND_LOG
    receipt["api_requests"] = _API_REQUEST_LOG
    receipt["api_auth_source"] = _API_AUTH_SOURCE
    receipt["api_raw_inventory"] = [
        {"name": path.name, "bytes": path.stat().st_size,
         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in sorted((run_root / "api").iterdir()) if path.is_file()]
    cache_path = Path(launcher_cache["path"])
    cache_still_empty = cache_path.is_dir() and not any(cache_path.iterdir())
    receipt["launcher_bytecode_cache"]["empty_after_run"] = cache_still_empty
    if not cache_still_empty:
        receipt["status"] = "launcher_bytecode_cache_changed"
        result = EXIT_REJECTED
    if receipt["elapsed_seconds"] > MAX_TOTAL_SECONDS:
        receipt["status"] = "total_time_budget_exceeded"
        result = EXIT_REJECTED
    _save_receipt(run_root, receipt)
    return result, receipt


def main(argv: list[str] | None = None) -> int:
    global _ACTIVE_RUN_ROOT
    actual_argv = sys.argv[1:] if argv is None else argv
    if actual_argv and actual_argv[0] == "--api-worker":
        return _api_worker_main(actual_argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--coverage", required=True, type=Path)
    parser.add_argument("--routing", required=True, type=Path)
    parser.add_argument("--policy", type=Path,
                        help="optional exact-digest v0.6 policy; defaults to docs/current-corpus-source-v0.6.json")
    args = parser.parse_args(actual_argv)
    try:
        code, receipt = run(args)
    except (PreflightError, OSError, ValueError) as exc:
        if _ACTIVE_RUN_ROOT is not None:
            failure_path = _ACTIVE_RUN_ROOT / "preflight-failure.json"
            try:
                failure = {"schema": "canonical-source-acquisition-preflight-failure-v1",
                           "status": "preflight_rejected",
                           "run_root": str(_ACTIVE_RUN_ROOT),
                           "failure": f"{type(exc).__name__}: {exc}"}
                _write_exclusive(failure_path,
                                 (json.dumps(failure, indent=2, sort_keys=True) + "\n").encode(),
                                 mode=0o400)
            except OSError:
                pass
        print(f"canonical source preflight rejected: {exc}", file=sys.stderr)
        return EXIT_REJECTED
    policy_base = receipt.get("policy_base_provenance", {})
    print(json.dumps({"status": receipt.get("status"),
                      "receipt": str(Path(receipt["run_root"]) / "preflight-receipt.json"),
                      "source_oracle": receipt.get("source_oracle"),
                      "policy_base_provenance": {
                          "status": policy_base.get("status"),
                          "policy_base_commit": policy_base.get(
                              "base_commit", policy_base.get("policy_base_commit")),
                          "policy_base_git_commit_object_acquired": policy_base.get(
                              "policy_base_git_commit_object_acquired"),
                          "recipe_delta_clear_under_frozen_policy": policy_base.get(
                              "recipe_delta_clear_under_frozen_policy")}},
                     sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
