"""Read-only capture of a terminal failure for one authenticated start.

The key is supplied in process. No queue mutation, signer, artifact download,
or automatic retry is available from this module.
"""

import os
import sqlite3
import subprocess
from contextlib import ExitStack, suppress
from pathlib import Path
from typing import TypedDict

from tools import default_branch_authenticated_start as authenticated
from tools import default_branch_backlog_issued as issued
from tools import default_branch_live_observation as live
from tools import default_branch_private_final_capture as custody
from tools import default_branch_private_start as private
from tools import default_branch_reservation_reconcile as reconcile

SCHEMA = "operator-default-branch-failed-execution-bytes-v1"
CAPTURE_DIR = "failed-execution-captures"
ALLOWED_PAIRS = frozenset({(value, value) for value in issued.FAILURE_CONCLUSIONS})


class FailedExecutionError(ValueError):
    """The exact failure execution or its custody was not verified."""


class VerifiedFailedExecutionBytes(TypedDict):
    schema: str
    status: str
    verification_scope: str
    queue_id: str
    start_sha256: str
    observation_sha256: str
    repository: str
    workflow: str
    run_id: int
    attempt: int
    job_id: int
    consumer_commit: str
    terminal: dict
    observed_at: list[str]
    raw_files: dict
    fetches: list[dict]
    terminal_action_issued: bool
    receipt_sha256: str
    capture_path: str


def _need(condition, message):
    if not condition:
        raise FailedExecutionError(message)


def _start_bytes(root, key, expected):
    with custody._directory(None, root) as root_fd:
        conn, before = authenticated._open_read_only(root_fd)
        try:
            issued._check_v3_schema(conn)
            head = issued.verify_issued_chain(conn, key)
            _need(
                head["seq"] == head["action_count"] == 1
                and head["hmac_verified"]
                and head["sha256"] == expected["start_sha256"]
                and head["queue_id"] == expected["queue_id"],
                "authenticated issued head changed before start reread",
            )
            row = conn.execute(
                "SELECT document_json,action_sha256 FROM issued_actions WHERE seq=1"
            ).fetchone()
            _need(
                row is not None and row["action_sha256"] == head["sha256"],
                "authenticated start disappeared",
            )
            _, _, raw = issued._load_document(row["document_json"])
            _need(
                issued.digest(raw) == expected["start_sha256"],
                "authenticated start bytes changed",
            )
            after = authenticated._db_fingerprint(
                os.stat(issued.DATABASE_NAME, dir_fd=root_fd, follow_symlinks=False)
            )
            _need(after == before, "private database changed while reading start")
            authenticated._sidecars_absent(root_fd)
            return raw
        finally:
            conn.rollback()
            conn.close()


def _terminal(run, jobs, signed, start, run_id, attempt, observed):
    att, start_time, run_started, job_started, _ = start
    _need(
        type(run.get("id")) is int
        and run["id"] == run_id
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] == attempt
        and isinstance(run.get("repository"), dict)
        and type(run["repository"].get("id")) is int
        and run["repository"]["id"] == custody.REPOSITORY_ID
        and run["repository"].get("full_name") == reconcile.REPOSITORY
        and isinstance(run.get("head_repository"), dict)
        and type(run["head_repository"].get("id")) is int
        and run["head_repository"]["id"] == custody.REPOSITORY_ID
        and run["head_repository"].get("full_name") == reconcile.REPOSITORY
        and type(run.get("workflow_id")) is int
        and run["workflow_id"] == custody.WORKFLOW_ID
        and run.get("path") == reconcile.SCAN_WORKFLOW
        and run.get("event") == "workflow_dispatch"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == att["consumer_commit"]
        and run.get("status") == "completed",
        "terminal run differs from signed main workflow attempt",
    )
    rows = live._complete_listing(jobs, "jobs", "terminal jobs API")
    matches = [item for item in rows if item.get("name") == reconcile.SCAN_JOB]
    _need(len(matches) == 1, "signed scan job is absent or ambiguous")
    job = matches[0]
    pair = (run.get("conclusion"), job.get("conclusion"))
    _need(
        pair in ALLOWED_PAIRS
        and type(job.get("id")) is int
        and job["id"] == signed["job_id"]
        and type(job.get("run_id")) is int
        and job["run_id"] == run_id
        and type(job.get("run_attempt")) is int
        and job["run_attempt"] == attempt
        and job.get("head_sha") == att["consumer_commit"]
        and job.get("status") == "completed",
        "run and signed scan job lack one consistent terminal failure",
    )
    run_start = custody._time(run.get("run_started_at"), "terminal run start")
    job_start = custody._time(job.get("started_at"), "terminal job start")
    completed = custody._time(job.get("completed_at"), "terminal job completed")
    updated = custody._time(run.get("updated_at"), "terminal run updated")
    _need(
        run_start == run_started
        and job_start == job_started
        and run_start <= job_start <= start_time <= completed <= updated <= observed,
        "terminal time is inconsistent with authenticated sequence-one start",
    )
    return {
        "run_status": run["status"],
        "run_conclusion": pair[0],
        "job_status": job["status"],
        "job_conclusion": pair[1],
        "job_id": job["id"],
        "run_updated_at": run["updated_at"],
        "job_completed_at": job["completed_at"],
        "job_count": len(rows),
    }


def _network():
    # Reuse the canonical direct-200 HTTPS transport, without a ZIP callback.
    fetch, _ = custody._network()
    return fetch


def _capture(root, key, run_id, attempt, network):
    _need(
        type(run_id) is int
        and 0 < run_id <= issued.MAX_SQLITE_INT
        and type(attempt) is int
        and 0 < attempt <= issued.MAX_SQLITE_INT,
        "run ID and attempt are invalid",
    )
    signed = authenticated.verify_authenticated_start(root, key)
    _need(
        (signed["run_id"], signed["run_attempt"]) == (run_id, attempt),
        "requested execution differs from authenticated start",
    )
    start_raw = _start_bytes(root, key, signed)
    with custody._directory(None, root) as root_fd:
        start = custody._start_evidence(
            root_fd,
            start_raw,
            run_id,
            attempt,
            expected_entries={"receipt.json"}
            | {item[0] for item in custody.START_RAW.values()},
        )
    endpoint = f"repos/{reconcile.REPOSITORY}/actions/runs/{run_id}"
    endpoints = {
        "run": endpoint,
        "jobs": f"{endpoint}/attempts/{attempt}/jobs?per_page=100",
    }
    name = f"default-branch-failed-{run_id}-{attempt}"
    with ExitStack() as publisher:
        with ExitStack() as stack:
            root_fd = stack.enter_context(custody._directory(None, root))
            parent = stack.enter_context(
                custody._directory(root_fd, CAPTURE_DIR, create=True)
            )
            directory = stack.enter_context(
                custody._directory(parent, name, create=True, exclusive=True)
            )
            _need(
                set(os.listdir(directory)) == set(),
                "new failure capture directory is not empty",
            )
            fetch = network()
            files, requests, times, parsed, snapshots = {}, [], [], [], []
            for prefix in ("first", "second"):
                bodies = {}
                for role, url in endpoints.items():
                    raw, request = fetch(url, reconcile.MAX_API)
                    filename = f"{prefix}-{role}-api.json"
                    files[filename] = custody._write(
                        directory, filename, raw, reconcile.MAX_API
                    )
                    requests.append(request)
                    bodies[role] = reconcile.parse_json(raw, filename)
                observed = custody._now()
                times.append(custody._utc(observed))
                snapshots.append(bodies)
                parsed.append(
                    _terminal(
                        bodies["run"],
                        bodies["jobs"],
                        signed,
                        start,
                        run_id,
                        attempt,
                        observed,
                    )
                )
            _need(
                snapshots[0] == snapshots[1]
                and parsed[0] == parsed[1]
                and times[0] <= times[1],
                "canonical failure observations differ or clock moved backwards",
            )
            # Reauthenticate the same durable head and retained start after both
            # fresh observations. This is a read-only check, not a CAS guarantee.
            again = authenticated.verify_authenticated_start(root, key)
            _need(
                again == signed and _start_bytes(root, key, again) == start_raw,
                "authenticated start changed during terminal capture",
            )
            for filename, identity in files.items():
                raw = custody._read(directory, filename, reconcile.MAX_API)
                _need(
                    identity == {"size": len(raw), "sha256": reconcile.digest(raw)},
                    "raw API custody changed before receipt publication",
                )
            receipt = {
                "schema": SCHEMA,
                "status": "verified_failed_execution_bytes",
                "verification_scope": "read_only_authenticated_start_and_two_canonical_failure_observations",
                "queue_id": signed["queue_id"],
                "start_sha256": signed["start_sha256"],
                "observation_sha256": signed["observation_sha256"],
                "repository": reconcile.REPOSITORY,
                "workflow": signed["workflow"],
                "run_id": run_id,
                "attempt": attempt,
                "job_id": signed["job_id"],
                "consumer_commit": start[0]["consumer_commit"],
                "terminal": parsed[0],
                "observed_at": times,
                "raw_files": files,
                "fetches": requests,
                "terminal_action_issued": False,
            }
            receipt_raw = issued.canonical_bytes(receipt)
            receipt_identity = custody._write(
                directory, custody.PENDING_RECEIPT, receipt_raw, custody.MAX_RECEIPT
            )
            pending = os.stat(
                custody.PENDING_RECEIPT, dir_fd=directory, follow_symlinks=False
            )
            receipt_inode = (pending.st_dev, pending.st_ino)
            _need(
                set(os.listdir(directory)) == set(files) | {custody.PENDING_RECEIPT},
                "failure capture directory has unexpected entries",
            )
            publish_fd = os.dup(directory)

            @publisher.callback
            def close_publish_fd():
                with suppress(OSError):
                    os.close(publish_fd)

            result = {
                **receipt,
                "receipt_sha256": receipt_identity["sha256"],
                "capture_path": f"{CAPTURE_DIR}/{name}",
            }

        # The directory, parent and root post-use checks all succeeded before
        # the receipt is published. The pending bytes remain unauthoritative.
        custody._publish_receipt(publish_fd, receipt_raw)
        try:
            _need(
                custody._read(
                    publish_fd,
                    custody.RECEIPT,
                    custody.MAX_RECEIPT,
                    expected_inode=receipt_inode,
                )
                == receipt_raw,
                "published failure receipt differs",
            )
        except BaseException:
            os.unlink(custody.RECEIPT, dir_fd=publish_fd)
            os.fsync(publish_fd)
            raise
        return result


def capture_failed_execution(
    private_root: Path, key: bytes, run_id: int, attempt: int
) -> VerifiedFailedExecutionBytes:
    """Capture only an exact terminal failure; the key never leaves this call."""
    try:
        issued._validate_key(key)
        root = private._root_is_durable(
            private_root, Path(__file__).resolve().parents[1]
        )
        return _capture(root, key, run_id, attempt, _network)
    except FailedExecutionError:
        raise
    except (
        OSError,
        sqlite3.Error,
        subprocess.SubprocessError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        OverflowError,
    ):
        raise FailedExecutionError("failed-execution capture did not verify") from None
