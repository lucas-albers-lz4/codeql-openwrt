#!/usr/bin/env python3
"""Opt-in released R2.5 run for the exact current three-package LuCI profile."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
from urllib.parse import unquote, urlsplit

from tools import r25_package_handoff as handoff
from tools import r25_package_stage as stage
from tools.r3_linux_handoff import Run, bootstrap_verified_release, pinned

ROOT = Path(__file__).resolve().parents[1]
PROFILE_IDS = {"luci-base-cb87", "luci-app-adblock-fast", "luci-mod-status"}
SOURCE_NAMES = {"luci-base-cb87": "luci-base",
                "luci-app-adblock-fast": "luci-app-adblock-fast",
                "luci-mod-status": "luci-mod-status"}
EXPECTED_SOURCE_REVISIONS = {
    "openwrt": "4e9642517b48bae612ff10fb72fb9199e559500e",
    "luci": "cb87fe60e1e2e052af36a93647f2264577829e0a",
    "packages": "07e0d16305d2b5903b37ad7913e33e18795f81a4",
    "openwrt_tree": "328d4df01c038d365176b72753b778e10c3ff413",
    "luci_tree": "1d7bf89bc8708fca69d005b0690ca823c9071692",
    "packages_tree": "a6b0fc0935cbfeedb810e6e991b6940f71548ea7",
}
PINNED_ORACLES = {
    "luci-base-cb87": ("81a8dd0eb2d587db51ff08b4f7e97825ddd0f8c16dc255a1023b95b1032c2b52",
                       76, {"plain": 10, "markup": 8, "excluded": 58}),
    "luci-app-adblock-fast": ("f071c8d6f37e1e873cb5c7d549458e4ff77f9a1697fb595d2eaa147e24e760dc",
                               9, {"plain": 1, "markup": 0, "excluded": 8}),
    "luci-mod-status": ("987f4d79caac219d11f9e0da1878a85114744986d5705a77f23c860fce5a6a9e",
                         33, {"plain": 0, "markup": 1, "excluded": 32}),
}
PINNED_ARTIFACTS = {
    "luci-base-cb87": (45741119647, 15084046585,
        "8d8baeacb21e3699535969c1c2009d15d84ca5d8103c3fc7e94312db923d9236",
        "41376c6774b35ff140ff3fa441643a184be252070cd3f462f645c6a98e527d6b",
        "luci-base", "26.317.52279~1c75ea4", "x86_64", "luci-base.ipk", "issue173-lucibase-45741119647-1"),
    "luci-app-adblock-fast": (45748188587, 15087445880,
        "49367dcc1058f0ce1fec71079f64cbf42c4307de3c687c73da0e3f4c8c750807",
        "b3d18c736a970f0ba17919e1249c837dae393b04f5ec541950a6cce737110e0f",
        "luci-app-adblock-fast", "1.2.4-r4", "all", "luci-app-adblock-fast.ipk", "issue173-adblock-batches-45748188587-1"),
    "luci-mod-status": (45761966404, 15092505063,
        "7432735425f220c12c0a51acc7cc2ef16ae68d14f157a7d33fdb239bd1d55dd2",
        "bfa86d24ef4fcdd32e0343fc88322c6ef57417be88fe357323959ae80b9e611a",
        "luci-mod-status", "26.284.22350~8125d12", "x86_64", "luci-mod-status.ipk", "issue173-core-module-batches-45761966404-1"),
}
RUNNER_ID = "0480553ff6598438bbcaf7d973f8dfef20097728480a94cdcdea0f011b0611fa"
STAGE_HELPER_ID = "991c92bb72f5c7a048d25b12021ff03b28c2d3c462a977b6a596d070aa7122a9"
MEMBER_INDEX_SHA256 = "d5a9044b9e674eff5bb4d3c02083e0f0ccd836565a67f6ee3efdd16eb0693f78"
RELEASE_LOCK_SHA256 = "53ef87cdaa69ae58be3da9386f4e710050309368649f8ae886c0a7f9ee5c2526"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_pinned_release_lock(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    stage.need(digest(raw) == RELEASE_LOCK_SHA256,
               "R3 release lock differs from the reviewed immutable producer pin")
    lock = json.loads(raw)
    pinned(lock)
    return lock, raw


def load_current_lock(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    lock = json.loads(raw)
    stage.need(lock.get("schema") == "openwrt-r25-current-luci-package-lock-v1" and
               lock.get("profile_set") == "issue176-current-luci-cb87-v1",
               "unsupported current LuCI package profile set")
    stage.need(set(lock.get("packages", {})) == PROFILE_IDS,
               "current LuCI lane package allowlist changed")
    validated_lock, validated_raw = stage._load_lock(path, profile_set="current-luci")
    stage.need(validated_raw == raw and validated_lock == lock,
               "shared package lock validation differs from current preflight")
    producer = lock.get("producer", {})
    stage.need(producer.get("runner", {}).get("sha256") == RUNNER_ID and
               producer.get("stage_helper", {}).get("sha256") == STAGE_HELPER_ID and
               producer.get("source_revisions") == {
                   "openwrt": EXPECTED_SOURCE_REVISIONS["openwrt"],
                   "luci": EXPECTED_SOURCE_REVISIONS["luci"],
                   "packages": EXPECTED_SOURCE_REVISIONS["packages"]},
               "current lane producer interface/source pins changed")
    inventory = lock.get("member_inventory", {})
    inventory_path = ROOT / inventory.get("path", "")
    stage.need(inventory.get("sha256") == MEMBER_INDEX_SHA256 and
               inventory_path.is_file() and not inventory_path.is_symlink() and
               digest(inventory_path.read_bytes()) == MEMBER_INDEX_SHA256,
               "whole-package member inventory differs from frozen source packet")
    member_index = json.loads(inventory_path.read_text())
    stage.need(member_index.get("schema") == "issue176-observed-package-oracles-v1" and
               set(member_index.get("packages", {})) == set(SOURCE_NAMES.values()),
               "whole-package member inventory identities changed")
    for package_id, source_name in SOURCE_NAMES.items():
        profile = lock["packages"][package_id]
        expected = PINNED_ARTIFACTS[package_id]
        ipk = profile.get("ipk", {})
        package = profile.get("package", {})
        stage.need((ipk.get("run_id"), ipk.get("artifact_id"), ipk.get("archive_sha256"),
                    ipk.get("sha256"), package.get("name"), package.get("version"),
                    package.get("architecture"), ipk.get("filename"), ipk.get("artifact_name")) == expected,
                   f"artifact/control identity differs from reviewed pin: {package_id}")
        stage.need(profile.get("source_revisions") == EXPECTED_SOURCE_REVISIONS and
                   profile.get("expected_default_suite_result_count") == 0 and
                   "pre-run hypothesis" in profile.get("expected_count_basis", ""),
                   f"source pin or pre-run result hypothesis changed: {package_id}")
        oracle_info = profile.get("oracle", {})
        pinned_oracle_sha, pinned_count, pinned_routes = PINNED_ORACLES[package_id]
        oracle_path = ROOT / oracle_info.get("path", "")
        stage.need(oracle_info.get("sha256") == pinned_oracle_sha and
                   oracle_info.get("regular_member_count") == pinned_count and
                   oracle_info.get("route_counts") == pinned_routes and
                   oracle_path.is_file() and not oracle_path.is_symlink() and
                   digest(oracle_path.read_bytes()) == pinned_oracle_sha,
                   f"source-first oracle/profile counts changed: {package_id}")
        oracle, expected_rows = stage.validate_oracle(oracle_path.read_bytes(),
                                                       oracle_info["sha256"], profile)
        source_package = member_index["packages"][source_name]
        stage.need(source_package.get("ipk_sha256") == ipk.get("sha256") and
                   source_package.get("oracle_sha256") == oracle_info.get("sha256"),
                   f"whole-package inventory is not bound to the pinned IPK/oracle: {package_id}")
        rows = source_package["observed_members"]
        regular = [row for row in rows if row.get("type") == "file"]
        member_map = {row.get("path"): row for row in regular}
        stage.need(len(member_map) == len(regular) == len(expected_rows),
                   f"raw package member multiplicity differs from oracle: {package_id}")
        for name, oracle_row in expected_rows.items():
            row = member_map.get(name)
            stage.need(row is not None and row.get("sha256") == oracle_row["sha256"] and
                       isinstance(row.get("mode"), str) and len(row["mode"]) == 4 and
                       all(c in "01234567" for c in row["mode"]),
                       f"raw package member/hash/mode is absent from whole-package inventory: {package_id}/{name}")
        stage.need(len(rows) == member_index["packages"][source_name]["regular_member_count"],
                   f"whole-package raw row count changed: {package_id}")
    return lock, raw


def preserve_stage_archive(lane_root: Path, package_id: str,
                           profile: dict) -> dict:
    """Retain and verify one hidden-inclusive analysis-stage tar before producer execution."""
    archive_dir = lane_root / "stage-archives"
    if not archive_dir.exists():
        archive_dir.mkdir(mode=0o700)
    stage_root = lane_root / "stages" / package_id
    stage.need(stage_root.is_dir() and not stage_root.is_symlink(),
               f"analysis stage missing: {package_id}")
    oracle_path = ROOT / profile["oracle"]["path"]
    expected = {row["path"]: row["sha256"] for row in json.loads(
        oracle_path.read_text())["files"]}
    actual, actual_modes, stage_entries = {}, {}, {
        package_id: ("directory", stat.S_IMODE(stage_root.stat().st_mode))}
    for path in stage_root.rglob("*"):
        mode = path.lstat().st_mode
        stage.need(not stat.S_ISLNK(mode) and (stat.S_ISDIR(mode) or stat.S_ISREG(mode)),
                   f"unsafe stage entry: {package_id}/{path.relative_to(stage_root)}")
        rel = path.relative_to(stage_root).as_posix()
        kind = "directory" if stat.S_ISDIR(mode) else "file"
        stage_entries[f"{package_id}/{rel}"] = (kind, stat.S_IMODE(mode))
        if stat.S_ISREG(mode):
            stage.need(path.stat().st_nlink == 1,
                       f"analysis-stage file has a hardlink alias: {package_id}/{path}")
            actual[rel] = digest(path.read_bytes())
            actual_modes[rel] = f"{stat.S_IMODE(mode):04o}"
    stage.need(actual == expected, f"analysis-stage bytes differ from source oracle: {package_id}")
    archive_path = archive_dir / f"{package_id}.tar"
    stage.need(not archive_path.exists() and not archive_path.is_symlink(),
               f"stage preservation archive already exists: {package_id}")
    with tarfile.open(archive_path, "x") as archive:
        archive.add(stage_root, arcname=package_id, recursive=True)
    with tarfile.open(archive_path, "r:") as archive:
        tar_files, tar_entries, names = {}, {}, set()
        for member in archive:
            stage.need(member.name not in names, f"duplicate retained stage path: {member.name}")
            names.add(member.name)
            stage.need(member.isfile() or member.isdir(),
                       f"nonregular retained stage member: {package_id}/{member.name}")
            stage.need(member.name == package_id or member.name.startswith(package_id + "/"),
                       f"retained stage archive path escapes package prefix: {member.name}")
            kind = "directory" if member.isdir() else "file"
            tar_entries[member.name] = (kind, member.mode)
            if member.isfile():
                rel = member.name[len(package_id) + 1:]
                source_path = stage_root / rel
                stage.need(stat.S_IMODE(source_path.stat().st_mode) == member.mode and
                           source_path.stat().st_nlink == 1,
                           f"retained analysis-stage mode/link differs: {package_id}/{rel}")
                stream = archive.extractfile(member)
                stage.need(stream is not None, "retained stage member could not be read")
                tar_files[rel] = digest(stream.read())
        stage.need(tar_files == expected and tar_entries == stage_entries,
                   f"hidden-inclusive stage tar inventory/type/mode differs: {package_id}")
    return {
        "archive": archive_path.relative_to(lane_root).as_posix(),
        "archive_sha256": digest(archive_path.read_bytes()),
        "member_count": len(actual),
        "hidden_paths": sorted(name for name in actual if any(
            part.startswith(".") for part in Path(name).parts)),
        "analysis_stage_sha256_by_path": actual,
        "analysis_stage_mode_by_path": actual_modes,
        "note": "analysis copies are private 0600; original installed modes are bound separately by the whole-IPK member inventory and raw IPK",
    }


def write_stage_preservation(lane_root: Path, reports: dict) -> None:
    receipt = {"schema": "r25-current-luci-stage-preservation-v1", "packages": reports}
    (lane_root / "stage-preservation.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def audit_raw_producer_outputs(lane_root: Path, lock: dict,
                              resolved_query_paths: list[str]) -> dict:
    """Join raw released-runner query JSON to its independent stage and receipt rows."""
    audits = {}
    for package_id, profile in lock["packages"].items():
        run_root = lane_root / "producer-runs" / package_id
        stage_root = lane_root / "stages" / package_id
        receipt_path = run_root / "receipt.json"
        coverage_path = run_root / "output/coverage-manifest.json"
        successful_path = run_root / "output/success.json"
        errors_path = run_root / "output/errors.json"
        resolved_path = run_root / "output/resolved-suite.json"
        paths = (receipt_path, coverage_path, successful_path, errors_path, resolved_path)
        stage.need(all(path.is_file() and not path.is_symlink() for path in paths),
                   f"raw producer diagnostic or suite evidence missing: {package_id}")
        receipt = json.loads(receipt_path.read_text())
        coverage = json.loads(coverage_path.read_text())
        successes = json.loads(successful_path.read_text()).get("#select", {}).get("tuples")
        errors = json.loads(errors_path.read_text()).get("#select", {}).get("tuples")
        resolved = json.loads(resolved_path.read_text())
        producer_bundle = run_root / "bundle"
        stage.need(isinstance(successes, list) and isinstance(errors, list) and
                   isinstance(resolved, list),
                   f"raw diagnostics or resolved suite have invalid shape: {package_id}")
        resolved_relative = []
        for query_path in resolved:
            stage.need(isinstance(query_path, str) and Path(query_path).is_absolute(),
                       f"resolved suite query is not an absolute path: {package_id}")
            lexical_query = Path(query_path)
            query_file = lexical_query.resolve(strict=True)
            ql_src = (producer_bundle / "ql/src").resolve(strict=True)
            stage.need(lexical_query == query_file and
                       query_file.is_relative_to(ql_src) and query_file.is_file(),
                       f"resolved suite path escapes the producer-private bundle copy: {package_id}")
            resolved_relative.append(query_file.relative_to(ql_src).as_posix())
        stage.need(resolved_relative == resolved_query_paths,
                   f"raw resolved suite paths differ from verified R3 query identities: {package_id}")
        observed = Counter()
        for row in successes:
            stage.need(isinstance(row, list) and len(row) == 2 and row[1] == "" and
                       isinstance(row[0], dict) and isinstance(row[0].get("url"), dict),
                       f"malformed successful-file row: {package_id}")
            uri = row[0]["url"].get("uri")
            parsed = urlsplit(uri if isinstance(uri, str) else "")
            stage.need(parsed.scheme == "file" and parsed.netloc in ("", "localhost"),
                       f"successful-file URI is not local: {package_id}")
            lexical_target = Path(unquote(parsed.path))
            target = lexical_target.resolve(strict=True)
            stage_real = stage_root.resolve(strict=True)
            stage.need(lexical_target == target and uri == target.as_uri() and
                       target.is_relative_to(stage_real) and target.is_file(),
                       f"successful-file URI is aliased or escapes the exact staged package: {package_id}")
            cursor = stage_real
            for component in target.relative_to(stage_real).parts:
                cursor = cursor / component
                stage.need(not cursor.is_symlink(),
                           f"successful-file path traverses a symlink: {package_id}")
            rel = target.relative_to(stage_root.resolve(strict=True)).as_posix()
            stage.need(PurePosixPath(rel).as_posix() == rel,
                       f"noncanonical successful-file identity: {package_id}/{rel}")
            observed[rel] += 1
        oracle = json.loads((ROOT / profile["oracle"]["path"]).read_text())
        expected = Counter(row["path"] for row in oracle["files"] if row["expect_success"])
        stage.need(observed == expected,
                   f"raw success query multiset differs from oracle: {package_id}")
        stage.need(errors == receipt.get("extraction_errors") == [] and
                   receipt.get("successful_files") == dict(sorted(observed.items())),
                   f"raw diagnostic tuples disagree with producer receipt: {package_id}")
        stage.need(digest(resolved_path.read_bytes()) == coverage.get("resolved_suite_sha256") ==
                   receipt.get("resolved_suite_sha256") and
                   digest(coverage_path.read_bytes()) == receipt.get("coverage_manifest_sha256"),
                   f"raw resolved-suite/coverage digests disagree with receipt: {package_id}")
        audits[package_id] = {
            "success_json_sha256": digest(successful_path.read_bytes()),
            "errors_json_sha256": digest(errors_path.read_bytes()),
            "resolved_suite_sha256": digest(resolved_path.read_bytes()),
            "success_row_count": sum(observed.values()),
            "error_row_count": len(errors),
            "resolved_query_paths": resolved,
        }
    return audits


def run_current_lane(release_lock_path: Path, package_lock_path: Path,
                     run_root: Path, run_id: str) -> dict:
    # Validate every local pin before network access or any package execution.
    lock, package_lock_raw = load_current_lock(package_lock_path)
    release_lock, release_lock_raw = load_pinned_release_lock(release_lock_path)
    consumer_sha = handoff.subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = handoff.subprocess.check_output(
        ["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).strip()
    stage.need(not dirty, "consumer source checkout must be clean")
    run_root = Path(os.path.abspath(run_root))
    parent = run_root.parent
    stage.need(parent.is_dir() and not parent.is_symlink() and
               parent.resolve(strict=True) == parent and
               run_root.parent == parent and
               not run_root.exists() and not run_root.is_symlink(),
               "fresh run root must be a direct child of an existing physical directory")
    stage.need(shutil.disk_usage(parent).free >= 15 * 1024**3,
               "less than 15 GiB free before released package run")
    run = Run(run_root, run_id)
    (run.root / "preflight.json").write_text(json.dumps({
        "schema": "r25-current-luci-preflight-v1", "run_id": run_id,
        "consumer_sha": consumer_sha, "consumer_dirty": False,
        "release_lock_sha256": digest(release_lock_raw),
        "package_lock_sha256": digest(package_lock_raw),
        "package_allowlist": sorted(PROFILE_IDS),
        "package_default_suite_result_count": "pre-run source-derived hypothesis: zero per package",
        "actual_results_observed": False,
    }, indent=2, sort_keys=True) + "\n")
    bootstrap = bootstrap_verified_release(run, release_lock)
    preservation = {}
    lane_root = run.root / "r25-package"
    def retain_after_stage(package_id, _stage_root, _stage_receipt, _staged):
        preservation[package_id] = preserve_stage_archive(
            lane_root, package_id, lock["packages"][package_id])
        write_stage_preservation(lane_root, preservation)
    result = handoff.run_package_lane(run.root, run_id, release_lock_path,
                                      package_lock_path, profile_set="current-luci",
                                      after_stage=retain_after_stage)
    raw_audit = audit_raw_producer_outputs(run.root / "r25-package", lock,
                                           bootstrap["resolved_query_paths"])
    stage.need(package_lock_path.read_bytes() == package_lock_raw,
               "current package lock changed during the lane")
    stage.need(release_lock_path.read_bytes() == release_lock_raw,
               "R3 release lock changed during the lane")
    receipt = {"schema": "r25-current-luci-handoff-candidate-v1",
        "run_id": run_id, "consumer_sha": consumer_sha, "consumer_dirty": False,
        "release_bootstrap": {
            "release_commit": bootstrap["producer"]["sha"],
            "bundle_manifest_sha256": digest((bootstrap["bundle"] / "bundle-manifest.json").read_bytes()),
            "codeql_archive_sha256": digest(bootstrap["codeql_archive"].read_bytes()),
            "resolved_rules": bootstrap["resolved_rules"],
        }, "handoff": result, "stage_preservation": preservation,
        "raw_producer_output_audit": raw_audit,
        "disposition": "candidate evidence only; no automatic security or coverage conclusion"}
    (run.root / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: r25_current_luci_handoff.py RELEASE_LOCK CURRENT_PACKAGE_LOCK FRESH_RUN_ROOT RUN_ID", file=sys.stderr)
        return 2
    try:
        result = run_current_lane(Path(sys.argv[1]), Path(sys.argv[2]),
                                  Path(sys.argv[3]), sys.argv[4])
    except Exception as error:
        print(f"current LuCI R2.5 handoff failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
