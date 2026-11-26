#!/usr/bin/env python3
"""Run the frozen current-source corpus after a successful same-job R3 handoff.

The manifest is a source-staged oracle. No package-installed byte claim is made.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

from tools.r3_linux_handoff import (EXPECTED_QUERIES, ROOT, Run, digest,
                                    file_rows, need, pinned, query_id, write_json)

MANIFEST_SHA256 = "9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490"
PINS = {
    "luci": "b2e0be4b46ec0fd43394c081fa7c50657af14011",
    "openwrt": "bce40f6a15c273778061e8fceced7b9e0f58d99b",
    "packages": "07e0d16305d2b5903b37ad7913e33e18795f81a4",
}
REPOSITORIES = {
    "luci": "https://github.com/openwrt/luci.git",
    "openwrt": "https://github.com/openwrt/openwrt.git",
    "packages": "https://github.com/openwrt/packages.git",
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def relative_path(value: object) -> str:
    need(isinstance(value, str) and value and "\\" not in value, "invalid source/stage path")
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value and
         all(part not in (".", "..") for part in path.parts), "unsafe source/stage path")
    return value


def validate_manifest(manifest: dict) -> None:
    need(manifest.get("schema") == "mvp-bounded-corpus-v0.6", "unreviewed corpus schema")
    need(manifest.get("pins") == PINS, "unreviewed source pins")
    selected, excluded = manifest.get("selected"), manifest.get("excluded")
    need(isinstance(selected, list) and len(selected) == 128 and
         isinstance(excluded, list) and len(excluded) == 13, "corpus denominator changed")
    identities, staged = [], []
    routes = Counter()
    repos = Counter()
    for row in selected:
        need(isinstance(row, dict), "invalid selected row")
        repo = row.get("repo")
        need(repo in PINS and row.get("source_commit") == PINS[repo], "selected source pin mismatch")
        source = relative_path(row.get("source_path"))
        stage = relative_path(row.get("proposed_installed_path"))
        need(isinstance(row.get("source_sha256"), str) and HEX64.fullmatch(row["source_sha256"]) and
             isinstance(row.get("git_blob"), str) and HEX40.fullmatch(row["git_blob"]),
             "missing selected source digest/blob")
        route = row.get("expected_route")
        need(isinstance(route, dict) and route.get("classification") in ("plain", "markup") and
             isinstance(route.get("reason"), str) and route["reason"], "invalid expected route")
        identities.append((repo, source))
        staged.append(stage)
        repos[repo] += 1
        routes[route["classification"]] += 1
    need(len(set(identities)) == 128 and len(set(staged)) == 128, "duplicate selected identity/stage")
    need(repos == Counter({"luci": 65, "openwrt": 51, "packages": 12}) and
         routes == Counter({"plain": 93, "markup": 35}), "corpus selection/route count drift")
    excluded_ids = []
    for row in excluded:
        need(isinstance(row, dict) and row.get("repo") in PINS, "invalid excluded row")
        source = relative_path(row.get("source_path"))
        need(isinstance(row.get("sha256"), str) and HEX64.fullmatch(row["sha256"]),
             "missing excluded source digest")
        excluded_ids.append((row["repo"], source))
    need(len(set(excluded_ids)) == 13 and not set(identities).intersection(excluded_ids),
         "excluded/selected overlap or duplicate")


def source_bytes(path: Path) -> bytes:
    if path.is_symlink():
        return os.readlink(path).encode()
    need(path.is_file(), f"missing source: {path}")
    return path.read_bytes()


def index_and_validate_routes(run: Run, db: Path, stage: Path, codeql: Path,
                              common: Path, env: dict, manifest: dict) -> dict:
    route_path = db / "trap/ucode/routing.json"
    retained = run.root / "out/routing.json"
    try:
        run.call("db-index", [codeql, "database", "index-files", "--language=ucode",
                              "--include=**/*", f"--working-dir={stage}",
                              f"--common-caches={common}", "--threads=1", "--ram=2048", db], env=env)
    finally:
        if route_path.is_file():
            shutil.copyfile(route_path, retained)
    routing = json.loads(retained.read_text())
    actual_routes = Counter((d["installed_path"], d["classification"], d["reason"], d["status"])
                            for d in routing["decisions"])
    expected_routes = Counter((row["proposed_installed_path"],
                               row["expected_route"]["classification"],
                               row["expected_route"]["reason"],
                               "plain_route_selected" if row["expected_route"]["classification"] == "plain" else "inconclusive")
                              for row in manifest["selected"])
    need(actual_routes == expected_routes and routing.get("input_count") == 128 and
         routing.get("plain_count") == 93 and routing.get("markup_count") == 35 and
         routing.get("markup_inconclusive_count") == 35 and
         all(routing.get(k) == 0 for k in ("excluded_count", "uncertain_count", "duplicate_input_count")),
         "route identities/counts differ from source oracle")
    return routing


def run_current(lock_path: Path, manifest_path: Path, prior_root: Path, run_id: str) -> None:
    lock = json.loads(lock_path.read_text())
    pinned(lock)
    need(digest(manifest_path) == MANIFEST_SHA256, "current corpus manifest digest drift")
    manifest = json.loads(manifest_path.read_text())
    validate_manifest(manifest)
    prior = json.loads((prior_root / "receipt.json").read_text())
    need(prior.get("status") == "accepted" and
         prior.get("preflight", {}).get("run_id") == run_id and
         prior["preflight"].get("lock_sha256") == digest(lock_path),
         "fresh R3 handoff receipt absent or mismatched")
    release = lock["release"]
    need(prior["release"].get("tag") == release["tag"] and
         prior["release"].get("producer_commit") == release["commit"] and
         prior["release"].get("asset_sha256") == release["asset_sha256"] and
         prior["release"].get("isImmutable") is True and
         prior["codeql"].get("binary_sha256") == release["codeql_binary_sha256"],
         "prior handoff used a different release or CodeQL binary")
    consumer_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    need(consumer_sha == prior["preflight"].get("consumer_sha") and
         not subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).strip(),
         "consumer revision/dirty state changed after handoff")
    codeql = prior_root / "cli/codeql/codeql"
    original_bundle = prior_root / "bundle/codeql-ucode-linux"
    need(digest(codeql) == release["codeql_binary_sha256"] and
         digest(original_bundle / "bundle-manifest.json") == release["manifest_sha256"],
         "released tool or bundle changed after R3")
    free_bytes = shutil.disk_usage(prior_root).free
    need(free_bytes >= 5 * 1024**3 and (os.cpu_count() or 0) >= 2,
         "insufficient disk or CPU for current-corpus run")
    memory = Path("/proc/meminfo").read_text()
    available = re.search(r"(?m)^MemAvailable:\s*(\d+) kB$", memory)
    need(available is not None and int(available.group(1)) >= 2 * 1024**2,
         "less than 2 GiB available memory")
    run = Run(prior_root / "current-corpus", run_id)
    try:
        bundle = run.root / "bundle/codeql-ucode-linux"
        need(not any(path.is_symlink() for path in original_bundle.rglob("*")),
             "release bundle gained a symlink after R3")
        shutil.copytree(original_bundle, bundle, symlinks=True)
        suite = bundle / "ql/src/codeql-suites/code-scanning.qls"
        need(digest(suite) == release["suite_sha256"] and
             digest(bundle / "extractor-pack/tools/linux64/extractor") == release["extractor_sha256"],
             "copied release suite/extractor differs")
        for key, rel in (("library_lock_sha256", "ql/lib/codeql-pack.lock.yml"),
                         ("query_lock_sha256", "ql/src/codeql-pack.lock.yml")):
            need(digest(bundle / rel) == release[key], "copied release lock differs")
        dependencies = prior_root / "home/.codeql/packages"
        need(dependencies.is_dir(), "R3 locked dependencies missing")
        (run.root / "home/.codeql").mkdir(parents=True)
        shutil.copytree(dependencies, run.root / "home/.codeql/packages")
        run.env["PATH"] = str(codeql.parent) + os.pathsep + run.env.get("PATH", "")
        stage = run.root / "stage"
        repos = {}
        for name, pin in PINS.items():
            repo = run.root / "sources" / name
            run.call(f"{name}-init", ["git", "init", repo])
            run.call(f"{name}-remote", ["git", "-C", repo, "remote", "add", "origin", REPOSITORIES[name]])
            run.call(f"{name}-fetch", ["git", "-C", repo, "fetch", "--depth=1", "origin", pin])
            run.call(f"{name}-checkout", ["git", "-C", repo, "checkout", "--detach", pin])
            need(run.call(f"{name}-head", ["git", "-C", repo, "rev-parse", "HEAD"]).strip() == pin and
                 not run.call(f"{name}-status", ["git", "-C", repo, "status", "--porcelain=v1"]).strip(),
                 f"{name} checkout SHA/dirty mismatch")
            repos[name] = repo
        for index, row in enumerate(manifest["excluded"]):
            source = repos[row["repo"]] / row["source_path"]
            need(hashlib.sha256(source_bytes(source)).hexdigest() == row["sha256"],
                 f"excluded source mismatch: {row['source_path']}")
            if row.get("git_blob"):
                got = run.call(f"excluded-blob-{index:03d}", ["git", "-C", repos[row["repo"]], "rev-parse",
                                                   PINS[row["repo"]] + ":" + row["source_path"]]).strip()
                need(got == row["git_blob"], "excluded Git blob mismatch")
        for index, row in enumerate(manifest["selected"]):
            repo = repos[row["repo"]]
            source = repo / row["source_path"]
            need(source.is_file() and not source.is_symlink() and digest(source) == row["source_sha256"],
                 f"selected source mismatch: {row['source_path']}")
            got = run.call(f"selected-blob-{index:03d}", ["git", "-C", repo, "rev-parse",
                                                row["source_commit"] + ":" + row["source_path"]]).strip()
            need(got == row["git_blob"], "selected Git blob mismatch")
            target = stage / row["proposed_installed_path"]
            need(not target.exists(), "staged-path collision")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            need(digest(target) == row["source_sha256"], "stage/source byte mismatch")
        write_json(run.root / "preflight.json", {"run_id": run_id, "consumer_sha": consumer_sha,
                   "r3_receipt_sha256": digest(prior_root / "receipt.json"),
                   "manifest_sha256": digest(manifest_path), "release_tag": release["tag"],
                   "release_commit": release["commit"], "source_pins": PINS,
                   "free_disk_bytes": free_bytes, "cpu_count": os.cpu_count(),
                   "available_memory_kib": int(available.group(1)),
                   "selected_count": 128, "excluded_count": 13,
                   "actual_package_installed_bytes_verified": False,
                   "wifi_scripts_config_assumed": "CONFIG_WIFI_SCRIPTS_UCODE=y"})
        db = run.root / "db/current"
        common = run.root / "cache/common"
        compile_cache = run.root / "cache/compilation"
        search = os.pathsep.join(str(bundle / p) for p in ("extractor-pack", "ql/lib", "ql/src"))
        env = dict(run.env, CODEQL_UCODE_STAGED_ROOT=str(stage))
        run.call("db-init", [codeql, "database", "init", db, "--language=ucode",
                             f"--search-path={search}", f"--common-caches={common}",
                             f"--source-root={stage}"], env=env)
        routing = index_and_validate_routes(run, db, stage, codeql, common, env, manifest)
        out = run.root / "out"
        run.call("db-finalize", [codeql, "database", "finalize", db,
                                 f"--common-caches={common}"], env=env)
        diagnostics = {}
        for label, query in (("successful", "SuccessfullyExtractedFiles.ql"),
                             ("errors", "ExtractionErrors.ql")):
            bqrs = out / (label + ".bqrs")
            run.call(label + "-query", [codeql, "query", "run", bundle / "ql/src/diagnostics" / query,
                                        f"--database={db}", f"--search-path={search}",
                                        f"--common-caches={common}", f"--compilation-cache={compile_cache}",
                                        "--no-default-compilation-cache", "--threads=1", "--ram=2048",
                                        f"--output={bqrs}"])
            decoded = run.call(label + "-decode", [codeql, "bqrs", "decode", "--format=json",
                                                   "--entities=url,string", bqrs])
            (out / (label + ".json")).write_text(decoded)
            diagnostics[label] = json.loads(decoded)["#select"]["tuples"]
        successes = file_rows(diagnostics["successful"], stage)
        expected_files = [row["proposed_installed_path"] for row in manifest["selected"]]
        need(Counter(successes) == Counter(expected_files) and not diagnostics["errors"],
             "successful identity or extraction-error mismatch")
        decisions = {d["installed_path"]: d for d in routing["decisions"]}
        success_counts = Counter(successes)
        coverage = {"schema": "ucode-current-corpus-coverage-v0.6",
                    "source_manifest_sha256": digest(manifest_path),
                    "release_tag": release["tag"], "producer_commit": release["commit"],
                    "source_pins": PINS, "actual_package_installed_bytes_verified": False,
                    "counts": {"selected": 128, "extracted_once": 128, "errored": 0,
                               "modeled_markup_inconclusive": 35, "excluded": 13},
                    "selected": [{"repo": row["repo"], "source_commit": row["source_commit"],
                                  "source_path": row["source_path"],
                                  "source_sha256": row["source_sha256"],
                                  "git_blob": row["git_blob"],
                                  "staged_path": row["proposed_installed_path"],
                                  "route_classification": decisions[row["proposed_installed_path"]]["classification"],
                                  "route_reason": decisions[row["proposed_installed_path"]]["reason"],
                                  "route_status": decisions[row["proposed_installed_path"]]["status"],
                                  "extracted_count": success_counts[row["proposed_installed_path"]],
                                  "extraction_error_count": 0}
                                 for row in manifest["selected"]],
                    "excluded": manifest["excluded"]}
        write_json(out / "coverage-v0.6.json", coverage)
        resolved = json.loads(run.call("resolve-suite", [codeql, "resolve", "queries", "--format=json", suite,
                                                       f"--search-path={search}", f"--common-caches={common}"]))
        rules = []
        for path_text in resolved:
            path = Path(path_text).resolve()
            need(path.is_relative_to((bundle / "ql/src").resolve()), "suite query outside release bundle")
            rel = path.relative_to(bundle / "ql/src").as_posix()
            need(rel in EXPECTED_QUERIES and query_id(path) == EXPECTED_QUERIES[rel],
                 "suite query path/ID mismatch")
            rules.append(EXPECTED_QUERIES[rel])
        need(Counter(rules) == Counter(release["expected_rules"]), "resolved suite changed")
        sarif = out / "default-suite.sarif"
        run.call("analyze", [codeql, "database", "analyze", db, suite, "--format=sarifv2.1.0",
                             f"--output={sarif}", f"--search-path={search}",
                             f"--common-caches={common}", f"--compilation-cache={compile_cache}",
                             "--no-default-compilation-cache", "--threads=1", "--ram=2048"])
        producer = {"sha": release["commit"], "pack_sha256": release["asset_sha256"],
                    "codeql_version": lock["codeql"]["version"], "suite_sha256": release["suite_sha256"]}
        acceptance = {"schema": "ucode-sarif-acceptance-v1", "producer": producer,
                      "sources": [{"uri": row["proposed_installed_path"], "sha256": row["source_sha256"]}
                                  for row in manifest["selected"]],
                      "expected_extracted": expected_files, "expected_rules": release["expected_rules"],
                      "expected_sarif_descriptors": ["ucode/m4/direct-rpc-shell-word"],
                      "expected_results": []}
        write_json(out / "source-first-acceptance.json", acceptance)
        receipt = {"schema": "ucode-sarif-run-v1", "run_id": run_id, "producer": producer,
                   "sarif_sha256": digest(sarif), "successful_files": successes,
                   "extraction_errors": diagnostics["errors"], "resolved_rules": rules,
                   "commands": list(run.commands), "route_sha256": digest(out / "routing.json"),
                   "consumer_sha": consumer_sha, "release_tag": release["tag"],
                   "codeql_binary_sha256": digest(codeql)}
        write_json(out / "producer-receipt.json", receipt)
        accepted_text = run.call("accept", [sys.executable, "-B", ROOT / "tools/sarif_accept.py",
                                                 "--sarif", sarif, "--manifest", out / "source-first-acceptance.json",
                                                 "--receipt", out / "producer-receipt.json", "--source-root", stage])
        (out / "accepted.json").write_text(accepted_text)
        for name, pin in PINS.items():
            repo = repos[name]
            need(subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                         text=True).strip() == pin and
                 not subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain=v1"],
                                             text=True).strip(),
                 f"{name} source checkout changed during run")
        for row in manifest["selected"]:
            need(digest(repos[row["repo"]] / row["source_path"]) == row["source_sha256"] and
                 digest(stage / row["proposed_installed_path"]) == row["source_sha256"],
                 f"selected source/stage changed during run: {row['source_path']}")
        for row in manifest["excluded"]:
            need(hashlib.sha256(source_bytes(repos[row["repo"]] / row["source_path"])).hexdigest()
                 == row["sha256"], f"excluded source changed during run: {row['source_path']}")
        write_json(run.root / "receipt.json", {"schema": "ucode-current-corpus-linux-v1",
                   "status": "accepted", "run_id": run_id, "release_tag": release["tag"],
                   "producer_commit": release["commit"], "consumer_sha": consumer_sha,
                   "manifest_sha256": digest(manifest_path), "source_pins": PINS,
                   "selected_count": len(expected_files), "route_counts": {k: routing.get(k) for k in
                    ("input_count", "plain_count", "markup_count", "markup_inconclusive_count",
                     "uncertain_count", "excluded_count", "duplicate_input_count")},
                   "successful_count": len(successes), "extraction_error_count": 0,
                   "coverage_sha256": digest(out / "coverage-v0.6.json"),
                   "resolved_rules": rules, "sarif_sha256": digest(sarif),
                   "accepted_sha256": digest(out / "accepted.json"),
                   "commands_sha256": digest(run.root / "commands.json"),
                   "actual_package_installed_bytes_verified": False})
    except Exception as exc:
        write_json(run.root / "failure.json", {"status": "failed, not a pass", "error": repr(exc),
                                              "commands_sha256": digest(run.root / "commands.json") if
                                              (run.root / "commands.json").exists() else None})
        raise


if __name__ == "__main__":
    need(len(sys.argv) == 5,
         "usage: current_corpus_linux.py RELEASE_LOCK CORPUS_MANIFEST R3_RUN_ROOT RUN_ID")
    run_current(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
