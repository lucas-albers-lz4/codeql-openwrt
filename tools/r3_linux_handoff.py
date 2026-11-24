#!/usr/bin/env python3
"""Run the pinned released ucode bundle through the historical OpenVPN consumer gate.

The lock is deliberately unpopulated until an immutable release is published.
This program is the trusted same-process-chain producer of sarif_accept inputs.
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
import time
from urllib.parse import unquote, urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_QUERIES = {
    "m4/DirectRpcShellWord.ql": "ucode/m4/direct-rpc-shell-word",
    "diagnostics/ExtractionErrors.ql": "ucode/diagnostics/extraction-errors",
    "diagnostics/SuccessfullyExtractedFiles.ql": "ucode/diagnostics/successfully-extracted-files",
}


def need(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def pinned(lock: dict) -> None:
    need(lock.get("schema") == "ucode-r3-release-lock-v1", "unsupported release lock")
    release, cli = lock.get("release", {}), lock.get("codeql", {})
    for name, value, pattern in (
        ("release commit", release.get("commit"), HEX40),
        ("release asset SHA", release.get("asset_sha256"), HEX64),
        ("manifest SHA", release.get("manifest_sha256"), HEX64),
        ("verifier SHA", release.get("verifier_sha256"), HEX64),
        ("suite SHA", release.get("suite_sha256"), HEX64),
        ("extractor SHA", release.get("extractor_sha256"), HEX64),
        ("library lock SHA", release.get("library_lock_sha256"), HEX64),
        ("query lock SHA", release.get("query_lock_sha256"), HEX64),
        ("CodeQL archive SHA", cli.get("sha256"), HEX64),
        ("CodeQL executable SHA", release.get("codeql_binary_sha256"), HEX64),
    ):
        need(isinstance(value, str) and bool(pattern.fullmatch(value)), f"unpopulated/invalid {name}")
    need(isinstance(release.get("tag"), str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", release["tag"]), "invalid release tag")
    repo = "https://github.com/lucas-albers-lz4/codeql-ucode"
    need(release.get("repository") == repo, "unexpected producer repository")
    need(release.get("asset_url") == f"{repo}/releases/download/{release['tag']}/codeql-ucode-linux-x64.tar.gz", "unreviewed release URL")
    need(cli.get("version") == "2.27.4" and cli.get("url") == "https://github.com/github/codeql-cli-binaries/releases/download/v2.27.4/codeql-linux64.zip", "unreviewed CodeQL URL/version")
    need(release.get("artifact_kind") == "versioned-release", "bundle must declare versioned release kind")
    packs = release.get("packs")
    need(isinstance(packs, dict) and set(packs) == {"library", "queries"}, "missing pack pins")
    for part, name in (("library", "lucas-albers-lz4/ucode-all"), ("queries", "lucas-albers-lz4/ucode-queries")):
        need(isinstance(packs.get(part), dict) and packs[part].get("name") == name and
             isinstance(packs[part].get("version"), str) and packs[part]["version"], "unreviewed pack name/version")
    need(release.get("expected_rules") == list(EXPECTED_QUERIES.values()), "unreviewed exact suite rules")
    need(isinstance(lock.get("source_oracle_sha256"), str) and
         HEX64.fullmatch(lock["source_oracle_sha256"]) is not None, "unpopulated source-oracle pin")


class Run:
    def __init__(self, root: Path, run_id: str):
        need(not root.exists(), f"run root already exists: {root}")
        root.mkdir(parents=True)
        self.root, self.run_id, self.commands = root.resolve(), run_id, []
        for sub in ("home", "tmp", "cache", "downloads", "sources", "stage", "db", "out", "commands"):
            (root / sub).mkdir()
        self.env = os.environ.copy()
        self.env.update(HOME=str(root / "home"), TMPDIR=str(root / "tmp"),
                        XDG_CACHE_HOME=str(root / "cache"), CODEQL_PLATFORM="linux64")

    def call(self, label: str, argv: list[str | Path], *, env: dict | None = None, cwd: Path = ROOT) -> str:
        need(re.fullmatch(r"[a-z0-9-]+", label) is not None, "unsafe command label")
        args = list(map(str, argv))
        base = self.root / "commands" / label
        started = time.monotonic()
        with base.with_suffix(".stdout").open("w") as out, base.with_suffix(".stderr").open("w") as err:
            proc = subprocess.run(["/usr/bin/time", "-v", "-o", str(base.with_suffix(".time")), *args],
                                  cwd=cwd, env=env or self.env, stdout=out, stderr=err, check=False)
        timing = base.with_suffix(".time").read_text(errors="replace")
        rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", timing)
        row = {"label": label, "argv": args, "cwd": str(cwd), "exit": proc.returncode,
               "wall_seconds": round(time.monotonic() - started, 3),
               "peak_rss_bytes": int(rss.group(1)) * 1024 if rss else None,
               "stdout": str(base.with_suffix(".stdout").relative_to(self.root)),
               "stderr": str(base.with_suffix(".stderr").relative_to(self.root)),
               "time": str(base.with_suffix(".time").relative_to(self.root))}
        self.commands.append(row)
        write_json(self.root / "commands.json", self.commands)
        need(proc.returncode == 0, f"{label} failed with {proc.returncode}; see {base}.stderr")
        if args[0].endswith("/codeql") and len(args) > 1 and args[1] in ("database", "query", "resolve"):
            stderr = base.with_suffix(".stderr").read_text()
            warnings = [line for line in stderr.splitlines() if re.search(r"\bWARNING:", line, re.IGNORECASE)]
            invalidating = [line for line in warnings if not re.search(
                r"WARNING: Not caching stages during query-loading, since max heap size is only \d+ MB\.", line)]
            need(not invalidating and not re.search(r"\bERROR:", stderr, re.IGNORECASE),
                 f"{label} emitted CodeQL warning/error requiring review: {invalidating}")
        return base.with_suffix(".stdout").read_text()


def safe_unzip(archive: Path, destination: Path) -> None:
    need(not destination.exists(), "CLI output directory already exists")
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        need(len(names) == len(set(names)) and names, "duplicate/empty CLI archive")
        for item in z.infolist():
            p = PurePosixPath(item.filename)
            need(p.parts and p.parts[0] == "codeql" and not p.is_absolute() and
                 ".." not in p.parts and "\\" not in item.filename and
                 (item.external_attr >> 16) & 0o170000 != 0o120000,
                 f"unsafe CLI archive member: {item.filename}")
        destination.mkdir()
        z.extractall(destination)
        for item in z.infolist():
            target = destination / item.filename
            if target.is_file():
                target.chmod((item.external_attr >> 16) & 0o777 or 0o644)
    binary = destination / "codeql" / "codeql"
    need(binary.is_file(), "CodeQL executable missing")
    binary.chmod(binary.stat().st_mode | 0o111)


def file_rows(rows: list, stage: Path) -> list[str]:
    result = []
    for row in rows:
        uri = row[0]["url"]["uri"]
        parsed = urlsplit(uri)
        need(parsed.scheme == "file" and not parsed.netloc, f"bad extracted URI: {uri}")
        path = Path(unquote(parsed.path)).resolve()
        need(path.is_relative_to(stage.resolve()), f"extracted path outside stage: {path}")
        result.append(path.relative_to(stage.resolve()).as_posix())
    return result


def query_id(path: Path) -> str:
    match = re.search(r"(?m)^\s*\*\s*@id\s+(\S+)", path.read_text())
    need(match is not None, f"query ID absent: {path}")
    return match.group(1)


def run_handoff(lock_path: Path, run_root: Path, run_id: str) -> None:
    lock = json.loads(lock_path.read_text())
    pinned(lock)
    oracle_path = ROOT / "docs/r3-openvpn-source-oracle.json"
    need(digest(oracle_path) == lock["source_oracle_sha256"], "source-oracle digest mismatch")
    oracle = json.loads(oracle_path.read_text())
    need(oracle.get("expected_rules") == list(EXPECTED_QUERIES.values()), "source oracle rule drift")
    need(len(oracle.get("cases", [])) == 2, "source oracle case drift")
    consumer_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    consumer_dirty = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).strip()
    need(not consumer_dirty and HEX40.fullmatch(consumer_sha), "consumer checkout must be clean")
    need(shutil.disk_usage(run_root.parent).free >= 15 * 1024**3, "less than 15 GiB free")
    run = Run(run_root, run_id)
    release, cli = lock["release"], lock["codeql"]
    preflight = {"consumer_sha": consumer_sha, "consumer_dirty": False, "lock_sha256": digest(lock_path),
                 "oracle_sha256": digest(oracle_path), "free_bytes": shutil.disk_usage(run_root).free,
                 "run_id": run_id, "run_root": str(run.root), "actual_package_installed_bytes_verified": False}
    write_json(run.root / "preflight.json", preflight)
    producer_git = run.root / "sources/producer.git"
    run.call("producer-init", ["git", "init", "--bare", producer_git])
    run.call("producer-remote", ["git", "--git-dir", producer_git, "remote", "add", "origin", release["repository"] + ".git"])
    run.call("producer-fetch-tag", ["git", "--git-dir", producer_git, "fetch", "--depth=1", "origin", "refs/tags/" + release["tag"] + ":refs/tags/" + release["tag"]])
    tag_commit = run.call("producer-tag-commit", ["git", "--git-dir", producer_git, "rev-parse", release["tag"] + "^{}"] ).strip()
    need(tag_commit == release["commit"], "release tag resolves to wrong producer commit")
    api = f"https://api.github.com/repos/lucas-albers-lz4/codeql-ucode/releases/tags/{release['tag']}"
    release_json = run.root / "downloads/release.json"
    run.call("release-api", ["curl", "--fail", "--location", "--retry", "3", "-H", "Accept: application/vnd.github+json", "--output", release_json, api])
    published = json.loads(release_json.read_text())
    immutable = json.loads(run.call("release-immutability", ["gh", "release", "view", release["tag"],
                       "--repo", "lucas-albers-lz4/codeql-ucode", "--json", "isImmutable"]))
    need(immutable.get("isImmutable") is True and not published.get("draft") and
         not published.get("prerelease"), "GitHub release is not immutable/published")
    need(published.get("tag_name") == release["tag"], "GitHub release tag mismatch")
    assets = [a for a in published.get("assets", []) if a.get("browser_download_url") == release["asset_url"]]
    need(len(assets) == 1, "pinned asset absent from immutable release")
    archive = run.root / "downloads/producer.tar.gz"
    cli_zip = run.root / "downloads/codeql-linux64.zip"
    run.call("producer-download", ["curl", "--fail", "--location", "--retry", "3", "--output", archive, release["asset_url"]])
    run.call("codeql-download", ["curl", "--fail", "--location", "--retry", "3", "--output", cli_zip, cli["url"]])
    need(digest(archive) == release["asset_sha256"] and digest(cli_zip) == cli["sha256"], "download archive digest mismatch")
    verifier = run.root / "downloads/verify-linux-release-bundle.py"
    run.call("fetch-verifier", ["git", "--git-dir", producer_git, "show", release["commit"] + ":scripts/verify-linux-release-bundle.py"])
    verifier.write_text((run.root / "commands/fetch-verifier.stdout").read_text())
    need(digest(verifier) == release["verifier_sha256"], "producer verifier digest mismatch")
    bundle_parent = run.root / "bundle"
    run.call("verify-extract-bundle", [sys.executable, "-B", verifier, "--archive", archive,
                                     "--expected-sha256", release["asset_sha256"], "--output-dir", bundle_parent,
                                     "--expected-release-tag", release["tag"],
                                     "--expected-producer-commit", release["commit"],
                                     "--expected-manifest-sha256", release["manifest_sha256"]])
    bundle = bundle_parent / "codeql-ucode-linux"
    manifest_path = bundle / "bundle-manifest.json"
    need(digest(manifest_path) == release["manifest_sha256"], "bundle manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text())
    need(manifest.get("artifact_kind") == "versioned-release" and
         manifest.get("release_tag") == release["tag"] and
         manifest.get("producer_commit") == release["commit"], "bundle provenance/kind mismatch")
    need(manifest["build"]["codeql_cli_linux_zip_sha256"] == cli["sha256"] and
         manifest["build"]["codeql_cli_version"] ==
         f"CodeQL command-line toolchain release {cli['version']}.", "bundle toolchain mismatch")
    need(manifest["build"]["built_extractor_sha256"] == release["extractor_sha256"], "extractor pin mismatch")
    for key, rel in (("library_lock_sha256", "ql/lib/codeql-pack.lock.yml"), ("query_lock_sha256", "ql/src/codeql-pack.lock.yml")):
        need(digest(bundle / rel) == release[key], f"{key} mismatch")
    packs = manifest["packs"]
    need(all(packs[part]["name"] == release["packs"][part]["name"] and
             packs[part]["version"] == release["packs"][part]["version"] for part in ("library", "queries")), "pack identities mismatch")
    suite = bundle / "ql/src" / packs["queries"]["default_suite"]
    need(digest(suite) == release["suite_sha256"], "suite digest mismatch")
    cli_root = run.root / "cli"
    safe_unzip(cli_zip, cli_root)
    codeql = cli_root / "codeql/codeql"
    version = run.call("codeql-version", [codeql, "version"])
    need(re.search(r"(?m)^CodeQL command-line toolchain release 2\.27\.4\.$", version) is not None, "CodeQL version mismatch")
    need(digest(codeql) == release["codeql_binary_sha256"], "CodeQL executable digest mismatch")
    run.env["PATH"] = str(codeql.parent) + os.pathsep + run.env.get("PATH", "")
    for part in ("lib", "src"):
        before = digest(bundle / "ql" / part / "codeql-pack.lock.yml")
        run.call(f"pack-install-{part}", [codeql, "pack", "install", bundle / "ql" / part], cwd=bundle)
        need(digest(bundle / "ql" / part / "codeql-pack.lock.yml") == before, f"{part} lock mutated")
    search = os.pathsep.join(str(bundle / p) for p in ("extractor-pack", "ql/lib", "ql/src"))
    resolved = json.loads(run.call("resolve-suite", [codeql, "resolve", "queries", "--format=json", suite, f"--search-path={search}"]))
    ids = []
    for path_text in resolved:
        path = Path(path_text).resolve()
        need(path.is_relative_to((bundle / "ql/src").resolve()), f"suite query outside bundle: {path}")
        rel = path.relative_to(bundle / "ql/src").as_posix()
        need(rel in EXPECTED_QUERIES, f"unexpected suite query: {rel}")
        got = query_id(path)
        need(got == EXPECTED_QUERIES[rel], f"query ID mismatch: {rel}")
        ids.append(got)
    need(Counter(ids) == Counter(release["expected_rules"]), "resolved suite rule set mismatch")
    producer = {"sha": release["commit"], "pack_sha256": release["asset_sha256"],
                "codeql_version": cli["version"], "suite_sha256": digest(suite)}
    summary = {"schema": "ucode-r3-linux-handoff-v1", "preflight": preflight,
               "release": {"tag": release["tag"], "asset_sha256": digest(archive), "manifest_sha256": digest(manifest_path),
                           "producer_commit": tag_commit, "isImmutable": immutable["isImmutable"]},
               "codeql": {"archive_sha256": digest(cli_zip), "binary_sha256": digest(codeql), "version": version.strip()},
               "packs": packs, "resolved_rules": ids, "network_dependency_bootstrap": True, "cases": {}}
    for case in oracle["cases"]:
        name, source = case["name"], case["source"]
        need(name in ("openvpn-parent", "openvpn-fixed"), "unexpected oracle case")
        repo = run.root / "sources" / name
        run.call(f"{name}-init", ["git", "init", repo])
        run.call(f"{name}-remote", ["git", "-C", repo, "remote", "add", "origin", source["repository"] + ".git"])
        run.call(f"{name}-fetch", ["git", "-C", repo, "fetch", "--depth=1", "origin", source["commit"]])
        run.call(f"{name}-checkout", ["git", "-C", repo, "checkout", "--detach", source["commit"]])
        need(run.call(f"{name}-head", ["git", "-C", repo, "rev-parse", "HEAD"]).strip() == source["commit"], "LuCI HEAD mismatch")
        need(not run.call(f"{name}-status", ["git", "-C", repo, "status", "--porcelain=v1"]).strip(), "LuCI checkout dirty")
        need(run.call(f"{name}-blob", ["git", "-C", repo, "rev-parse", source["commit"] + ":" + source["path"]]).strip() == source["git_blob"], "LuCI blob mismatch")
        src = repo / source["path"]
        need(digest(src) == source["sha256"], "LuCI source hash mismatch")
        stage = run.root / "stage" / name
        rel = case["proposed_stage_path"]
        staged = stage / rel
        staged.parent.mkdir(parents=True)
        shutil.copyfile(src, staged)
        need(digest(staged) == source["sha256"], "staged bytes mismatch")
        source_receipt = {"commit": source["commit"], "blob": source["git_blob"], "source_path": source["path"],
                          "source_sha256": digest(src), "stage_path": rel, "stage_sha256": digest(staged),
                          "actual_package_installed_bytes_verified": False}
        acceptance = {"schema": "ucode-sarif-acceptance-v1", "producer": producer,
                      "sources": [{"uri": rel, "sha256": source["sha256"]}], "expected_extracted": [rel],
                      "expected_rules": release["expected_rules"],
                      "expected_sarif_descriptors": case["expected_sarif_descriptors"],
                      "expected_results": case["expected_results"]}
        out = run.root / "out" / name
        out.mkdir()
        write_json(out / "source-first-manifest.json", acceptance)
        db = run.root / "db" / name
        db_cache = run.root / "cache" / "database" / name
        common = run.root / "cache" / "query" / name
        compile_cache = run.root / "cache" / "compile" / name
        for d in (db_cache, common, compile_cache):
            d.mkdir(parents=True)
        packages = run.root / "home/.codeql/packages"
        need(packages.is_dir(), "locked CodeQL dependencies missing")
        shutil.copytree(packages, common / "packages")
        env = dict(run.env, CODEQL_UCODE_STAGED_ROOT=str(stage))
        run.call(f"{name}-db-init", [codeql, "database", "init", db, "--language=ucode", f"--search-path={bundle / 'extractor-pack'}", f"--common-caches={db_cache}", f"--source-root={stage}"], env=env)
        run.call(f"{name}-db-index", [codeql, "database", "index-files", "--language=ucode", "--include=**/rpcd/ucode/*", f"--working-dir={stage}", f"--common-caches={db_cache}", db], env=env)
        route_path = db / "trap/ucode/routing.json"
        route = json.loads(route_path.read_text())
        expected_route = {"path": str(staged.resolve()), "installed_path": rel, "classification": "plain",
                          "reason": "rpcd_raw_mode_full_path", "status": "plain_route_selected"}
        need(route.get("decisions") == [expected_route] and route.get("input_count") == 1 and
             route.get("plain_count") == 1 and all(route.get(k) == 0 for k in
             ("excluded_count", "uncertain_count", "markup_count", "duplicate_input_count")), "route mismatch")
        shutil.copyfile(route_path, out / "routing.json")
        run.call(f"{name}-db-finalize", [codeql, "database", "finalize", db, f"--common-caches={db_cache}"], env=env)
        diagnostics = {}
        for key, query in (("successful", "SuccessfullyExtractedFiles.ql"), ("errors", "ExtractionErrors.ql")):
            q = bundle / "ql/src/diagnostics" / query
            bqrs = out / (key + ".bqrs")
            run.call(f"{name}-{key}-query", [codeql, "query", "run", q, f"--database={db}", f"--search-path={search}", f"--common-caches={common}", f"--compilation-cache={compile_cache}", "--no-default-compilation-cache", f"--output={bqrs}", "--threads=1", "--ram=2048"])
            decoded = run.call(f"{name}-{key}-decode", [codeql, "bqrs", "decode", "--format=json", "--entities=url,string", bqrs])
            (out / (key + ".json")).write_text(decoded)
            diagnostics[key] = json.loads(decoded)["#select"]["tuples"]
        successful = file_rows(diagnostics["successful"], stage)
        need(Counter(successful) == Counter([rel]) and diagnostics["errors"] == [], "diagnostic identity/error mismatch")
        sarif = out / "default-suite.sarif"
        run.call(f"{name}-analyze", [codeql, "database", "analyze", db, suite, "--format=sarifv2.1.0", f"--output={sarif}", f"--search-path={search}", f"--common-caches={common}", f"--compilation-cache={compile_cache}", "--no-default-compilation-cache", "--threads=1", "--ram=2048"])
        receipt = {"schema": "ucode-sarif-run-v1", "run_id": run_id, "producer": producer,
                   "sarif_sha256": digest(sarif), "successful_files": successful, "extraction_errors": diagnostics["errors"],
                   "resolved_rules": ids, "commands": list(run.commands), "source": source_receipt,
                   "route_sha256": digest(out / "routing.json"), "consumer_sha": consumer_sha,
                   "release_tag": release["tag"], "codeql_binary_sha256": digest(codeql)}
        write_json(out / "producer-receipt.json", receipt)
        accepted = run.call(f"{name}-accept", [sys.executable, "-B", ROOT / "tools/sarif_accept.py", "--sarif", sarif,
                        "--manifest", out / "source-first-manifest.json", "--receipt", out / "producer-receipt.json", "--source-root", stage])
        (out / "accepted.json").write_text(accepted)
        summary["cases"][name] = {"source": source_receipt, "routing_sha256": digest(out / "routing.json"),
                                  "successful_files": successful, "extraction_errors": [], "sarif_sha256": digest(sarif),
                                  "accepted": json.loads(accepted)}
        write_json(run.root / "receipt.json", summary)
    need(set(summary["cases"]) == {"openvpn-parent", "openvpn-fixed"}, "case set incomplete")
    summary["status"] = "accepted"
    summary["commands_sha256"] = digest(run.root / "commands.json")
    write_json(run.root / "receipt.json", summary)


if __name__ == "__main__":
    need(len(sys.argv) == 4, "usage: r3_linux_handoff.py LOCK NEW_RUN_ROOT RUN_ID")
    run_handoff(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
