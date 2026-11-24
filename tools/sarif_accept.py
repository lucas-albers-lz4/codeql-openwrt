"""Fail-closed check of a fresh producer SARIF packet against a source-first manifest.

This validates consistency of supplied bytes. It cannot authenticate an arbitrary
receipt; CI must generate the receipt and hand this module the actual output.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

SCHEMA = "ucode-sarif-acceptance-v1"
EVENT_SCHEMA = "ucode-sarif-event-triage-v1"
RUN_SCHEMA = "ucode-sarif-run-v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_object(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"expected JSON object: {path}")
    return data


def relative_uri(uri: str) -> str:
    require(isinstance(uri, str) and uri, "empty or non-string SARIF URI")
    parts = urlsplit(uri)
    require(not (parts.scheme or parts.netloc or parts.query or parts.fragment),
            f"URI must be relative and unqualified: {uri!r}")
    path = unquote(parts.path)
    require(path and not path.startswith("/") and "\\" not in path,
            f"URI must be a relative POSIX path: {uri!r}")
    components = PurePosixPath(path).parts
    require(all(part not in (".", "..") for part in components) and
            str(PurePosixPath(path)) == path,
            f"URI contains unsafe or noncanonical path: {uri!r}")
    return path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def result_tuple(result: dict, levels: dict[str, str]) -> tuple:
    rule = result.get("ruleId")
    require(isinstance(rule, str) and rule in levels, f"unknown SARIF rule: {rule!r}")
    locations = result.get("locations")
    require(isinstance(locations, list) and len(locations) == 1,
            "each accepted result needs exactly one primary location")
    physical = locations[0].get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    require(artifact.get("uriBaseId") == "%SRCROOT%", "unexpected SARIF URI base")
    uri = relative_uri(artifact.get("uri"))
    region = physical.get("region", {})
    start_line, start_col = region.get("startLine"), region.get("startColumn")
    end_line, end_col = region.get("endLine", start_line), region.get("endColumn")
    require(all(isinstance(n, int) and not isinstance(n, bool) and n >= 1
                for n in (start_line, start_col, end_line, end_col)),
            "missing or invalid SARIF region")
    require((end_line, end_col) >= (start_line, start_col), "reversed SARIF region")
    level = result.get("level", levels[rule])
    require(level in ("error", "warning", "note"), "invalid effective SARIF level")
    return (rule, uri, start_line, start_col, end_line, end_col, level)


def expected_tuple(item: dict) -> tuple:
    require(isinstance(item, dict), "expected result must be an object")
    return (item["rule_id"], relative_uri(item["uri"]), item["start_line"],
            item["start_column"], item["end_line"], item["end_column"],
            item["level"])


def inspect(sarif_path: Path, manifest_path: Path, receipt_path: Path,
            source_root: Path, *, event: bool = False) -> dict:
    manifest, receipt, sarif = map(load_object,
                                   (manifest_path, receipt_path, sarif_path))
    require(manifest.get("schema") == (EVENT_SCHEMA if event else SCHEMA),
            "wrong acceptance manifest schema")
    require(receipt.get("schema") == RUN_SCHEMA, "wrong producer receipt schema")
    require(manifest.get("producer") == receipt.get("producer"),
            "producer/release identity mismatch")
    require(isinstance(receipt.get("run_id"), str) and receipt["run_id"],
            "missing CI run identity")
    require(receipt.get("sarif_sha256") == sha256(sarif_path),
            "SARIF bytes differ from producer receipt")
    commands = receipt.get("commands")
    require(isinstance(commands, list) and commands and all(
        isinstance(c, dict) and c.get("exit") == 0 and
        isinstance(c.get("argv"), list) and c["argv"] for c in commands),
        "missing or failed producer command")
    require(receipt.get("extraction_errors") == [], "extraction errors")
    expected_files = manifest.get("expected_extracted")
    actual_files = receipt.get("successful_files")
    require(isinstance(expected_files, list) and isinstance(actual_files, list),
            "missing extracted-file inventory")
    normalized_expected = list(map(relative_uri, expected_files))
    require(len(normalized_expected) == len(set(normalized_expected)),
            "duplicate expected extracted-file identity")
    require(Counter(map(relative_uri, actual_files)) ==
            Counter(normalized_expected),
            "successful-file multiset differs from source-first expectation")
    sources = manifest.get("sources")
    require(isinstance(sources, list) and sources, "missing source list")
    allowed = set()
    for source in sources:
        require(isinstance(source, dict), "invalid source record")
        uri = relative_uri(source.get("uri"))
        require(uri not in allowed, f"duplicate source URI: {uri}")
        allowed.add(uri)
        digest = source.get("sha256")
        require(isinstance(digest, str) and len(digest) == 64,
                f"missing SHA-256 for {uri}")
        path = source_root / uri
        require(path.is_file() and path.resolve().is_relative_to(source_root.resolve()),
                f"missing or escaping source: {uri}")
        require(sha256(path) == digest, f"source-byte mismatch: {uri}")
    require(allowed == set(normalized_expected),
            "source records differ from extraction inventory")
    require(sarif.get("version") == "2.1.0", "unsupported SARIF version")
    runs = sarif.get("runs")
    require(isinstance(runs, list) and len(runs) == 1, "expected one SARIF run")
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    require(driver.get("name") == "CodeQL" and
            driver.get("semanticVersion") == manifest["producer"]["codeql_version"],
            "unexpected SARIF producer/tool version")
    require(run.get("columnKind") == "utf16CodeUnits",
            "unexpected SARIF column convention")
    invocations = run.get("invocations")
    require(isinstance(invocations, list) and invocations and
            all(i.get("executionSuccessful") is True for i in invocations),
            "SARIF reports failed or missing invocation")
    rules = driver.get("rules")
    require(isinstance(rules, list), "missing SARIF rule descriptors")
    levels = {}
    for rule in rules:
        rule_id = rule.get("id")
        require(isinstance(rule_id, str) and rule_id and rule_id not in levels,
                "duplicate or invalid rule descriptor")
        levels[rule_id] = rule.get("defaultConfiguration", {}).get("level")
    expected_rules = manifest.get("expected_rules")
    resolved_rules = receipt.get("resolved_rules")
    require(isinstance(expected_rules, list) and expected_rules and
            all(isinstance(rule, str) and rule for rule in expected_rules) and
            len(set(expected_rules)) == len(expected_rules),
            "missing or duplicated expected suite rule")
    require(isinstance(resolved_rules, list) and
            all(isinstance(rule, str) and rule for rule in resolved_rules) and
            len(set(resolved_rules)) == len(resolved_rules) and
            set(resolved_rules) == set(expected_rules),
            "resolved suite rule set differs from manifest")
    expected_descriptors = manifest.get("expected_sarif_descriptors")
    require(isinstance(expected_descriptors, list) and
            all(isinstance(rule, str) and rule for rule in expected_descriptors) and
            len(set(expected_descriptors)) == len(expected_descriptors) and
            set(expected_descriptors).issubset(expected_rules),
            "invalid expected SARIF descriptor set")
    require(set(levels) == set(expected_descriptors),
            "SARIF rule descriptors differ from manifest")
    results = run.get("results", [])
    require(isinstance(results, list), "invalid SARIF results")
    actual = Counter(result_tuple(item, levels) for item in results)
    require(all(uri in allowed for _, uri, *_ in actual),
            "SARIF result refers to source outside selected stage")
    if event:
        require("expected_results" not in manifest,
                "event triage cannot borrow output-generated expected results")
    else:
        expected = manifest.get("expected_results")
        require(isinstance(expected, list), "missing expected results")
        wanted = Counter(expected_tuple(item) for item in expected)
        require(actual == wanted, f"SARIF result multiset mismatch: got {actual}, wanted {wanted}")
    rows = [dict(zip(("rule_id", "uri", "start_line", "start_column",
                      "end_line", "end_column", "level"), row))
            for row in sorted(actual.elements())]
    packet = {"schema": EVENT_SCHEMA if event else SCHEMA, "run_id": receipt["run_id"],
              "producer": manifest["producer"], "successful_files": sorted(actual_files),
              "sarif_sha256": receipt["sarif_sha256"]}
    if event:
        packet.update(status="triage_required" if actual else "clean_scan",
                      result_count=len(rows), results_for_triage=rows)
    else:
        packet["accepted_results"] = rows
    return packet


def accept(sarif_path: Path, manifest_path: Path, receipt_path: Path,
           source_root: Path) -> dict:
    return inspect(sarif_path, manifest_path, receipt_path, source_root)


def triage(sarif_path: Path, manifest_path: Path, receipt_path: Path,
           source_root: Path) -> dict:
    return inspect(sarif_path, manifest_path, receipt_path, source_root, event=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--event-triage", action="store_true",
                        help="retain structurally valid event alerts for review")
    args = parser.parse_args()
    evaluator = triage if args.event_triage else accept
    print(json.dumps(evaluator(args.sarif, args.manifest, args.receipt,
                               args.source_root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
