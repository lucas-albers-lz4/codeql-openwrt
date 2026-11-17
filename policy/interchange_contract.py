"""Offline validation for typed records emitted by the ucode pack.

This intentionally implements only the JSON Schema keywords used by the
authoritative finding schema. A new keyword must be implemented here before
the schema can use it, so validation fails closed as the schema evolves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
TYPED_ARRAY_NAMES = {
    "m3-findings.json",
    "m4-findings.json",
    "m4-getfeatures-direct-exec.json",
    "m4-imported-callee-findings.json",
    "m4-shellquote-findings.json",
}
REPORT_ONLY_OBJECT_NAMES = {
    "m3-coverage.json",
    "m4-coverage.json",
    "m4-getfeatures-direct-exec-coverage.json",
    "m4-shellquote-coverage.json",
}


class ContractError(ValueError):
    """Raised when producer output violates the interchange contract."""


SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "enum",
    "items",
    "minimum",
    "allOf",
    "if",
    "then",
    "not",
}


def _check_schema_keywords(schema: Any, where: str = "schema") -> None:
    if not isinstance(schema, dict):
        raise ContractError(f"{where}: schema node must be an object")
    unknown = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    if unknown:
        raise ContractError(f"{where}: unsupported schema keyword(s): {', '.join(sorted(unknown))}")
    if "type" in schema and schema["type"] not in {
        "object", "array", "string", "integer", "number", "boolean", "null"
    }:
        raise ContractError(f"{where}.type: unsupported schema type {schema['type']!r}")
    if "required" in schema and (
        not isinstance(schema["required"], list)
        or not all(isinstance(key, str) for key in schema["required"])
    ):
        raise ContractError(f"{where}.required: expected an array of strings")
    if "enum" in schema and not isinstance(schema["enum"], list):
        raise ContractError(f"{where}.enum: expected an array")
    if "minimum" in schema and not isinstance(schema["minimum"], (int, float)):
        raise ContractError(f"{where}.minimum: expected a number")
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        raise ContractError(f"{where}.properties: expected object")
    for key, child in props.items():
        _check_schema_keywords(child, f"{where}.properties.{key}")
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, (bool, dict)):
        raise ContractError(f"{where}.additionalProperties: expected boolean or schema")
    if isinstance(additional, dict):
        _check_schema_keywords(additional, f"{where}.additionalProperties")
    if "items" in schema:
        _check_schema_keywords(schema["items"], f"{where}.items")
    for key in ("allOf",):
        if key in schema:
            value = schema[key]
            if not isinstance(value, list):
                raise ContractError(f"{where}.{key}: expected array")
            for index, child in enumerate(value):
                _check_schema_keywords(child, f"{where}.{key}[{index}]")
    for key in ("if", "then", "not"):
        if key in schema:
            _check_schema_keywords(schema[key], f"{where}.{key}")


def _matches_schema(instance: Any, schema: dict[str, Any]) -> bool:
    """Return whether instance matches schema; errors are reported separately."""
    if "type" in schema and not _has_type(instance, schema["type"]):
        return False
    if "enum" in schema and instance not in schema["enum"]:
        return False
    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        return False
    if isinstance(instance, dict):
        if any(key not in instance for key in schema.get("required", [])):
            return False
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                if not _matches_schema(value, properties[key]):
                    return False
            elif additional is False:
                return False
            elif isinstance(additional, dict) and not _matches_schema(value, additional):
                return False
    if isinstance(instance, list) and "items" in schema:
        if not all(_matches_schema(item, schema["items"]) for item in instance):
            return False
    if any(not _matches_schema(instance, child) for child in schema.get("allOf", [])):
        return False
    if "if" in schema and _matches_schema(instance, schema["if"]):
        if "then" in schema and not _matches_schema(instance, schema["then"]):
            return False
    if "not" in schema and _matches_schema(instance, schema["not"]):
        return False
    return True


def _has_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ContractError(f"unsupported schema type: {expected}")


def _validate(instance: Any, schema: dict[str, Any], where: str) -> list[str]:
    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type is not None and not _has_type(instance, expected_type):
        errors.append(f"{where}: expected {expected_type}")
        return errors
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{where}: value {instance!r} is not in enum {schema['enum']!r}")
    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        errors.append(f"{where}: value is below minimum {schema['minimum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{where}: missing required property {key!r}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                errors.extend(_validate(value, properties[key], f"{where}.{key}"))
            elif additional is False:
                errors.append(f"{where}.{key}: additional property is not allowed")
            elif isinstance(additional, dict):
                errors.extend(_validate(value, additional, f"{where}.{key}"))
    if isinstance(instance, list) and "items" in schema:
        for index, value in enumerate(instance):
            errors.extend(_validate(value, schema["items"], f"{where}[{index}]"))
    for child in schema.get("allOf", []):
        errors.extend(_validate(instance, child, where))
    if "if" in schema and _matches_schema(instance, schema["if"]):
        if "then" in schema:
            errors.extend(_validate(instance, schema["then"], where))
    if "not" in schema and _matches_schema(instance, schema["not"]):
        errors.append(f"{where}: matched a forbidden schema")
    return errors


def _read_document(path: Path) -> Any:
    """Decode a producer document without silently normalizing ambiguous JSON."""
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    except (OSError, ValueError) as exc:
        raise ContractError(f"{path}: cannot read JSON: {exc}") from exc


def _typed_arrays(ucode_root: Path) -> list[tuple[Path, list[dict[str, Any]]]]:
    docs = ucode_root / "docs"
    if not docs.is_dir():
        raise ContractError(f"ucode root has no docs directory: {docs}")
    result: list[tuple[Path, list[dict[str, Any]]]] = []
    for path in sorted(docs.glob("*.json")):
        value = _read_document(path)
        if path.name in TYPED_ARRAY_NAMES:
            if not isinstance(value, list):
                raise ContractError(f"{path}: expected typed record array")
            if not value:
                raise ContractError(f"{path}: typed record array must not be empty")
            if not all(isinstance(row, dict) and "record_type" in row for row in value):
                raise ContractError(f"{path}: expected only typed record objects")
            result.append((path, value))
        elif path.name in REPORT_ONLY_OBJECT_NAMES:
            if not isinstance(value, dict):
                raise ContractError(f"{path}: report-only coverage output must be an object")
        else:
            raise ContractError(f"{path}: unfamiliar docs JSON file; classify it as typed or report-only")
    if not result:
        raise ContractError(f"no typed record arrays found under {docs}")
    return result


def _load_grants(repo_root: Path) -> dict[str, dict[str, Any]]:
    path = repo_root / "policy" / "grants.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ContractError(f"{path}: expected an array")
    grants: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("record_id"), str) or not row["record_id"].strip():
            raise ContractError(f"{path}: grant record_id must be a nonempty string")
        if row["record_id"] in grants:
            raise ContractError(f"{path}: duplicate grant record_id {row['record_id']!r}")
        grants[row["record_id"]] = row
    return grants


def _grant_ref_values(row: dict[str, Any]) -> list[str]:
    refs = row.get("evidence_refs", [])
    if not isinstance(refs, list):
        return []
    return [ref for ref in refs if isinstance(ref, str) and ref.startswith("policy:grant:")]


def _join_error(row: dict[str, Any], grant: dict[str, Any], where: str) -> str | None:
    join_fields = ["corpus_revision", "profile", "ingress", "entrypoint_id"]
    if row.get("ingress") == "ubus_http":
        join_fields.extend(["ubus_object", "method"])
    elif row.get("ingress") == "cgi_io":
        join_fields.append("cgi_endpoint")
    for key in join_fields:
        left, right = row.get(key), grant.get(key)
        if not isinstance(left, str) or not left.strip() or not isinstance(right, str) or not right.strip():
            return f"{where}: cited grant is missing required join key {key}"
        if left != right:
            return f"{where}: cited grant has mismatched {key}: {right!r} != {left!r}"
    return None


def join_policy_grants(
    row: dict[str, Any], grants: dict[str, dict[str, Any]], *, scope: str,
    requested_caller: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve cited grants; supplementary aggregate links do not assess callers."""
    if scope not in {"aggregate", "caller"}:
        raise ContractError("unsupported join scope")
    if scope == "aggregate" and (row.get("record_type") != "handler_effect" or "session_class" in row or requested_caller is not None):
        raise ContractError("aggregate handler_effect must be session-neutral")
    if scope == "caller" and row.get("record_type") != "taint_path":
        raise ContractError("caller-specific scope requires taint_path")
    if "session_class" in row and (not isinstance(row["session_class"], str) or not row["session_class"].strip()):
        raise ContractError("session_class must be nonempty")
    if requested_caller is not None and (not isinstance(requested_caller, str) or not requested_caller.strip()):
        raise ContractError("requested session_class must be nonempty")
    refs = _grant_ref_values(row)
    expectation = row.get("expectation_id")
    assessed = row.get("assessment") in ("intended_access", "risky_delegation", "authorization_violation")
    if assessed and not refs:
        raise ContractError("authorization assessment requires a cited policy grant")
    if (assessed or (scope == "caller" and refs)) and (not isinstance(expectation, str) or not expectation.strip()):
        raise ContractError("assessment/grant requires nonempty expectation_id")
    primary, supplementary = [], []
    callers = set()
    for grant_id in refs:
        grant = grants.get(grant_id)
        if grant is None:
            raise ContractError(f"cited grant ID does not exist: {grant_id}")
        if grant.get("record_id") != grant_id or (grant.get("record_type"), grant.get("evidence_status"), grant.get("producer")) != ("policy_grant", "fact", "policy_facts"):
            raise ContractError(f"invalid cited policy grant: {grant_id}")
        mismatch = _join_error(row, grant, "join")
        if mismatch:
            raise ContractError(mismatch)
        if row.get("ingress") not in ("ubus_http", "cgi_io"):
            raise ContractError("unsupported policy-linked ingress")
        session = grant.get("session_class")
        if not isinstance(session, str) or not session.strip():
            raise ContractError("cited grant missing session_class")
        if not isinstance(grant.get("expectation_id"), str) or not grant["expectation_id"].strip():
            raise ContractError("cited grant missing expectation_id")
        if grant["expectation_id"] == expectation:
            primary.append(grant)
        else:
            supplementary.append(grant)
        callers.add(session)
    if scope == "caller":
        if supplementary:
            raise ContractError("cited grant has mismatched expectation_id")
        declared = row.get("session_class")
        if declared is not None:
            callers.add(declared)
        if requested_caller is not None:
            callers.add(requested_caller)
        if len(callers) > 1:
            raise ContractError("conflicting session_class among row, request and grants")
    if assessed and not primary:
        raise ContractError("assessment requires a primary expectation-matching grant")
    return primary, supplementary


def validate_ucode_root(ucode_root: Path, repo_root: Path = REPO_ROOT) -> tuple[int, int]:
    schema_path = repo_root / "schemas" / "finding.schema.json"
    lock_path = repo_root / "corpus" / "lock.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    _check_schema_keywords(schema)
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    expected_revision = "sha256:" + hashlib.sha256(lock_bytes).hexdigest()
    known_profiles: set[str] = set()
    for profile_path in (repo_root / "corpus" / "profiles").glob("*/profile.json"):
        profile_data = json.loads(profile_path.read_text(encoding="utf-8"))
        profile_name = profile_data.get("profile")
        if isinstance(profile_name, str):
            known_profiles.add(profile_name)
    grants = _load_grants(repo_root)
    files = _typed_arrays(ucode_root)
    manifest = json.loads((repo_root / "policy/ucode_snapshot_manifest.json").read_text(encoding="utf-8"))
    historical = {rid: (name, spec["rows"][rid], semantic)
                  for name, spec in manifest["typed"].items()
                  for rid, semantic in spec["semantics"].items()}
    historical_revisions = {spec["revision"] for spec in manifest["typed"].values()}
    row_count = 0
    errors: list[str] = []
    seen_record_ids: dict[str, Path] = {}
    for path, rows in files:
        spec = manifest["typed"][path.name]
        ids = [row.get("record_id") for row in rows]
        reserved = [row.get("analysis_revision") for row in rows
                    if isinstance(row.get("analysis_revision"), str)
                    and row["analysis_revision"] in historical_revisions]
        if any(revision != spec["revision"] for revision in reserved):
            errors.append(f"{path}: historical revision belongs to a different document family")
        if reserved or any(isinstance(rid, str) and rid in historical for rid in ids):
            if len(ids) != len(spec["rows"]) or any(rid not in ids for rid in spec["rows"]):
                errors.append(f"{path}: snapshot record identity mismatch")
        for index, row in enumerate(rows):
            where = f"{path}:{index}"
            row_count += 1
            errors.extend(_validate(row, schema, where))
            record_id = row.get("record_id")
            if not isinstance(record_id, str) or not record_id.strip():
                errors.append(f"{where}: record_id must be a nonempty string")
            elif record_id in seen_record_ids:
                errors.append(
                    f"{where}: duplicate record_id {record_id!r} also appears in {seen_record_ids[record_id]}"
                )
            else:
                seen_record_ids[record_id] = path
            if isinstance(record_id, str) and record_id in historical:
                expected_file, required_refs, semantic = historical[record_id]
                if path.name != expected_file:
                    errors.append(f"{where}: historical record identity belongs in {expected_file}")
                for key, value in semantic.items():
                    if key == "required_unknowns":
                        actual = row.get("unknowns")
                        if not isinstance(actual, list) or any(item not in actual for item in value):
                            errors.append(f"{where}: historical unknowns missing")
                    elif row.get(key) != value:
                        errors.append(f"{where}: historical {key} mismatch for {record_id}")
                refs = row.get("evidence_refs", [])
                if not isinstance(refs, list) or any(ref not in refs for ref in required_refs):
                    errors.append(f"{where}: historical required evidence missing")
            refs = row.get("evidence_refs", [])
            if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
                errors.append(f"{where}: evidence_refs must contain nonempty strings")
            unknowns = row.get("unknowns")
            if row.get("evidence_status") == "inconclusive" and (
                not isinstance(unknowns, list) or not any(isinstance(item, str) and item.strip() for item in unknowns)
            ):
                errors.append(f"{where}: inconclusive requires a nonempty unknowns entry")
            analysis_revision = row.get("analysis_revision")
            if (
                not isinstance(analysis_revision, str)
                or re.fullmatch(r"step3:[^\s:]+", analysis_revision) is None
            ):
                errors.append(f"{where}: analysis_revision must be a nonempty producer-local 'step3:' revision")
            if row.get("corpus_revision") != expected_revision:
                errors.append(f"{where}: corpus_revision does not match sha256(corpus/lock.json)")
            if not isinstance(row.get("profile"), str) or row["profile"] not in known_profiles:
                errors.append(f"{where}: unknown profile {row.get('profile')!r}")
            elif row["profile"] != "luci-ssl-25.12":
                errors.append(f"{where}: unsupported ucode profile {row['profile']!r}")
            if row.get("producer") != "step3":
                errors.append(f"{where}: ucode records must use producer 'step3'")
            if row.get("record_type") not in ("handler_effect", "taint_path"):
                errors.append(f"{where}: record_type is not a supported ucode capability")
            if row.get("record_type") in ("handler_effect", "taint_path"):
                try:
                    join_policy_grants(row, grants, scope="aggregate" if row["record_type"] == "handler_effect" else "caller")
                except ContractError as exc:
                    errors.append(f"{where}: {exc}")
    for name, spec in manifest["coverage"].items():
        path = ucode_root / "docs" / name
        if path.exists():
            _validate_coverage(name, _read_document(path), spec)
    if errors:
        raise ContractError("\n".join(errors))
    return len(files), row_count


def validate_ucode_snapshot(ucode_root: Path, repo_root: Path = REPO_ROOT) -> tuple[int, int]:
    """Validate the classified historical snapshot, not a live completeness claim.

    The manifest is consumer-owned. It pins row identities and required evidence
    for this particular snapshot; it is not an oracle for future live output.
    """
    manifest = json.loads((repo_root / "policy/ucode_snapshot_manifest.json").read_text(encoding="utf-8"))
    docs = ucode_root / "docs"
    expected = set(manifest["typed"]) | set(manifest["coverage"])
    actual = {p.name for p in docs.glob("*.json")}
    if actual != expected:
        raise ContractError(f"snapshot documents missing {sorted(expected - actual)} or unfamiliar {sorted(actual - expected)}")
    counts = validate_ucode_root(ucode_root, repo_root)
    for name, spec in manifest["typed"].items():
        rows = _read_document(docs / name)
        ids = {row["record_id"] for row in rows}
        if ids != set(spec["rows"]):
            raise ContractError(f"{name}: snapshot record identity mismatch")
        for row in rows:
            if row.get("profile") != "luci-ssl-25.12" or row.get("analysis_revision") != spec["revision"]:
                raise ContractError(f"{name}: row family profile/revision mismatch")
            if spec.get("evidence_status") is not None and row.get("evidence_status") != spec["evidence_status"]:
                raise ContractError(f"{name}: snapshot evidence_status mismatch")
            refs = row.get("evidence_refs", [])
            if not isinstance(refs, list) or not set(spec["rows"][row["record_id"]]).issubset(refs):
                raise ContractError(f"{name}: {row['record_id']} missing required evidence")
    return counts



def _validate_coverage(name: str, report: Any, spec: dict[str, Any]) -> None:
    if (not isinstance(report, dict) or set(report) != set(spec["keys"])
            or report.get("profile") != "luci-ssl-25.12"
            or report.get("analysis_revision") != spec["revision"]
            or report.get("status") != "partial"
            or (spec["entrypoint_id"] is not None and report.get("entrypoint_id") != spec["entrypoint_id"])):
        raise ContractError(f"{name}: coverage identity or fields mismatch")
    for key, value in report.items():
        if key in {"profile", "analysis_revision", "entrypoint_id", "status"}:
            continue
        if not isinstance(value, list):
            raise ContractError(f"{name}: coverage {key} must be an array")
        if key == "call_sites":
            if not value or any(not isinstance(x, dict) or set(x) != {"line", "kind", "command"}
                or not isinstance(x["line"], int) or isinstance(x["line"], bool) or x["line"] < 1
                or not isinstance(x["kind"], str) or not x["kind"].strip()
                or not isinstance(x["command"], str) or not x["command"].strip() for x in value):
                raise ContractError(f"{name}: malformed coverage call_sites")
        elif any(not isinstance(x, str) or not x.strip() for x in value):
            raise ContractError(f"{name}: coverage {key} must contain nonempty strings")
        if key in {"analyzed", "extracted_files"} and not value:
            raise ContractError(f"{name}: coverage {key} must not be empty")
    for key, expected in spec["contents"].items():
        actual = report[key]
        if (key != "unknowns" and len(actual) != len(expected)) or any(item not in actual for item in expected):
            raise ContractError(f"{name}: coverage {key} identity mismatch")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ucode-root", type=Path, required=True, help="ucode checkout containing docs/")
    parser.add_argument("--snapshot", action="store_true", help="also check the pinned historical document/evidence manifest")
    args = parser.parse_args(argv)
    try:
        validator = validate_ucode_snapshot if args.snapshot else validate_ucode_root
        file_count, row_count = validator(args.ucode_root.resolve())
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    lock = (REPO_ROOT / "corpus" / "lock.json").read_bytes()
    revision = "sha256:" + hashlib.sha256(lock).hexdigest()
    if args.snapshot:
        mode = "historical snapshot (not live conformance)"
    else:
        actual = {p.name for p in (args.ucode_root.resolve() / "docs").glob("*.json")}
        missing = sorted((TYPED_ARRAY_NAMES | REPORT_ONLY_OBJECT_NAMES) - actual)
        mode = f"limited partial documents; not full conformance; missing documents: {', '.join(missing) if missing else 'none'}"
    print(f"validated {row_count} typed ucode records in {file_count} arrays against {revision}; {mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
