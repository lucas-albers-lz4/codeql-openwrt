"""Offline validation for typed records emitted by the ucode pack.

This intentionally implements only the JSON Schema keywords used by the
authoritative finding schema. A new keyword must be implemented here before
the schema can use it, so validation fails closed as the schema evolves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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


def _typed_arrays(ucode_root: Path) -> list[tuple[Path, list[dict[str, Any]]]]:
    docs = ucode_root / "docs"
    if not docs.is_dir():
        raise ContractError(f"ucode root has no docs directory: {docs}")
    result: list[tuple[Path, list[dict[str, Any]]]] = []
    for path in sorted(docs.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContractError(f"{path}: cannot read JSON: {exc}") from exc
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
        if isinstance(row, dict) and isinstance(row.get("record_id"), str):
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
    if "expectation_id" in row:
        join_fields.append("expectation_id")
    for key in join_fields:
        if not isinstance(row.get(key), str) or not isinstance(grant.get(key), str):
            return f"{where}: cited grant is missing required join key {key}"
        if row[key] != grant[key]:
            return f"{where}: cited grant has mismatched {key}: {grant[key]!r} != {row[key]!r}"
    return None


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
    row_count = 0
    errors: list[str] = []
    seen_record_ids: dict[str, Path] = {}
    for path, rows in files:
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
            analysis_revision = row.get("analysis_revision")
            if (
                not isinstance(analysis_revision, str)
                or not analysis_revision.startswith("step3:")
                or len(analysis_revision) <= len("step3:")
            ):
                errors.append(f"{where}: analysis_revision must be a nonempty producer-local 'step3:' revision")
            if row.get("corpus_revision") != expected_revision:
                errors.append(f"{where}: corpus_revision does not match sha256(corpus/lock.json)")
            if row.get("profile") not in known_profiles:
                errors.append(f"{where}: unknown profile {row.get('profile')!r}")
            if row.get("producer") != "step3":
                errors.append(f"{where}: ucode records must use producer 'step3'")
            if row.get("record_type") == "coverage":
                errors.append(f"{where}: coverage ledgers are report-only, not typed interchange records")
            for grant_id in _grant_ref_values(row):
                grant = grants.get(grant_id)
                if grant is None:
                    errors.append(f"{where}: cited grant ID does not exist: {grant_id}")
                    continue
                mismatch = _join_error(row, grant, where)
                if mismatch:
                    errors.append(mismatch)
            assessment = row.get("assessment")
            needs_grant = assessment in {"intended_access", "risky_delegation", "authorization_violation"}
            if needs_grant and not _grant_ref_values(row):
                errors.append(f"{where}: authorization assessment requires a cited policy grant")
    if errors:
        raise ContractError("\n".join(errors))
    return len(files), row_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ucode-root", type=Path, required=True, help="ucode checkout containing docs/")
    args = parser.parse_args(argv)
    try:
        file_count, row_count = validate_ucode_root(args.ucode_root.resolve())
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    lock = (REPO_ROOT / "corpus" / "lock.json").read_bytes()
    revision = "sha256:" + hashlib.sha256(lock).hexdigest()
    print(f"validated {row_count} typed ucode records in {file_count} arrays against {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
