"""Import one pinned setBlockDetect source-observation table.

This adapter does not run CodeQL or authenticate the origin of supplied input.
It validates the observation and pinned source bytes before replacing the retained effect.
"""
from __future__ import annotations

import argparse
import csv
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from .oracle import REPO_ROOT, corpus_revision

COLUMNS = ("observation_kind", "method", "sink_kind", "command", "source_path",
           "start_line", "start_column", "end_line", "end_column")
SOURCE_PATH = "usr/share/rpcd/ucode/luci"
LUCISHA = "b2e0be4b46ec0fd43394c081fa7c50657af14011"
SOURCE_SHA256 = "6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e"
EXPECTED = ("callback_body_call", "setBlockDetect", "system",
            "/sbin/block detect > /etc/config/fstab", SOURCE_PATH,
            "532", "21", "532", "68")
PROFILE = "luci-ssl-25.12"
LEGACY_ANALYSIS_REVISION = "step3:luci-fixed-exec-v1"
ANALYSIS_REVISION = "step3:setblock-table-v1"
TYPED_REVISION = "step3:setblock-typed-v1"
TYPED_IMPORT_REVISION = "step3:setblock-typed-import-v1"
EFFECT_ID = "m4:effect:luci-setBlockDetect-system"
EFFECT_NAME = "setBlockDetect.block-detect.system"
CONDITIONS = ["setBlockDetect.call body", "builtin system of literal /sbin/block detect",
              "call takes no request.args"]
GRANT_IDS = {
    "luci-mod-system-mounts": "policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect",
    "root": "policy:grant:root:ubus_http:luci.setBlockDetect",
}
JOIN_KEYS = ("corpus_revision", "profile", "ingress", "entrypoint_id", "ubus_object", "method")
SNAPSHOT = Path("reports/m4-block-device-exec.json")
CATALOG = Path("reports/handler_effects.json")
DECISIONS = Path("policy/policy_decisions.json")
EXPECTATION_ID = "luci-mod-system-mounts"
QUERY_REF = "ql/src/m4/SetBlockDetectEffectTable.ql"
SOURCE_EVIDENCE_REF = (
    "luci@b2e0be4b modules/luci-base/root/usr/share/rpcd/ucode/luci "
    "setBlockDetect.call system('/sbin/block detect > /etc/config/fstab')"
)
SOURCE_LOCATION = {
    "path": SOURCE_PATH, "start_line": 532, "start_column": 21,
    "end_line": 532, "end_column": 68,
}
LEGACY_KEYS = {
    "record_type", "evidence_status", "producer", "record_id", "corpus_revision", "profile",
    "analysis_revision", "ingress", "entrypoint_id", "ubus_object", "method", "effect_id",
    "target_id", "op", "sink_kind", "assessment", "expectation_id", "conditions", "assumptions",
    "evidence_refs", "unknowns",
}
IMPORTED_KEYS = LEGACY_KEYS | {"source_location"}
LEGACY_SNAPSHOT_ASSUMPTIONS = [
    "Transcribed from pinned luci rpcd plugin at b2e0be4b; not a taint path",
    "Fixed argv; this is not luci.sys and not request.args interpolation",
    "shellquote and basename are not sanitizers; they are not present on this sink",
]
LEGACY_CATALOG_ASSUMPTIONS = [
    *LEGACY_SNAPSHOT_ASSUMPTIONS,
    "Collected from reports/m4-block-device-exec.json; not a new query run",
]
IMPORTED_ASSUMPTIONS = [
    "Source observation in the pinned callback body; not a taint path",
    "The supplied CSV is not authenticated as CodeQL output",
    "Fixed argv; this is not luci.sys and not request.args interpolation",
    "Assessment uses the independent synthetic mounts expectation, not the source table",
    "shellquote and basename are not sanitizers; they are not present on this sink",
]
LEGACY_SNAPSHOT_EVIDENCE_REFS = [GRANT_IDS["luci-mod-system-mounts"], SOURCE_EVIDENCE_REF]
LEGACY_CATALOG_EVIDENCE_REFS = [
    GRANT_IDS["luci-mod-system-mounts"], GRANT_IDS["root"], SOURCE_EVIDENCE_REF,
]
IMPORTED_EVIDENCE_REFS = [
    GRANT_IDS["luci-mod-system-mounts"], GRANT_IDS["root"], SOURCE_EVIDENCE_REF,
    QUERY_REF,
    f"openwrt/luci@{LUCISHA} modules/luci-base/root/usr/share/rpcd/ucode/luci:532",
]
LEGACY_UNKNOWNS = ["live uhttpd/rpcd not executed"]
IMPORTED_UNKNOWNS = [
    "live uhttpd/rpcd not executed",
    "Callback registration, actual execution and live uhttpd/rpcd are not established by the table",
    "Lexical shadowing and unmodeled call shapes are not resolved by the table",
]
TYPED_ASSUMPTIONS = [
    "Source observation in the pinned callback body; not a taint path",
    "The supplied CSV and typed JSON are not authenticated as CodeQL output",
    "Fixed argv; this is not luci.sys and not request.args interpolation",
    "shellquote and basename are not sanitizers; they are not present on this sink",
]
TYPED_RETAINED_ASSUMPTIONS = [*TYPED_ASSUMPTIONS,
    "Assessment uses the independent synthetic mounts expectation, not the source table"]


def same_json(a, b):
    """JSON comparison that does not equate bool, int, and float."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_json(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_json(x, y) for x, y in zip(a, b))
    return a == b


def valid_unknowns(value, required):
    return (type(value) is list and all(type(x) is str and x.strip() for x in value)
            and len(value) == len(set(value)) and all(x in value for x in required))


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_typed(path: Path, source_root: Path, repo_root: Path) -> dict:
    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")
    records = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs,
                         parse_constant=invalid_constant)
    lock = read_json(repo_root / "corpus/lock.json")
    if lock["repos"]["luci"]["sha"] != LUCISHA:
        raise ValueError("luci lock revision is not the supported source pin")
    source_bytes = (source_root / SOURCE_PATH).read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != SOURCE_SHA256:
        raise ValueError("source bytes do not match pinned luci")
    return validate_typed_records(records, source_bytes, lock, corpus_revision(repo_root))


def validate_typed_records(records, source_bytes, lock, selected_corpus):
    """Validate already-parsed neutral records and source bytes without writes."""
    if lock["repos"]["luci"]["sha"] != LUCISHA:
        raise ValueError("luci lock revision is not the supported source pin")
    if hashlib.sha256(source_bytes).hexdigest() != SOURCE_SHA256:
        raise ValueError("source bytes do not match pinned luci")
    expected = {
        "record_type": "handler_effect", "evidence_status": "fact", "producer": "step3",
        "record_id": EFFECT_ID, "corpus_revision": selected_corpus, "profile": PROFILE,
        "analysis_revision": TYPED_REVISION, "ingress": "ubus_http",
        "entrypoint_id": "ubus_http:luci.setBlockDetect", "ubus_object": "luci",
        "method": "setBlockDetect", "effect_id": EFFECT_NAME, "target_id": "command:block-detect",
        "op": "exec", "sink_kind": "system", "assessment": "unassessed",
        "source_location": SOURCE_LOCATION, "conditions": CONDITIONS,
        "assumptions": TYPED_ASSUMPTIONS, "evidence_refs": IMPORTED_EVIDENCE_REFS[2:],
    }
    if type(records) is not list or len(records) != 1 or type(records[0]) is not dict:
        raise ValueError("expected exactly one typed setBlockDetect record")
    record = records[0]
    if (set(record) != set(expected) | {"unknowns"}
            or not same_json({k: record[k] for k in expected if k in record}, expected)
            or not valid_unknowns(record.get("unknowns"), IMPORTED_UNKNOWNS)):
        raise ValueError("typed setBlockDetect record does not match the supported family")
    return record


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_table(csv_path: Path, source_root: Path, repo_root: Path) -> dict[str, str]:
    lock = read_json(repo_root / "corpus/lock.json")
    if lock["repos"]["luci"]["sha"] != LUCISHA:
        raise ValueError("luci lock revision is not the supported source pin")
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f, strict=True)
        header = next(reader, None)
        if header != list(COLUMNS):
            raise ValueError("unexpected table columns")
        rows = list(reader)
    if rows != [list(EXPECTED)]:
        raise ValueError("expected exactly the supported pinned source observation")
    source = source_root / SOURCE_PATH
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("source bytes do not match pinned luci")
    return dict(zip(COLUMNS, rows[0]))


def _validate_grant(grants: list[dict], record_id: str, session: str,
                    expectation_id: str, keys: dict[str, str]) -> None:
    matches = [g for g in grants if g.get("record_id") == record_id]
    if (len(matches) != 1 or any(matches[0].get(k) != keys[k] for k in JOIN_KEYS)
            or matches[0].get("session_class") != session
            or matches[0].get("record_type") != "policy_grant"
            or matches[0].get("evidence_status") != "fact"
            or matches[0].get("producer") != "policy_facts"
            or matches[0].get("assessment") != "intended_access"
            or matches[0].get("expectation_id") != expectation_id
            or matches[0].get("target_id") != "ubus:luci.setBlockDetect"
            or matches[0].get("op") != "invoke"):
        raise ValueError(f"missing or mismatched grant: {record_id}")


def _validate_unauthenticated_deny(repo_root: Path, keys: dict[str, str]) -> None:
    grants = read_json(repo_root / "policy/grants.json")
    if any(g.get("session_class") == "unauthenticated"
           and all(g.get(k) == keys[k] for k in JOIN_KEYS) for g in grants):
        raise ValueError("unauthenticated setBlockDetect grant must remain absent")
    decisions = read_json(repo_root / DECISIONS).get("decisions", [])
    record_id = "policy:decision:unauthenticated-setBlockDetect-deny"
    matches = [d for d in decisions if d.get("record_id") == record_id]
    if (len(matches) != 1 or matches[0].get("corpus_revision") != keys["corpus_revision"]
            or matches[0].get("profile") != PROFILE
            or matches[0].get("session_class") != "unauthenticated"
            or matches[0].get("ingress") != "ubus_http"
            or matches[0].get("entrypoint_id") != keys["entrypoint_id"]
            or matches[0].get("ubus_object") != "luci"
            or matches[0].get("method") != "setBlockDetect"
            or matches[0].get("outcome") != "deny"):
        raise ValueError("missing or mismatched unauthenticated deny decision")


def validate_existing_effect(effect: object, repo_root: Path, artifact: Path, *, typed_mode=False) -> dict:
    if not isinstance(effect, dict):
        raise ValueError("existing setBlockDetect effect must be an object")
    revision = corpus_revision(repo_root)
    expected = {
        "record_type": "handler_effect", "evidence_status": "fact", "producer": "step3",
        "record_id": EFFECT_ID, "corpus_revision": revision, "profile": PROFILE,
        "ingress": "ubus_http", "entrypoint_id": "ubus_http:luci.setBlockDetect",
        "ubus_object": "luci", "method": "setBlockDetect", "effect_id": EFFECT_NAME,
        "target_id": "command:block-detect", "op": "exec", "sink_kind": "system",
        "assessment": "intended_access", "expectation_id": EXPECTATION_ID,
        "conditions": CONDITIONS,
    }
    for key, value in expected.items():
        if not same_json(effect.get(key), value):
            raise ValueError(f"existing setBlockDetect effect has mismatched {key}")
    analysis_revision = effect.get("analysis_revision")
    if analysis_revision == LEGACY_ANALYSIS_REVISION:
        expected_keys = LEGACY_KEYS
        if artifact == SNAPSHOT:
            expected_assumptions = LEGACY_SNAPSHOT_ASSUMPTIONS
            expected_refs = LEGACY_SNAPSHOT_EVIDENCE_REFS
        elif artifact == CATALOG:
            expected_assumptions = LEGACY_CATALOG_ASSUMPTIONS
            expected_refs = LEGACY_CATALOG_EVIDENCE_REFS
        else:
            raise ValueError("unsupported setBlockDetect effect artifact")
        expected_unknowns = LEGACY_UNKNOWNS
    elif analysis_revision in (ANALYSIS_REVISION, TYPED_IMPORT_REVISION):
        expected_keys = IMPORTED_KEYS
        expected_assumptions = (TYPED_RETAINED_ASSUMPTIONS if analysis_revision == TYPED_IMPORT_REVISION
                                else IMPORTED_ASSUMPTIONS)
        expected_refs = IMPORTED_EVIDENCE_REFS
        expected_unknowns = IMPORTED_UNKNOWNS
        if not same_json(effect.get("source_location"), SOURCE_LOCATION):
            raise ValueError("existing setBlockDetect effect has mismatched source location")
    else:
        raise ValueError("existing setBlockDetect effect has unsupported analysis revision")
    if set(effect) != expected_keys:
        raise ValueError("existing setBlockDetect effect has unexpected or missing fields")
    if (effect.get("assumptions") != expected_assumptions
            or effect.get("evidence_refs") != expected_refs
            or (not valid_unknowns(effect.get("unknowns"), expected_unknowns) if typed_mode
                else not same_json(effect.get("unknowns"), expected_unknowns))):
        raise ValueError("existing setBlockDetect effect has changed source or uncertainty claims")
    return effect


def _existing_effect(rows: object, repo_root: Path, artifact: Path, *, typed_mode=False) -> dict:
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"{artifact} must be a list of objects")
    matches = [row for row in rows if row.get("record_id") == EFFECT_ID]
    if len(matches) != 1:
        raise ValueError(f"{artifact} must contain exactly one setBlockDetect effect")
    return validate_existing_effect(matches[0], repo_root, artifact, typed_mode=typed_mode)


def build_effect(row: dict[str, str], repo_root: Path, existing: dict) -> dict:
    revision = corpus_revision(repo_root)
    keys = {"corpus_revision": revision, "profile": PROFILE, "ingress": "ubus_http",
            "entrypoint_id": "ubus_http:luci.setBlockDetect", "ubus_object": "luci",
            "method": "setBlockDetect"}
    grants = read_json(repo_root / "policy/grants.json")
    _validate_grant(grants, GRANT_IDS["luci-mod-system-mounts"], "luci-mod-system-mounts",
                    EXPECTATION_ID, keys)
    _validate_grant(grants, GRANT_IDS["root"], "root", "root-administration", keys)
    _validate_unauthenticated_deny(repo_root, keys)

    expectations = read_json(repo_root / f"corpus/profiles/{PROFILE}/expected-capabilities.json")["expectations"]
    matches = [e for e in expectations if e.get("expectation_id") == EXPECTATION_ID]
    if (len(matches) != 1 or matches[0].get("session_class") != "luci-mod-system-mounts"
            or matches[0].get("ingress") != "ubus_http"
            or {"target_id": "ubus:luci.setBlockDetect", "op": "invoke"}
            not in matches[0].get("intended_access", [])
            or not any(x.get("sink_kind") == "system" and x.get("constraint") == "fixed_command"
                       and "/sbin/block detect > /etc/config/fstab" in x.get("examples", [])
                       for x in matches[0].get("allowed_helper_effects", []))):
        raise ValueError("missing or mismatched independent mounts expectation")

    # Preserve the manually transcribed assessment and policy context. Only replace
    # its source evidence and identify the query revision that supplied the row.
    effect = copy.deepcopy(existing)
    effect["analysis_revision"] = ANALYSIS_REVISION
    source_location = {
        "path": row["source_path"], "start_line": int(row["start_line"]),
        "start_column": int(row["start_column"]), "end_line": int(row["end_line"]),
        "end_column": int(row["end_column"]),
    }
    if source_location != SOURCE_LOCATION:
        raise ValueError("source location does not match the supported pinned call")
    effect["source_location"] = source_location
    effect["assumptions"] = IMPORTED_ASSUMPTIONS
    effect["evidence_refs"] = IMPORTED_EVIDENCE_REFS
    effect["unknowns"] = IMPORTED_UNKNOWNS
    return effect


class EffectIdentityCollision(ValueError):
    """The replacement effect identity already belongs to another record."""


class PrestateMismatch(ValueError):
    """The paired retained targets do not agree."""


def replace_effect(rows: object, effect: dict) -> list:
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("effect artifact must be a list of objects")
    if any(row.get("effect_id") == effect["effect_id"] and row.get("record_id") != EFFECT_ID
           for row in rows):
        raise EffectIdentityCollision("effect identity is already used by a different record")
    indices = [i for i, row in enumerate(rows) if row.get("record_id") == EFFECT_ID]
    if len(indices) != 1:
        raise ValueError("expected exactly one existing setBlockDetect effect")
    return [effect if i == indices[0] else row for i, row in enumerate(rows)]


def prepare_updates(snapshot_rows: object, catalog_rows: object, row: dict[str, str],
                    repo_root: Path, *, typed=None) -> tuple[list, list]:
    """Validate paired pre-state and compute adapter updates without writing."""
    snapshot_effect = _existing_effect(snapshot_rows, repo_root, SNAPSHOT, typed_mode=typed is not None)
    catalog_effect = _existing_effect(catalog_rows, repo_root, CATALOG, typed_mode=typed is not None)
    provenance_fields = {"assumptions", "evidence_refs"}
    snapshot_shared = {k: v for k, v in snapshot_effect.items() if k not in provenance_fields}
    catalog_shared = {k: v for k, v in catalog_effect.items() if k not in provenance_fields}
    if not same_json(snapshot_shared, catalog_shared):
        raise PrestateMismatch("setBlockDetect snapshot and catalog rows are not in lockstep")
    if typed is None and catalog_effect["analysis_revision"] == TYPED_IMPORT_REVISION:
        raise ValueError("typed-to-CSV downgrade is not supported")
    # Reject aliases before deriving a post-state or consulting policy joins.
    replace_effect(snapshot_rows, catalog_effect)
    replace_effect(catalog_rows, catalog_effect)
    effect = build_effect(row, repo_root, catalog_effect)
    if typed is not None:
        effect["analysis_revision"] = TYPED_IMPORT_REVISION
        effect["assumptions"] = TYPED_RETAINED_ASSUMPTIONS
        effect["unknowns"] = list(dict.fromkeys([*IMPORTED_UNKNOWNS, *catalog_effect["unknowns"], *typed["unknowns"]]))
    return replace_effect(snapshot_rows, effect), replace_effect(catalog_rows, effect)


def import_table(csv_path: Path, source_root: Path, repo_root: Path = REPO_ROOT) -> None:
    row = validate_table(csv_path, source_root, repo_root)
    _import_observation(row, repo_root)


def import_typed(path: Path, source_root: Path, repo_root: Path = REPO_ROOT) -> None:
    record = validate_typed(path, source_root, repo_root)
    _import_observation(dict(zip(COLUMNS, EXPECTED)), repo_root, typed=record)


def _import_observation(row, repo_root, *, typed=None):
    snapshot_path = repo_root / SNAPSHOT
    catalog_path = repo_root / CATALOG
    snapshot_rows = read_json(snapshot_path)
    catalog_rows = read_json(catalog_path)
    snapshot_update, catalog_update = prepare_updates(snapshot_rows, catalog_rows, row, repo_root, typed=typed)
    updates = [(snapshot_path, snapshot_update), (catalog_path, catalog_update)]
    staged = []
    backups = []
    replaced = []
    recovery_needed = set()
    try:
        for path, value in updates:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                             prefix=".setblock-", delete=False) as f:
                staged.append((Path(f.name), path))
                json.dump(value, f, indent=2, ensure_ascii=True)
                f.write("\n")
            os.chmod(staged[-1][0], stat.S_IMODE(path.stat().st_mode))
            with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                             prefix=".setblock-backup-", delete=False) as f:
                backups.append((Path(f.name), path))
                f.write(path.read_bytes())
            os.chmod(backups[-1][0], stat.S_IMODE(path.stat().st_mode))
        for (temporary, path), (backup, _) in zip(staged, backups):
            os.replace(temporary, path)
            replaced.append((backup, path))
    except Exception:
        for backup, path in reversed(replaced):
            try:
                os.replace(backup, path)
            except OSError as exc:
                recovery_needed.add(backup)
                raise RuntimeError(f"failed to restore {path}; original retained at {backup}") from exc
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
        for backup, _ in backups:
            if backup not in recovery_needed:
                backup.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--csv", type=Path)
    inputs.add_argument("--typed-json", type=Path)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    if args.typed_json is not None:
        import_typed(args.typed_json, args.source_root)
    else:
        import_table(args.csv, args.source_root)


if __name__ == "__main__":
    main()
