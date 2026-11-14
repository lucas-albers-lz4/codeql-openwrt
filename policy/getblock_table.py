"""Import one pinned getBlockDevices source-observation table.

This adapter does not run CodeQL or authenticate the origin of a supplied CSV.
It validates its contents and source bytes before replacing the retained effect.
"""
from __future__ import annotations

import argparse
import csv
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
EXPECTED = ("callback_body_call", "getBlockDevices", "popen", "/sbin/block info 2>/dev/null",
            SOURCE_PATH, "481", "18", "481", "54")
PROFILE = "luci-ssl-25.12"
EFFECT_ID = "m4:effect:luci-getBlockDevices-popen"
GRANT_IDS = {
    "luci-mod-system-mounts": "policy:grant:luci-mod-system-mounts:ubus_http:luci.getBlockDevices",
    "root": "policy:grant:root:ubus_http:luci.getBlockDevices",
}
JOIN_KEYS = ("corpus_revision", "profile", "ingress", "entrypoint_id", "ubus_object", "method")
SNAPSHOT = Path("reports/m4-block-device-exec.json")
CATALOG = Path("reports/handler_effects.json")


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


def build_effect(row: dict[str, str], repo_root: Path) -> dict:
    revision = corpus_revision(repo_root)
    keys = {"corpus_revision": revision, "profile": PROFILE, "ingress": "ubus_http",
            "entrypoint_id": "ubus_http:luci.getBlockDevices", "ubus_object": "luci",
            "method": "getBlockDevices"}
    grants = read_json(repo_root / "policy/grants.json")
    for session, record_id in GRANT_IDS.items():
        expected_expectation = "root-administration" if session == "root" else "luci-mod-system-mounts"
        matches = [g for g in grants if g.get("record_id") == record_id]
        if (len(matches) != 1 or any(matches[0].get(k) != keys[k] for k in JOIN_KEYS)
                or matches[0].get("session_class") != session
                or matches[0].get("record_type") != "policy_grant"
                or matches[0].get("evidence_status") != "fact"
                or matches[0].get("producer") != "policy_facts"
                or matches[0].get("assessment") != "intended_access"
                or matches[0].get("expectation_id") != expected_expectation
                or matches[0].get("target_id") != "ubus:luci.getBlockDevices"
                or matches[0].get("op") != "invoke"):
            raise ValueError(f"missing or mismatched grant: {record_id}")
    expectations = read_json(repo_root / f"corpus/profiles/{PROFILE}/expected-capabilities.json")["expectations"]
    matches = [e for e in expectations if e.get("expectation_id") == "luci-mod-system-mounts"]
    if (len(matches) != 1 or matches[0].get("session_class") != "luci-mod-system-mounts"
            or matches[0].get("ingress") != "ubus_http"
            or {"target_id": "ubus:luci.getBlockDevices", "op": "invoke"} not in matches[0].get("intended_access", [])
            or not any(x.get("sink_kind") == "popen" and x.get("constraint") == "fixed_command"
                       and "/sbin/block info" in x.get("examples", [])
                       for x in matches[0].get("allowed_helper_effects", []))):
        raise ValueError("missing or mismatched independent mounts expectation")
    return {
        "record_type": "handler_effect", "evidence_status": "fact", "producer": "step3",
        "record_id": EFFECT_ID, **keys, "analysis_revision": "step3:getblock-table-v1",
        "effect_id": "getBlockDevices.block-info.popen", "target_id": "command:block-info",
        "op": "exec", "sink_kind": row["sink_kind"], "assessment": "intended_access",
        "expectation_id": "luci-mod-system-mounts",
        "conditions": ["pinned getBlockDevices.call callback contains literal popen call"],
        "requirements": ["matching profile and corpus revision", "HTTP ubus grant for the caller"],
        "source_location": {"path": SOURCE_PATH, "start_line": int(row["start_line"]),
                            "start_column": int(row["start_column"]), "end_line": int(row["end_line"]),
                            "end_column": int(row["end_column"])},
        "assumptions": ["Source observation in the pinned callback body; not a taint path",
                        "The supplied CSV is not authenticated as CodeQL output",
                        "Assessment uses the independent synthetic mounts expectation, not the source table"],
        "evidence_refs": [GRANT_IDS["luci-mod-system-mounts"], GRANT_IDS["root"],
                          "ql/src/m4/GetBlockDevicesEffectTable.ql",
                          f"openwrt/luci@{LUCISHA} modules/luci-base/root/usr/share/rpcd/ucode/luci:481"],
        "unknowns": ["Callback registration, actual execution and live uhttpd/rpcd are not established by the table",
                     "Lexical shadowing and unmodeled call shapes are not resolved by the table"],
    }


def replace_effect(rows: object, effect: dict) -> list:
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("effect artifact must be a list of objects")
    if any(row.get("effect_id") == effect["effect_id"] and row.get("record_id") != EFFECT_ID
           for row in rows):
        raise ValueError("effect identity is already used by a different record")
    indices = [i for i, row in enumerate(rows) if row.get("record_id") == EFFECT_ID]
    if not indices:
        raise ValueError("existing effect is missing")
    # Preserve position and every unrelated row, and deduplicate this effect.
    return [effect if i == indices[0] else row for i, row in enumerate(rows)
            if i == indices[0] or row.get("record_id") != EFFECT_ID]


def import_table(csv_path: Path, source_root: Path, repo_root: Path = REPO_ROOT) -> None:
    row = validate_table(csv_path, source_root, repo_root)
    effect = build_effect(row, repo_root)
    updates = [(repo_root / path, replace_effect(read_json(repo_root / path), effect))
               for path in (SNAPSHOT, CATALOG)]
    # All validation is complete before touching either artifact.
    staged = []
    backups = []
    replaced = []
    recovery_needed = set()
    try:
        for path, value in updates:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                             prefix=".getblock-", delete=False) as f:
                staged.append((Path(f.name), path))
                json.dump(value, f, indent=2, ensure_ascii=False)
                f.write("\n")
            os.chmod(staged[-1][0], stat.S_IMODE(path.stat().st_mode))
            with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                             prefix=".getblock-backup-", delete=False) as f:
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
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    import_table(args.csv, args.source_root)


if __name__ == "__main__":
    main()
