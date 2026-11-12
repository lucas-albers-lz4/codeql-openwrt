from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from . import cgi_backup, cgi_exec, oracle


def emit_all(repo_root: Optional[Path] = None) -> tuple[Path, ...]:
    repo_root = repo_root or oracle.REPO_ROOT
    fixtures = repo_root / "policy" / "fixtures"
    luci_grants, luci_bundle = oracle.build_artifacts(fixtures, repo_root)
    backup_grants, backup_bundle, backup_effect = cgi_backup.build_artifacts(fixtures, repo_root)
    exec_grants, exec_bundle, exec_effect = cgi_exec.build_artifacts(fixtures, repo_root)
    grants_path = repo_root / "policy" / "grants.json"
    luci_decisions_path = repo_root / "policy" / "policy_decisions.json"
    backup_decisions_path = repo_root / "policy" / "cgi_backup_decisions.json"
    exec_decisions_path = repo_root / "policy" / "cgi_exec_decisions.json"
    exec_effect_path = repo_root / "reports" / "m2-cgi-exec-effect.json"
    oracle.dump_json(grants_path, luci_grants + backup_grants + exec_grants)
    oracle.dump_json(luci_decisions_path, luci_bundle)
    oracle.dump_json(backup_decisions_path, backup_bundle)
    oracle.dump_json(exec_decisions_path, {"grants": exec_grants, **exec_bundle})
    oracle.dump_json(exec_effect_path, exec_effect)
    cgi_backup.upsert_handler_effect(backup_effect, repo_root)
    effect_path = cgi_backup.upsert_handler_effect(exec_effect, repo_root)
    return (
        grants_path,
        luci_decisions_path,
        backup_decisions_path,
        exec_decisions_path,
        effect_path,
    )


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] == "emit":
        for path in emit_all():
            print(path)
        return 0
    return oracle.main(argv)


raise SystemExit(main())
