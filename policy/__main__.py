from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from . import cgi_backup, oracle


def emit_all(repo_root: Optional[Path] = None) -> tuple[Path, Path, Path, Path]:
    repo_root = repo_root or oracle.REPO_ROOT
    fixtures = repo_root / "policy" / "fixtures"
    luci_grants, luci_bundle = oracle.build_artifacts(fixtures, repo_root)
    cgi_grants, cgi_bundle, effect = cgi_backup.build_artifacts(fixtures, repo_root)
    grants_path = repo_root / "policy" / "grants.json"
    luci_decisions_path = repo_root / "policy" / "policy_decisions.json"
    cgi_decisions_path = repo_root / "policy" / "cgi_backup_decisions.json"
    oracle.dump_json(grants_path, luci_grants + cgi_grants)
    oracle.dump_json(luci_decisions_path, luci_bundle)
    oracle.dump_json(cgi_decisions_path, cgi_bundle)
    effect_path = cgi_backup.upsert_handler_effect(effect, repo_root)
    return grants_path, luci_decisions_path, cgi_decisions_path, effect_path


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] == "emit":
        for path in emit_all():
            print(path)
        return 0
    return oracle.main(argv)


raise SystemExit(main())
