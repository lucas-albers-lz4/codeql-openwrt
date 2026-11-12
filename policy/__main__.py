from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from . import cgi_backup, cgi_download, cgi_upload, oracle


def emit_all(repo_root: Optional[Path] = None) -> tuple[Path, ...]:
    repo_root = repo_root or oracle.REPO_ROOT
    fixtures = repo_root / "policy" / "fixtures"
    luci_grants, luci_bundle = oracle.build_artifacts(fixtures, repo_root)
    backup_grants, backup_bundle, backup_effect = cgi_backup.build_artifacts(fixtures, repo_root)
    upload_grants, upload_bundle, upload_effect = cgi_upload.build_artifacts(fixtures, repo_root)
    download_grants, download_bundle, download_effect = cgi_download.build_artifacts(
        fixtures, repo_root
    )
    grants_path = repo_root / "policy" / "grants.json"
    luci_decisions_path = repo_root / "policy" / "policy_decisions.json"
    backup_decisions_path = repo_root / "policy" / "cgi_backup_decisions.json"
    upload_decisions_path = repo_root / "policy" / "cgi_upload_decisions.json"
    download_decisions_path = repo_root / "policy" / "cgi_download_decisions.json"
    upload_effect_path = repo_root / "reports" / "m2-cgi-upload-effect.json"
    download_effect_path = repo_root / "reports" / "m2-cgi-download-effect.json"
    oracle.dump_json(
        grants_path,
        luci_grants + backup_grants + upload_grants + download_grants,
    )
    oracle.dump_json(luci_decisions_path, luci_bundle)
    oracle.dump_json(backup_decisions_path, backup_bundle)
    oracle.dump_json(upload_decisions_path, {"grants": upload_grants, **upload_bundle})
    oracle.dump_json(download_decisions_path, {"grants": download_grants, **download_bundle})
    oracle.dump_json(upload_effect_path, upload_effect)
    oracle.dump_json(download_effect_path, download_effect)
    cgi_backup.upsert_handler_effect(backup_effect, repo_root)
    cgi_backup.upsert_handler_effect(upload_effect, repo_root)
    effect_path = cgi_backup.upsert_handler_effect(download_effect, repo_root)
    return (
        grants_path,
        luci_decisions_path,
        backup_decisions_path,
        upload_decisions_path,
        download_decisions_path,
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
