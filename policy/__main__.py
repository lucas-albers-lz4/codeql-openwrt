from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from . import (
    cgi_backup,
    cgi_download,
    cgi_exec,
    cgi_exec_file,
    cgi_exec_status,
    cgi_upload,
    no_ubusauth,
    oracle,
)


def emit_all(repo_root: Optional[Path] = None) -> tuple[Path, ...]:
    repo_root = repo_root or oracle.REPO_ROOT
    fixtures = repo_root / "policy" / "fixtures"
    luci_grants, luci_bundle = oracle.build_artifacts(fixtures, repo_root)
    backup_grants, backup_bundle, backup_effect = cgi_backup.build_artifacts(fixtures, repo_root)
    upload_grants, upload_bundle, upload_effect = cgi_upload.build_artifacts(fixtures, repo_root)
    download_grants, download_bundle, download_effect = cgi_download.build_artifacts(
        fixtures, repo_root
    )
    exec_grants, exec_bundle, exec_effect = cgi_exec.build_artifacts(fixtures, repo_root)
    helper_grants, helper_bundle, helper_effects = cgi_exec_file.build_artifacts(
        fixtures, repo_root
    )
    status_grants, status_bundle, status_effects = cgi_exec_status.build_artifacts(
        fixtures, repo_root
    )
    noauth_bundle = no_ubusauth.build_artifacts(fixtures, repo_root)
    grants_path = repo_root / "policy" / "grants.json"
    luci_decisions_path = repo_root / "policy" / "policy_decisions.json"
    backup_decisions_path = repo_root / "policy" / "cgi_backup_decisions.json"
    upload_decisions_path = repo_root / "policy" / "cgi_upload_decisions.json"
    download_decisions_path = repo_root / "policy" / "cgi_download_decisions.json"
    exec_decisions_path = repo_root / "policy" / "cgi_exec_decisions.json"
    helper_decisions_path = repo_root / "policy" / "cgi_exec_file_decisions.json"
    status_decisions_path = repo_root / "policy" / "cgi_exec_status_decisions.json"
    noauth_decisions_path = repo_root / "policy" / "no_ubusauth_decisions.json"
    upload_effect_path = repo_root / "reports" / "m2-cgi-upload-effect.json"
    download_effect_path = repo_root / "reports" / "m2-cgi-download-effect.json"
    exec_effect_path = repo_root / "reports" / "m2-cgi-exec-effect.json"
    helper_effect_path = repo_root / "reports" / "m2-cgi-exec-file-effect.json"
    status_effect_path = repo_root / "reports" / "m2-cgi-exec-status-effect.json"
    oracle.dump_json(
        grants_path,
        luci_grants
        + backup_grants
        + upload_grants
        + download_grants
        + exec_grants
        + helper_grants
        + status_grants,
    )
    oracle.dump_json(luci_decisions_path, luci_bundle)
    oracle.dump_json(backup_decisions_path, backup_bundle)
    oracle.dump_json(upload_decisions_path, {"grants": upload_grants, **upload_bundle})
    oracle.dump_json(download_decisions_path, {"grants": download_grants, **download_bundle})
    oracle.dump_json(exec_decisions_path, {"grants": exec_grants, **exec_bundle})
    oracle.dump_json(helper_decisions_path, {"grants": helper_grants, **helper_bundle})
    oracle.dump_json(status_decisions_path, {"grants": status_grants, **status_bundle})
    oracle.dump_json(noauth_decisions_path, noauth_bundle)
    oracle.dump_json(upload_effect_path, upload_effect)
    oracle.dump_json(download_effect_path, download_effect)
    oracle.dump_json(exec_effect_path, exec_effect)
    oracle.dump_json(helper_effect_path, helper_effects)
    oracle.dump_json(status_effect_path, status_effects)
    cgi_backup.upsert_handler_effect(backup_effect, repo_root)
    cgi_backup.upsert_handler_effect(upload_effect, repo_root)
    cgi_backup.upsert_handler_effect(download_effect, repo_root)
    cgi_backup.upsert_handler_effect(exec_effect, repo_root)
    effect_path = repo_root / "reports" / "handler_effects.json"
    for helper_effect in helper_effects:
        effect_path = cgi_backup.upsert_handler_effect(helper_effect, repo_root)
    for status_effect in status_effects:
        effect_path = cgi_backup.upsert_handler_effect(status_effect, repo_root)
    return (
        grants_path,
        luci_decisions_path,
        backup_decisions_path,
        upload_decisions_path,
        download_decisions_path,
        exec_decisions_path,
        helper_decisions_path,
        status_decisions_path,
        noauth_decisions_path,
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
