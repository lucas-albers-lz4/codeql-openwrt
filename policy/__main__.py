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
    ubus_file_exec,
    ubus_file_exec_ifup,
    ubus_file_exec_kill,
    ubus_file_exec_list_backup,
    ubus_file_exec_mounts,
    ubus_rc_init,
    ubus_rc_list,
    ubus_hostapd_del_client,
    ubus_hostapd_wps_start,
    ubus_luci_getunixtime,
    ubus_luci_getversion,
    ubus_system_board,
    ubus_system_info,
    ubus_system_reboot,
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
    file_exec_grants, file_exec_bundle, file_exec_effects = ubus_file_exec.build_artifacts(
        fixtures, repo_root
    )
    ifup_grants, ifup_bundle, ifup_effects = ubus_file_exec_ifup.build_artifacts(
        fixtures, repo_root
    )
    kill_grants, kill_bundle, kill_effects = ubus_file_exec_kill.build_artifacts(
        fixtures, repo_root
    )
    mounts_grants, mounts_bundle, mounts_effects = ubus_file_exec_mounts.build_artifacts(
        fixtures, repo_root
    )
    list_backup_grants, list_backup_bundle, list_backup_effects = (
        ubus_file_exec_list_backup.build_artifacts(fixtures, repo_root)
    )
    reboot_grants, reboot_bundle, reboot_effects = ubus_system_reboot.build_artifacts(
        fixtures, repo_root
    )
    rc_init_grants, rc_init_bundle, rc_init_effects = ubus_rc_init.build_artifacts(
        fixtures, repo_root
    )
    rc_list_grants, rc_list_bundle, rc_list_effects = ubus_rc_list.build_artifacts(
        fixtures, repo_root
    )
    board_grants, board_bundle, board_effects = ubus_system_board.build_artifacts(
        fixtures, repo_root
    )
    info_grants, info_bundle, info_effects = ubus_system_info.build_artifacts(
        fixtures, repo_root
    )
    getversion_grants, getversion_bundle, getversion_effects = (
        ubus_luci_getversion.build_artifacts(fixtures, repo_root)
    )
    getunixtime_grants, getunixtime_bundle, getunixtime_effects = (
        ubus_luci_getunixtime.build_artifacts(fixtures, repo_root)
    )
    hostapd_grants, hostapd_bundle, hostapd_effects = ubus_hostapd_del_client.build_artifacts(
        fixtures, repo_root
    )
    wps_grants, wps_bundle, wps_effects = ubus_hostapd_wps_start.build_artifacts(
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
    file_exec_decisions_path = repo_root / "policy" / "ubus_file_exec_decisions.json"
    ifup_decisions_path = repo_root / "policy" / "ubus_file_exec_ifup_decisions.json"
    kill_decisions_path = repo_root / "policy" / "ubus_file_exec_kill_decisions.json"
    mounts_decisions_path = repo_root / "policy" / "ubus_file_exec_mounts_decisions.json"
    list_backup_decisions_path = repo_root / "policy" / "ubus_file_exec_list_backup_decisions.json"
    reboot_decisions_path = repo_root / "policy" / "ubus_system_reboot_decisions.json"
    rc_init_decisions_path = repo_root / "policy" / "ubus_rc_init_decisions.json"
    rc_list_decisions_path = repo_root / "policy" / "ubus_rc_list_decisions.json"
    board_decisions_path = repo_root / "policy" / "ubus_system_board_decisions.json"
    info_decisions_path = repo_root / "policy" / "ubus_system_info_decisions.json"
    getversion_decisions_path = repo_root / "policy" / "ubus_luci_getversion_decisions.json"
    getunixtime_decisions_path = repo_root / "policy" / "ubus_luci_getunixtime_decisions.json"
    hostapd_decisions_path = repo_root / "policy" / "ubus_hostapd_del_client_decisions.json"
    wps_decisions_path = repo_root / "policy" / "ubus_hostapd_wps_start_decisions.json"
    noauth_decisions_path = repo_root / "policy" / "no_ubusauth_decisions.json"
    upload_effect_path = repo_root / "reports" / "m2-cgi-upload-effect.json"
    download_effect_path = repo_root / "reports" / "m2-cgi-download-effect.json"
    exec_effect_path = repo_root / "reports" / "m2-cgi-exec-effect.json"
    helper_effect_path = repo_root / "reports" / "m2-cgi-exec-file-effect.json"
    status_effect_path = repo_root / "reports" / "m2-cgi-exec-status-effect.json"
    file_exec_effect_path = repo_root / "reports" / "m2-ubus-file-exec-effect.json"
    ifup_effect_path = repo_root / "reports" / "m2-ubus-file-exec-ifup-effect.json"
    kill_effect_path = repo_root / "reports" / "m2-ubus-file-exec-kill-effect.json"
    mounts_effect_path = repo_root / "reports" / "m2-ubus-file-exec-mounts-effect.json"
    list_backup_effect_path = repo_root / "reports" / "m2-ubus-file-exec-list-backup-effect.json"
    reboot_effect_path = repo_root / "reports" / "m2-ubus-system-reboot-effect.json"
    rc_init_effect_path = repo_root / "reports" / "m2-ubus-rc-init-effect.json"
    rc_list_effect_path = repo_root / "reports" / "m2-ubus-rc-list-effect.json"
    board_effect_path = repo_root / "reports" / "m2-ubus-system-board-effect.json"
    info_effect_path = repo_root / "reports" / "m2-ubus-system-info-effect.json"
    getversion_effect_path = repo_root / "reports" / "m2-ubus-luci-getversion-effect.json"
    getunixtime_effect_path = repo_root / "reports" / "m2-ubus-luci-getunixtime-effect.json"
    hostapd_effect_path = repo_root / "reports" / "m2-ubus-hostapd-del-client-effect.json"
    wps_effect_path = repo_root / "reports" / "m2-ubus-hostapd-wps-start-effect.json"
    oracle.dump_json(
        grants_path,
        luci_grants
        + backup_grants
        + upload_grants
        + download_grants
        + exec_grants
        + helper_grants
        + status_grants
        + file_exec_grants
        + ifup_grants
        + kill_grants
        + mounts_grants
        + list_backup_grants
        + reboot_grants
        + rc_init_grants
        + rc_list_grants
        + board_grants
        + info_grants
        + getversion_grants
        + getunixtime_grants
        + hostapd_grants
        + wps_grants,
    )
    oracle.dump_json(luci_decisions_path, luci_bundle)
    oracle.dump_json(backup_decisions_path, backup_bundle)
    oracle.dump_json(upload_decisions_path, {"grants": upload_grants, **upload_bundle})
    oracle.dump_json(download_decisions_path, {"grants": download_grants, **download_bundle})
    oracle.dump_json(exec_decisions_path, {"grants": exec_grants, **exec_bundle})
    oracle.dump_json(helper_decisions_path, {"grants": helper_grants, **helper_bundle})
    oracle.dump_json(status_decisions_path, {"grants": status_grants, **status_bundle})
    oracle.dump_json(file_exec_decisions_path, {"grants": file_exec_grants, **file_exec_bundle})
    oracle.dump_json(ifup_decisions_path, {"grants": ifup_grants, **ifup_bundle})
    oracle.dump_json(kill_decisions_path, {"grants": kill_grants, **kill_bundle})
    oracle.dump_json(mounts_decisions_path, {"grants": mounts_grants, **mounts_bundle})
    oracle.dump_json(list_backup_decisions_path, {"grants": list_backup_grants, **list_backup_bundle})
    oracle.dump_json(reboot_decisions_path, {"grants": reboot_grants, **reboot_bundle})
    oracle.dump_json(rc_init_decisions_path, {"grants": rc_init_grants, **rc_init_bundle})
    oracle.dump_json(rc_list_decisions_path, {"grants": rc_list_grants, **rc_list_bundle})
    oracle.dump_json(board_decisions_path, {"grants": board_grants, **board_bundle})
    oracle.dump_json(info_decisions_path, {"grants": info_grants, **info_bundle})
    oracle.dump_json(getversion_decisions_path, {"grants": getversion_grants, **getversion_bundle})
    oracle.dump_json(getunixtime_decisions_path, {"grants": getunixtime_grants, **getunixtime_bundle})
    oracle.dump_json(hostapd_decisions_path, {"grants": hostapd_grants, **hostapd_bundle})
    oracle.dump_json(wps_decisions_path, {"grants": wps_grants, **wps_bundle})
    oracle.dump_json(noauth_decisions_path, noauth_bundle)
    oracle.dump_json(upload_effect_path, upload_effect)
    oracle.dump_json(download_effect_path, download_effect)
    oracle.dump_json(exec_effect_path, exec_effect)
    oracle.dump_json(helper_effect_path, helper_effects)
    oracle.dump_json(status_effect_path, status_effects)
    oracle.dump_json(file_exec_effect_path, file_exec_effects)
    oracle.dump_json(ifup_effect_path, ifup_effects)
    oracle.dump_json(kill_effect_path, kill_effects)
    oracle.dump_json(mounts_effect_path, mounts_effects)
    oracle.dump_json(list_backup_effect_path, list_backup_effects)
    oracle.dump_json(reboot_effect_path, reboot_effects)
    oracle.dump_json(rc_init_effect_path, rc_init_effects)
    oracle.dump_json(rc_list_effect_path, rc_list_effects)
    oracle.dump_json(board_effect_path, board_effects)
    oracle.dump_json(info_effect_path, info_effects)
    oracle.dump_json(getversion_effect_path, getversion_effects)
    oracle.dump_json(getunixtime_effect_path, getunixtime_effects)
    oracle.dump_json(hostapd_effect_path, hostapd_effects)
    oracle.dump_json(wps_effect_path, wps_effects)
    cgi_backup.upsert_handler_effect(backup_effect, repo_root)
    cgi_backup.upsert_handler_effect(upload_effect, repo_root)
    cgi_backup.upsert_handler_effect(download_effect, repo_root)
    cgi_backup.upsert_handler_effect(exec_effect, repo_root)
    effect_path = repo_root / "reports" / "handler_effects.json"
    for helper_effect in helper_effects:
        effect_path = cgi_backup.upsert_handler_effect(helper_effect, repo_root)
    for status_effect in status_effects:
        effect_path = cgi_backup.upsert_handler_effect(status_effect, repo_root)
    for file_exec_effect in file_exec_effects:
        effect_path = cgi_backup.upsert_handler_effect(file_exec_effect, repo_root)
    for ifup_effect in ifup_effects:
        effect_path = cgi_backup.upsert_handler_effect(ifup_effect, repo_root)
    for kill_effect in kill_effects:
        effect_path = cgi_backup.upsert_handler_effect(kill_effect, repo_root)
    for mounts_effect in mounts_effects:
        effect_path = cgi_backup.upsert_handler_effect(mounts_effect, repo_root)
    for list_backup_effect in list_backup_effects:
        effect_path = cgi_backup.upsert_handler_effect(list_backup_effect, repo_root)
    for reboot_effect in reboot_effects:
        effect_path = cgi_backup.upsert_handler_effect(reboot_effect, repo_root)
    for rc_init_effect in rc_init_effects:
        effect_path = cgi_backup.upsert_handler_effect(rc_init_effect, repo_root)
    for rc_list_effect in rc_list_effects:
        effect_path = cgi_backup.upsert_handler_effect(rc_list_effect, repo_root)
    for board_effect in board_effects:
        effect_path = cgi_backup.upsert_handler_effect(board_effect, repo_root)
    for info_effect in info_effects:
        effect_path = cgi_backup.upsert_handler_effect(info_effect, repo_root)
    for getversion_effect in getversion_effects:
        effect_path = cgi_backup.upsert_handler_effect(getversion_effect, repo_root)
    for getunixtime_effect in getunixtime_effects:
        effect_path = cgi_backup.upsert_handler_effect(getunixtime_effect, repo_root)
    for hostapd_effect in hostapd_effects:
        effect_path = cgi_backup.upsert_handler_effect(hostapd_effect, repo_root)
    for wps_effect in wps_effects:
        effect_path = cgi_backup.upsert_handler_effect(wps_effect, repo_root)
    return (
        grants_path,
        luci_decisions_path,
        backup_decisions_path,
        upload_decisions_path,
        download_decisions_path,
        exec_decisions_path,
        helper_decisions_path,
        status_decisions_path,
        file_exec_decisions_path,
        ifup_decisions_path,
        kill_decisions_path,
        mounts_decisions_path,
        list_backup_decisions_path,
        reboot_decisions_path,
        rc_init_decisions_path,
        rc_list_decisions_path,
        board_decisions_path,
        info_decisions_path,
        getversion_decisions_path,
        getunixtime_decisions_path,
        hostapd_decisions_path,
        wps_decisions_path,
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
