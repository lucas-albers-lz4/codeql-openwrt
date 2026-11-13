# Policy-facts (M2)

Canonical `/ubus` luci policy oracle plus cgi-io backup/upload/download/exec ingresses. Producer is `policy_facts`.
Luci `analysis_revision` is `policy:ubus-luci-exec-methods-v2`. cgi-backup is `policy:cgi-backup-v1`. cgi-upload is `policy:cgi-upload-v1`. cgi-download is `policy:cgi-download-v1`. cgi-exec is `policy:cgi-exec-v1`. cgi-exec file.exec of three luci-ssl libexec helpers is `policy:cgi-exec-file-v1`. luci-mod-status dmesg/firewall cgi-exec file.exec is `policy:cgi-exec-status-v1`. ubus `file.exec` of luci-mod-status iptables `-Z` and routes `ip` is `policy:ubus-file-exec-v1`. ubus `file.exec` of luci-mod-network-config ifup/ifdown/wifi is `policy:ubus-file-exec-ifup-v1`. The `no_ubusauth=1` variant is `policy:no-ubusauth-v1` (profile `luci-ssl-25.12-no-ubusauth`).

The HTTP gate is uhttpd `uh_ubus_allowed` → ubus `session.access` (uhttpd omits `scope`; rpcd defaults `scope` to `ubus`). Missing SID with `no_ubusauth=0` is JSON-RPC `ERROR_PARSE`, not the all-zero sentinel and not rpcd `file`/`uci` absent-SID skip.

cgi-backup, cgi-upload, and cgi-download are separate C ingresses (`policy/cgi_backup.py`, `policy/cgi_upload.py`, `policy/cgi_download.py`). Their oracles and C doubles accept already-decoded form fields: successful form-body framing and URL decoding are preconditions. cgi-backup and cgi-download check the content-type prefix and model authorization, but do not model `CONTENT_LENGTH` validation, truncated bodies, or percent-decoding failures in upstream `postdecode`. cgi-upload models a complete multipart request with sessionid/filename before filedata when present; it does not model arbitrary part order, truncated framing, tempfile creation, or copy/chmod. Given those decoded inputs, cgi-io supplies `scope=cgi-io`. Upload and download are conjunctive: the cgi-io ACL is not enough without the matching `file` ACL on `canonicalize_path(...)`. A missing sessionid on cgi-backup/cgi-download yields HTTP 403, not the `/ubus` parse failure. cgi-upload failures use `response()` Status 200 with a JSON body.

## Run

From the repository root:

```sh
python3 -m policy emit
python3 -m unittest discover -s policy/tests -t .
```

`emit` rewrites `policy/grants.json` (luci grants, then cgi-backup, cgi-upload, cgi-download, cgi-exec, cgi-exec file.exec helpers, cgi-exec status file.exec, ubus file.exec, ubus file.exec ifup), `policy/policy_decisions.json` (luci), the per-endpoint cgi decision files, `policy/ubus_file_exec_decisions.json`, `policy/ubus_file_exec_ifup_decisions.json`, and `policy/no_ubusauth_decisions.json` (no grants). The luci grant emitter refuses anything except `luci.getFeatures`, the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`. It also refuses grants for `no_ubusauth=1`. Synthetic cgi and ubus `file.exec` `handler_effect` rows are upserted into `reports/handler_effects.json` and checked against the oracles. All rows share the `corpus/lock.json` hash. Profile `luci-ssl-25.12-no-ubusauth` does not join luci-ssl grants (`profile` differs).

Tests compare the luci evaluator to handwritten cases in `policy/fixtures/expected_cases.json` and the cgi/ubus evaluators to `policy/fixtures/cgi_backup_cases.json`, `cgi_upload_cases.json`, `cgi_download_cases.json`, `cgi_exec_cases.json`, `cgi_exec_file_cases.json`, `cgi_exec_status_cases.json`, `ubus_file_exec_cases.json`, and `ubus_file_exec_ifup_cases.json` (transcribed from pinned C and ACL JSON, not from the evaluator). They compile the C doubles with:

```sh
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/uh_ubus_policy policy/c_double/uh_ubus_policy.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_backup policy/c_double/cgi_backup.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_upload policy/c_double/cgi_upload.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_download policy/c_double/cgi_download.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_exec policy/c_double/cgi_exec.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_exec_file policy/c_double/cgi_exec_file.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_exec_status policy/c_double/cgi_exec_status.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/ubus_file_exec policy/c_double/ubus_file_exec.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/ubus_file_exec_ifup policy/c_double/ubus_file_exec_ifup.c
```

Those C doubles cover the decoded-input gate + `session.access` matching without a live daemon. They do not model raw HTTP form parsing, and live uhttpd/rpcd/cgi-io/`sysupgrade` are not executed.

## In scope

- Profile `luci-ssl-25.12`, `no_ubusauth=0`
- Profile `luci-ssl-25.12-no-ubusauth`, `option no_ubusauth 1` / `uhttpd -a`: empty SID rewrites to the all-zero default and `uh_ubus_allowed` is skipped. Unauthenticated `setPassword` allow is that skip (`unassessed`), not an invented luci-ssl grant. Null or omitted SID slots in the usual call array and missing data still fail parsing. Object lookup precedes the gate; a gate allow does not establish plugin success. The flag also skips authorization on uhttpd `/call/<object>` and GET subscriptions, which remain unmodeled. cgi-io / dispatcher unchanged.
- Stock unauthenticated session (present all-zero SID) → `luci`/`getFeatures` allow
- Same session → `luci`/`getSwconfigFeatures`, `getSwconfigPortState`, `getRealtimeStats`, `setPassword`, `setLocaltime`, `getBlockDevices`, `setBlockDetect`, `getConntrackList`, `getProcessList` deny (no invented grant)
- Synthetic delegated fixture sessions → matching methods allow (`luci-mod-network-config`, `luci-mod-network-config-write` for ubus `file.exec` of ifup/ifdown/wifi, `luci-mod-status-realtime`, `luci-mod-status-processes`, `luci-mod-system-config`, `luci-mod-system-mounts`, `luci-base` write login for cgi-upload, `luci-mod-system-flash` for cgi-backup/cgi-download, `luci-mod-status-logs` for dmesg/syslog-wrapper, `luci-mod-status-firewall` for nft/iptables/firewall-init, `luci-mod-status-routes` / `luci-mod-status-routes-json` for ubus `file.exec` of `ip`); these are not stock logins. Their intended-access assessments are conditional on those fixture roles. The processes fixture is read-only (write `file.exec` `/bin/kill` is not granted). The network-config read fixture has ubus `file.exec` but not write `file.exec` of ifup/ifdown/wifi.
- Missing SID → JSON-RPC parse failure
- Stock root `list read '*' / list write '*'` → those methods allow (not a violation)
- Literal object/method names only
- Emission bounded to `getFeatures` plus the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`
- cgi-backup (`/cgi-bin/cgi-backup`) → `sensitive_backup_read` only: unauthenticated 403; fixture `luci-mod-system-flash` allow; root `*` allow (not a violation). cgi-io supplies `scope=cgi-io`.
- cgi-upload (`/cgi-bin/cgi-upload`) → conjunctive `file_write`: cgi-io `upload` write **and** `file` write of `canonicalize_path(filename)`. Unauthenticated is denied (Status 200 JSON). Fixture `luci-base` (write login) and stock root `*` allow `/etc/luci-uploads/example.bin`. The `luci-mod-system-flash` fixture login is `list read` only, so upload write is not in session.
- cgi-download (`/cgi-bin/cgi-download`) → conjunctive `file_read`: cgi-io `download` read **and** `file` read of `canonicalize_path(path)`. Unauthenticated 403. Fixture `luci-mod-system-flash` and stock root `*` allow `/dev/mtdblock0`. `../` is collapsed before the file ACL.
- cgi-exec (`/cgi-bin/cgi-exec`) → `exec` session gate only: `session.access(sid, "cgi-io", "exec", "read")`. Unauthenticated 403. Fixture `luci-mod-network-config` and stock root `*` allow the cgi-io exec read gate. Does not model `execv`. File.exec of the three luci-ssl libexec helpers is `policy:cgi-exec-file-v1`.
- cgi-exec file.exec helpers → conjunctive `file_exec` of `/usr/libexec/{syslog-wrapper,luci-peeraddr,package-manager-call}`. Unauthenticated 403. Fixtures `luci-mod-status-logs`, `luci-mod-network-config`, `luci-app-package-manager`, and stock root `*` allow as `intended_access`. Does not model `execv` or arbitrary commands.
- cgi-exec file.exec luci-mod-status → conjunctive `file_exec` of `/bin/dmesg -r`, nft/iptables listing and `*-save`, and `/etc/init.d/firewall restart` (`policy:cgi-exec-status-v1`). Unauthenticated 403. Fixtures `luci-mod-status-logs` (dmesg), `luci-mod-status-firewall` (read+write), and stock root `*` allow as `intended_access`. A read-only firewall fixture cannot restart. Does not staff ubus `file.exec` (`iptables -Z`, routes `ip`). Does not model `execv`.
- ubus `file.exec` luci-mod-status → conjunctive `file_exec` of `iptables -Z` / `ip6tables -Z` and routes `/sbin/ip` (`policy:ubus-file-exec-v1`). Unauthenticated is JSON-RPC `ERROR_ACCESS`. Missing SID is `ERROR_PARSE`. Fixtures `luci-mod-status-firewall` (write), `luci-mod-status-routes`, `luci-mod-status-routes-json`, and stock root `*` allow as `intended_access`. A ubus `file.exec` grant without the matching file ACL is `UBUS_STATUS_PERMISSION_DENIED`. rpcd-mod-file checks the executable ACL first, then the cmdline. Does not model `execv`.
- ubus `file.exec` luci-mod-network-config → conjunctive `file_exec` of `/sbin/ifup`, `/sbin/ifdown`, and `/sbin/wifi` (`policy:ubus-file-exec-ifup-v1`). Unauthenticated is JSON-RPC `ERROR_ACCESS`. Missing SID is `ERROR_PARSE`. Fixture `luci-mod-network-config-write` and stock root `*` allow as `intended_access`. The read `luci-mod-network-config` fixture is `UBUS_STATUS_PERMISSION_DENIED` (ubus `file.exec` without the write file ACL). Inventoried ACLs grant the bare executables; extra tokens are `intended_access` for that fixture, not `authorization_violation` and not a PoC. Does not model `execv`.

## Out of scope (not M2)

- M4, Alloy, `alloy_input.json`, `producer: step4`
- Markup, Track A, dispatcher / `admin/ubus` SID rewrite (`no_ubusauth` does not apply there)
- luci-ssl `files[]` routing (`inventory:luci-ssl-files-v1`); not emitted into `grants.json`
- `file.exec` / `hostapd.*` rows present in the loaded ACL files other than the three luci-ssl libexec helpers, luci-mod-status cgi-exec status commands, the inventoried ubus `file.exec` iptables `-Z` / routes `ip` commands, and luci-mod-network-config ifup/ifdown/wifi (matching accuracy only; not emitted by the luci emitter)
- `setInitAction` (no luci-ssl delegated grant at luci `b2e0be4b`)
- fnmatch-witness generation (transcribed wildcard rows only; see `TestMatching.test_ubus_wildcard_object_hostapd_dot_star`)

## fnmatch witnesses (C double)

Handwritten rows in `policy/tests/test_conformance.py` tie Python `acl_match` / `login_test_permission` to `uh_ubus_policy match` and `group`. Wildcard ubus object `hostapd.*` with `del_client` is transcribed from luci `b2e0be4b` `luci-mod-network.json` (`luci-mod-network-config` write grant), not from a generator. Inventoried exec methods use literal `match` / `decide` against their own names (ALLOW) and against the unauthenticated `getFeatures` grant (DENY).

Pins live in `corpus/lock.json`. Luci join keys: `session_class`, `ingress=ubus_http`, `entrypoint_id`, `analysis_revision=policy:ubus-luci-exec-methods-v2`. cgi-backup: `ingress=cgi_io`, `cgi_endpoint=cgi-backup`, `analysis_revision=policy:cgi-backup-v1`. cgi-upload: `cgi_endpoint=cgi-upload`, `analysis_revision=policy:cgi-upload-v1`. cgi-download: `cgi_endpoint=cgi-download`, `analysis_revision=policy:cgi-download-v1`. cgi-exec: `cgi_endpoint=cgi-exec`, `analysis_revision=policy:cgi-exec-v1`. cgi-exec file.exec helpers: `entrypoint_id=cgi_io:cgi-exec:<fs_path>`, `analysis_revision=policy:cgi-exec-file-v1`. cgi-exec status file.exec: same join keys, `analysis_revision=policy:cgi-exec-status-v1`. ubus file.exec: `ingress=ubus_http`, `ubus_object=file`, `method=exec`, `entrypoint_id=ubus_http:file.exec:<fs_path>` (routes JSON uses `…/sbin/ip:-j`), `analysis_revision=policy:ubus-file-exec-v1`. ubus file.exec ifup: same join keys, `analysis_revision=policy:ubus-file-exec-ifup-v1`. Do not reuse `policy:ubus-getfeatures-v1` for this catalog. All producers share the lockfile `corpus_revision`.

Grant ↔ effect joins against `reports/handler_effects.json` use `corpus_revision`, `profile`, `ingress`, `entrypoint_id`, plus `ubus_object`/`method` or `cgi_endpoint`, and grant `record_id` in the effect `evidence_refs`. See [reports/handler_effects.md](../reports/handler_effects.md). luci.sys `getConntrackList` / `getProcessList` popens join those grants; see [m4-luci-sys-status-exec.md](../reports/m4-luci-sys-status-exec.md).

`policy:no-ubusauth-v1` join keys: `corpus_revision` (lockfile hash), `profile=luci-ssl-25.12-no-ubusauth`, `ingress=ubus_http`, `entrypoint_id`. No grant `record_id` (no grants). Do not join these decisions to luci-ssl-25.12 grants.
