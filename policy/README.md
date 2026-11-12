# Policy-facts (M2)

Canonical `/ubus` luci policy oracle plus cgi-io backup/upload/download/exec ingresses. Producer is `policy_facts`.
Luci `analysis_revision` is `policy:ubus-luci-exec-methods-v2`. cgi-backup is `policy:cgi-backup-v1`. cgi-upload is `policy:cgi-upload-v1`. cgi-download is `policy:cgi-download-v1`. cgi-exec is `policy:cgi-exec-v1`. The `no_ubusauth=1` variant is `policy:no-ubusauth-v1` (profile `luci-ssl-25.12-no-ubusauth`).

The HTTP gate is uhttpd `uh_ubus_allowed` → ubus `session.access` (uhttpd omits `scope`; rpcd defaults `scope` to `ubus`). Missing SID with `no_ubusauth=0` is JSON-RPC `ERROR_PARSE`, not the all-zero sentinel and not rpcd `file`/`uci` absent-SID skip.

cgi-backup, cgi-upload, and cgi-download are separate C ingresses (`policy/cgi_backup.py`, `policy/cgi_upload.py`, `policy/cgi_download.py`). Their oracles and C doubles accept already-decoded form fields: successful form-body framing and URL decoding are preconditions. cgi-backup and cgi-download check the content-type prefix and model authorization, but do not model `CONTENT_LENGTH` validation, truncated bodies, or percent-decoding failures in upstream `postdecode`. cgi-upload models a complete multipart request with sessionid/filename before filedata when present; it does not model arbitrary part order, truncated framing, tempfile creation, or copy/chmod. Given those decoded inputs, cgi-io supplies `scope=cgi-io`. Upload and download are conjunctive: the cgi-io ACL is not enough without the matching `file` ACL on `canonicalize_path(...)`. A missing sessionid on cgi-backup/cgi-download yields HTTP 403, not the `/ubus` parse failure. cgi-upload failures use `response()` Status 200 with a JSON body.

## Run

From the repository root:

```sh
python3 -m policy emit
python3 -m unittest discover -s policy/tests -t .
```

`emit` rewrites `policy/grants.json` (luci grants, then cgi-backup, cgi-upload, cgi-download, cgi-exec), `policy/policy_decisions.json` (luci), the per-endpoint cgi decision files, and `policy/no_ubusauth_decisions.json` (no grants). The luci grant emitter refuses anything except `luci.getFeatures`, the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`. It also refuses grants for `no_ubusauth=1`. Synthetic cgi `handler_effect` rows are upserted into `reports/handler_effects.json` and checked against the oracles. All rows share the `corpus/lock.json` hash. Profile `luci-ssl-25.12-no-ubusauth` does not join luci-ssl grants (`profile` differs).

Tests compare the luci evaluator to handwritten cases in `policy/fixtures/expected_cases.json` and the cgi evaluators to `policy/fixtures/cgi_backup_cases.json`, `cgi_upload_cases.json`, `cgi_download_cases.json`, and `cgi_exec_cases.json` (transcribed from pinned C and ACL JSON, not from the evaluator). They compile the C doubles with:

```sh
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/uh_ubus_policy policy/c_double/uh_ubus_policy.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_backup policy/c_double/cgi_backup.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_upload policy/c_double/cgi_upload.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_download policy/c_double/cgi_download.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_exec policy/c_double/cgi_exec.c
```

Those C doubles cover the decoded-input gate + `session.access` matching without a live daemon. They do not model raw HTTP form parsing, and live uhttpd/rpcd/cgi-io/`sysupgrade` are not executed.

## In scope

- Profile `luci-ssl-25.12`, `no_ubusauth=0`
- Profile `luci-ssl-25.12-no-ubusauth`, `option no_ubusauth 1` / `uhttpd -a`: empty SID rewrites to the all-zero default and `uh_ubus_allowed` is skipped. Unauthenticated `setPassword` allow is that skip (`unassessed`), not an invented luci-ssl grant. Missing data is still JSON-RPC parse failure. cgi-io / dispatcher unchanged.
- Stock unauthenticated session (present all-zero SID) → `luci`/`getFeatures` allow
- Same session → `luci`/`getSwconfigFeatures`, `getSwconfigPortState`, `getRealtimeStats`, `setPassword`, `setLocaltime`, `getBlockDevices`, `setBlockDetect`, `getConntrackList`, `getProcessList` deny (no invented grant)
- Synthetic delegated fixture sessions → matching methods allow (`luci-mod-network-config`, `luci-mod-status-realtime`, `luci-mod-status-processes`, `luci-mod-system-config`, `luci-mod-system-mounts`, `luci-base` write login for cgi-upload, `luci-mod-system-flash` for cgi-backup/cgi-download); these are not stock logins. Their intended-access assessments are conditional on those fixture roles. The processes fixture is read-only (write `file.exec` `/bin/kill` is not granted).
- Missing SID → JSON-RPC parse failure
- Stock root `list read '*' / list write '*'` → those methods allow (not a violation)
- Literal object/method names only
- Emission bounded to `getFeatures` plus the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`
- cgi-backup (`/cgi-bin/cgi-backup`) → `sensitive_backup_read` only: unauthenticated 403; fixture `luci-mod-system-flash` allow; root `*` allow (not a violation). cgi-io supplies `scope=cgi-io`.
- cgi-upload (`/cgi-bin/cgi-upload`) → conjunctive `file_write`: cgi-io `upload` write **and** `file` write of `canonicalize_path(filename)`. Unauthenticated is denied (Status 200 JSON). Fixture `luci-base` (write login) and stock root `*` allow `/etc/luci-uploads/example.bin`. The `luci-mod-system-flash` fixture login is `list read` only, so upload write is not in session.
- cgi-download (`/cgi-bin/cgi-download`) → conjunctive `file_read`: cgi-io `download` read **and** `file` read of `canonicalize_path(path)`. Unauthenticated 403. Fixture `luci-mod-system-flash` and stock root `*` allow `/dev/mtdblock0`. `../` is collapsed before the file ACL.
- cgi-exec (`/cgi-bin/cgi-exec`) → `exec` session gate only: `session.access(sid, "cgi-io", "exec", "read")`. Unauthenticated 403. Fixture `luci-mod-network-config` and stock root `*` allow the cgi-io exec read gate. Does not model `file.exec` of a command, `parse_command`, or `execv`.

## Out of scope (not M2)

- M4, Alloy, `alloy_input.json`, `producer: step4`
- Markup, Track A, dispatcher / `admin/ubus` SID rewrite (`no_ubusauth` does not apply there)
- `file.exec` / `hostapd.*` rows present in the loaded ACL files (matching accuracy only; not emitted)
- `setInitAction` (no luci-ssl delegated grant at luci `b2e0be4b`)
- fnmatch-witness generation (transcribed wildcard rows only; see `TestMatching.test_ubus_wildcard_object_hostapd_dot_star`)

## fnmatch witnesses (C double)

Handwritten rows in `policy/tests/test_conformance.py` tie Python `acl_match` / `login_test_permission` to `uh_ubus_policy match` and `group`. Wildcard ubus object `hostapd.*` with `del_client` is transcribed from luci `b2e0be4b` `luci-mod-network.json` (`luci-mod-network-config` write grant), not from a generator. Inventoried exec methods use literal `match` / `decide` against their own names (ALLOW) and against the unauthenticated `getFeatures` grant (DENY).

Pins live in `corpus/lock.json`. Luci join keys: `session_class`, `ingress=ubus_http`, `entrypoint_id`, `analysis_revision=policy:ubus-luci-exec-methods-v2`. cgi-backup: `ingress=cgi_io`, `cgi_endpoint=cgi-backup`, `analysis_revision=policy:cgi-backup-v1`. cgi-upload: `cgi_endpoint=cgi-upload`, `analysis_revision=policy:cgi-upload-v1`. cgi-download: `cgi_endpoint=cgi-download`, `analysis_revision=policy:cgi-download-v1`. cgi-exec: `cgi_endpoint=cgi-exec`, `analysis_revision=policy:cgi-exec-v1`. Do not reuse `policy:ubus-getfeatures-v1` for this catalog. All producers share the lockfile `corpus_revision`.

Grant ↔ effect joins against `reports/handler_effects.json` use `corpus_revision`, `profile`, `ingress`, `entrypoint_id`, plus `ubus_object`/`method` or `cgi_endpoint`, and grant `record_id` in the effect `evidence_refs`. See [reports/handler_effects.md](../reports/handler_effects.md). luci.sys `getConntrackList` / `getProcessList` popens join those grants; see [m4-luci-sys-status-exec.md](../reports/m4-luci-sys-status-exec.md).

`policy:no-ubusauth-v1` join keys: `corpus_revision` (lockfile hash), `profile=luci-ssl-25.12-no-ubusauth`, `ingress=ubus_http`, `entrypoint_id`. No grant `record_id` (no grants). Do not join these decisions to luci-ssl-25.12 grants.
