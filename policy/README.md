# Policy-facts (M2)

Canonical `/ubus` luci policy oracle plus cgi-backup and cgi-exec ingresses. Producer is `policy_facts`.
Luci `analysis_revision` is `policy:ubus-luci-exec-methods-v2`. cgi-backup is `policy:cgi-backup-v1`. cgi-exec is `policy:cgi-exec-v1`.

The HTTP gate is uhttpd `uh_ubus_allowed` → ubus `session.access` (uhttpd omits `scope`; rpcd defaults `scope` to `ubus`). Missing SID with `no_ubusauth=0` is JSON-RPC `ERROR_PARSE`, not the all-zero sentinel and not rpcd `file`/`uci` absent-SID skip.

cgi-backup and cgi-exec are separate C ingresses (`policy/cgi_backup.py`, `policy/cgi_exec.py`). Their oracles and C doubles accept already-decoded form fields: successful form-body framing and URL decoding are preconditions. The slices check the content-type prefix and model authorization, but do not model `CONTENT_LENGTH` validation, truncated bodies, or percent-decoding failures in upstream `postdecode`. Given a valid decoded form body, cgi-io supplies `scope=cgi-io`. `main_backup` checks `session.access` object `backup` function `read`. `main_exec` is bounded to `session.access` object `exec` function `read` and does not model `parse_command`, `canonicalize_path`, `lookup_executable`, `file.exec` of a command, or `execv`. A missing sessionid then yields HTTP 403, not the `/ubus` parse failure.

## Run

From the repository root:

```sh
python3 -m policy emit
python3 -m unittest discover -s policy/tests -t .
```

`emit` rewrites `policy/grants.json` (luci grants, then cgi-backup, then cgi-exec), `policy/policy_decisions.json` (luci), `policy/cgi_backup_decisions.json`, and `policy/cgi_exec_decisions.json`. The luci grant emitter refuses anything except `luci.getFeatures`, the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`. Synthetic cgi `handler_effect` rows are maintained in `reports/handler_effects.json` and checked against the oracles.

Tests compare the luci evaluator to handwritten cases in `policy/fixtures/expected_cases.json` and the cgi evaluators to `policy/fixtures/cgi_backup_cases.json` and `cgi_exec_cases.json` (transcribed from pinned C and ACL JSON, not from the evaluator). They compile the C doubles with:

```sh
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/uh_ubus_policy policy/c_double/uh_ubus_policy.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_backup policy/c_double/cgi_backup.c
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/cgi_exec policy/c_double/cgi_exec.c
```

Those C doubles cover the decoded-input gate + `session.access` matching without a live daemon. They do not model raw HTTP form parsing, and live uhttpd/rpcd/cgi-io/`sysupgrade` are not executed.

## In scope

- Profile `luci-ssl-25.12`, `no_ubusauth=0`
- Stock unauthenticated session (present all-zero SID) → `luci`/`getFeatures` allow
- Same session → `luci`/`getSwconfigFeatures`, `getSwconfigPortState`, `getRealtimeStats`, `setPassword`, `setLocaltime`, `getBlockDevices`, `setBlockDetect`, `getConntrackList`, `getProcessList` deny (no invented grant)
- Synthetic delegated fixture sessions → matching methods allow (`luci-mod-network-config`, `luci-mod-status-realtime`, `luci-mod-status-processes`, `luci-mod-system-config`, `luci-mod-system-mounts`); these are not stock logins. Their intended-access assessments are conditional on those fixture roles. The processes fixture is read-only (write `file.exec` `/bin/kill` is not granted).
- Missing SID → JSON-RPC parse failure
- Stock root `list read '*' / list write '*'` → those methods allow (not a violation)
- Literal object/method names only
- Emission bounded to `getFeatures` plus the inventoried request.args exec methods, `getBlockDevices` / `setBlockDetect`, and luci.sys `getConntrackList` / `getProcessList`
- cgi-backup (`/cgi-bin/cgi-backup`) → `sensitive_backup_read` only: unauthenticated 403; fixture `luci-mod-system-flash` allow; root `*` allow (not a violation). cgi-io supplies `scope=cgi-io`.
- cgi-exec (`/cgi-bin/cgi-exec`) → cgi-io `exec` read gate only: unauthenticated 403; fixture `luci-mod-network-config` allow; root `*` allow (not a violation). Does not invent grants for unstaffed `luci-mod-status-logs` / `luci-mod-status-firewall` / `luci-app-package-manager` logins.

## Out of scope (not M2)

- M4, Alloy, `alloy_input.json`, `producer: step4`
- Markup, Track A, cgi-upload / cgi-download, dispatcher / `admin/ubus` SID rewrite
- cgi-exec `parse_command` / `canonicalize_path` / `lookup_executable` / `file.exec` of a command / `execv`
- `file.exec` / `hostapd.*` rows present in the loaded ACL files (matching accuracy only; not emitted)
- `setInitAction` (no luci-ssl delegated grant at luci `b2e0be4b`)
- fnmatch-witness generation (transcribed wildcard rows only; see `TestMatching.test_ubus_wildcard_object_hostapd_dot_star`)
- A `no_ubusauth=1` profile (the SID rewrite is implemented in the oracle and noted as an assumption/unknown)

## fnmatch witnesses (C double)

Handwritten rows in `policy/tests/test_conformance.py` tie Python `acl_match` / `login_test_permission` to `uh_ubus_policy match` and `group`. Wildcard ubus object `hostapd.*` with `del_client` is transcribed from luci `b2e0be4b` `luci-mod-network.json` (`luci-mod-network-config` write grant), not from a generator. Inventoried exec methods use literal `match` / `decide` against their own names (ALLOW) and against the unauthenticated `getFeatures` grant (DENY).

Pins live in `corpus/lock.json`. Luci join keys: `session_class`, `ingress=ubus_http`, `entrypoint_id`, `analysis_revision=policy:ubus-luci-exec-methods-v2`. cgi-backup: `ingress=cgi_io`, `cgi_endpoint=cgi-backup`, `analysis_revision=policy:cgi-backup-v1`. cgi-exec: `cgi_endpoint=cgi-exec`, `analysis_revision=policy:cgi-exec-v1`. Do not reuse `policy:ubus-getfeatures-v1` for this catalog.

Grant ↔ effect joins against `reports/handler_effects.json` use `corpus_revision`, `profile`, `ingress`, `entrypoint_id`, plus `ubus_object`/`method` or `cgi_endpoint`, and grant `record_id` in the effect `evidence_refs`. See [reports/handler_effects.md](../reports/handler_effects.md). luci.sys `getConntrackList` / `getProcessList` popens join those grants; see [m4-luci-sys-status-exec.md](../reports/m4-luci-sys-status-exec.md).
