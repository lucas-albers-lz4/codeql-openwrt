# Policy-facts (M2)

Canonical `/ubus` luci policy oracle. Producer is `policy_facts`.
`analysis_revision` is `policy:ubus-luci-exec-methods-v1`.

The HTTP gate is uhttpd `uh_ubus_allowed` → ubus `session.access` (uhttpd omits `scope`; rpcd defaults `scope` to `ubus`). Missing SID with `no_ubusauth=0` is JSON-RPC `ERROR_PARSE`, not the all-zero sentinel and not rpcd `file`/`uci` absent-SID skip.

## Run

From the repository root:

```sh
python3 -m policy emit
python3 -m unittest discover -s policy/tests -t .
```

`emit` rewrites `policy/grants.json` and `policy/policy_decisions.json`. Tests compare the evaluator to handwritten cases in `policy/fixtures/expected_cases.json` (transcribed from pinned C and ACL JSON, not from the evaluator) and compile `policy/c_double/uh_ubus_policy.c` with:

```sh
gcc -std=c11 -Wall -Wextra -Werror -O0 -o policy/c_double/uh_ubus_policy policy/c_double/uh_ubus_policy.c
```

That C double covers parse + `session.access` matching without a live ubus daemon. Live uhttpd/rpcd are not executed.

## In scope

- Profile `luci-ssl-25.12`, `no_ubusauth=0`
- Stock unauthenticated session (present all-zero SID) → `luci`/`getFeatures` allow
- Same session → `luci`/`getSwconfigFeatures`, `getSwconfigPortState`, `getRealtimeStats`, `setPassword`, `setLocaltime` deny (no invented grant)
- Delegated fixture sessions → matching methods allow (`luci-mod-network-config`, `luci-mod-status-realtime`, `luci-mod-system-config`)
- Missing SID → JSON-RPC parse failure
- Stock root `list read '*' / list write '*'` → those methods allow (not a violation)
- Literal object/method names only
- Emission bounded to `getFeatures` plus the five inventoried request.args exec methods

## Out of scope (not M2)

- M4, Alloy, `alloy_input.json`, `producer: step4`
- Markup, Track A, cgi-io, dispatcher / `admin/ubus` SID rewrite
- `file.exec` / `hostapd.*` rows present in the loaded ACL files (matching accuracy only; not emitted)
- `setInitAction` (no luci-ssl delegated grant at luci `b2e0be4b`)
- fnmatch-witness generation (transcribed wildcard rows only; see `TestMatching.test_ubus_wildcard_object_hostapd_dot_star`)
- A `no_ubusauth=1` profile (the SID rewrite is implemented in the oracle and noted as an assumption/unknown)

## fnmatch witnesses (C double)

Handwritten rows in `policy/tests/test_conformance.py` tie Python `acl_match` / `login_test_permission` to `uh_ubus_policy match` and `group`. Wildcard ubus object `hostapd.*` with `del_client` is transcribed from luci `b2e0be4b` `luci-mod-network.json` (`luci-mod-network-config` write grant), not from a generator. The five exec methods use literal `match` / `decide` against their own names (ALLOW) and against the unauthenticated `getFeatures` grant (DENY).

Pins live in `corpus/lock.json`. Join keys: `session_class`, `ingress=ubus_http`, `entrypoint_id`, `analysis_revision=policy:ubus-luci-exec-methods-v1`. Do not reuse `policy:ubus-getfeatures-v1` for this catalog.
