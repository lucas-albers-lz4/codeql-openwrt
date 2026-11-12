# Policy-facts (M2)

Canonical `/ubus` `luci.getFeatures` oracle. Producer is `policy_facts`.

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
- Same session → `luci`/`setPassword` deny (no invented grant)
- Missing SID → JSON-RPC parse failure
- Stock root `list read '*' / list write '*'` → `getFeatures` allow (not a violation)
- Literal object/method names only

## Out of scope (not M2)

- M4, Alloy, `alloy_input.json`, `producer: step4`
- Markup, Track A, cgi-io, dispatcher / `admin/ubus` SID rewrite
- fnmatch-witness generation
- A `no_ubusauth=1` profile (the SID rewrite is implemented in the oracle and noted as an assumption/unknown)

Pins live in `corpus/lock.json`. Join keys: `session_class`, `ingress=ubus_http`, `entrypoint_id=ubus_http:luci.getFeatures`, `analysis_revision=policy:ubus-getfeatures-v1`.
