# M2: uhttpd `option no_ubusauth 1` profile

Policy-facts (`policy:no-ubusauth-v1`) evaluates `/ubus` JSON-RPC `call` when
uhttpd `option no_ubusauth 1` / `uhttpd -a` is set. Profile id
`luci-ssl-25.12-no-ubusauth` is distinct from `luci-ssl-25.12` (`no_ubusauth=0`).
Both share `corpus/lock.json` (same `corpus_revision`).

Pinned uhttpd `ubus.c` @ `93b05e0`:

1. An empty string SID rewrites to `UH_UBUS_DEFAULT_SID` when
   `conf.ubus_noauth` is set. A null or omitted SID slot is skipped by the
   typed libubox array scan, shifting later strings and causing the usual call
   to fail parse.
2. Object lookup occurs first and can return `ERROR_OBJECT`. For an existing
   object, `uh_ubus_handle_request_object` calls `uh_ubus_allowed` only when
   `!conf.ubus_noauth`. The skip is a gate fact, not an ACL grant or a
   guarantee that the plugin call succeeds.

The flag also skips uhttpd authorization on `/call/<object>` and GET
subscriptions. Those paths are not modeled in this JSON-RPC slice.

Stock overlay @ openwrt `4e964251` leaves `# option no_ubusauth 0` commented
and maps the UCI flag with `append_bool no_ubusauth -a`. luci-ssl does not
ship this as default.

Unauthenticated `setPassword` on `luci-ssl-25.12` stays **deny**. On this
variant the HTTP gate **allows** because `session.access` is skipped
(`unassessed`, `grant_emitted=false`). Unknown SID is the same skip, not
"become unauthenticated". Missing data is still JSON-RPC `ERROR_PARSE`.

Does not rewrite the luci grant emitter. Does not invent luci-ssl grants.
Does not emit `authorization_violation`, `path_found`, cgi-io, dispatcher,
or handler effects. cgi-io and `admin/ubus` are unchanged.

Decisions: `policy/no_ubusauth_decisions.json`. C double:
`policy/c_double/uh_ubus_policy.c`.
