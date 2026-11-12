# M2: cgi-io cgi-exec oracle

C, not ucode. Policy-facts (`policy:cgi-exec-v1`) evaluates `/cgi-bin/cgi-exec`
from pinned cgi-io `main_exec` @ `31cb3c89`.

Bounded gate:

1. `CONTENT_TYPE` `application/x-www-form-urlencoded`
2. `session.access(sid, "cgi-io", "exec", "read")`

Missing SID is HTTP 403, not 400. Invalid content-type is HTTP 400.

This slice does **not** model `parse_command`, `canonicalize_path` of argv0,
`lookup_executable`, `file.exec` of a command, or `execv`. A cgi-io exec read
grant is not a claim that an arbitrary command is authorized.

Artifacts: `policy/cgi_exec_decisions.json`, `reports/m2-cgi-exec-effect.json`,
appended `cgi_io` grants in `policy/grants.json`, and a synthetic row in
`reports/handler_effects.json`. The luci `/ubus` emitter is unchanged.

Does not emit cgi-backup, cgi-upload, cgi-download, dispatcher,
`authorization_violation`, or `path_found`. `shellquote` and `basename` are
not sanitizers. Does not invent luci-ssl grants.

Unauthenticated is deny (403). Fixture `luci-mod-network-config` and stock root
`*` allow the cgi-io exec read gate as `intended_access`.
`luci-mod-status-logs`, `luci-mod-status-firewall`, and
`luci-app-package-manager` also grant cgi-io exec at luci `b2e0be4b`; those
logins are not staffed here.
