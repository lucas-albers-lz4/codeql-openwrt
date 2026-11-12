# M2: cgi-io cgi-exec oracle

C, not ucode. Policy-facts (`policy:cgi-exec-v1`) evaluates `/cgi-bin/cgi-exec`
from pinned cgi-io `main_exec` @ `31cb3c89`.

Bounded gate:

1. `CONTENT_TYPE` `application/x-www-form-urlencoded`
2. `session.access(sid, "cgi-io", "exec", "read")`

Missing SID is HTTP 403, not 400. Invalid content-type is HTTP 400.

This slice does **not** model `parse_command`, `canonicalize_path` of argv0,
`lookup_executable`, or `execv`. File.exec of the three luci-ssl libexec
helpers is `policy:cgi-exec-file-v1`. A cgi-io exec read grant is not a
claim that an arbitrary command is authorized.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-cgi-exec-effect.json`; decisions:
`policy/cgi_exec_decisions.json`.

Does not emit cgi-backup, cgi-upload, cgi-download, dispatcher,
`authorization_violation`, or `path_found`. `shellquote` and `basename` are
not sanitizers. Does not invent luci-ssl grants.

Unauthenticated is deny (403). Fixture `luci-mod-network-config` and stock root
`*` allow the cgi-io exec read gate as `intended_access`.
`luci-mod-status-firewall` also grants cgi-io exec at luci `b2e0be4b`; that
login is not staffed here. `luci-mod-status-logs` and
`luci-app-package-manager` file.exec helpers are `policy:cgi-exec-file-v1`.
