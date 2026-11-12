# M2: cgi-io cgi-download oracle

C, not ucode. Policy-facts (`policy:cgi-download-v1`) evaluates `/cgi-bin/cgi-download`
from pinned cgi-io `main_download` @ `31cb3c89`.

Conjunctive gate:

1. `CONTENT_TYPE` `application/x-www-form-urlencoded`
2. `session.access(sid, "cgi-io", "download", "read")`
3. `canonicalize_path(path)` then `session.access(sid, "file", canon, "read")`

A cgi-io download grant without the file-read grant is **not** enough.
`../` is collapsed before the file ACL so it cannot ride `/dev/mtdblock[0-9]*`.

This slice does **not** rewrite `policy/grants.json` or
`reports/handler_effects.json` (those files are on other in-flight PRs).
Artifacts: `policy/cgi_download_decisions.json`,
`reports/m2-cgi-download-effect.json`.

Does not open/stat/sendfile. Does not emit cgi-upload, cgi-exec, dispatcher,
`authorization_violation`, or `path_found`. `shellquote` and `basename` are
not sanitizers; `canonicalize_path` is not a taint sanitizer.

Unauthenticated is deny (403). Fixture `luci-mod-system-flash` and stock root
`*` allow `/dev/mtdblock0` as `intended_access`.
