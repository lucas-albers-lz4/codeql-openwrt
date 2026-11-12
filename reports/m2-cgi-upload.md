# M2: cgi-io cgi-upload oracle

C, not ucode. Policy-facts (`policy:cgi-upload-v1`) evaluates `/cgi-bin/cgi-upload`
from pinned cgi-io `main_upload` @ `31cb3c89`.

Conjunctive gate:

1. `CONTENT_TYPE` `multipart/form-data;` with a boundary `=`
2. `session.access(sid, "cgi-io", "upload", "write")`
3. `canonicalize_path(filename)` then `session.access(sid, "file", canon, "write")`

A cgi-io upload grant without the file-write grant is **not** enough.
`../` is collapsed before the file ACL so it cannot ride `/etc/luci-uploads/*`.

cgi-io upload failures use `response()` **Status 200** with a JSON failure
body, not `failure(403)`.

This slice does **not** rewrite `policy/grants.json` or
`reports/handler_effects.json` (those files are on other in-flight PRs).
Artifacts: `policy/cgi_upload_decisions.json`,
`reports/m2-cgi-upload-effect.json`.

Does not copy/chmod files. Does not emit cgi-download, cgi-exec, dispatcher,
`authorization_violation`, or `path_found`. `shellquote` and `basename` are
not sanitizers; `canonicalize_path` is not a taint sanitizer.

Unauthenticated is deny. Fixture `luci-base` (synthesized write login) and
stock root `*` allow `/etc/luci-uploads/example.bin` as `intended_access`.
The `luci-mod-system-flash` fixture login is `list read` only, so its ACL
group's upload write is not in session.
