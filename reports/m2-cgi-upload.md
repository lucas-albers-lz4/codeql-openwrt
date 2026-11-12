# M2: cgi-io cgi-upload oracle

C, not ucode. Policy-facts (`policy:cgi-upload-v1`) evaluates `/cgi-bin/cgi-upload`
from pinned cgi-io `main_upload` @ `31cb3c89`.

Conjunctive gate:

1. `CONTENT_TYPE` `multipart/form-data;` with a boundary `=`
2. `session.access(sid, "cgi-io", "upload", "write")`
3. `canonicalize_path(filename)` then `session.access(sid, "file", canon, "write")`

A cgi-io upload grant without the file-write grant is **not** enough.
`../` is collapsed before the file ACL so it cannot ride `/etc/luci-uploads/*`.

Emitted cgi-io upload failures use `response()` **Status 200** with a JSON
failure body, not `failure(403)`. The upload ACL runs at `data_end_cb` only
when a `sessionid` part is present. An absent sessionid with a `filedata`
part instead produces `File data without session` at `data_begin_cb`
(`missing_session`, Status 200); this is separate from a present unauthorized
or empty SID (`upload_denied`). A complete request without `filedata` and
without a rejected sessionid part returns from `main_upload` without
`response()` (`no_response`, `http_status: null`), so it is not an ACL denial.

Cases assume complete multipart framing, with sessionid/filename parts before
filedata when present. `filedata_present` defaults to true; SID `None` means
an absent part and `""` means a present empty part. Arbitrary ordering,
truncated framing, temp-file creation, and file copying remain outside the slice.

Canonical `python3 -m policy emit` appends the luci-base and root grants
to `policy/grants.json` and upserts this effect into
`reports/handler_effects.json` (same `corpus_revision` lock hash).
Per-endpoint artifacts remain `policy/cgi_upload_decisions.json` and
`reports/m2-cgi-upload-effect.json`.

Does not copy/chmod files. Does not emit cgi-download, cgi-exec, dispatcher,
`authorization_violation`, or `path_found`. `shellquote` and `basename` are
not sanitizers; `canonicalize_path` is not a taint sanitizer.

The present unauthenticated SID is denied by the upload ACL. Fixture `luci-base` (synthesized write login) and
stock root `*` allow `/etc/luci-uploads/example.bin` as `intended_access`.
The `luci-mod-system-flash` fixture login is `list read` only, so its ACL
group's upload write is not in session.
