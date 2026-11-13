# M2: cgi-exec file.exec of three luci-ssl libexec helpers

C, not ucode. Policy-facts (`policy:cgi-exec-file-v1`) evaluates the conjunctive
**second** gate of `/cgi-bin/cgi-exec` from pinned cgi-io `main_exec` @
`31cb3c89`, bounded to the three inventoried luci-ssl `#!/bin/sh` helpers at
luci pin `b2e0be4b`.

Callers at that pin use `fs.exec_direct` → cgi-exec (Track A is unstaffed).
These are not luci object methods. Do not invent luci-ssl ubus grants.

Bounded gate, after already-decoded form input:

1. `CONTENT_TYPE` `application/x-www-form-urlencoded`
2. `session.access(sid, "cgi-io", "exec", "read")`
3. `parse_command` then `canonicalize_path` of argv0
4. `session.access(sid, "file", cmdline, "exec")`, or else
   `session.access(sid, "file", exe, "exec")`

A cgi-io exec read grant is not authorization to run an arbitrary command.
`lookup_executable` is not a live PATH/stat search: only the three installed
absolute helper paths are treated as found. This oracle does not fork `execv`.

| Helper | Delegated fixture | File ACL |
| --- | --- | --- |
| `/usr/libexec/syslog-wrapper` | `luci-mod-status-logs` | bare path `exec` (executable fallback allows extra argv; the helper ignores `$1`) |
| `/usr/libexec/luci-peeraddr` | `luci-mod-network-config` | bare path `exec` |
| `/usr/libexec/package-manager-call` | `luci-app-package-manager` | cmdline `list-*` exact; write `install` / `install *` / `remove *` / `upgrade` / `upgrade *` / `update` |

Unauthenticated is deny (403) at the cgi-io exec read gate. A session with
cgi-io exec but without the helper file ACL is 403 `Access to command denied
by ACL`. Stock root `*` is `intended_access` (`root-administration`), not a
violation. The `install *` glob matching extra package tokens is
`intended_access` for the package-manager fixture, not `authorization_violation`
and not a PoC.

`shellquote` and `basename` are not sanitizers. `canonicalize_path` is a
textual path normalizer, not a taint sanitizer. Helper-internal commands
(logread, apk/opkg, `ip route get`) are transcribed in
[m4-luci-ssl-files.md](m4-luci-ssl-files.md), not executed here.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-cgi-exec-file-effect.json`; decisions:
`policy/cgi_exec_file_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`. Does not
staff ubus `file.exec` (rpcd-mod-file) or `execv`. luci-mod-status
dmesg/nft/iptables/firewall-init `fs.exec_direct` commands are
`policy:cgi-exec-status-v1`. The luci `/ubus` emitter is unchanged.
cgi-exec-v1 remains the first-gate oracle.
