# M2: cgi-exec file.exec of luci-mod-status dmesg and firewall

C, not ucode. Policy-facts (`policy:cgi-exec-status-v1`) evaluates the
conjunctive **second** gate of `/cgi-bin/cgi-exec` from pinned cgi-io
`main_exec` @ `31cb3c89`, bounded to luci-mod-status commands the pinned
views reach via `fs.exec_direct` at luci pin `b2e0be4b`.

These are not luci object methods. Do not invent luci-ssl ubus grants.
The three luci-ssl libexec helpers stay on `policy:cgi-exec-file-v1`.

Bounded gate, after already-decoded form input:

1. `CONTENT_TYPE` `application/x-www-form-urlencoded`
2. `session.access(sid, "cgi-io", "exec", "read")`
3. `parse_command` then `canonicalize_path` of argv0
4. `session.access(sid, "file", cmdline, "exec")`, or else
   `session.access(sid, "file", exe, "exec")`

A cgi-io exec read grant is not authorization to run an arbitrary command.
`lookup_executable` is not a live PATH/stat search: only the inventoried
absolute paths below are treated as found. This oracle does not fork `execv`.

| Command | Delegated fixture | File ACL |
| --- | --- | --- |
| `/bin/dmesg -r` | `luci-mod-status-logs` | exact cmdline (`dmesg.js`) |
| `/usr/sbin/nft --terse --json list ruleset` | `luci-mod-status-firewall` | exact cmdline (`nftables.js`) |
| `/usr/sbin/iptables --line-numbers -w -nvxL -t *` | `luci-mod-status-firewall` | trailing glob (`iptables.js` tables) |
| `/usr/sbin/ip6tables --line-numbers -w -nvxL -t *` | `luci-mod-status-firewall` | trailing glob; `/usr/sbin/ip6tables` `list` is not exec |
| `/usr/sbin/iptables-save` | `luci-mod-status-firewall` | exact cmdline (`nftables.js` fallback) |
| `/usr/sbin/ip6tables-save` | `luci-mod-status-firewall` | exact cmdline (`nftables.js` fallback) |
| `/etc/init.d/firewall restart` | `luci-mod-status-firewall` write | exact cmdline (`iptables.js` handleRestart) |

Unauthenticated is deny (403) at the cgi-io exec read gate. A session with
cgi-io exec but without the command file ACL is 403 `Access to command denied
by ACL`. A read-only firewall fixture cannot restart. Extra tokens on the
iptables `-t *` glob are `intended_access` for the firewall fixture, not
`authorization_violation` and not a PoC. Stock root `*` is
`intended_access` (`root-administration`). Bare executable fallback is not
granted for these commands. `iptables-legacy-save` is HTTP 404 here (not
inventoried, not a live PATH search).

`iptables.js` `handleCounterReset` uses `fs.exec` (ubus `file.exec` /
rpcd-mod-file) for `iptables -Z` and is not this slice.
`luci-mod-status-routes` `ip` exec is ubus `file.exec`, not cgi-io.

`shellquote` and `basename` are not sanitizers. `canonicalize_path` is a
textual path normalizer, not a taint sanitizer.

Canonical `python3 -m policy emit` appends grants to `policy/grants.json` and
upserts `reports/handler_effects.json` (same `corpus_revision` lock hash).
Snapshot: `reports/m2-cgi-exec-status-effect.json`; decisions:
`policy/cgi_exec_status_decisions.json`.

Does not emit dispatcher, `authorization_violation`, or `path_found`.
Does not rewrite the luci `/ubus` emitter.
