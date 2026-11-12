# M4: `shellquote` complete-argument barrier

`shellquote` is **not** a global sanitizer. This slice models one supported context: the quoted value is a template substitution inside a larger `popen`/`system` command string (a complete shell word next to a literal command).

| Fixture / method | Taint reaches sink | Complete-argument quote | Shell-injection candidate |
| --- | --- | --- | --- |
| `taint_pos` (`popen(request.args.cmd)`) | yes | no | **yes** |
| `quote_ok` (`swconfig dev ${shellquote(...)} help`) | yes | **yes** | **no** |
| `quote_exe` (`popen(shellquote(request.args.cmd))`) | yes | no (whole command) | **yes** (executable selection) |
| `taint_neg` | no | — | no |
| luci `getSwconfigFeatures` / `getSwconfigPortState` | yes | **yes** | **no** |

Unsupported (still taint, not a barrier): quoted executable selection, interpreter program input, embedding the quoted value in an unsafe context, and same-function locals (`getRealtimeStats` `flags`, `setPassword` `u`/`p`; inventoried in [m4-realtime-password-unquoted.md](m4-realtime-password-unquoted.md)).

See `reports/m4-shellquote-findings.json`.
