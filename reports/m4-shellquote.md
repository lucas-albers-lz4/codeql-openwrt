# M4: `shellquote` findings and conservative limits

The retained report reflects the producer's `step3:shellquote-barrier-v2` snapshot at `ae946190661eb221bc1f562fdba02088ef83de2d`. No `shellquote` implementation has a trusted semantic model. Direct complete-argument syntax alone is not a recognized safety barrier; the syntactic shape checks are not a shell grammar or a semantic sanitizer proof.

| Fixture / method | Retained conclusion |
| --- | --- |
| `quote_ok` (`swconfig dev ${shellquote(...)} help`) | **inconclusive**; candidate retained |
| luci `getSwconfigFeatures` / `getSwconfigPortState` | **inconclusive**; candidates retained |
| `quote_exe` (`popen(shellquote(request.args.cmd))`) | **path_found**, synthetic executable-selection control only |

The three IDs ending in `no-injection` are historical identifiers retained for interchange compatibility, **not** current no-injection conclusions. Binding and quoting semantics are unmodeled; runtime execution and exploitability are not established. This correction does not retract existing request-argument-to-sink observations, change policy grants, or establish an authorization violation.

The producer coverage also records an untainted negative control and syntactic controls for interpreter, transformed output, command position, binding ambiguity, and word boundaries. These controls do not establish a trusted barrier. Same-function quoted locals (`getRealtimeStats` `flags`, `setPassword` `u`/`p`) remain outside the modeled scope; see [m4-realtime-password-quoted-locals.md](m4-realtime-password-quoted-locals.md). Quote characters are preserved through local storage and command template interpolation in the pinned source; this observation does not prove overall command safety.

This is a reconciliation of retained reports with a pinned producer snapshot, not a fresh query run, full pinned-corpus reanalysis, or runtime test. See [findings](m4-shellquote-findings.json) and [coverage](m4-shellquote-coverage.json).
