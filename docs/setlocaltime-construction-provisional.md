# Provisional setLocaltime source-construction consumer

This is **design-stage consumer code**, not a completed producer handoff. The
41-column interface is a proposed contract, not a claim about any landed query
or its diagnostics. The source oracle was transcribed from the pinned LuCI bytes
and checked against those bytes by the local test. The implementer had seen the
design's proposed spans: this is **not blinded, independent reviewer approval**.
A separate source-first review and reconciliation with the eventual producer
are required before acceptance. Do not substitute the tests' synthetic CSV for
producer output or publish a synthetic annotation as an observed finding.

The source oracle is consumer-owned, not supplied by the producer. One exact
construction consists of six rows. The header, in order, is:

```text
observation_kind,ubus_object,method,source_path,local_name,format_value,callback_start_line,callback_start_column,callback_end_line,callback_end_column,initializer_start_line,initializer_start_column,initializer_end_line,initializer_end_column,input_start_line,input_start_column,input_end_line,input_end_column,guard_start_line,guard_start_column,guard_end_line,guard_end_column,formatter_start_line,formatter_start_column,formatter_end_line,formatter_end_column,format_start_line,format_start_column,format_end_line,format_end_column,sink_start_line,sink_start_column,sink_end_line,sink_end_column,slot_index,conversion,field_name,field_start_line,field_start_column,field_end_line,field_end_column
```

CSV is UTF-8 without BOM, strict quoted syntax, exact widths and canonical
positive decimal coordinates. Coordinates are 1-based inclusive source byte
columns; tabs count as one. Transport row order is irrelevant; full row
multiplicity, identity, span and index association are not. An empty/missing
or rejected table, diagnostic failure, unsupported path or context is
**unassessed**, not a no-path result. Only the pinned source bytes, lock,
profile, consumer oracle and existing report/policy context are accepted.
Diagnostic CSV currently uses the exact `f,col1` and `error,col1,col2` headers
of the existing diagnostics, with one absolute source entity and zero errors.
The producer's actual decoded representation must be reconciled before use;
these assumptions are not proof of a working producer interface.

Example after a compatible producer and independently reviewed run exist:

```sh
python3 -B -m policy.setlocaltime_construction \
  --table /absolute/path/table.csv --extracted /absolute/path/extracted.csv \
  --errors /absolute/path/errors.csv --source-root /absolute/canonical/source/root \
  --format json
```

Use `--format markdown` for a deterministic rendering of the checked format,
anchors and slots beside the identified historical date effect. Output goes to
stdout as UTF-8 without BOM, independent of ambient stream encoding. The tool
writes no files; errors go to stderr with nonzero exit and no output payload.
For publication, capture to a fresh staging file, check the exit status and
review the output before installing it; shell redirection directly to a retained
file can truncate it on failure. No report is retained by this change because
there is no actual new producer result yet.

The tool binds the date-effect identity and historical taint identity separately
from the existing aggregate/caller grant joins; joins do **not** validate source,
sink, helper permission or runtime registration. It preserves the primary
synthetic delegated caller, supplementary root grant and unauthenticated deny
references without making new policy assessments. The old effect's analysis
revision and taint status are not refreshed. The checked table is not a new
finding-schema record, effect, grant, taint edge, suppression, barrier, numeric
sanitizer or new coverage claim. Reflective global writes and import side
effects remain unresolved even if source shape is compatible. Source and
context hashes establish consistency only, not execution or authenticity.
`execution_verified` is always false.

Tests:

```sh
python3 -B -m unittest policy.tests.test_setlocaltime_construction
python3 -B -O -m unittest policy.tests.test_setlocaltime_construction
python3 -B -m unittest discover -s policy/tests
```

A real handoff still needs the final producer and consumer revisions, an
independent oracle review, compatible decoded table and diagnostic headers,
actual paired execution with recorded tool/context and subprocess evidence,
and reconciliation of the resulting JSON/Markdown against the untouched
historical reports. Synthetic controls are not an execution receipt.
