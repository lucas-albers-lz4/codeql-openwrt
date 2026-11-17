# Provisional setLocaltime source-construction consumer

The paired producer and consumer run is complete. An independent reviewer audited the evidence.
The ucode #97 producer merged as `c318d404de690c98eabf7eacf69f81defb39bf12`.
The OpenWrt #98 consumer merged as `4b767dc178fed8e06b918459c1534780b3f4af56`, from reviewed head `84d995879c608fb407b4a07169be18cd997753eb`.

The 41-column interface served as the consumer contract. It does not describe other queries or diagnostics.
The source oracle came from pinned LuCI bytes. A local test compared it with those bytes.
The implementer saw the design's proposed spans before this run. The run was not blinded.

Do not substitute synthetic test CSV for producer output. Do not publish a synthetic annotation as an observed finding.

The run covered 16 exact, ordered launches across 16 boundaries. Review authenticated 300 captures.
The 16 launches had unique InvocationIDs.
The run recorded 31 declared consumptions and 10 staged-source observations. Routing checkpoints stayed original. All 16 cgroups were absent.

The output had 41 columns and six rows. Review compared the rows as a multiset.
The annotation and Markdown matched the exact expectations. Review validated five existing linked records against the schema.
The run produced no new record. The five linked records are the historical effect, the historical taint, the primary grant, the supplementary grant and the unauthenticated deny decision.

At review issuance, every inventory scope had zero integrity deltas:

| Scope | Entries | Deltas |
|---|---:|---:|
| Protected inputs | 8,799 | 0 |
| Source | 6 | 0 |
| Attempt | 1,655 | 0 |
| Operator | 263 | 0 |

The independent reviewer returned `INCOMPLETE` and withheld formal acceptance because 85 run commands used literal `python3.13` instead of the approved `/usr/bin/python3.13`.
Each command retained `-I -S -B`. The evidence does not determine that a different interpreter ran.
The owner accepted the bounded evidence with this deviation disclosed.

The source oracle is consumer-owned, not supplied by the producer. One exact
construction consists of six rows. The header, in order, is:

```text
observation_kind,ubus_object,method,source_path,local_name,format_value,callback_start_line,callback_start_column,callback_end_line,callback_end_column,initializer_start_line,initializer_start_column,initializer_end_line,initializer_end_column,input_start_line,input_start_column,input_end_line,input_end_column,guard_start_line,guard_start_column,guard_end_line,guard_end_column,formatter_start_line,formatter_start_column,formatter_end_line,formatter_end_column,format_start_line,format_start_column,format_end_line,format_end_column,sink_start_line,sink_start_column,sink_end_line,sink_end_column,slot_index,conversion,field_name,field_start_line,field_start_column,field_end_line,field_end_column
```

CSV uses UTF-8 without BOM. The consumer requires strict quoted syntax, exact widths and canonical
positive decimal coordinates. Coordinates are 1-based inclusive source byte columns. Tabs count as one.
Transport row order is irrelevant. Full row multiplicity, identity, span and index association are relevant.

An empty/missing or rejected table, diagnostic failure, unsupported path or context is
**unassessed**, not a no-path result. The consumer accepts only the pinned source bytes, lock,
profile, consumer oracle and existing report/policy context.
Diagnostic CSV currently uses the exact `f,col1` and `error,col1,col2` headers
of the existing diagnostics, with one absolute source entity and zero errors.

The run reconciled the producer's decoded representation with this consumer contract.
These results do not prove a broader producer interface.

Example consumer command:

```sh
python3 -B -m policy.setlocaltime_construction \
  --table /absolute/path/table.csv --extracted /absolute/path/extracted.csv \
  --errors /absolute/path/errors.csv --source-root /absolute/canonical/source/root \
  --format json
```

Use `--format markdown` for a deterministic rendering of the checked format,
anchors and slots beside the identified historical date effect. Output goes to
stdout as UTF-8 without BOM, independent of ambient stream encoding.

The tool writes no files. On error, the tool writes diagnostics to stderr, exits with nonzero status and emits no output payload.

For publication, capture the output to a fresh staging file. Check the exit status. Review the output before you install it.
If the command fails, direct shell redirection can truncate a retained file. This document does not include the run's output report.

The tool binds the date-effect identity and historical taint identity separately
from the existing aggregate/caller grant joins. These joins do not validate source,
sink, helper permission or runtime registration.
The tool preserves references to the primary synthetic delegated caller, supplementary root grant and unauthenticated deny decision.
It makes no new policy assessments. The tool does not refresh the old effect's analysis revision or taint status.

The checked table is not a new
finding-schema record, effect, grant, taint edge, suppression, barrier, numeric
sanitizer or new coverage claim. Reflective global writes and import side
effects remain unresolved even if source shape is compatible. Source and
context hashes establish consistency only, not execution or authenticity.

The run does not attest the source-to-binary build. It does not prove that all host and Python bytes executed as inventoried.
It provides no cryptographic proof of execution or freshness. It makes no sanitizer, authorization, or broader taint, security, or runtime claim.

The launch window expired. `execution_verified` is always false.

Tests:

```sh
python3 -B -m unittest policy.tests.test_setlocaltime_construction
python3 -B -O -m unittest policy.tests.test_setlocaltime_construction
python3 -B -m unittest discover -s policy/tests
```

The paired run is complete. Synthetic controls are not an execution receipt.
