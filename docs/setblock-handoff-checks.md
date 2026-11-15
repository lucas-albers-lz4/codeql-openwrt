# Bounded setBlockDetect handoff: offline bundle checker

`python3 -B -m policy.setblock_handoff BUNDLE --expected-context EXPECTED.json --oracle policy/fixtures/setblock-handoff-v1.json --consumer-root CONSUMER --producer-root PRODUCER`

The CLI prints `consistent_offline` on a consistent bundle and exits nonzero on
failure. `execution_verified` and `freshness_verified` are **always false**.
The checker does not run CodeQL or the adapter. A successful offline check is
not live acceptance, even when a manifest calls itself `live`: a trusted,
observed runner must establish actual execution, exclusive fresh output paths,
clean checkouts, sanitized environment, and reads at the claimed boundaries.
Hashes and receipts are not cryptographic attestation. A failed or missing stage,
diagnostic or observation is inconclusive, not `no_path`. Coverage remains
partial. The independent oracle identifies one source-body observation, not
registration, reachability, a taint path, or a general completeness claim.

## Caller trust and roots

Supply a reviewed expected context and consumer-owned oracle independently of
the bundle. The CLI rejects either file inside the bundle. Review and freeze
expected context **after** the paired commits and preparation are known. Its
JSON is version `setblock-handoff-context-v1`, with `clean: true`, full lowercase
40-hex `producer_commit` and `consumer_commit`, `oracle_sha256` of the supplied
oracle bytes, and `consumer_files` / `producer_files` maps of relative paths to
raw SHA-256. Context claims in the manifest must exactly equal this external
object. The root files are actually read and hashed. The checker checks minimum
known inputs, the complete `policy/*.py` inventory, and every file under
producer `ql/src`, `ql/lib`, `extractor-pack`, and `resolved-packs`. The last
must be a staged copy of the packs actually resolved by CodeQL; the actual
`extractor-pack/tools/linux64/extractor` is mandatory. Symlink and traversal
file paths are rejected. Include all other consumed/generated/executable inputs
in the maps. Maps do **not** independently prove the selected roots, actual
external pack resolution, executable identity, Git HEAD, or cleanliness. The
observed runner/reviewer must verify those and the completeness of additional
inputs and preparation. The checker, package initializer, oracle, adapter and
schema module files loaded by Python must match their context-pinned files. This
is a file-byte comparison, not proof against a malicious interpreter, stale
bytecode, forged runner or in-process monkeypatching. No globbed profile discovery is
used by this checker; the explicitly selected profile and expectations are pinned.

The context also contains absolute run-owned `handoff_csv`,
`handoff_source_root`, `producer_run_root`, `codeql` and `python` (reviewed
absolute executable paths),
`database`, and `bqrs_paths` (absolute, distinct `effects`, `extracted`, and
`errors` paths), plus a `commands` object keyed by every stage below.
Each command is `{ "argv": [nonempty strings], "cwd": "..." }`, frozen by the
reviewer before execution. The checker requires `codeql database init`,
`index-files`, and `finalize` on the pinned database, `--language=ucode`, the
pinned source root, and `codeql query run` and `codeql bqrs decode --format=csv`
commands using each specified query, database, BQRS path and `--output=PATH`.
Use `--source-root=PATH`, `--working-dir=PATH`, and `--database=PATH` forms.
Adapter and reimport argv must start with the pinned `python`, `-B`, `-m`,
`policy.setblock_table`, followed only by `--csv PATH` and `--source-root PATH`
(in either order), using the exact sealed paths. The reviewer must verify the
pinned executable is actually the approved Python interpreter; a string cannot
prove executable identity. Arrange the CodeQL
search path to use the pinned prepared packs. Record
and independently check the interpreter/CodeQL binaries, version, sanitized
environment, generator inputs and commands, and fresh DB/output creation; the
checker does not infer these from command strings. In particular, do not use
this checker as proof that the commands actually ran.

## Evidence layout and receipt contract

`manifest.json` is an object with exactly `version`
(`setblock-handoff-bundle-v1`), `run_kind` (`offline_fixture`, `historical`, or
`live`), `context` (a copy of the externally trusted object), `coverage`
(`partial`), `advertised` (the list of CSV row arrays), and `receipts`.
Unexpected top-level claim fields are rejected. JSON duplicate keys fail.
All other files are fixed role names immediately in BUNDLE; no manifest-selected
paths are loaded. Each receipt has the reviewed `argv` and `cwd`, integer
`exit_code: 0`, `inputs` and `outputs` role-to-raw-SHA256 maps, and `stdout`
and `stderr` hashes of files named `<stage>_stdout` and `<stage>_stderr`. Each
`*_decode_stdout` must be byte-identical to its corresponding decoded CSV.
Required edges, in execution order:

| stage | inputs | outputs |
|---|---|---|
| init, index | source | — |
| finalize | — | — |
| effects_query / extracted_query / errors_query | — | effects_bqrs / extracted_bqrs / errors_bqrs respectively |
| effects_decode / extracted_decode / errors_decode | matching BQRS | csv / extracted_csv / errors_csv respectively |
| adapter | csv, source, before_0, before_1, consumer_at_handoff | after_0, after_1, consumer_after_import |
| reimport | csv_after, source_after, after_0, after_1, consumer_after_import | reimport_0, reimport_1, consumer_after_reimport |

`source` and `source_after` must be identical pinned installed-source bytes;
`csv` and `csv_after` must be identical. The three `consumer_*` artifacts are
JSON maps of actual captured consumer file digests at those boundaries; each
must match `consumer_files` in the expected context. Each numbered state is the
whole artifact, in oracle `artifacts` order. The two after/reimport artifacts
must be byte-identical. Non-target rows must be preserved in order; the prior
target must be a supported valid adapter input. Both final targets, their
unknowns, source span, primary/supplementary grants, deny, schema and independent
expectation are checked. The exact decoded table is compared both to the
advertisement and independently authored oracle, preserving duplicates.

For the pinned diagnostic queries and CodeQL 2.27.4 CSV format, `extracted_csv`
must have exactly the two-column header `f,col1` and one row: the absolute file
path formed from the reviewed `handoff_source_root` and oracle-relative source
path, then an empty message. `errors_csv` must have exactly the three-column
header `error,col1,col2` and no rows. Headers, column positions and row counts
are exact; quoting is interpreted as CSV. Wrong roots, extra files, extraction
errors and malformed headers yield `execution_inconclusive`. Other versions or
query formats require explicit review and adaptation; historical #76 raw bytes
are compatibility controls only. Empty/missing diagnostics are never evidence
of no errors.
BQRS bytes and stage logs are retained and hashed, not independently decoded or
proven to be CodeQL output by this checker. Receipt edge hashes are checked
against files, not trusted as success booleans. The caller is responsible for
retaining suite logs and all non-target changed-path observations; this compact
bundle does not verify those. Test bundle receipts are synthetic and do not
represent a live execution.

Before checking any post-state, the checker reuses the adapter's non-writing
pre-state transition calculation. Mixed legacy/imported targets yield
`retained_prestate_mismatch`; an effect identity used by another record yields
`effect_identity_collision`. Supported paired legacy inputs are accepted. The
entire post-state must match the adapter's computed transition, including row
position; unrelated changes or reimport byte differences are `unexpected_mutation`.
An executed module file that differs from the trusted copy yields
`execution_code_mismatch`.

## Observed execution required separately

After review/commit of both sides, freeze expected context from clean isolated
checkouts and separately recorded preparation. Stage only the pinned source in a
fresh source root; create a new CodeQL DB and exclusively created BQRS/CSV/log
outputs. Run init/index/finalize, both extraction diagnostic queries and the
setBlockDetect query, decode each, and record real receipts and exact bytes.
Independently verify successful extraction of the exact source and no extraction
errors, and check the independent CSV oracle before looking at retained targets.
Seal source and CSV and execute the adapter twice under sanitized Python in a
separate disposable consumer. Retain both pre/post/reimport effects and immutable
input maps before disposing of the copies. Compare all other files/dirty status,
then run and retain both repositories' required suites at the recorded revisions.
A prior row or prior deterministic CSV, synthetic receipts, historical #76
output, or this checker alone do not satisfy that operational gate.

Tests: `python3 -B -m unittest discover -s policy/tests -p 'test_setblock*.py' -t . -v`;
aggregate: `python3 -B -m unittest discover -s policy/tests -t . -v`.
