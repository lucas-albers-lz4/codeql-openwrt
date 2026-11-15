# CodeQL diagnostic CSV fixtures

These are the unmodified CSV outputs of a local CodeQL extraction and query run
completed 2026-11-14, using CodeQL CLI 2.27.4 and producer revision
`afb1400b09fa0ad76370458ab085c2abe58412a7`. They were decoded with
`codeql bqrs decode --format=csv` from the results of
`diagnostics/SuccessfullyExtractedFiles.ql` and `diagnostics/ExtractionErrors.ql`,
respectively. The source root recorded in `extracted.csv` was
`/root/workspace/wt-ucode-76/ql/test/extractor-smoke`. This is historical data,
not a path the test accesses. The test replaces just this root with its temporary
approved source root; the rest of the CSV bytes are unchanged.

| File | SHA-256 (original bytes) |
| --- | --- |
| `extracted.csv` | `ec3e03204e89ebbab63489f2493bb3b67f91253b66c663f5e1b7e963133a0668` |
| `errors.csv` | `0bb9068729a2970f4b125b6893565812fdd2d1fc6510626f214f3d055b4f94f5` |

The original local evidence is identified as `ucode76-afb1400-handoff`; this
fixture documents format and is neither a signed attestation nor evidence of a
fresh CodeQL execution by the test.
