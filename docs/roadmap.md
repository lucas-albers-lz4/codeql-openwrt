# Contract roadmap

This roadmap uses current tracked contracts at the revisions in its source links.
It does not reconstruct `PLAN.md`.
It assigns no meaning to historical section numbers.
It commits to no new feature work and does not claim issue closure.

The related epics are [OpenWrt #56](https://github.com/lucas-albers-lz4/codeql-openwrt/issues/56) and [ucode #43](https://github.com/lucas-albers-lz4/codeql-ucode/issues/43).

The paired roadmap is in [codeql-ucode](https://github.com/lucas-albers-lz4/codeql-ucode/blob/main/docs/roadmap.md).

## Ownership and limits

`codeql-openwrt` owns the corpus, schema, policy facts, and reports.
`codeql-ucode` owns the ucode extractor and CodeQL packs.
Reserved roles do not establish implemented analysis or assign work.
Sources: [openwrt:docs/pack-contract.md:3-19](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L3-L19), [ucode:README.md:3-32](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/README.md#L3-L32), [openwrt:docs/pack-contract.md:114-118](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L114-L118).

The policy contracts cover named HTTP gates and bounded C behavior.
The routing policy classifies source format, not extraction, reachability, command safety, or authorization.
Sources: [openwrt:policy/README.md:76-124](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/policy/README.md#L76-L124), [openwrt:docs/file-routing.md:3-3](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/file-routing.md#L3-L3).

Production `LocalTaint` and `RequestArgsExec` stay on Models.
Experimental data flow does not replace them.
Missing results and unsupported forms do not establish safety.
Sources: [ucode:README.md:96-141](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/README.md#L96-L141).

The `setLocaltime` table records source shape, not sanitizer authority or a safe result.
The table does not remove the production candidate.
Sources: [ucode:docs/m4-setlocaltime-construction.md:3-34](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/docs/m4-setlocaltime-construction.md#L3-L34), [ucode:docs/m4-setlocaltime-construction.md:72-99](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/docs/m4-setlocaltime-construction.md#L72-L99).

This roadmap does not staff dispatcher, markup, JavaScript, Track A, or Alloy work.
Sources: [openwrt:docs/pack-contract.md:3-19](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L3-L19), [openwrt:docs/pack-contract.md:114-118](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L114-L118), [openwrt:docs/pack-contract.md:133-133](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L133-L133).

## Ordered dependencies

This order describes the contract boundaries for a paired handoff.
The producer and consumer can prepare their separate prerequisites in parallel.
The family contracts define the applicable details.

### 1. Corpus and contract context

The corpus lock, profile, schema, grants, and independent expectations define the consumer context.
Joins require the same `corpus_revision` and `profile`.
The producer-local `analysis_revision` is not a cross-producer join key.
Sources: [openwrt:docs/pack-contract.md:19-57](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L19-L57), [openwrt:docs/pack-contract.md:204-257](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L204-L257).

### 2. Producer and consumer prerequisites

The producer bootstrap clones the pinned grammar before generator initialization.
It applies patches after initialization and before the extractor build.
Sources: [ucode:README.md:7-32](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/README.md#L7-L32), [ucode:patches/README.md:3-16](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/patches/README.md#L3-L16).

The producer selects the installed root and input paths.
For a staged root, extraction status alone does not establish completeness.
The routing and extraction diagnostics identify the applicable source and errors.
Sources: [ucode:README.md:34-66](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/README.md#L34-L66).

The consumer independently establishes the relevant policy grants and expectations.
The typed `setBlockDetect` import also requires a coherent retained state.
Sources: [openwrt:docs/pack-contract.md:40-57](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L40-L57), [openwrt:docs/setblock-typed-import.md:11-27](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-typed-import.md#L11-L27).

### 3. Bounded observation

A source table describes only its supported source shapes.
For example, the `getBlockDevices` table does not establish callback registration or execution.
The family contract defines the table fields, source locations, and limits.
Sources: [ucode:docs/m4-getblock-effect-table.md:3-26](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/docs/m4-getblock-effect-table.md#L3-L26).

The `setLocaltime` table represents one construction as six rows.
The producer contract requires independent consumer checks of source bytes, routing, diagnostics, and a source-first oracle.
The table carries no policy or safety authority.
Sources: [ucode:docs/m4-setlocaltime-construction.md:36-59](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/docs/m4-setlocaltime-construction.md#L36-L59).

### 4. Consumer assessment and preservation

The consumer uses its own grants and expectations for policy assessment.
The typed `setBlockDetect` import preserves required unknowns and additional unknowns.
A successful reimport is byte-idempotent.
Sources: [openwrt:docs/setblock-typed-import.md:11-27](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-typed-import.md#L11-L27).

The `getBlockDevices` adapter preserves unrelated report rows.
It does not write grants.
Sources: [openwrt:docs/pack-contract.md:204-257](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L204-L257).

### 5. Evidence for a new paired run

A live paired run needs both revisions and the actual inputs bound to a reviewed consumer context.
An execution claim needs observed execution, diagnostics, outputs, and receipts.
A scoped completeness claim needs an independent oracle.
Sources: [openwrt:docs/pack-contract.md:76-108](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L76-L108), [openwrt:docs/setblock-handoff-checks.md:5-14](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-handoff-checks.md#L5-L14), [openwrt:docs/setblock-handoff-checks.md:18-38](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-handoff-checks.md#L18-L38).

The offline `setBlockDetect` bundle checker does not establish execution or freshness.
That checker covers CSV, not the typed edge.
Sources: [openwrt:docs/setblock-handoff-checks.md:5-14](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-handoff-checks.md#L5-L14), [openwrt:docs/setblock-typed-import.md:29-35](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-typed-import.md#L29-L35).

### 6. Retained reports and test evidence

The CSV handoff contract requires retained inputs, reports, and reimport results.
It also requires retained test results for both recorded revisions.
A historical preservation check does not prove a new live run.
Sources: [openwrt:docs/setblock-handoff-checks.md:122-139](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/setblock-handoff-checks.md#L122-L139), [openwrt:docs/pack-contract.md:76-108](https://github.com/lucas-albers-lz4/codeql-openwrt/blob/4b767dc178fed8e06b918459c1534780b3f4af56/docs/pack-contract.md#L76-L108).

The producer interchange checks preserve historical identities and unknowns.
A query reference does not prove that the query ran.
Sources: [ucode:docs/interchange.md:19-46](https://github.com/lucas-albers-lz4/codeql-ucode/blob/ecfc24e992674891c5305f7d2505156238868df9/docs/interchange.md#L19-L46).
