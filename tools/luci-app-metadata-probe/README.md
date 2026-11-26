# LuCI app dependency metadata probe

This proposed #173 probe captures the generated dependency metadata for `luci-app-dockerman` and `luci-app-statistics` from pinned OpenWrt `4e9642517b48bae612ff10fb72fb9199e559500e`, LuCI `cb87fe60e1e2e052af36a93647f2264577829e0a`, and packages feed `07e0d16305d2b5903b37ad7913e33e18795f81a4`. It does not itself establish a resolved transitive graph, successful package compilation, IPK membership, image installation, runtime behavior or security coverage. The scoped source-first `source-oracle.json` enumerates both pinned app trees; its generator cross-checks the #172 inventory. Companion and scheduler manifests identify source blobs only.

The only explicit make **target** the probe runs is `make defconfig` (it also invokes `make --version`). The pinned feeds scanner and defconfig's metadata generation run nested make processes and `DUMP=1` recipe scans; the pinned host prerequisite checks may compile `mkhash`, C/C++ probe programs and Kconfig tools. This is not a claim of zero host compilation. It never intentionally invokes tools/install, toolchain/install, target/kernel, package/image compilation or installation, `make -n`, `NO_DEPS`, `QUILT`, CodeQL extraction or queries. It requires `.config` absent throughout feed update/install so the pinned feed script cannot start an implicit defconfig. The two feed index links must point to fresh, physical nonempty generated package metadata with expected scoped package records. Scanner `dump.txt` files cause a stop even if a feed command reports success; they are retained.

The resolved config and `.packagedeps` are observations for later independent review, not build permission. Final config must differ from the seed, contain `CONFIG_HAVE_DOT_CONFIG=y`, retain x86/x86_64, both app selections and luci-base, the per-feed IPK settings and disabled minifiers, and have no duplicate symbols. Final package metadata must identify both exact source recipes; `.packagedeps` must contain each app's package declaration and compile edge. These presence checks do not prove complete graph closure or evaluate Make conditions. In particular, pinned source describes a potential dockerd/containerd compile cycle and kmod/kernel requirements; inspect the actual full metadata and conditions before deciding on any subsequent build.

## Diagnostics and safety

A previous same-pin two-feed run emitted missing-dependency scanner warnings and six exact Kconfig recursive-dependency diagnostics despite a zero defconfig exit. `known-diagnostics.json` retains phase-specific historical lines and provenance. This probe preserves all warnings and classifies historical matches without treating them as harmless or as build approval. Only the six exact historical Kconfig error pairs, at most once each, may pass the error gate for metadata capture; an additional/unknown error, scanner failure, circular warning or nonzero command stops the probe. Nonfatal unknown warnings remain visible as unreviewed. Every completed result is `metadata_collected_review_required`, never an automatically accepted graph.

The run owns a new exclusive physical root; it clones and checks out only the three pins, verifies clean source and feed links, records the exact consumer commit/tree, and uses a scrubbed subprocess environment with private HOME/TMPDIR, fixed PATH/locale/timezone and no inherited build overrides or Git credentials. Logs and phase receipts retain argv, cwd, allowed environment, UTC times and elapsed seconds; peak RSS is not measured. Timed-out subprocesses run in a private process group and are terminated before capture. If group quiescence or output safety cannot be established, the evidence bundle is withheld. Effects of a process that deliberately escapes its process group are outside this local observation.

Partial safe metadata is retained on failure and marked `partial_or_unvalidated`; it must not be treated as a successful defconfig. The portable USTAR bundler reads only a manifest-verified inventory of physical single-link regular files and rejects missing, extra, changed, symlink, hardlink or special entries. If a failure produces unsafe output, bundling/upload is withheld rather than following it. Metadata and failure evidence are raw and may contain runner-local paths; review before wider sharing.

## Execution and tests

The workflow has offline tests on pull requests and a separate manual-only metadata job. No workflow is dispatched by this change. A future reviewed local invocation on GNU/Linux x86_64 uses an absent physical path and an exact clean consumer checkout commit:

```sh
python3 -I -B tools/luci-app-metadata-probe/run.py --root /absolute/fresh/metadata-root --consumer-commit <40-character-consumer-commit>
python3 -I -B tools/luci-app-metadata-probe/package.py --output-root /absolute/fresh/metadata-root/output --archive /absolute/fresh/evidence.tar
```

The first command contacts the pinned public Git sources and runs feeds plus metadata generation. The second reads retained output and creates a fresh archive; it does not execute a build. Preserve failures and audit the actual receipt, raw metadata, warning scope and exact workflow head before interpreting any result. Independent review and resource/kernel planning remain prerequisites to a separate package build.

Offline contract controls run without network or real make:

```sh
python3 -I -B -m unittest discover -s tools/luci-app-metadata-probe -p 'test_*.py'
python3 -I -B -O -m unittest discover -s tools/luci-app-metadata-probe -p 'test_*.py'
```

The workflow performs no apt or system-package installation. Missing host prerequisites are retained as a failure; prior Ubuntu runner packages do not establish the state of a future runner. Local partial files are uploaded only when the safe bundler succeeds; hosted durable failure evidence is not guaranteed if output is unsafe or the process group cannot be confirmed quiescent.
