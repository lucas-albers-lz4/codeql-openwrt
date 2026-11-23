# Bounded typed setBlockDetect handoff repeat

On 2026-11-23 a separately reviewed context produced a local Darwin arm64 observation with producer `d3981986ac685d6fcbb78a3b369aa4ed526c1e4b`, consumer `fe5952073eeef913fef4b3324d9541ff66426492` and CodeQL 2.27.4. The consumer was a clean, disposable checkout. The observed coverage is partial; it does not establish trusted execution, runtime reachability, policy correctness, security impact or completeness. Neither a digest nor a receipt authenticates execution.

The twelve ordered stages exited zero. The runner checked the exact single extracted file, zero extraction-error rows, one effect row and complete neutral typed record before import. Only `reports/handler_effects.json` and `reports/m4-block-device-exec.json` changed. Full before, immediate post-import and post-reimport bytes were captured; the expected complete targets and all other rows matched, and the complete consumer inventory and both report bytes were unchanged by reimport. The before report SHA-256 values were `2644d1187afaaf126afa71572cc980afbecd3f22592057809951491f90a436a0` and `f81718031bdfe53fdde5ee0641683a7dc564329d2c655f85fc5c8eb629b95373`; after and replay values were `d55e0a799e916f8728b9bb34a9689b81f070dbe25eceddd2db9c0cc3b4417fab` and `660e12712928a99b22e0a8c80247bcd63b54967e465ed3fa9b28354593045a6e`, respectively.

`retry-packet.tar.gz` contains the complete offline-verifiable packet: database and runtime inventories, BQRS and decoded CSV, typed output, per-stage receipts and streams, full report snapshots, retained source and lock, implementation bytes and frozen context/oracle. The separate context and oracle files are the external review anchors, with SHA-256 `012ba54c704780c95d6b0fdacc208b4bfe0300f26cba5098104e96a79c95fb1c` and `9b05e02fcad136c9794d80c19ac0ceb4d1702debe8d80b391abfb1f9b1506574`. Paths in the context record the original execution; they need not exist for offline verification. A separate independent audit also decoded each retained BQRS with the pinned CLI and matched its CSV byte-for-byte; its command/environment manifest and streams are in `independent-bqrs-audit/`. The original query stderr reported that it could not retrieve the QL pack commit hash and did not cache query-loading stages because of the available heap. The offline verifier itself does not decode BQRS or authenticate the packet.

The separately reviewed first attempt stopped after its extracted query exited zero because CodeQL created three empty evaluator-cache directories not in the then-frozen policy. It did not decode or import. `first-attempt.tar.gz` and the first-attempt streams preserve that invalid attempt. The revised policy allowed exactly those three directory creations in the first query, with existing database entries unchanged and only the two expected new query logs; the retry used a distinct output directory and a newly reviewed context. The producer, consumer, source, executable and pack roots were reused after the stopped query snapshots showed no changes and both checkouts were clean. Preparation was then amended with the retry boundary and revised context generator; `preparation.tar.gz` captures that later retry state.

`preparation.tar.gz` retains build/install/resolve and isolated Python startup observations and their description. A fresh extractor was built from the pinned producer, using a copied historical Cargo cache; resolved packages were copied, pinned and independently checked as candidates. Python ran from staged symlink-free stdlib trees using `-I -S -B` and explicit `python3.15._pth` path configuration; its original framework dylib was separately inventoried. These choices differ from the historical #144 command environment. The CodeQL loaded-pack set and platform/system libraries are not independently authenticated.

To check the retained packet on Darwin, run these commands from the repository root. They use physical absolute paths without symlink components, as required by the verifier:

```sh
repo_dir=$(pwd -P)
packet_dir=$(mktemp -d /private/tmp/typed-handoff-check.XXXXXXXX)
tar -xzf "$repo_dir/evidence/typed-handoff-repeat-20261123/retry-packet.tar.gz" -C "$packet_dir"
python3 -B "$repo_dir/tools/typed_handoff/verify.py" "$packet_dir/retry-run" \
  "$repo_dir/evidence/typed-handoff-repeat-20261123/context.json" \
  "$repo_dir/evidence/typed-handoff-repeat-20261123/oracle.json" \
  012ba54c704780c95d6b0fdacc208b4bfe0300f26cba5098104e96a79c95fb1c \
  9b05e02fcad136c9794d80c19ac0ceb4d1702debe8d80b391abfb1f9b1506574
```

This check was repeated successfully after extracting the archive into a fresh directory. Only extract archives into a new private directory. The original local workspace is `/private/tmp/openwrt-typed-handoff-live-20261123`; that path is not a durable reference.
