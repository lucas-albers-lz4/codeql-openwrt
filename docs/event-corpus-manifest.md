# Source-first incoming event corpus oracle

The manual incoming-event workflow prepares `event-corpus-manifest.json` after
the API-bound identity receipt, bounded source-policy drift check and full-tree
candidate inventory. The generator reruns the candidate inventory from the
same checked-out Git objects and requires exact agreement with the retained
report. The reviewed v0.6 source manifest is pinned by SHA-256 and supplies
the selected and excluded source identities, installation projections, package
conditions and routing policy. A selected content edit refreshes its Git blob,
SHA-256 and source commit from the event head; an excluded edit, new candidate,
missing candidate, changed signal, changed route or installed-path collision
fails closed before extraction. A changed Makefile, Config.in, Kconfig or `.mk`
input under a selected owner's root (or a shared `include/` build file) also
requires review. This bounded rule does not prove all possible build-system
effects absent.

The output records the upstream PR number, base and head commits, head tree,
frozen policy digest, input receipt and inventory digests, and the route-oracle
script digest. The mirrored route precedence names its reviewed producer PR
source and SHA-256; equivalence to a future immutable release remains unproved.
It removes historical extraction observations from refreshed
rows and replaces historical counts with event selection counts. Other
repositories remain at their frozen v0.6 pins. It has a
separate schema from the frozen current-corpus gate; the latter's fixed pins,
counts and zero-result SARIF expectation must not be relaxed to consume an
event manifest. The event manifest is an input oracle only: it does not run
CodeQL, prove installed bytes, infer previously unreviewed package recipes,
or establish the released producer-to-consumer Gate 8 handoff.
Incoming alerts use a separate [SARIF triage contract](event-sarif-triage.md)
so valid new results remain visible for review.

Run the focused controls with:

```sh
python3 -B -m unittest tools.test_event_corpus_manifest -v
```
