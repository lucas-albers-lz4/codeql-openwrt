## APPROVE — bounded observed execution only

**Approved manifest SHA-256:** `047bfd055820e2512a4b01b4722229e137cba734c4a9a694c50a1edd0ad05dd1`

This approves the reviewed **a3 packet and its fixed recipe for one bounded observed run**, not a claim that the run has happened or that issue #89 is complete. The separate external acknowledgment gate remains necessary; I did not write an acknowledgment.

### Review results

- The manifest digest matches, all **49 packet entries** match their bytes, modes and path set, and all five staged input inventories match. The attempt directory is absent.
- The staged exports match all **408 producer** and **315 consumer** tracked files at the specified commits. The producer’s 83 additional files are confined to the inventoried generated extractor and dependency-pack roots.
- Relative to a2, bootstrap, runner, recorder, comparator and all three oracles are byte-identical. The test changes bind fixtures to the a3 packet and staged consumer. The exact documented suite now runs directly from the frozen packet: **34 tests passed normally and 34 under `-O`**, without monkeypatching.
- Neutral and retained expectations match independently extracted consumer-owned literals; the CSV fixture matches the committed consumer fixture, and the corpus revision matches the raw lock hash.
- The 15 command vectors, working directories and environments match the reviewed recipe. The retained dependency resolutions stay inside the inventoried producer tree and select the external attempt cache. Routing, diagnostic, source-archive and transition checks were reviewed and exercised synthetically; their compatibility with real output remains to be observed.
- Wrong-digest, direct-runner and missing-isolation preflight probes failed before attempt creation. The suite’s approval fixtures were synthetic and temporary.

**Separate startup anchors:** bootstrap SHA-256 `6e91c66a9f7c856f01c376687947634e0037ca966349f7e3dc7035b580e5620c`; `/usr/bin/python3.13` SHA-256 `889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9`. Use the packet’s clean-environment, `-I -S -B`, no-`-X` bootstrap boundary.

**Limits and operational conditions:** OS/stdlib/native and descendant-tool closure is not fully verified, and the reused extractor is not proven built from the merged producer commit. The runner does not guarantee descendant cleanup after interruption: retain any failed attempt, establish that its processes have stopped, and do not reuse it. Full consumer/producer gates and controlled mutations remain separate issue-acceptance work.

No CodeQL database, real query, exporter or importer was run during this review; no product or GitHub state was changed.