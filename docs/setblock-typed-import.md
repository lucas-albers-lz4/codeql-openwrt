# Opt-in typed setBlockDetect import

`python3 -B -m policy.setblock_table --typed-json OBSERVATION.json --source-root INSTALLED_ROOT`
selects the typed interface. `--typed-json` and `--csv` are mutually exclusive.
Neither path runs CodeQL or authenticates the supplied input as CodeQL output.
The typed input is a single neutral, unassessed record of the reviewed provisional
`step3:setblock-typed-v1` family. Exact source location, source bytes, raw-lock
corpus identity, profile, conditions, assumptions and source evidence are checked;
policy fields and extra fields are rejected. JSON duplicate keys are rejected.
Missing, invalid or unsupported input is failure, not a safety finding.

The consumer independently revalidates the mounts expectation, its primary grant,
the supplementary root grant, and the unauthenticated deny before updating both
retained reports with `step3:setblock-typed-import-v1` provenance. Producer-supplied
policy authority is not accepted. The shared paired transaction restores replaced
reports if a later replacement fails; if rollback itself fails, the error names the
retained backup. Existing CSV imports remain available, but typed state cannot be
downgraded to CSV.

Input and coherent prestate unknowns must be unique nonempty strings and include all
required family limitations. Additional unknowns are preserved exactly once: required
limitations first, then previously retained extras in their order, then new input
extras in their order. Both retained targets must agree on their uncertainty list.
The input and prestate are revalidated on every import. Successful reimport is
byte-idempotent.

The paired producer merged at `ae946190661eb221bc1f562fdba02088ef83de2d`;
the reviewed head was `c59d769933ec6294d0f482865cc4863762aa7672`. These commits
have the same tree. Use the merged revision, not the reviewed head, as the producer
pin for a future handoff. The historical `policy.setblock_handoff` checker remains
**CSV-only**; it does not verify this typed edge. Synthetic tests are not a
producer execution, and neither hashes nor
these checks authenticate producer origin, establish runtime reachability or a broad
completeness claim. Coverage remains partial. A fresh, separately pinned real producer
and consumer handoff with diagnostics and retained evidence is still required after
producer merge.
