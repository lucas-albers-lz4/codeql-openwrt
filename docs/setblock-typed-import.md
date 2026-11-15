# Opt-in typed setBlockDetect import

Run this command to select the typed interface:

```sh
python3 -B -m policy.setblock_table --typed-json OBSERVATION.json --source-root INSTALLED_ROOT
```

The `--typed-json` and `--csv` options are mutually exclusive. Neither import path runs CodeQL or authenticates input as CodeQL output.

The typed input must be one neutral, unassessed record from the reviewed provisional `step3:setblock-typed-v1` family. The consumer checks the exact source location, source bytes, raw-lock corpus identity, profile, conditions, assumptions, and source evidence. It rejects policy fields, extra fields, and duplicate JSON keys. Missing, invalid, or unsupported input causes failure. It does not create a safety finding.

## Validation and report updates

Before it updates either report, the consumer independently revalidates the mounts expectation, its primary grant, the supplementary root grant, and the unauthenticated deny. It then updates both retained reports with `step3:setblock-typed-import-v1` provenance. The consumer does not accept policy authority from the producer.

If a later replacement fails, the shared paired transaction restores replaced reports. If rollback fails, the error names the retained backup. Existing CSV imports remain available. Typed state cannot be downgraded to CSV.

## Unknowns and reimport

Input and coherent prestate unknowns must be unique, nonempty strings. They must include all required family limitations. The consumer preserves each additional unknown exactly once, in this order:

1. Required limitations.
2. Previously retained extras, in their original order.
3. New input extras, in their original order.

Both retained targets must agree on their uncertainty list. The consumer revalidates the input and prestate on every import. A successful reimport is byte-idempotent.

## Producer handoff

The paired producer merged at `ae946190661eb221bc1f562fdba02088ef83de2d`. The reviewed head was `c59d769933ec6294d0f482865cc4863762aa7672`. These commits have the same tree. Use the merged revision, not the reviewed head, as the producer pin for a future handoff.

The historical `policy.setblock_handoff` checker remains **CSV-only**. It does not verify this typed edge. Synthetic tests do not count as a producer execution. Neither hashes nor these checks authenticate producer origin, establish runtime reachability, or support a broad completeness claim. Coverage remains partial.

After producer merge, a fresh, separately pinned handoff between the real producer and consumer remains necessary. The handoff must include diagnostics and retained evidence.
