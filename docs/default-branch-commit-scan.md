# Linked default-branch commit scan

The manual `default-branch-commit-scan.yml` workflow runs only from consumer
`main`. It accepts exact predecessor/successor discovery run IDs, attempts,
checkpoint digests, a gap digest, one first-parent commit SHA and a distinct
canonical control SHA. It checks the run metadata, downloads both named
artifacts, verifies their digests, replays the gap and resolves the selected
commit against canonical Git objects. A commit outside the bounded linked
interval fails before source selection or CodeQL. Pull requests run only the
contract tests; their checkout cannot produce a released scan receipt.

`tools/default_branch_corpus_manifest.py` applies frozen v0.6 candidate
policy to the exact first-parent-to-commit interval. It stages the full
selected corpus at the commit and retains the other repositories at their
policy pins. It compares the source-first manifest with fresh Git objects,
routes and selected/excluded identities, including relevant recipe drift
from the policy pin. The distinct `mvp-default-branch-commit-corpus-v1`
schema includes linked checkpoint/gap digests and contains no PR number.
A new candidate, changed excluded source or unreviewed recipe drift fails
closed for policy review.

After a same-job immutable R3 handoff, `tools/default_branch_corpus_linux.py`
rebuilds that input oracle, snapshots its bytes in a run-owned directory and
runs the released extractor and default suite. It requires exact successful
file identities, zero extraction errors and matching routes before passing
the actual SARIF to the triage consumer. Its directory, coverage and receipt
schemas are separate from PR and historical OpenVPN runs. A clean result is
only a bounded result for the selected source-staged files; the control SHA
is an identity reference and is not asserted as a clean or fixed scan.

This manual path exercises a real linked upstream direct commit. It does not
automatically select the seven discovered commits, provide durable scheduling
or satisfy Gate 8 without a predeclared incoming known alert and control.
GitHub discovery artifacts expire after 30 days. Source paths are projected
to reviewed installed paths; actual installed package bytes remain unverified.
