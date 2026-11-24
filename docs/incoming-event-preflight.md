# Incoming event identity preflight

This workflow is a bounded `workflow_dispatch` drill for resolving pinned
OpenWrt or LuCI event and control revisions. Inputs must name full commit
SHAs. The resolver verifies the canonical GitHub origin, resolves each SHA as
a commit, records the corresponding tree SHA, and rejects a branch name,
missing object, repository mismatch, or identical source/control commit.

The receipt status is deliberately `identities_resolved_only`. The PR number
and timestamp are caller-supplied metadata. This workflow does not authenticate
that the commit belongs to the stated PR, discover PRs, validate dynamic
source-policy coverage, invoke the released producer, or pass SARIF to the
consumer. It does not establish Gate 8 or security behavior. Do not turn this
preflight into blocking incoming CI until those steps have a reviewed
implementation and a live end-to-end drill.

Run the mechanical tests with:

```sh
python3 -B -m unittest policy.tests.test_incoming_event -v
```

The tests use temporary local Git repositories; they do not access GitHub.
