# Historical markup reference v1

This read-only reference admits only the #136 historical observation. The
reference bytes and inventory digest are fixed independently in `validate.py`;
the reference cannot authorize its own revisions or artifact hashes. The
reference binds #136's bundle commit and #137's later checker hardening, the
original producer, consumer, source, tools and query identities. Hashes bind
bytes; they do not authenticate execution. A different run needs a separate
reviewed contract, even if its output bytes happen to match.

Run with a Git repository containing the pinned LuCI commit:

```sh
python3 evidence/markup-historical-reference/validate.py --source /path/to/luci
OPENWRT68_LUCI_SOURCE=/path/to/luci python3 evidence/markup-historical-reference/test_validate.py
```

The source repository must contain LuCI commit `b2e0be4b46ec0fd43394c081fa7c50657af14011` and its selected objects. Without `OPENWRT68_LUCI_SOURCE`, the tests skip the end-to-end admission control; other controls still run. Hosted CI checks out that exact public commit separately, verifies its revision, and supplies it to the test.

The JSON result is `admitted`, `incomplete` (required evidence unavailable),
or `rejected` (present contradictory, malformed or unsupported input).
Admission checks the exact inventory mappings, source Git object bytes and
blob hashes, routing, and the two diagnostic result schemas and full tuples.
The AST output has only the independently specified first-import six-column
projection checked semantically. The remaining projections and parent index
are retained bytes, not an independent node-identity or completeness oracle.
Only `uhttpd.uc` is in the AST query scope; the other rows are outside scope.

The stage from the original run is no longer available. Source/stage equality
is a historical report, not revalidated by this reference. The source-relative
success query and empty error query are bounded observations, not a universal
diagnostic audit. Routing remains inconclusive / markup_not_modeled. No
installed-image, runtime, policy, data-flow, security, or trusted-execution
claim follows. This reference does not change historical inventory or policy.
