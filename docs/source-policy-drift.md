# Bounded source-policy drift report

`tools/source_policy_drift.py` compares a clean OpenWrt or LuCI checkout with
the checked-in `docs/current-corpus-source-v0.4.json` source-policy manifest.
The script accepts only this exact manifest SHA-256:
`1e25cf9c2adc40c854502fed8d1ccc0977a3c4825d6ee4a1c0a543ffe0a76699`.
The manifest's top-level `pins` bind baseline source commits. The comparison
validates those pins, all present source commit/blob/hash values, source path
safety and uniqueness, including excluded entries.

```sh
python3 -B tools/source_policy_drift.py docs/current-corpus-source-v0.4.json luci /path/to/clean-luci-checkout FULL_EVENT_SHA FULL_API_BASE_SHA drift.json
```

The incoming-event workflow reads `base.sha` and `head.sha` from the exact
captured GitHub PR API response, checks the head against the requested SHA, then
fetches the exact API base SHA into the PR checkout. The drift report requires
both commits to resolve, records their tree IDs, and diffs the explicit base
commit against the event head. It does not depend on PR checkout history depth.
The workflow uses only the checked-in, digest-pinned manifest above and retains
the report even when drift causes the job to fail.

The report recalculates Git blob IDs and SHA-256 content hashes for all
baseline selected and excluded source paths in the chosen repository. It
preserves package owner, configuration condition, exclusion reason and
expected route. Source byte changes appear in `changed_selected_or_excluded`
with their fresh event identities, but do not fail by themselves. Missing
baseline paths, renames, added `.uc`, `.ut` or extensionless candidates, and
changes to policy inputs under selected package roots fail closed with exit 1.
The roots are derived from selected source paths: OpenWrt package roots before
`files*`, and LuCI owning package roots, plus LuCI's root `luci.mk`. Unrelated
Makefile/Config.in/Kconfig/`*.mk` changes are listed in
`unrelated_policy_files` and do not fail the report. Invalid identities,
manifest bytes, pins, duplicate/unsafe paths or dirty checkouts fail with exit
2. Exit 0 means no bounded path or relevant policy-input drift was observed;
the report can still contain source content changes.

This is an incremental source-policy check, not the full dynamic selector in
the incoming-CI design. It inspects baseline identities plus candidate paths in
the explicit base-to-event diff. It does not find unmodified candidate paths
already present outside that diff, infer installation from recipes, evaluate
package conditions semantically, detect every possible route change, or identify
every candidate naming convention. In particular, Makefile-only activation of
previously unselected source outside selected package roots is not covered.
Changes to recognized policy files under selected package roots fail for review;
their semantic effect is not evaluated here. It does
not run extraction or CodeQL and does not establish Gate 8.

Mechanical tests:

```sh
python3 -B -m unittest policy.tests.test_source_policy_drift -v
python3 -B -m unittest policy.tests.test_incoming_event -v
```
