# Current LuCI R2.5 package lane

This lane is a separate, exact three-profile consumer for the cb87 LuCI package
artifacts. It keeps the existing historical `luci-base`/`wifi-scripts-ucode-y`
lock unchanged and accepts only these identifiers:

- `luci-base-cb87` (OpenWrt `x86_64`)
- `luci-app-adblock-fast` (`all`)
- `luci-mod-status` (`x86_64`)

`docs/r25-current-luci-package-lock.json` pins the three artifact run/ID/name,
outer ZIP and IPK digests, package control identity, source oracle, all source
revision/tree identities, and whole-package member inventory. The member
inventory binds every regular data member path, mode, and digest to the pinned
raw IPK digest. The source oracle independently marks every regular data member
as plain, markup, or excluded for the released extractor.

The pre-run expectation is zero default-suite SARIF results for each package.
This is a falsifiable, source-derived hypothesis for the released
`DirectRpcShellWord` rule. It is not a recorded observation. The consumer still
checks exact routed and successful-file identities, zero extraction errors,
resolved released rules, SARIF structure, and result count. Any result count
change fails closed for review. Markup remains inconclusive and is not reported
as successful plain-Ucode extraction. The diagnostics and result rule have
separate acceptance checks; the zero result hypothesis is not a coverage claim.

The wrapper reuses the R3 immutable-release bootstrap to verify the tag and
release immutability, producer bundle, verifier, CodeQL archive and binary,
pack locks, and exact resolved suite. It then invokes the shared package
artifact downloader, strict IPK stage parser, and coverage verifier with the
current profile set as an explicit argument. The historical default profile
set and hardcoded acceptance counts remain unchanged. No release lock or
prerelease policy is changed.

Before each package producer invocation, the wrapper writes a safe tar archive
of that complete private analysis stage and verifies the archive's paths,
bytes, types, and modes. After producer execution, it reopens the raw successful-
file and extraction-error query JSON and resolved-suite JSON, checks the exact
successful path multiset and empty error rows, confirms resolved query paths
inside each producer-private bundle copy against normalized paths from the
verified shared bundle, and joins their hashes and rows to the stage, coverage
manifest, and producer receipt. This includes hidden files such as
`etc/luci-uploads/.placeholder`; the workflow also enables hidden-file upload
for its explicitly scoped run-owned stage, receipt, command, archive, IPK, and
producer-output paths. Package analysis stages use private `0600` copies. They
do not attest installed file mode: the source-first whole-IPK inventory and raw
IPK pin retain that separate mode evidence. Each stage archive is created
before its package scan so a later scan or acceptance failure still retains
that package's stage.

The workflow's `run_scan` input defaults to false. Pull requests run offline
contract tests only through this workflow. The existing R3 workflow also
watches the shared bootstrap and R2.5 engine files; its existing released R3
and historical package/corpus validation may run on a pull request touching
those paths. The current three-package producer is never started by pull
request automation and requires an explicit manual dispatch with `run_scan` set
to true. No scan has been run by preparing this lane.

## Scope limits

The three package builds and IPKs are retained evidence from the source-pinned
OpenWrt/LuCI builds listed in the lock; this workflow consumes those exact
immutable artifacts and does not rebuild them. The expected zero SARIF count is
not an observed result until a manual run completes and passes consumer
validation. Extraction diagnostics only establish the declared package-stage
outcomes for that run. They do not establish runtime behavior or security
coverage beyond the released query and its accepted result set.
