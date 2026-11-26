# Canonical source acquisition preflight

Status: local candidate based on merged main
`8ae2fb4bae82eb770287ed388235b96dd04e0454` (PR #260). This is a bounded
source-acquisition and oracle launcher for a **local disposable** checkout
inside the ledger's ignored `work/`. It does not add a scan, issuer, queue
reader, key reader, or completion action.

`tools/canonical_source_preflight.py` accepts the exact run manifest, coverage,
routing, and optional policy paths. It requires the v0.6 policy bytes with SHA
`9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490`. It
derives the event source pin from the manifest and the other two source pins
from that policy. The event must be an OpenWrt first-parent commit, its control
must be a distinct commit, and the event base must equal the recorded first
parent. All repository URLs are fixed in the tool:

| Repository | Fixed remote | Fallback ref if a direct SHA fetch fails |
|---|---|---|
| LuCI | `https://github.com/openwrt/luci.git` | `refs/heads/master` |
| OpenWrt | `https://github.com/openwrt/openwrt.git` | `refs/heads/main` |
| Packages | `https://github.com/openwrt/packages.git` | `refs/heads/master` |

The run root must be a new direct child of ledger `work/`; the tool refuses an
existing path, parent traversal, a symlinked path, or a checkout outside that
layout. It copies the four input documents into its private run root before
using them. It initializes distinct object stores from the fixed HTTPS
remotes, fetches exact commits, binds successful direct fetches to the exact
`FETCH_HEAD`, and checks exact commits and trees in clean detached checkouts.
If a direct fetch fails, the only fallback is one depth-2048 fetch of the
fixed branch for that repository; the requested commit must be an ancestor of
the fetched tip. Source roots are made read-only before the existing
`tools.default_branch_source_truth` verifier reads them. A direct SHA fetch
does not establish branch reachability; only the advertised-ref fallback
checks that relationship.

The OpenWrt policy-base pin is `bce40f6a15c273778061e8fceced7b9e0f58d99b`.
The tool tries one direct SHA fetch without a local fallback and always makes
authenticated, no-redirect GitHub Git Commit and recursive Trees API requests
for the frozen base and event head. The API tree delta is always performed,
independent of the direct Git fetch outcome. If the direct fetch fails, the
policy-base identity is supported by API responses only and its Git commit
object remains unavailable; if it succeeds, both identity sources are recorded
and compared. The API host and repository are fixed. The
body limits are 1 MiB for a
commit response and 32 MiB/100,000 entries for a recursive tree response.
Each response must be complete; the commit SHA/tree relation is checked, every
listed Git tree object (including empty trees) is reconstructed and hashed,
and all non-tree path/mode/type/object-ID tuples are compared. The frozen
recipe-path policy is then applied to the resulting delta. A nonempty
relevant recipe delta requires review. This API-only proof does not acquire
the policy-base Git commit object or fetch its blob contents, and does not
prove build effects or installed package bytes.

GitHub API authentication uses `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token`
for `github.com`. The token is held in memory and sent to the fixed API host
through a pipe to a separately supervised HTTP worker. It is not placed in an
argument, receipt, or file. The worker rejects redirects, bypasses ambient
proxies, checks response framing and `Content-Length`, caps output, and has an
absolute request deadline. Git uses no shell, system/global config, credential
helpers, prompts, hooks, templates, LFS smudge, or redirect following.

The source verifier receives snapshots of the exact manifest, coverage, and
routing bytes plus the three owned source roots. Its source-oracle JSON is
retained separately from the preflight receipt. The verifier's own
`canonical_git_provenance_verified: false` remains unchanged; the enclosing
preflight records the canonical remote, commit, tree, checkout state, fetch
commands, source-oracle digest, and the API-only policy-base limits. The
manifest and producer artifacts remain supplied observations and do not
authenticate a signed start, hosted scan, or live completion.

## Bounds

The local run requires at least 12 GB of free space at start. It has a 2,400
second overall deadline, a 600 second per-fetch deadline, a 45 second local
Git-command deadline, a 600 second source-oracle deadline, and a 30 second API
request deadline. Default captured stdout/stderr is 256 KiB per command; the
API worker, tracked-tree listing, and source-oracle commands have explicit
larger limits of 32 MiB, 64 MiB, and 8 MiB respectively. JSON inputs are
limited to 8 MiB. Each Git object store is checked against 1.5 GB, all object
stores against 4 GB, each source tree against 2 GB of tracked blob bytes, and
all materialized source trees against 4 GB. Git subprocesses also have a 1.5
GB per-file `RLIMIT_FSIZE`. These are explicit preflight accounting and
per-file process limits; they are not filesystem quotas. The actual
materialized worktree size and Git object-store size are checked and retained.
`HOME`, `TMPDIR`, and child Python bytecode-cache prefixes are fresh and
run-owned. The launcher itself must start with a fresh, empty, mode-0700
`PYTHONPYCACHEPREFIX` direct child of ledger `work/`; this prevents `-B` from
loading stale ignored bytecode while suppressing cache writes. Peak RSS is not
measured by this wrapper.

## Invocation

Run from the disposable codeql-openwrt checkout inside ledger `work/`, with a
new run-root name each time. The example rechecks retained run 45875169837; it
does not start or rerun CodeQL.

```sh
mkdir -m 700 ../canonical-source-launcher-cache-45875169837-20261126
PYTHONPYCACHEPREFIX=../canonical-source-launcher-cache-45875169837-20261126 \
python3 -B -m tools.canonical_source_preflight \
  --run-root canonical-source-run-45875169837-20261126 \
  --manifest ../source-truth-preflight-45875169837-pr254-20261126/artifact-inputs/default-branch-inputs-45875169837-1/manifest.json \
  --coverage ../source-truth-preflight-45875169837-pr254-20261126/artifact-inputs/r3-ucode-45875169837-1/default-branch-corpus/out/coverage-default-branch.json \
  --routing ../source-truth-preflight-45875169837-pr254-20261126/artifact-inputs/r3-ucode-45875169837-1/default-branch-corpus/out/routing.json
```

Exit 0 means the policy-base recipe delta was clear and the selected/excluded
source oracle returned 0. Exit 3 means canonical acquisitions and API tree
delta passed and selected/excluded source identities/routes matched, while
candidate source signals remain outside the frozen denominator. Exit 4 means
the policy-base API proof is unresolved or a relevant recipe path needs
review. Exit 2 means an input, source pin, checkout, or source-oracle check
was rejected. In particular, the known 17 packages-feed source signals are a
partial-scope result, not a fetch failure or proof of package installability.

## Contract tests

The `contract` job for `default-branch-commit-scan.yml` runs this network-free
suite in the ordinary Actions checkout layout; its integration fixture builds
a synthetic ledger `work/` tree for the local run-root boundary:

```sh
python3 -B -m unittest tools.test_canonical_source_preflight -v
```

These network-free controls cover frozen pin derivation, control separation,
fixed API scope, no-follow redirects, chunked response framing and
`Content-Length` checks, nested and empty Git tree hashing, duplicate and
truncated tree rejection, tree mode/type constraints, omitted descendants,
recipe-review versus unresolved outcomes, create-only output, path traversal,
and an offline launcher orchestration that preserves the source verifier's
exit-3 partial result.
