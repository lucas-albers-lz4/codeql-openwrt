# Default-branch gap preflight

`tools/default_branch_gap.py` is a read-only preflight for two
successive incoming-discovery checkpoints. It does not dispatch scans, change
the queue, or approve a commit for analysis.
Set `GITHUB_TOKEN` for authenticated GitHub API reads; `GH_TOKEN` alone is not
used by this tool's fetch path.

```sh
python3 -B -m tools.default_branch_gap \
  --previous /private/path/previous-decisions.json \
  --current /private/path/current-decisions.json \
  --output-dir /private/path/new-gap-output

python3 -B -m tools.default_branch_gap \
  --previous /private/path/previous-decisions.json \
  --current /private/path/current-decisions.json \
  --verify-gap /private/path/new-gap-output/gap.json
```

The tool validates the current checkpoint against its exact predecessor and
replays both snapshots from retained responses. For each upstream default
branch whose observed tip changed, it requests one bounded GitHub compare
page. It requires a fast-forward relation, exact base and head identities,
matching trees, a complete count of at most 100 commits, and a reconstructible
first-parent path. Side-branch commits in a merge are not reported as former
default-branch tips. An unchanged tip makes no compare request. Divergence,
truncation, pagination to another page, an inconsistent tree, or an API error
produces `failure.json` rather than a partial success.

Successful `gap.json` retains the exact prior/current checkpoint digests,
first-parent commit/tree identities, and raw compare-response custody through
the existing request-log format, plus sanitized retryable HTTP failures.
Verification replays response bodies and decisions without network, proving
internal consistency only. It does not authenticate the API fetch or the
checkpoint's external custody; those remain the caller's responsibility.
The result is **discovery
evidence only**: each enumerated commit still needs canonical membership,
source selection, a released producer scan, and a consumer disposition.
The manual discovery workflow runs and replays this preflight after each
non-genesis poll on `main`, retaining its gap record or failure in the same
artifact. It does not dispatch the enumerated commits or add them to the
poller's capacity-one selection. The current v3 poller still observes only
poll-time tips, and PR-head gaps remain outside this preflight.

The one-commit LuCI OpenVPN introduction interval
`7f6ba9d46028635f0d5aa2e15fcab9ffd163a688` →
`5306e007656fe9a77aee2d2a94072d003b0b5a7d` was checked against an
actual GitHub compare response, including its `Link: ...; rel="first"`
self-link. This verifies the supported response shape on one historical
interval, not all merge or pagination patterns.
