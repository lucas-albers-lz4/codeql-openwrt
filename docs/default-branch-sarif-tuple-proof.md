# Historical OpenVPN SARIF tuple proof

Status: candidate offline regression contract. Base is clean
`1741537d2845d5c044e0d766aab4e52bbba9affa` (merged PR #263). This
module has no CLI, key, queue, network or signing path. Its caller passes
immutable byte strings and receives an ordinary Python receipt with
`authority: none`. It is not a completion issuer.

## Decision and provenance

The source-first oracle is copied byte-for-byte from the ledger's
`evidence/mvp-openvpn-introduction-replay-20261126/source-first.json` at
SHA-256 `cdea67fa3983576df3cea44a19e74eb2d015866ad5d2ebc24141d357055e2fb4`.
The introduced and fixed source files are copied from LuCI Git objects
`5306e007656fe9a77aee2d2a94072d003b0b5a7d` and
`e4ff45ecbc6ad212951815c8c99b2749fbd7de6b`, respectively. The expected
query tuple is one `ucode/m4/direct-rpc-shell-word` warning at the staged
OpenVPN URI, line 71 columns 115–132, versus zero for the fixed source.
Both sources are eligible plain-route files with one expected extraction
identity and no expected errors. The absent-file parent is a selection
control, not a query negative.

The SARIF and producer receipt fixtures are exact retained bytes from the
historical `45833426577-1` R3 parent/fixed cases. The event manifest and
triage packet fixtures are **offline reference wrappers**, not proof that a
hosted event consumer ran. The parent producer receipt scans commit
`b45584b4e6068b9b096872dd02494a048d869c36`; its source blob and SHA-256
match the introduction. The fixed producer receipt scans the fixed commit.
The verifier keeps those producer commits distinct from the oracle commits.

The verifier pins the checked-in oracle, R3 release lock and reviewed local
`tools/sarif_accept.py` bytes by SHA-256 before executing a copied consumer in
random private temporary scratch. It checks source SHA-256 and Git blob,
source path, staged path, producer release, suite, CLI, unique rule set,
reported extraction identity and the source-first tuple multiset. The actual
consumer checks UTF-16 region bounds. The existing final-proof and consumer
replay comparators check the SARIF/reference packet tuple multiset and exact
replayed packet bytes, including duplicates.

This is a one-file historical source-stage regression. It does not rederive
route decisions, decode BQRS extraction rows, authenticate the historical
producer run, fetch canonical Git objects, verify installed package bytes,
or prove an arbitrary incoming event's expected alert set. A nonzero tuple
remains `triage_required` without alert disposition. The v0.6 corpus still
has 17 package source signals outside its frozen denominator.

## Gate and resources

`python3 -B -m unittest tools.test_default_branch_sarif_tuple_proof -v` is
the focused local check and is wired to the `contract` job of
`default-branch-commit-scan.yml`. It runs the actual pinned consumer for
the historical positive and fixed eligible near miss, then mutates source,
oracle, release, raw URI alias, duplicate tuple, in-bounds column and
out-of-bounds UTF-16 column. Each invocation owns temporary scratch; fixture
input is under 100 KiB and the focused suite takes under a second locally.
The hosted contract and full repository gates remain to be run on an exact
reviewed head before promotion. No release, live dispatch or consumer handoff
is inferred from the local fixture pass.
