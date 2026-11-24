# Bounded UCI source-site observation

This is a report of local attempts `corpus-20261124-a` and
`fixture-20261124-d`; it is not a new run. The corpus result below is the
runner's recorded result and a decoded-output comparison. An independent raw
audit verified the staged and archived bytes, 88 selected paths, all 576 full
tuples and unique IDs, and the 15 recorded commands. This report does not assert trusted
execution, source completeness, resolved bindings or calls, runtime behavior,
installed packages, authorization, or security coverage.

The corpus attempt used OpenWrt base `32b0c2f9b2d2e73de2839ef4c106aa2fa2d91797`
and LuCI `b2e0be4b46ec0fd43394c081fa7c50657af14011`. It reconstructed the
88-row selected manifest, staged its blobs, created one JavaScript database,
and ran the selected-file and `JSParseError` checks twice on that database
before the UCI query. Both decoded file checks contain the exact 88 selected
paths and both diagnostics have zero `JSParseError` rows. `files.ql` reports
distinct paths; this is not a count of TopLevel entities or a check of every
extractor diagnostic. The recorded run used one thread, 2048 MB and allowed
minified files. It logged an absent extern trap cache, inability to retrieve a
qlpack Git commit hash, and disabled stage caching with an observed 1160 MB evaluator heap. Extraction progress
listed exactly the 88 selected source paths, alongside 110 pinned bundled externs. The
source archive `src.zip` SHA-256 is
`9b93720b6aff9c42b70cf4501f927c2b7252c9c684c50670672442a94dcae080`.

The strict projection of the decoded UCI output has 576 unique database-local
IDs and 576 public tuples, exactly matching the pinned source-first multiset
including spans, receiver, property-known status and multiplicity. There are
574 bare `uci` and two `L.uci` rows; all 576 are dot accesses. This is a
comparison of source-site candidates, not evidence of computed-key corpus
coverage. The source multiset has no CodeQL identities; IDs are local to this
database.

## Portable inventory

The version-controlled [inventory](inventory.json) records each relative source
path, inclusive span, receiver form, access kind, property-known flag,
property and positive multiplicity, with artifact-level `rpc_surface` and
`candidate` labels. Its SHA-256 is
`91bf4add23d23e0c852131e39107a779d596ce02bd7e625d47c65b4676e9b477`.
It is a projection of the audited `candidates.json` named below, with
machine-local database IDs omitted and common classification labels lifted to the artifact level. Every full tuple and its multiplicity was
compared to the pinned source-first multiset; no span was used as a substitute
for database identity in the original audit. The inventory is a portable
record of that bounded comparison, not an independently rerunnable extraction
receipt.

## Inputs and toolchain

| Input | Identity |
| --- | --- |
| 88-path manifest SHA-256 | `3161274241e086d121fd5122e0dfe0c5fb5d97872710d79c87f86244be2b2627` |
| Corpus lock SHA-256 | `b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a` |
| Source-first multiset SHA-256 | `341e1e41a21edc9114c5ec3eee9f76bc022ea4b89f6856d8b80854cf5b8c2a98` |
| CodeQL CLI 2.27.4 executable SHA-256 | `bb3a754e126ed061b5f3356531cd5501872ab3864bd665b2d1afdbf8a67a146d` |
| JavaScript extractor JAR SHA-256 | `04f6ff290bad5e3387d9df6b962905b038e6f309ba2e8720e9518e241b3bf80c` |
| CodeQL JAR SHA-256 | `ebb281fad305c343c06981a1418fb70ae158c403610376bc6180036341b1d0ab` |
| `codeql/javascript-all` | `3.0.0`, with 12 locked transitive packs |
| Pack lock SHA-256 | `eb487627c92c867a5760b9c24405db13d028eff5582378a9c4ff252debe13925` |
| Pack inventory SHA-256 | `091e007ca44cd8e17a085f21e8dcf8729352422d0141e24ee7f2011e6b3da0ff` |
| UCI query SHA-256 | `0cda9ffc13b95bd20ff05a67a6ae271835456b2da2e010877157ce4bf33452e9` |
| Runner used for this historical attempt SHA-256 | `aca36f3b5182469117eeebe163713453b58d3b5b65b35af4464aa9c3c91790b8` |
| Isolation wrapper SHA-256 | `c3bacd28300f3578ca6b48c71bb22b3227cd92a1e22b4f1124ac8aa64050c40a` |
| Reviewed run pins SHA-256 | `e98e056855ec07e4de0f0acd4ed66caf41f0883f7937c9882474524c7070115b` |

The recorded pack inventory covers 743 files. Hashes bind the recorded bytes;
they do not authenticate their origin or establish the execution environment.

## Fixture mutation controls

In a separate two-file fixture database, the baseline projected 82 tuples with
82 distinct IDs. Against the frozen source-first fixture oracle, the receiver
mutation removed exactly three rows; the optional-member mutation added exactly
three; the computed-name mutation retained 82 rows while replacing 33 known
property tuples with unknown-property tuples. The observed deltas match the
predeclared source expectations. These controls exercise the named syntactic
predicates on the fixture; they do not establish corpus completeness.

| Fixture decoded artifact | SHA-256 |
| --- | --- |
| Baseline `uci_surface.json` | `570876ae4c07f35cc8f498cc93f60a0e29412e2903bac0a9adf2cb95d2723ac4` |
| Receiver mutation JSON | `b7363e3563b3e87a6d2dbbdfabad969ca37a7bed643f2f318fea9cdc520f4524` |
| Optional mutation JSON | `502d70b8e0c21d79a8a5f0fa392a0148b980ca619b4d5123a2221e213f41401f` |
| Computed mutation JSON | `95d250f0f026b78533127e55c90fa7aa387c6225b69c29c74e11c772cec065b3` |

The corresponding fixture BQRS hashes are baseline
`2747614fa5a9315db505293dc10018677b7c7774b758423f90f66a36ba705941`,
receiver `34d89b82dd8741f2ddee09a9e8468d5a753f5c6b9f10189ec44b192e310263ff`,
optional `d962f82a3d655175602e1b8910bf666f30141b0a655d194f22fd79a25c07bcbc`,
and computed `4330efb0c9c5ca6e2e28ef4935a0c97db1d6eef9557c7871a09627eb8fb030d7`.
The fixture files and `JSParseError` decoded output hashes are respectively
`c11d78b85ba171e0c6c86ca1784d9051a30c2a6dec6f42584e3a68b2d21eec28`
and `466630e39d4cc0502e3c5e67053a87ac6e6d0f3e8b58b35ed82ae72af089e390`.

## Retained corpus artifact hashes

The raw BQRS, decoded JSON, source staging, command and wrapper logs, database,
and reviewed pin packet remain in local run storage. The logs and decoded paths
are machine-specific and are not reproduced here. Their hashes support byte
identity, not trusted execution. The local receipt SHA-256 is
`7ac1f83960cfb6e55f07af08a8caae130a9e5e8f522e3a866bbffe07f8ded870`.

| Artifact | SHA-256 |
| --- | --- |
| `accept-errors.bqrs` | `64005bf2393dbd7288790a4e33061243bc69ebafef1b9d18076d42e4861c8d63` |
| `accept-errors.json` | `466630e39d4cc0502e3c5e67053a87ac6e6d0f3e8b58b35ed82ae72af089e390` |
| `accept-files.bqrs` | `d01729258d20b9ea324f085ce4a48eb3e45155f49d83febdba49b6791750e2cd` |
| `accept-files.json` | `f56b48d59a139dc920be0c2e12cc8cdabdf2cb99e5b48b0397693ab38dac1316` |
| `candidates.json` | `cd809ba458cc1c5790ec46b91616291f04c17b7a7f78995f621d5c958d71524b` |
| `check-errors.bqrs` | `6728745842f7b72f79f0d4f23ce36f26677e68ffc7e5459aa7d4333fa848c881` |
| `check-errors.json` | `466630e39d4cc0502e3c5e67053a87ac6e6d0f3e8b58b35ed82ae72af089e390` |
| `check-files.bqrs` | `60d63c3afdb6f1be96d5fc627b08b8514cef011de82fd5c5e879b3fd8a3a0935` |
| `check-files.json` | `f56b48d59a139dc920be0c2e12cc8cdabdf2cb99e5b48b0397693ab38dac1316` |
| `commands.log` | `a41dc21c8df15b4b3fa10b8b591a93c0900420ba07634574a0e601c485aadf00` |
| `reviewed-pins.json` | `e98e056855ec07e4de0f0acd4ed66caf41f0883f7937c9882474524c7070115b` |
| `uci_surface.bqrs` | `8073a5e9d29b14ec72f6f91227353626bc2b1554036a39ceeec3fac3e47eed91` |
| `uci_surface.json` | `b5ef60ee8491dc7d5269e5fb46785d618a9c400ff69a19837c824ce4d0856c42` |
| `wrapper.log` | `30980dae8d8129d70bc62e50b1c86db6d02d5dbe2f32bba4a679cedf6d6cde5e` |
