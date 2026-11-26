# Historical OpenVPN source policy v0.1

`openvpn-historical-source-v0.1.json` is a separate, SHA-256 pinned
source-staged policy for the LuCI OpenVPN introduction at
`5306e007656fe9a77aee2d2a94072d003b0b5a7d` and first parent
`7f6ba9d46028635f0d5aa2e15fcab9ffd163a688`. It does not replace
`current-corpus-source-v0.6.json` or change current incoming scans.

The historical LuCI tree contains 48 v0.6 selected paths, two v0.6 excluded
paths, and the new OpenVPN path. Nineteen later v0.6 baseline paths are
absent at both historical commits, so they are omitted from this snapshot.
For every retained LuCI row, the snapshot refreshes the commit, blob and
content SHA-256 from the pinned historical Git tree. The selected routes
matched their prior route policies on source inspection. Other repository
rows retain their v0.6 pins and dispositions for later corpus staging; the
historical selector schema accepts only LuCI.

The selector admits exactly one `candidate_added` event: the OpenVPN path
with its pinned source blob, SHA-256, first-parent/head pair and package and
shared recipe blobs. It verifies every selected/excluded LuCI row against
the actual head tree. An extra candidate, missing selected path, changed
blob, wrong recipe or different revision fails closed. The ordinary v0.6
selector contract and output remain unchanged.
An ordinary selected content edit is scan-eligible under the general
selector contract; the fixed historical policy pins exact source blobs at
this head, so a different head cannot use this admission.

This is a source policy decision for an **offline historical replay**. It
does not authenticate live checkpoint custody, prove actual installed IPK
bytes, produce a CodeQL alert or establish a clean control. A later
direct-commit event manifest must bind this policy to the identity receipt
and the separately checked admission input before scanning.

Run focused controls with:

```sh
python3 -B -m unittest tools.test_historical_openvpn_policy -v
```
