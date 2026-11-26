# Historical OpenVPN direct-commit admission input

`direct-commit-openvpn-admission-v1.json` freezes the parent-absent,
introduced and fixed LuCI Git blob identities for one OpenVPN package path,
its package Makefile and `luci.mk`. The review input comes from a clean
disposable historical LuCI checkout and is pinned by SHA-256 in
`tools/direct_commit_admission.py`.

The checker accepts an identity-only receipt from
`tools/default_branch_event.py`, a clean source checkout at the introducing
commit and a separate clean checkout at the fixed commit. It verifies the
first parent, trees, exact blobs, package recipe syntax, root install rule,
and the proposed `usr/share/rpcd/ucode/luci.openvpn.uc` route. Output is
created exclusively outside both checkouts and binds the input identity
receipt by byte digest. It says `source_policy_input_verified_only`.

This is a frozen **input to** a later versioned policy admission. It does
not change v0.6, make the full-tree selector accept `candidate_added`, prove
actual IPK bytes, run CodeQL, or prove a clean control. The fixed commit's
source difference is an exact Git object observation; a no-alert control
requires its own released scan. The historical probe's interval was
synthetic and did not establish a live linked checkpoint gap.
The checker validates the input receipt's gap/checkpoint digest syntax but
does not replay those artifacts. It omits their values from its output so
this source check cannot be mistaken for checkpoint provenance.

Run the focused controls with:

```sh
python3 -B -m unittest tools.test_direct_commit_admission -v
```
