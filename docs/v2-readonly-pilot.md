# Experimental read-only v2 boundary

`python3 -B -m policy.v2_adapter --help` shows the explicit family and input
arguments. The caller must independently choose the selection document, policy,
corpus, profile, and evidence bytes. The v2 envelope repeats the selected
context; it cannot select or authenticate policy. All JSON enters as raw UTF-8,
with duplicate keys and non-finite numbers rejected. A matching digest binds
bytes to the selection, but is not authentication of their origin.

For a local demonstration, run `python3 -B -m unittest policy.tests.test_v2_adapter -v`.
Its status tests use synthetic package,
permission, and resource fixtures; its setBlockDetect test reads the archived
neutral observation and pinned source evidence. On Linux the modeled mounts
gate is `allow`; on Darwin and other non-Linux platforms it is `unknown`
because the evaluator depends on Linux libc behavior. The result stays
unassessed on every platform. This is a unit test, not a new runtime or CodeQL
run. The separate historical typed handoff evidence is archived in [the issue
#89 evidence record](../evidence/issue89-typed-ae946190-7f532ac/README.md); its
scope and limitations are recorded there and in its reproduction guide.

The status family is entirely synthetic. Its only supported target/operation
pairs are `status`/`read` and `status-metadata`/`inspect`; the read pair is
required. Selected caller and provider manifests have distinct roles, feed,
name, version and content hash. The caller permission
and provider resource records are separately bound inputs; missing or nonmatching
records leave the gate unknown. This tests policy resolution without claiming
that a real feed or provider has been authenticated. A selected valid fixture
can produce an assessed synthetic result; multiple selected authorities remain
an explicit conflict, and an invalid asserted reference is an error.

The setBlockDetect family accepts the separately pinned historical neutral
observation, source, extraction rows, diagnostics and routing, and validates
the actual tracked profile and selected corpus lock. Its source, ACL and fixture
login evidence is bounded to the historical LuCI, uhttpd and rpcd revisions.
On Linux it runs the existing libc-dependent evaluator for the pinned mounts
fixture; on other platforms the modeled gate remains unknown. Pinned source
recipes and feed configuration bind the modeled LuCI package names and profile
dependency chain. The route model additionally assumes the `uhttpd-mod-ubus`
default ran with no prior prefix and that its plugin is present; pinned recipe,
default, init and config bytes support that conditional model. On Linux, the
bounded gate is allow only when the exact pinned
mounts fixture matches the evaluator. The evaluator assumes the `luci` object
exists; live registration is not established. This is a source-model result,
not proof of a package build, installation, or live runtime. Missing evidence stays unknown. No real assessed reference is accepted until an
independent review approves the exact scope and policy authority. Archived
hashes and diagnostics do not authenticate producer origin, prove live
registration or execution, or establish complete extraction.

The API returns results in memory and the CLI prints JSON. Neither calls the
legacy writer or changes historical reports. The old typed and CSV entry points
remain separate. This is an experimental boundary; it does not establish an
authorization violation or general security coverage.
