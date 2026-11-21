# Bounded fnmatch experiment

This scratch experiment searches a finite candidate set, then validates each candidate against both patterns using a separately compiled libc C helper in the C locale, with FNM_NOESCAPE and no FNM_PATHNAME. It does not establish authorization, reachability, live OpenWrt behavior, disjointness, or complete glob intersection.

Example patterns come from `policy/fixtures/luci-mod-network.json` in codeql-openwrt at 2c05b69cded0590d333783eb11414679e7a9151b, same `luci-mod-network-config.read.file` scope. The fixture was compared byte-for-byte with pinned LuCI b2e0be4b46ec0fd43394c081fa7c50657af14011, `modules/luci-mod-network/root/usr/share/rpcd/acl.d/luci-mod-network.json`. The returned example is `/proc/sys/net/ipv6/conf/eth0/mtu`.

Run from this directory:

```
cc -std=c11 -Wall -Wextra -Werror check.c -o /tmp/wave2-fnmatch-check
python3 search.py /tmp/wave2-fnmatch-check '{"group":"luci-mod-network-config","verb":"read","scope":"file","ubus_object":null}' '/proc/sys/net/ipv6/conf/*/mtu' '{"group":"luci-mod-network-config","verb":"read","scope":"file","ubus_object":null}' '/proc/sys/net/ipv[46]/conf/*'
python3 -m unittest -v test_search
```

The generator expands only the first pattern: `*` uses four fixed substitutions and positive bracket lists enumerate literal members. It does not support `?`, backslashes, negated brackets, ranges or malformed brackets; unsupported patterns return inconclusive. The default cap is 256 candidates, checked in deterministic order. Exhaustion or hitting the cap is inconclusive, never evidence of no intersection. Inputs carry group, verb, scope and ubus object provenance; mismatched or missing fields return `scope_mismatch`. Ubus-function provenance requires an object. Provenance is caller-supplied and is not authenticated against source. Inputs are intended as small trusted experiment strings, not untrusted production input. C helper failures are errors, not negative matches.

Tests were run on Darwin 24.6.0 arm64; this host's libc is not Linux glibc/musl and results do not prove live rpcd parity. A separate independently written temporary C check also tested the returned witness against both patterns, an ipv5 negative and an FNM_PATHNAME control.

The Python text and process-argument interface cannot represent embedded NUL or arbitrary non-UTF-8 bytes; this does not cover all libc byte strings. The helper distinguishes `FNM_NOMATCH` from other errors. The helper recheck in the unit test shares the search validator and is not an independent implementation; the separate temporary C check described above is independent of the search code.

The `fnmatch-witness-experiment` job in the existing `m2-policy.yml` workflow is manual-dispatch only. On Ubuntu it records Python, compiler and libc versions, runs the unit tests, prints the search result, and compiles `independent_check.c` to verify and print the pinned witness separately, including negative controls. The tests read the checked-in fixture to assert both patterns and read permissions in the exact group/read/file context, and assert that the returned witness is the pinned witness. The fixture check does not independently establish upstream source provenance; the earlier byte comparison provides that separate evidence. Linux CI execution remains unverified until the workflow is actually dispatched; neither the workflow nor its presence implies live OpenWrt parity. Local Darwin verification: nine unit tests pass, and the independent C check prints the witness. No policy or producer artifacts are generated.
