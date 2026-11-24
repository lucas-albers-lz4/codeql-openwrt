# Manual luci-base IPK byte experiment

This workflow is a proposed, manually dispatched experiment, not evidence of a
package build. It uses fixed OpenWrt, LuCI, and packages-feed commits and a
fresh x86/64 OpenWrt build root. It compares the two pinned Git blobs against
prepared files, package staging files and IPK members. It does not establish a
root filesystem installation, device behavior, or broader coverage.

Run `.github/workflows/installed-byte-manual.yml` only on a reviewed workflow
revision. It retains the command log, GNU time records, configuration, source
and feed provenance, and comparison receipt as a short-lived artifact even
when a step fails. Source checkouts, downloads, build outputs, temporary files
and caches are private to the job. The build may require substantial disk,
network access and several hours. Failure, interruption, missing or duplicate
paths, and a missing receipt are not passes.

The pinned OpenWrt `scripts/ipkg-build` emits a gzip-compressed outer tar,
with `debian-binary`, `data.tar.gz` and `control.tar.gz`. The comparator reads
that format, retains the exact IPK in the artifact, checks selected members
against source, prepared and package staging bytes, and records
Package/Version/Architecture from the control file. Host tools and the
cross-toolchain are built explicitly before the package target. The PASS
receipt is written after source, feed, config and package-stage checks.

Manual run `45503598387` completed host tools and toolchain, then failed in
the original `make -n` target probe before the intended package build. The
pinned OpenWrt top-level recipe uses recursive `+` make, which executes under
`-n`; that probe reached a dependency and hid its underlying error. This
revision removes the probe and retains one verbose serial package build.
The failed run has no IPK or installed-byte comparison result.

The exact feed resolution, generated target and package-stage location have
not yet been exercised on Linux. The script intentionally stops on unexpected
resolution or multiplicity; inspect failure logs before changing it. The
version value reproduces the pinned `luci.mk` non-translation `findrev` rule;
the byte comparison checks it against the actual output, but it is not an
independent assertion of the build system's internal variables.

Local lightweight checks: `bash -n tools/installed-byte/run.sh`,
`python3 -m unittest discover -s tools/installed-byte -p 'test_*.py' -v`,
and `actionlint .github/workflows/installed-byte-manual.yml`. These are
contract checks only, not build or installed-byte evidence.
