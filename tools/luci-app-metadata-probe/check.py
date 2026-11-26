#!/usr/bin/env python3
"""Metadata-only probe guards. No package or dependency build authorization."""

import hashlib, json, os, re, stat
from collections import Counter
from pathlib import Path

SEED = (
    "CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=m\n"
    "CONFIG_PACKAGE_luci-app-dockerman=m\nCONFIG_PACKAGE_luci-app-statistics=m\n"
    "CONFIG_PER_FEED_REPO=y\nCONFIG_USE_APK=n\n# CONFIG_LUCI_JSMIN is not set\n"
    "# CONFIG_LUCI_CSSTIDY is not set\n"
)
REQUIRED = {
    "CONFIG_TARGET_x86": "y",
    "CONFIG_TARGET_x86_64": "y",
    "CONFIG_PACKAGE_luci-base": "m",
    "CONFIG_PACKAGE_luci-app-dockerman": "m",
    "CONFIG_PACKAGE_luci-app-statistics": "m",
    "CONFIG_PER_FEED_REPO": "y",
    "CONFIG_USE_APK": "n",
    "CONFIG_LUCI_JSMIN": "n",
    "CONFIG_LUCI_CSSTIDY": "n",
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(b):
    return hashlib.sha256(b).hexdigest()


def json_object(data):
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, "duplicate JSON key: " + k)
            out[k] = v
        return out

    def bad(v):
        raise ValueError("invalid JSON constant: " + v)

    v = json.loads(data, object_pairs_hook=pairs, parse_constant=bad)
    need(isinstance(v, dict), "JSON object required")
    return v


def fresh_root(path):
    p = Path(path)
    need(
        p.is_absolute()
        and p.resolve(strict=False) == p
        and not p.exists()
        and not p.is_symlink()
        and p.parent.is_dir()
        and p.parent.resolve(strict=True) == p.parent,
        "run root must be absent and physical",
    )
    p.mkdir()
    return p


def physical_file(path, root, nonempty=False):
    p = Path(path)
    root = Path(root)
    need(
        p.is_absolute()
        and p.is_relative_to(root)
        and p.resolve(strict=True) == p
        and p.is_file()
        and not p.is_symlink()
        and p.stat().st_nlink == 1,
        "unsafe file: " + str(p),
    )
    data = p.read_bytes()
    need(not nonempty or data, "empty file: " + str(p))
    return data


def validate_config(data):
    lines = data.decode("utf-8").splitlines()
    out = {}
    for line in lines:
        m = re.fullmatch(r"(CONFIG_[A-Za-z0-9_.-]+)=(.*)", line) or re.fullmatch(
            r"# (CONFIG_[A-Za-z0-9_.-]+) is not set", line
        )
        if not m:
            continue
        key = m.group(1)
        value = m.group(2) if m.lastindex == 2 else "n"
        need(key not in out, "duplicate config symbol: " + key)
        out[key] = value
    for k, v in REQUIRED.items():
        need(out.get(k) == v, "config symbol differs: " + k)
    return {k: v for k, v in out.items() if k.startswith("CONFIG_PACKAGE_") or k in REQUIRED}


def diagnostics(phase, streams, known):
    warnings = []
    errors = []
    fatal = []
    allowed_pairs = (
        Counter(tuple(p) for p in known["defconfig_recursive_pairs"])
        if phase == "defconfig"
        else Counter()
    )
    for data in streams:
        lines = data.decode("utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            line = line.strip("\r")
            if "WARNING:" in line.upper():
                warnings.append(line)
            if ":error:" in line.lower() or re.search(r"\b(?:ERROR|FATAL):", line, re.I):
                pair = (line, lines[i + 1] if i + 1 < len(lines) else "")
                if allowed_pairs[pair] > 0:
                    allowed_pairs[pair] -= 1
                    errors.append(list(pair))
                else:
                    fatal.append(line)
            if "circular" in line.lower() and "warning" in line.lower():
                fatal.append(line)
    known_warnings = Counter(
        known.get(
            {"feeds-install": "feeds_install_warnings", "defconfig": "defconfig_warnings"}.get(
                phase, ""
            ),
            [],
        )
    )
    seen = Counter(warnings)
    unexpected = list((seen - known_warnings).elements())
    return {
        "warnings": warnings,
        "historically_matched_warnings": list((seen & known_warnings).elements()),
        "unreviewed_warnings": unexpected,
        "known_kconfig_recursive_pairs": errors,
        "unexpected_errors": fatal,
        "disposition": "review_required",
    }


def validate_feed_index(openwrt, name):
    root = Path(openwrt)
    link = root / "feeds" / f"{name}.index"
    need(
        link.is_symlink() and os.readlink(link) == f"{name}.tmp/.packageinfo",
        "feed index link differs: " + name,
    )
    target = root / "feeds" / f"{name}.tmp" / ".packageinfo"
    data = physical_file(target, root, True)
    need(link.resolve(strict=True) == target, "feed index target differs: " + name)
    return data


def validate_link(path, expected):
    p = Path(path)
    e = Path(expected)
    need(
        p.is_symlink()
        and p.resolve(strict=True) == e
        and e.is_dir()
        and e.resolve(strict=True) == e,
        "feed link differs: " + str(p),
    )


def scan_dump_files(openwrt):
    root = Path(openwrt)
    logs = root / "logs"
    out = []
    if not logs.exists():
        return out
    need(logs.is_dir() and not logs.is_symlink(), "unsafe scanner log root")
    for p in logs.rglob("*"):
        need(not p.is_symlink(), "symlink in scanner logs")
        if p.is_file() and p.name == "dump.txt":
            out.append((p.relative_to(root).as_posix(), physical_file(p, root)))
        else:
            need(p.is_dir() or p.is_file(), "special scanner log entry")
    return sorted(out)


def validate_packageinfo(data, expected):
    """Require each scoped package once under its exact scan source Makefile."""
    source = None
    found = {name: [] for name in expected}
    for line in data.decode("utf-8").splitlines():
        if line.startswith("Source-Makefile: "):
            source = line.removeprefix("Source-Makefile: ").strip()
        elif line.startswith("Package: "):
            package = line.removeprefix("Package: ").strip()
            if package in found:
                found[package].append(source)
    for name, source in expected.items():
        need(found[name] == [source], "package metadata source differs: " + name)
    return found


def validate_final_config(data):
    need(data != SEED.encode(), "defconfig output is unchanged seed")
    values = validate_config(data)
    need(b"CONFIG_HAVE_DOT_CONFIG=y" in data.splitlines(), "defconfig completion marker missing")
    return values


def validate_packagedeps(data):
    lines = data.decode("utf-8").splitlines()
    for name in ("luci-app-dockerman", "luci-app-statistics"):
        package = f"package-$(CONFIG_PACKAGE_{name}) += feeds/luci/{name}"
        prefix = f"$(curdir)/feeds/luci/{name}/compile += "
        need(lines.count(package) == 1, "package graph declaration differs: " + name)
        need(
            sum(line.startswith(prefix) and len(line) > len(prefix) for line in lines) == 1,
            "package graph compile edge missing or ambiguous: " + name,
        )
