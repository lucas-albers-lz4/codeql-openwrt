"""luci-ssl files[] mapping and routing classification (inventory only).

Rules are the plan §2 order applied to installed paths from luci.mk at
luci pin b2e0be4b. This is not the codeql-ucode extractor seven-case gate.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = REPO_ROOT / "corpus" / "lock.json"
INVENTORY = REPO_ROOT / "reports" / "m4-luci-ssl-files.json"

PROFILE = "luci-ssl-25.12"
ANALYSIS_REVISION = "inventory:luci-ssl-files-v1"
PRODUCER = "corpus"
LUCI_PIN = "b2e0be4b46ec0fd43394c081fa7c50657af14011"

UCODE_LIBRARYDIR = "/usr/share/ucode/luci"
HTDOCS = "/www"
SHEBANG_UCODE = re.compile(r"^#!.*\bucode\b")
MARKUP_CONTENT = re.compile(r"(?m)^\s*\{[%{#]")

# luci-ssl → luci-light + luci-app-package-manager (+ SSL C libs, not luci.mk).
# luci-light → luci-mod-admin-full + luci-app-firewall + luci-theme-bootstrap
# + luci-proto-ppp + luci-proto-ipv6 (CONFIG_IPV6=y) + C/uhttpd packages.
# luci-mod-admin-full → luci-base + luci-mod-status + luci-mod-system
# + luci-mod-network.
LUCI_SSL_LUCI_PACKAGES = (
    "luci-ssl",
    "luci-light",
    "luci-app-package-manager",
    "luci-mod-admin-full",
    "luci-app-firewall",
    "luci-theme-bootstrap",
    "luci-proto-ppp",
    "luci-proto-ipv6",
    "luci-base",
    "luci-mod-status",
    "luci-mod-system",
    "luci-mod-network",
)

C_NOT_ANALYZED = (
    "rpcd-mod-luci",
    "rpcd-mod-rrdns",
    "rpcd-mod-iwinfo",
    "rpcd-mod-file",
    "rpcd-mod-ucode",
    "luci-bwc",
    "luci-base core.so",
)

COMMON_ASSUMPTIONS = [
    "Transcribed from luci pin b2e0be4b luci.mk install rules and file "
    "contents; not a new query run and not a live make install.",
    "The extractor seven-case gate lives in codeql-ucode and is not claimed.",
    "basename is not a sanitizer. shellquote is not a sanitizer unless a "
    "complete-argument barrier is already modeled.",
    "This slice does not rewrite the luci emitter, does not invent luci-ssl "
    "grants, and does not claim path_found.",
    "Dispatcher/menu.d, Alloy, markup extraction, Track A, and setInitAction "
    "are not staffed.",
]
COMMON_UNKNOWNS = [
    "live uhttpd/rpcd not executed",
    "OpenWrt C packages rpcd/uhttpd/cgi-io/firewall4 are not luci.mk copies "
    "and are not file-listed here",
]


def corpus_revision(repo_root: Path = REPO_ROOT) -> str:
    digest = hashlib.sha256((repo_root / "corpus" / "lock.json").read_bytes()).hexdigest()
    return f"sha256:{digest}"


def luci_mk_installed(kind: str, rel: str) -> str:
    """Installed path from luci.mk Package/install copy rules."""
    rel = rel.lstrip("/")
    if kind == "ucode":
        return f"{UCODE_LIBRARYDIR}/{rel}"
    if kind == "htdocs":
        return f"{HTDOCS}/{rel}"
    if kind == "root":
        return f"/{rel}"
    raise ValueError(f"unsupported luci.mk kind {kind}")


DISPATCHER_HINTS = (
    "dispatcher ingress",
    "dispatcher controller",
    "dispatcher support",
    "imports luci.dispatcher",
)


def classify_installed(
    installed: str,
    shebang: Optional[str] = None,
    content_prefix: str = "",
) -> tuple[str, str, int]:
    """Plan §2 route order. Returns (classification, reason, rule)."""
    rel = installed.lstrip("/")
    if rel.startswith("usr/share/rpcd/ucode/"):
        return "plain", "rpcd raw_mode plugin", 1
    if installed.endswith(".ut"):
        return "markup", ".ut", 2
    if shebang and SHEBANG_UCODE.search(shebang):
        return "plain", "shebang ucode", 3
    if content_prefix and MARKUP_CONTENT.search(content_prefix):
        return "markup", "tagged markup content", 4
    if installed.endswith(".uc") or installed.endswith(".ucode"):
        return "plain", ".uc/.ucode", 5
    if rel.startswith("usr/share/ucode/"):
        return "uncertain", "remaining usr/share/ucode", 6
    raise ValueError(f"no routing rule matched {installed}")


# Transcribed evidence at luci@b2e0be4b. classification is derived.
ROUTING_EVIDENCE: tuple[dict[str, Any], ...] = (
    {
        "package": "luci-base",
        "source": "modules/luci-base/root/usr/share/rpcd/ucode/luci",
        "kind": "root",
        "rel": "usr/share/rpcd/ucode/luci",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "extracted basename luci (M1/M3); remaining methods inventoried separately",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/sys.uc",
        "kind": "ucode",
        "rel": "sys.uc",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "extracted basename sys.uc for luci.sys helpers",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/dispatcher.uc",
        "kind": "ucode",
        "rel": "dispatcher.uc",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "plain .uc; dispatcher ingress not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/http.uc",
        "kind": "ucode",
        "rel": "http.uc",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "plain .uc; dispatcher support not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/runtime.uc",
        "kind": "ucode",
        "rel": "runtime.uc",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "plain .uc; dispatcher support not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/zoneinfo.uc",
        "kind": "ucode",
        "rel": "zoneinfo.uc",
        "shebang": None,
        "content_prefix": "// Autogenerated by zoneinfo2ucode.pl",
        "symlink_target": None,
        "analysis": "plain .uc; not extracted in this slice",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/controller/admin/index.uc",
        "kind": "ucode",
        "rel": "controller/admin/index.uc",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "plain .uc; dispatcher controller not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/controller/admin/uci.uc",
        "kind": "ucode",
        "rel": "controller/admin/uci.uc",
        "shebang": None,
        "content_prefix": "// Copyright 2022 Jo-Philipp Wich",
        "symlink_target": None,
        "analysis": "plain .uc; dispatcher controller not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/uhttpd.uc",
        "kind": "ucode",
        "rel": "uhttpd.uc",
        "shebang": None,
        "content_prefix": "{%",
        "symlink_target": None,
        "analysis": "markup_not_modeled; luci-base postinst ucode_prefix /cgi-bin/luci=/usr/share/ucode/luci/uhttpd.uc; dispatcher ingress not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/csrftoken.ut",
        "kind": "ucode",
        "rel": "template/csrftoken.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/error404.ut",
        "kind": "ucode",
        "rel": "template/error404.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/error500.ut",
        "kind": "ucode",
        "rel": "template/error500.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/footer.ut",
        "kind": "ucode",
        "rel": "template/footer.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/header.ut",
        "kind": "ucode",
        "rel": "template/header.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/sysauth.ut",
        "kind": "ucode",
        "rel": "template/sysauth.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/ucode/template/view.ut",
        "kind": "ucode",
        "rel": "template/view.ut",
        "shebang": None,
        "content_prefix": "{% include('header') %}",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/htdocs/cgi-bin/luci",
        "kind": "htdocs",
        "rel": "cgi-bin/luci",
        "shebang": "#!/usr/bin/env ucode",
        "content_prefix": "#!/usr/bin/env ucode",
        "symlink_target": None,
        "analysis": "plain shebang CGI at /www/cgi-bin/luci; imports luci.dispatcher; dispatcher ingress not staffed",
    },
    {
        "package": "luci-base",
        "source": "modules/luci-base/src/Makefile",
        "kind": "src-install",
        "rel": "version.uc",
        "installed": f"{UCODE_LIBRARYDIR}/version.uc",
        "shebang": None,
        "content_prefix": "export const revision = '",
        "symlink_target": None,
        "analysis": "generated by luci-base src install (not a git blob); plain .uc; not extracted",
    },
    {
        "package": "luci-mod-status",
        "source": "modules/luci-mod-status/ucode/template/admin_status/index.ut",
        "kind": "ucode",
        "rel": "template/admin_status/index.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-theme-bootstrap",
        "source": "themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/header.ut",
        "kind": "ucode",
        "rel": "template/themes/bootstrap/header.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-theme-bootstrap",
        "source": "themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/footer.ut",
        "kind": "ucode",
        "rel": "template/themes/bootstrap/footer.ut",
        "shebang": None,
        "content_prefix": "{% if (!blank_page): %}",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-theme-bootstrap",
        "source": "themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/sysauth.ut",
        "kind": "ucode",
        "rel": "template/themes/bootstrap/sysauth.ut",
        "shebang": None,
        "content_prefix": "{#",
        "symlink_target": None,
        "analysis": "markup_not_modeled",
    },
    {
        "package": "luci-theme-bootstrap",
        "source": "themes/luci-theme-bootstrap/ucode/template/themes/bootstrap-dark",
        "kind": "ucode",
        "rel": "template/themes/bootstrap-dark",
        "shebang": None,
        "content_prefix": "",
        "symlink_target": "bootstrap",
        "analysis": "extensionless symlink to bootstrap/ .ut directory; remaining usr/share/ucode",
    },
    {
        "package": "luci-theme-bootstrap",
        "source": "themes/luci-theme-bootstrap/ucode/template/themes/bootstrap-light",
        "kind": "ucode",
        "rel": "template/themes/bootstrap-light",
        "shebang": None,
        "content_prefix": "",
        "symlink_target": "bootstrap",
        "analysis": "extensionless symlink to bootstrap/ .ut directory; remaining usr/share/ucode",
    },
)

SHELL_HELPERS: tuple[dict[str, Any], ...] = (
    {
        "package": "luci-mod-status",
        "source": "modules/luci-mod-status/root/usr/libexec/syslog-wrapper",
        "kind": "root",
        "rel": "usr/libexec/syslog-wrapper",
        "shebang": "#!/bin/sh",
        "acl_group": "luci-mod-status-logs",
        "target_id": "command:syslog-wrapper",
    },
    {
        "package": "luci-mod-network",
        "source": "modules/luci-mod-network/root/usr/libexec/luci-peeraddr",
        "kind": "root",
        "rel": "usr/libexec/luci-peeraddr",
        "shebang": "#!/bin/sh",
        "acl_group": "luci-mod-network-config",
        "target_id": "command:luci-peeraddr",
    },
    {
        "package": "luci-app-package-manager",
        "source": "applications/luci-app-package-manager/root/usr/libexec/package-manager-call",
        "kind": "root",
        "rel": "usr/libexec/package-manager-call",
        "shebang": "#!/bin/sh",
        "acl_group": "luci-app-package-manager",
        "target_id": "command:package-manager-call",
    },
)

PLAN_SEVEN_CASES = {
    "shebang-less-extensionless-plugin": {
        "present": True,
        "fs_path": "/usr/share/rpcd/ucode/luci",
        "note": "luci-base rpcd plugin; rule 1 plain",
    },
    "dot-uc-rpcd-plugin": {
        "present": False,
        "fs_path": None,
        "note": "luci-ssl has no .uc file under /usr/share/rpcd/ucode; sys.uc and version.uc are libraries",
    },
    "shebang-libexec-ucode": {
        "present": False,
        "fs_path": None,
        "note": "luci-ssl /usr/libexec helpers are #!/bin/sh; shebang ucode is /www/cgi-bin/luci",
    },
    "ordinary-ut": {
        "present": True,
        "fs_path": "/usr/share/ucode/luci/template/header.ut",
        "note": "rule 2 markup",
    },
    "tagged-uc": {
        "present": True,
        "fs_path": "/usr/share/ucode/luci/uhttpd.uc",
        "note": "content {% matches rule 4 before .uc fallback",
    },
    "ut-under-rpcd": {
        "present": False,
        "fs_path": None,
        "note": "no .ut under usr/share/rpcd/ucode in luci-ssl",
    },
    "extensionless-usr-share-ucode": {
        "present": True,
        "fs_path": "/usr/share/ucode/luci/template/themes/bootstrap-dark",
        "note": "theme symlink; rule 6 uncertain",
    },
}


def _routing_record(evidence: dict[str, Any], revision: str) -> dict[str, Any]:
    if evidence["kind"] == "src-install":
        installed = evidence["installed"]
        luci_mk = "src Package/install (core.so + generated version.uc)"
    else:
        installed = luci_mk_installed(evidence["kind"], evidence["rel"])
        luci_mk = f"luci.mk {evidence['kind']}/ -> installed"
    classification, reason, rule = classify_installed(
        installed,
        shebang=evidence.get("shebang"),
        content_prefix=evidence.get("content_prefix") or "",
    )
    status = "fact" if classification == "plain" else "inconclusive"
    row: dict[str, Any] = {
        "record_type": "routing",
        "evidence_status": status,
        "producer": PRODUCER,
        "record_id": f"m4:routing:luci-ssl:{installed}",
        "corpus_revision": revision,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "fs_path": installed,
        "classification": classification,
        "package": evidence["package"],
        "source": evidence["source"],
        "luci_mk_rule": luci_mk,
        "rule": rule,
        "reason": reason,
        "shebang": evidence.get("shebang"),
        "content_prefix": evidence.get("content_prefix") or "",
        "conditions": [
            f"luci@{LUCI_PIN} {evidence['source']}",
            f"installed {installed} via {luci_mk}",
            f"plan section 2 rule {rule}: {reason}",
            evidence["analysis"],
        ],
        "assumptions": list(COMMON_ASSUMPTIONS),
        "evidence_refs": [
            f"luci@{LUCI_PIN} {evidence['source']}",
            f"luci@{LUCI_PIN} luci.mk Package/install",
        ],
        "unknowns": list(COMMON_UNKNOWNS),
    }
    if evidence.get("symlink_target"):
        row["symlink_target"] = evidence["symlink_target"]
        row["conditions"].append(f"git symlink -> {evidence['symlink_target']}")
    if classification == "markup":
        row["assumptions"].append(
            "Markup classification is markup_not_modeled; no second grammar."
        )
    if classification == "uncertain":
        row["assumptions"].append(
            "Unresolved remaining usr/share/ucode path is uncertain, not extracted."
        )
    if any(hint in evidence["analysis"] for hint in DISPATCHER_HINTS):
        row["assumptions"].append(
            "Dispatcher ingress and menu.d are not staffed; this is routing only."
        )
    return row


def _helper_record(evidence: dict[str, Any], revision: str) -> dict[str, Any]:
    installed = luci_mk_installed(evidence["kind"], evidence["rel"])
    return {
        "record_type": "exec_helper_inventory",
        "evidence_status": "inconclusive",
        "producer": PRODUCER,
        "record_id": f"m4:exec-helper:luci-ssl:{installed}",
        "corpus_revision": revision,
        "profile": PROFILE,
        "analysis_revision": ANALYSIS_REVISION,
        "fs_path": installed,
        "package": evidence["package"],
        "source": evidence["source"],
        "luci_mk_rule": "luci.mk root/ -> /",
        "shebang": evidence["shebang"],
        "op": "exec",
        "sink_kind": "file_exec",
        "target_id": evidence["target_id"],
        "acl_group": evidence["acl_group"],
        "conditions": [
            f"luci@{LUCI_PIN} {evidence['source']}",
            f"installed {installed} via luci.mk root/",
            f"shebang {evidence['shebang']}",
            "Not a luci object method; file.exec is C rpcd, not granted here",
        ],
        "assumptions": COMMON_ASSUMPTIONS
        + [
            "shell_not_analyzed. This is not a ucode shebang and not plan §2 rule 3.",
            "Do not invent a luci-ssl ubus grant for this helper.",
        ],
        "evidence_refs": [
            f"luci@{LUCI_PIN} {evidence['source']}",
            f"luci@{LUCI_PIN} luci.mk Package/install root/",
        ],
        "unknowns": COMMON_UNKNOWNS
        + [
            "file.exec matching of the helper argv is C and is not this slice",
        ],
    }


def build_records(repo_root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    revision = corpus_revision(repo_root)
    rows = [_routing_record(item, revision) for item in ROUTING_EVIDENCE]
    rows.extend(_helper_record(item, revision) for item in SHELL_HELPERS)
    return rows


def dump_inventory(repo_root: Path = REPO_ROOT) -> Path:
    path = repo_root / "reports" / "m4-luci-ssl-files.json"
    path.write_text(json.dumps(build_records(repo_root), indent=2) + "\n", encoding="utf-8")
    return path
