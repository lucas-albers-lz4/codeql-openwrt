"""Source-backed, non-exhaustive UCI configuration consumer inventory.

These relationships are not grants, source effects, or evidence that a service
is running. The default backing-file relationships are maintained separately
in the profile assets inventory.
"""
from pathlib import Path

from .oracle import REPO_ROOT, corpus_revision

PROFILE = "luci-ssl-25.12"
ANALYSIS_REVISION = "policy:uci-consumers-v1"
# One directly evidenced consumer for each UCI asset in this bounded slice.
# The URLs identify pinned source reads, not all consumers or runtime states.
CONSUMERS = (
    ("dropbear", "openwrt:dropbear-init", "https://github.com/openwrt/openwrt/blob/4e9642517b48bae612ff10fb72fb9199e559500e/package/network/services/dropbear/files/dropbear.init#L162-L164", "https://github.com/openwrt/openwrt/blob/4e9642517b48bae612ff10fb72fb9199e559500e/package/network/services/dropbear/files/dropbear.init#L390-L397"),
    ("rpcd", "rpcd:session-login", "https://github.com/openwrt/rpcd/blob/d99f703e4035d03fbcfbada3cb697db346c2b984/session.c#L863-L892"),
    ("uhttpd", "openwrt:uhttpd-init", "https://github.com/openwrt/openwrt/blob/4e9642517b48bae612ff10fb72fb9199e559500e/package/network/services/uhttpd/files/uhttpd.init#L299-L301"),
    ("system", "openwrt:system-init", "https://github.com/openwrt/openwrt/blob/4e9642517b48bae612ff10fb72fb9199e559500e/package/base-files/files/etc/init.d/system#L33-L35"),
    ("firewall", "firewall4:fw4", "https://github.com/openwrt/firewall4/blob/b6e5157527d361f99ad52eaa6da273cb0f2dfd59/root/usr/share/ucode/fw4.uc#L730-L751"),
    ("network", "netifd:config", "https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/config.c#L553-L576", "https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/config.c#L789-L812"),
)


def build_artifacts(repo_root: Path = REPO_ROOT) -> list[dict]:
    revision = corpus_revision(repo_root)
    return [
        {
            "record_type": "uci_consumer",
            "evidence_status": "fact",
            "producer": "policy_facts",
            "corpus_revision": revision,
            "profile": PROFILE,
            "analysis_revision": ANALYSIS_REVISION,
            "record_id": f"policy:uci-consumer:{config}:{consumer}",
            "uci_config": config,
            "consumer_id": consumer,
            "asset_id": f"uci:{config}",
            "evidence_refs": list(sources),
        }
        for config, consumer, *sources in CONSUMERS
    ]
