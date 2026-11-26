#!/usr/bin/env python3
"""Cross-check scoped inventory and retained app receipt; no extraction."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent
PINS = {
    HERE / 'scope.json': '64ccfbc70d21e59580a3022971e9782afbfaca03257f6e8d4542007bc75b4543',
    HERE / 'adblock-fast-api.json': '6e1a9ccb00b528da74265311b23c4c7190f2650cf4480c52a5fa94648fd105ed',
    EVIDENCE / 'issue172-luci-source-inventory-20261125/inventory.json': '91fcf7f84e2934a1df21c7438f898fb5cd097eb9f6cfde3bc80239369c0d7cbc',
    EVIDENCE / 'issue175-adblock-ipk-20261126/provenance/app-comparison.json': 'b00b66f746faf84ed761d142d9d54213eade3f5b78f24f564439e070acf9d658',
    EVIDENCE / 'issue175-adblock-ipk-20261126/stage/usr/share/rpcd/ucode/luci.adblock-fast': '3cb9d07b33a0aec36743326a5cb1e18885d245a132ef92174eb4c8b70aaebdd8',
    EVIDENCE / 'issue175-adblock-ipk-20261126/package-context/luci-app-adblock-fast-acl.json': 'af249e0610e568be8e7bac542c0ce9f402e1a95cd34d3c5eb9a9724aff46502d',
}

def need(value, message):
    if not value:
        raise ValueError(message)

def check_scope(scope, inventory, receipt):
    names = ['luci-app-firewall', 'luci-app-acl', 'luci-app-openvpn', 'luci-app-opkg', 'luci-app-package-manager', 'luci-app-adblock-fast']
    need(scope['lead_packages'] == names, 'lead package list differs')
    candidates = [r for r in inventory['candidates'] if r['package_owner'] in names]
    need(scope['source_candidates'] == candidates, 'source candidate disposition differs')
    need(len(candidates) == 5 and sum(r['disposition'] == 'selected source candidate' for r in candidates) == 1, 'source candidate count differs')
    need(scope['app_control'] == receipt['control'] == {'Package':'luci-app-adblock-fast','Version':'1.2.4-r4','Architecture':'all'}, 'package control differs')
    need(scope['app_ipk_sha256'] == receipt['ipk_sha256'] == 'b3d18c736a970f0ba17919e1249c837dae393b04f5ec541950a6cce737110e0f', 'package digest differs')
    mapping = {r['path']: r for r in receipt['source_mappings']}
    need(len(mapping) == len(receipt['source_mappings']) == 9, 'source mapping count differs')
    expected = []
    for row in receipt['data_members']:
        if row['type'] == 'file':
            r = mapping[row['path']]
            need(row['mode'] == r['ipk_mode'] and row['sha256'] == r['ipk_sha256'], 'IPK member mapping differs')
            expected.append({'path':row['path'], 'mode':row['mode'], 'sha256':row['sha256'], 'classification':r['disposition'], 'transform_provenance':r['transform_provenance'], 'source_sha256':r['source_sha256']})
    need(len(expected) == 9 and scope['app_regular_members'] == expected, 'package member inventory differs')
    need(sum(r['classification'] == 'selected_ucode_rpcd' for r in expected) == 1, 'selected provider count differs')
    need(sum(r['classification'].startswith('excluded_shell') for r in expected) == 2, 'shell control count differs')
    api = next(r for r in expected if r['path'] == 'usr/share/rpcd/acl.d/adblock-fast-api.json')
    need(api['source_sha256'] == api['sha256'] == PINS[HERE / 'adblock-fast-api.json'], 'alternate ACL package mapping differs')

def check_acl(acl):
    entry = acl['luci-app-adblock-fast']
    need('setInitAction' in entry['write']['ubus']['luci.adblock-fast'], 'declared ubus write grant differs')
    need('adblock-fast' in entry['write']['uci'], 'declared UCI write grant differs')

def check_api_acl(acl):
    entry = acl['adblock-fast-api']
    need('setInitAction' in entry['write']['ubus']['luci.adblock-fast'], 'alternate ubus write grant differs')
    need('getInitStatus' in entry['read']['ubus']['luci.adblock-fast'], 'alternate ubus read grant differs')
    need('uci' not in entry['write'], 'unexpected alternate UCI grant')

def main():
    for path, digest in PINS.items():
        need(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'evidence hash differs: ' + str(path))
    load = lambda path: json.loads(path.read_text())
    scope = load(HERE / 'scope.json')
    inventory = load(EVIDENCE / 'issue172-luci-source-inventory-20261125/inventory.json')
    receipt = load(EVIDENCE / 'issue175-adblock-ipk-20261126/provenance/app-comparison.json')
    check_scope(scope, inventory, receipt)
    check_acl(load(EVIDENCE / 'issue175-adblock-ipk-20261126/package-context/luci-app-adblock-fast-acl.json'))
    check_api_acl(load(HERE / 'adblock-fast-api.json'))
    print('source leads, nine app members and ACL declarations agree')

if __name__ == '__main__':
    main()
