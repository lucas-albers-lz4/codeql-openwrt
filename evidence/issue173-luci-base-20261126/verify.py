#!/usr/bin/env python3
"""Verify retained luci-base source and package evidence without building."""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat

ROOT = Path(__file__).resolve().parent
archive = None

ANCHORS = {
    'source-first-oracle.json':'5fe8593458900f5eca20e20de5e68e1d7cba079fd985e93ec53bff5551b5f999',
    'archive.py':'224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100',
    'raw-manifest.json':'2485edd84c2e9437cb8a16b620b061204118d88cc04df2ee2afbca7b92639ac1',
    'source/LICENSE':'43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1',
    'source/NOTICE':'0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2',
    'source/luci.mk':'9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d',
    'source/modules/luci-base/Makefile':'4a933ee77787783219bdeae45b03d89a6c3b5f1512e8ad8bc68d19f4b250c9bc',
    'source/modules/luci-base/src/Makefile':'f49e4d9472eef6052b6e3565f4e029fd3131d1a7721a016c995e402e363f169c',
}
IPK = '41376c6774b35ff140ff3fa441643a184be252070cd3f462f645c6a98e527d6b'
RECEIPT = '1c80809ed7c87a2a586d0df7bdebcfc35eaecf6370013b27f994a46d0324b677'
CONFIG = 'e0dc30db2219dfbf503042a7403419f181a6ed38a922e95fb9097bddffecb9ff'

def need(condition, message):
    if not condition: raise ValueError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def blob(data): return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
def obj(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('invalid JSON constant')))
    need(isinstance(value, dict), 'JSON object required')
    return value

def file_bytes(root, name):
    path = PurePosixPath(name)
    need(name and not path.is_absolute() and str(path) == name and '..' not in path.parts and '\\' not in name, 'unsafe packet path')
    current = root
    for part in path.parts:
        current = current / part
        need(not current.is_symlink(), 'packet path symlink')
    info = current.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'packet file missing or aliased')
    return current.read_bytes()

def inventory(root):
    need(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir() and not root.is_symlink(), 'packet root unsafe')
    expected = {}
    for line in file_bytes(root, 'SHA256SUMS').decode().splitlines():
        digest, sep, name = line.partition('  ')
        p = PurePosixPath(name)
        need(sep and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest) and name and not p.is_absolute() and str(p) == name and '..' not in p.parts and name not in expected, 'invalid checksum entry')
        expected[name] = digest
    actual = set()
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'packet symlink')
        if path.is_file():
            need(path.stat().st_nlink == 1, 'packet hardlink alias')
            if path != root / 'SHA256SUMS': actual.add(path.relative_to(root).as_posix())
        else: need(path.is_dir(), 'special packet entry')
    need(actual == set(expected), 'packet inventory differs')
    for name, value in expected.items(): need(sha(file_bytes(root, name)) == value, 'packet digest differs: ' + name)
    for name, value in ANCHORS.items(): need(expected.get(name) == value, 'fixed anchor differs: ' + name)

def load_archive(root):
    global archive
    need(sha(file_bytes(root, 'archive.py')) == ANCHORS['archive.py'], 'archive parser digest differs')
    if archive is None:
        spec = importlib.util.spec_from_file_location('retained_base_archive', root / 'archive.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        archive = module
    return archive

def control_fields(rows):
    need('control' in rows and rows['control']['type'] == 'file', 'control missing')
    fields = {}
    for line in rows['control']['bytes'].decode().splitlines():
        if line.startswith((' ', '\t')) or ':' not in line: continue
        key, value = line.split(':', 1)
        need(key not in fields, 'duplicate control field')
        fields[key] = value.strip()
    return {name:fields.get(name) for name in ('Package','Version','Architecture')}

def verify_package(root, oracle, receipt, ipk):
    load_archive(root)
    need(sha(ipk) == receipt['ipk']['sha256'] == IPK and receipt['status'] == 'PASS' and receipt['oracle_sha256'] == ANCHORS['source-first-oracle.json'], 'IPK or receipt identity differs')
    control, members, outer = archive.read_ipk(ipk)
    need(control_fields(control) == receipt['ipk']['control'] == {'Package':'luci-base','Version':'26.317.52279~1c75ea4','Architecture':'x86_64'}, 'package control differs')
    need(archive.receipts(control) == receipt['archive_control_members'] and archive.receipts(members) == receipt['archive_data_members'] and outer['control.tar.gz'] == receipt['ipk']['control_archive_sha256'], 'archive inventory differs')
    need(len(members) == 108 and sum(v['type'] == 'file' for v in members.values()) == 76, 'archive member count differs')
    source_rows = oracle['selected_source_candidates'] + oracle['unknown_extensionless_candidates']
    need(len(source_rows) == 20 and len({r['source_path'] for r in source_rows}) == 20, 'oracle source identities differ')
    expected_source = {r['source_path'] for r in source_rows} | {'LICENSE','NOTICE','luci.mk','modules/luci-base/Makefile','modules/luci-base/src/Makefile'}
    actual_source = {p.relative_to(root/'source').as_posix() for p in (root/'source').rglob('*') if p.is_file()}
    need(actual_source == expected_source, 'source file set differs')
    records = receipt['files']
    need(len(records) == 21 and len({r['installed_path'] for r in records}) == 21, 'receipt candidate count differs')
    bypath = {r['installed_path']:r for r in records}
    for source in source_rows:
        source_path, path = source['source_path'], source['expected_package_member_path']
        data = file_bytes(root, 'source/' + source_path)
        if path == 'etc/init.d/ucitrack': need(data.startswith(b'#!/bin/sh /etc/rc.common\n'), 'shell control shebang differs')
        need(sha(data) == source['sha256'] and blob(data) == source['git_blob'] and len(data) == source['bytes'], 'source identity differs: ' + source_path)
        need(stat.S_IMODE((root / 'source' / source_path).stat().st_mode) == int(source['git_mode'][-3:],8), 'source mode differs: ' + source_path)
        entry, record = members.get(path), bypath.get(path)
        need(entry is not None and entry['type'] == 'file' and record is not None, 'candidate member absent: ' + path)
        need(entry['mode'] == source['expected_member_mode_bits'] and record['mode'] == format(entry['mode'], '04o'), 'candidate mode differs: ' + path)
        need(record['source'] == source_path and record['source_sha256'] == record['prepared_sha256'] == sha(data), 'source/prepared receipt differs: ' + path)
        expected = data.replace(b'{# PKG_VERSION #}', b'26.317.52279~1c75ea4') if path.endswith('/template/header.ut') else data
        need(entry['bytes'] == expected and record['staged_sha256'] == record['ipk_sha256'] == sha(expected), 'stage/IPK bytes differ: ' + path)
        expected_status = 'selected present' if source['disposition'] == 'selected source candidate' else ('excluded shell control' if path == 'etc/init.d/ucitrack' else 'unknown present')
        need(record['status'] == expected_status, 'candidate status differs: ' + path)
    generated = oracle['generated_expected_members'][0]
    entry, record = members[generated['path']], bypath[generated['path']]
    body = generated['expected_bytes_utf8'].encode()
    need(entry['bytes'] == body and entry['mode'] == generated['expected_mode_bits_under_umask_022'] and sha(body) == generated['expected_source_derived_sha256'], 'generated version member differs')
    need(record['status'] == 'generated' and record['mode'] == '0644' and record['prepared_sha256'] == record['staged_sha256'] == record['ipk_sha256'] == sha(body), 'generated version receipt differs')
    return Counter(r['status'] for r in records)

def verify(root):
    inventory(root)
    raw = obj(file_bytes(root, 'raw-manifest.json'))
    need(raw['source_artifact_sha256'] == '8d8baeacb21e3699535969c1c2009d15d84ca5d8103c3fc7e94312db923d9236' and raw['original_run_log_sha256'] == 'ecf4b2695b99a72b60964e3bfd9644e30d75687253cf7a6d9d0559450b1ac84e', 'original artifact identity differs')
    need({p.name for p in (root/'raw').iterdir() if p.is_file()} == set(raw['files']), 'raw file set differs')
    for name, value in raw['files'].items(): need(sha(file_bytes(root, 'raw/' + name)) == value, 'raw evidence differs: ' + name)
    oracle = obj(file_bytes(root, 'source-first-oracle.json'))
    receipt_data = file_bytes(root, 'raw/byte-comparison.json')
    config = file_bytes(root, 'raw/config-final')
    need(sha(receipt_data) == RECEIPT and sha(config) == CONFIG, 'receipt or config digest differs')
    lines = config.decode().splitlines()
    for symbol in ('CONFIG_TARGET_x86=y','CONFIG_TARGET_x86_64=y','CONFIG_PACKAGE_luci-base=m','CONFIG_PER_FEED_REPO=y','# CONFIG_USE_APK is not set'):
        need(lines.count(symbol) == 1, 'config symbol differs: ' + symbol)
    receipt = obj(receipt_data)
    pins = {'luci':('cb87fe60e1e2e052af36a93647f2264577829e0a','1d7bf89bc8708fca69d005b0690ca823c9071692'), 'openwrt':('4e9642517b48bae612ff10fb72fb9199e559500e','328d4df01c038d365176b72753b778e10c3ff413'), 'packages':('07e0d16305d2b5903b37ad7913e33e18795f81a4','a6b0fc0935cbfeedb810e6e991b6940f71548ea7')}
    for name, (commit, tree) in pins.items(): need(receipt['pins'][name] == {'sha':commit, 'tree':tree, 'dirty':False}, 'source pin differs: ' + name)
    need(receipt['build_inputs']['config']['sha256'] == CONFIG and receipt['build_inputs']['per_feed_repo'] == 'CONFIG_PER_FEED_REPO=y', 'build config receipt differs')
    statuses = verify_package(root, oracle, receipt, file_bytes(root, 'raw/luci-base.ipk'))
    need(statuses == Counter({'selected present':17,'unknown present':2,'excluded shell control':1,'generated':1}), 'candidate disposition totals differ')
    lines = file_bytes(root, 'raw/diagnostic-lines.txt').splitlines()
    need(sum(b'warning:' in line.lower() for line in lines) == 2069 and sum(b':error: recursive dependency detected!' in line for line in lines) == 6 and sum(b'(ignored)' in line for line in lines) == 8, 'diagnostic counts differ')
    for path in (root/'raw').glob('*.time'): need(b'Exit status: 0' in file_bytes(root, 'raw/' + path.name), 'phase failure: ' + path.name)
    return {'status':'retained_evidence_consistent','data_regular_members':76,'candidate_rows':21,'prepared_stage':'runner receipt only'}

if __name__ == '__main__':
    print(json.dumps(verify(ROOT), sort_keys=True))
