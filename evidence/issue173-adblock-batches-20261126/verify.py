#!/usr/bin/env python3
"""Verify retained adblock app and service package evidence without building."""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat

ROOT = Path(__file__).resolve().parent
archive = None

ANCHORS = {
    'app-oracle.json':'ea71145e8da15d306d601227c4b74a710b44516823a0192ebed509d1d7e72e2d',
    'service-oracle.json':'ddbe34ee43f78824045ad60e1a114fd313b380ac7eaddb238407105603cd0758',
    'archive.py':'224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100',
    'raw-manifest.json':'89469700f95ad801a3bcba0d4448217c3bd4a36c369e055b7d3508f965e92238',
    'source/luci/LICENSE':'43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1',
    'source/luci/NOTICE':'0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2',
    'source/luci/luci.mk':'9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d',
    'source/luci/applications/luci-app-adblock-fast/Makefile':'7de3922a10944c8fa2f4a97b3f1d7d85db3aeb2f3404147f0df15430e26f0990',
    'source/packages/net/adblock-fast/Makefile':'2fb9177f3f92056fff594af91a590db4ec3aa08f3a38b82ce90cdbec9511f20b',
    'source/LICENSE-AGPL-3.0.txt':'0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0',
}
IPKS = {'app':'b3d18c736a970f0ba17919e1249c837dae393b04f5ec541950a6cce737110e0f',
        'service':'b7fd7dee577d32a2485fb65bf6205629f07e415c488ddc4b999c3825d2719dd7'}
CONFIG = '8946db83b06e591ffd3ea9bf48e47595a40bdfb56fa8a1a45cfe8099cb3324d6'

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


def verify_package(root, kind, oracle, receipt, ipk):
    load_archive(root)
    need(sha(ipk) == receipt['ipk_sha256'] == IPKS[kind] and receipt['package'] == kind, 'package digest or identity differs')
    expected_name = 'luci-app-adblock-fast' if kind == 'app' else 'adblock-fast'
    control, members, outer = archive.read_ipk(ipk)
    need(control_fields(control) == receipt['control'] == {'Package':expected_name,'Version':'1.2.4-r4','Architecture':'all'}, 'package control differs')
    need(archive.receipts(control) == receipt['control_members'] and archive.receipts(members) == receipt['data_members'] and outer == receipt['outer_sha256'], 'archive inventory differs')
    rows = oracle['projected_files'] if kind == 'app' else oracle['source_mapping']
    expected = {r['projected_member_path' if kind == 'app' else 'projected_member']:r for r in rows}
    files = {path for path, value in members.items() if value['type'] == 'file'}
    need(len(expected) == (9 if kind == 'app' else 5) and files == set(expected), 'package regular-member set differs')
    mapping = receipt['source_mappings']
    need(len(mapping) == len(expected) and len({r['path'] for r in mapping}) == len(mapping), 'source mapping count differs')
    for record in mapping:
        path = record['path']; source = expected.get(path)
        need(source is not None, 'unexpected source mapping')
        source_path = source['source_path']; source_root = 'luci' if kind == 'app' else 'packages'
        data = file_bytes(root, 'source/' + source_root + '/' + source_path)
        shell_controls = {
            'etc/uci-defaults/40_luci-adblock-fast': b'#!/bin/sh\n',
            'etc/uci-defaults/95_adblock-fast-api': b'#!/bin/sh\n',
            'etc/init.d/adblock-fast': b'#!/bin/sh /etc/rc.common\n',
            'etc/uci-defaults/90-adblock-fast': b'#!/bin/sh\n',
        }
        if path in shell_controls: need(data.startswith(shell_controls[path]), 'shell control shebang differs: ' + path)
        need(sha(data) == source['source_sha256'] and blob(data) == source['git_blob'] and len(data) == source['source_bytes' if kind == 'app' else 'source_size'], 'source identity differs: ' + source_path)
        need(stat.S_IMODE((root/'source'/source_root/source_path).stat().st_mode) == int(source['git_mode'][-3:],8), 'source mode differs')
        item = members[path]; mode = format(item['mode'], '04o')
        wanted_mode = format(source['projected_mode_bits'], '04o') if kind == 'app' else source['expected_member_mode']
        need(mode == wanted_mode == record['staged_mode'] == record['ipk_mode'] and sha(item['bytes']) == record['staged_sha256'] == record['ipk_sha256'], 'stage/IPK receipt differs: ' + path)
        need(record['source_sha256'] == sha(data) and record['source_git_mode'] == source['git_mode'], 'source receipt differs: ' + path)
        if kind == 'app':
            need(record['prepared_sha256'] == sha(data) and record['prepared_mode'] == '0' + source['git_mode'][-3:], 'prepared receipt differs')
            need(record['disposition'] == source['disposition'], 'source disposition differs')
            if source['disposition'] == 'auxiliary_htdocs_js':
                need(record['transform_provenance'] == 'minification_unverified' and item['bytes'] != data, 'JS transformation boundary differs')
            else:
                need(record['transform_provenance'] == 'source_equal' and item['bytes'] == data, 'direct app copy differs')
        else:
            need(record['prepared_sha256'] is None and record['prepared_mode'] is None and record['disposition'] == source['recipe_action'], 'service preparation or action differs')
            if source['recipe_action'] == 'version_sed':
                import re
                projected, count = re.subn(rb'(?m)^(\tversion:).*$', rb"\1 '1.2.4-r4',", data)
                need(count == 1, 'service version source token differs')
            else: projected = data
            need(item['bytes'] == projected and sha(projected) == source['expected_member_sha256'], 'service recipe projection differs: ' + path)
    return len(files)

def verify(root):
    inventory(root)
    raw = obj(file_bytes(root, 'raw-manifest.json'))
    need(raw['source_artifact_sha256'] == '49367dcc1058f0ce1fec71079f64cbf42c4307de3c687c73da0e3f4c8c750807' and raw['original_run_log_sha256'] == 'b3fbec069da42b86a3ad882c00e4937ff8cf079336367259f96c1530fce51ab4', 'original artifact identity differs')
    need({p.name for p in (root/'raw').iterdir() if p.is_file()} == set(raw['files']), 'raw file set differs')
    for name, value in raw['files'].items(): need(sha(file_bytes(root,'raw/'+name)) == value, 'raw evidence differs: '+name)
    app = obj(file_bytes(root,'app-oracle.json')); service = obj(file_bytes(root,'service-oracle.json'))
    app_data = file_bytes(root,'raw/app.json'); before = file_bytes(root,'raw/service-before.json'); after = file_bytes(root,'raw/service-after.json')
    need(sha(app_data) == 'b00b66f746faf84ed761d142d9d54213eade3f5b78f24f564439e070acf9d658' and sha(before) == '88d5a6f807ebf3f393af9a0733beaffce8cfde45417670af79941f41e15d036f' and before == after, 'receipt identity or service recheck differs')
    receipts = {'app':obj(app_data),'service':obj(before)}
    need(sha(file_bytes(root,'raw/config-final')) == CONFIG, 'config digest differs')
    config = file_bytes(root,'raw/config-final').decode().splitlines()
    for line in ('CONFIG_TARGET_x86=y','CONFIG_TARGET_x86_64=y','CONFIG_PACKAGE_luci-app-adblock-fast=m','CONFIG_PACKAGE_adblock-fast=m','CONFIG_PER_FEED_REPO=y','CONFIG_LUCI_JSMIN=y','# CONFIG_USE_APK is not set'):
        need(config.count(line) == 1, 'config symbol differs: '+line)
    pins = {'luci':'cb87fe60e1e2e052af36a93647f2264577829e0a','openwrt':'4e9642517b48bae612ff10fb72fb9199e559500e','packages':'07e0d16305d2b5903b37ad7913e33e18795f81a4'}
    for kind, receipt in receipts.items():
        need(receipt['source_pins'] == pins and receipt['config']['config']['sha256'] == CONFIG and receipt['config']['per_feed_repo'] == 'CONFIG_PER_FEED_REPO=y' and receipt['config']['js_minification'] is True, 'source or config receipt differs')
    need(receipts['app']['oracle_sha256'] == ANCHORS['app-oracle.json'] and receipts['service']['oracle_sha256'] == ANCHORS['service-oracle.json'], 'oracle receipt differs')
    app_count = verify_package(root,'app',app,receipts['app'],file_bytes(root,'raw/luci-app-adblock-fast.ipk'))
    service_count = verify_package(root,'service',service,receipts['service'],file_bytes(root,'raw/adblock-fast.ipk'))
    expected_sources = {'LICENSE-AGPL-3.0.txt','luci/LICENSE','luci/NOTICE','luci/luci.mk','luci/applications/luci-app-adblock-fast/Makefile','packages/net/adblock-fast/Makefile'}
    expected_sources.update('luci/'+r['source_path'] for r in app['projected_files'])
    expected_sources.update('packages/'+r['source_path'] for r in service['source_mapping'])
    actual_sources = {p.relative_to(root/'source').as_posix() for p in (root/'source').rglob('*') if p.is_file()}
    need(actual_sources == expected_sources, 'source file set differs')
    need(file_bytes(root,'raw/service-ipks.nul') == file_bytes(root,'raw/service-ipks-after.nul') and file_bytes(root,'raw/service-stages.nul') == file_bytes(root,'raw/service-stages-after.nul'), 'service path inventory changed')
    paths = {
        'app-ipks.nul': b'bin/packages/x86_64/luci/luci-app-adblock-fast_1.2.4-r4_all.ipk\0',
        'app-prepared.nul': b'build_dir/target-x86_64_musl/luci-app-adblock-fast/root/usr/share/rpcd/ucode/luci.adblock-fast\0',
        'app-stages.nul': b'build_dir/target-x86_64_musl/luci-app-adblock-fast/ipkg-all/luci-app-adblock-fast/usr/share/rpcd/ucode/luci.adblock-fast\0',
        'service-ipks.nul': b'/home/runner/work/_temp/issue173-adblock-batches/openwrt/bin/packages/x86_64/packages/adblock-fast_1.2.4-r4_all.ipk\0',
        'service-stages.nul': b'/home/runner/work/_temp/issue173-adblock-batches/openwrt/build_dir/target-x86_64_musl/adblock-fast-1.2.4/ipkg-all/adblock-fast/lib/adblock-fast/adblock-fast.uc\0',
    }
    for name, expected in paths.items(): need(file_bytes(root,'raw/'+name) == expected, 'package path inventory differs: '+name)
    lines = file_bytes(root,'raw/diagnostic-lines.txt').splitlines()
    need(sum(b'warning:' in line.lower() for line in lines) == 2098 and sum(b':error: recursive dependency detected!' in line for line in lines) == 6 and sum(b'(ignored)' in line for line in lines) == 8, 'diagnostic counts differ')
    for path in (root/'raw').glob('*.time'): need(b'Exit status: 0' in file_bytes(root,'raw/'+path.name), 'phase failure: '+path.name)
    return {'status':'retained_evidence_consistent','app_regular_members':app_count,'service_regular_members':service_count,'js_minification':'unverified','prepared_stage':'runner receipt only'}

if __name__ == '__main__':
    print(json.dumps(verify(ROOT), sort_keys=True))
