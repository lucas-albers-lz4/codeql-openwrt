#!/usr/bin/env python3
"""Validate retained #173 package and source evidence without running a build."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import archive

ORACLE = 'afa112d09dce539a3e51845cd0786938194cb8c8af7d4c67d9713361b83693a5'
RAW_MANIFEST = 'f326040f6540d9dc53a4794ae9611d9312037ed7fa22d8af4273a724278340ad'
CONFIG = '32dcd3e6663d22a79d522c78793a83ff019c11a46eabaf30b16deac917e17948'
IPKS = {
    'luci-mod-status': 'bfa86d24ef4fcdd32e0343fc88322c6ef57417be88fe357323959ae80b9e611a',
    'luci-mod-network': '0f866ae15e72244d4e8ddcda68c1dcf95e9159eeef0e1e0946f9b9853ede4398',
    'luci-mod-system': '6b113f502ad17fc3505d4d1112f183cf0496d3e1f926818712ee39931a2aa608',
}
RECEIPTS = {
    'luci-mod-status': '3d43385bdd0d9b1b531ab08b80ee5e131b7152412e6f1356ca99021995dd44af',
    'luci-mod-network': 'c598fac9d9cca7a2697dd3e2bc5dbed185b3f8f89d38f6db8f8b652a7ece97b6',
    'luci-mod-system': '4f25eb49f52fe92596df29f8c19000e47f19a7d401caa6e2c7a22f10b057eaf2',
}
PINS = {
    'openwrt': ('4e9642517b48bae612ff10fb72fb9199e559500e', '328d4df01c038d365176b72753b778e10c3ff413'),
    'luci': ('cb87fe60e1e2e052af36a93647f2264577829e0a', '1d7bf89bc8708fca69d005b0690ca823c9071692'),
    'packages': ('07e0d16305d2b5903b37ad7913e33e18795f81a4', 'a6b0fc0935cbfeedb810e6e991b6940f71548ea7'),
}
ANCHORS = {
    'source-oracle.json': ORACLE,
    'raw-manifest.json': RAW_MANIFEST,
    'archive.py': '224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100',
    'source/LICENSE': '43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1',
    'source/NOTICE': '0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2',
    'source/luci.mk': '9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d',
}

def need(value, message):
    if not value:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def obj(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def bad(value):
        raise ValueError('invalid JSON constant: ' + value)
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=bad)
    need(isinstance(value, dict), 'JSON object required')
    return value

def file_bytes(root, name):
    path = PurePosixPath(name)
    need(name and not path.is_absolute() and str(path) == name and '..' not in path.parts and '\\' not in name, 'unsafe packet path')
    current = root
    for part in path.parts:
        current = current / part
        need(not current.is_symlink(), 'packet path symlink')
    need(current.is_file() and current.stat().st_nlink == 1, 'packet file missing or aliased')
    return current.read_bytes()

def inventory(root):
    need(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir() and not root.is_symlink(), 'packet root unsafe')
    manifest = file_bytes(root, 'SHA256SUMS').decode().splitlines()
    expected = {}
    for line in manifest:
        digest, sep, name = line.partition('  ')
        path = PurePosixPath(name)
        need(sep and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest) and name and not path.is_absolute() and str(path) == name and '..' not in path.parts and name not in expected, 'invalid checksum entry')
        expected[name] = digest
    actual = set()
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'packet symlink')
        if path.is_file():
            need(path.stat().st_nlink == 1, 'packet hardlink alias')
            name = path.relative_to(root).as_posix()
            if name != 'SHA256SUMS':
                actual.add(name)
        else:
            need(path.is_dir(), 'special packet entry')
    need(actual == set(expected), 'packet inventory differs')
    for name, digest in expected.items():
        need(sha(file_bytes(root, name)) == digest, 'packet digest differs: ' + name)
    for name, digest in ANCHORS.items():
        need(expected.get(name) == digest, 'fixed anchor differs: ' + name)
    return expected

def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def validate_source(root, oracle):
    rows = oracle.get('rows')
    need(isinstance(rows, list) and len(rows) == 73, 'source row count differs')
    source_names = {'LICENSE', 'NOTICE', 'luci.mk'}
    for row in rows:
        path = row['source_path']
        need(path not in source_names, 'duplicate source path')
        source_names.add(path)
        data = file_bytes(root, 'source/' + path)
        need(sha(data) == row['source_sha256'] and git_blob(data) == row['git_blob'] and len(data) == row['size'], 'source identity differs: ' + path)
        need(stat.S_IMODE((root / 'source' / path).stat().st_mode) == int(row['git_mode'][-3:], 8), 'source mode differs: ' + path)
    for recipe in oracle['recipes'].values():
        path = recipe['recipe']
        need(path not in source_names, 'duplicate source recipe')
        source_names.add(path)
        data = file_bytes(root, 'source/' + path)
        need(sha(data) == recipe['recipe_sha256'] and git_blob(data) == recipe['recipe_blob'], 'source recipe differs: ' + path)
    actual = {p.relative_to(root / 'source').as_posix() for p in (root / 'source').rglob('*') if p.is_file()}
    need(actual == source_names, 'source inventory differs')

def control_fields(rows):
    item = rows.get('control')
    need(item and item['type'] == 'file', 'control missing')
    fields = {}
    for line in item['bytes'].decode('utf-8').splitlines():
        if line.startswith((' ', '\t')) or ':' not in line:
            continue
        key, value = line.split(':', 1)
        need(key not in fields, 'duplicate control field')
        fields[key] = value.strip()
    need(all(fields.get(x) for x in ('Package', 'Version', 'Architecture')), 'control identity missing')
    return {key: fields[key] for key in ('Package', 'Version', 'Architecture')}

def verify_package(root, name, oracle):
    ipk = file_bytes(root, 'raw/' + name + '.ipk')
    before = file_bytes(root, 'raw/' + name + '.json')
    after = file_bytes(root, 'raw/' + name + '-after.json')
    need(sha(ipk) == IPKS[name] and sha(before) == RECEIPTS[name] and before == after, 'package or recheck receipt differs: ' + name)
    receipt = obj(before)
    need(receipt['status'] == 'PASS' and receipt['package'] == name and receipt['ipk_sha256'] == IPKS[name], 'receipt identity differs')
    need(receipt['build_output']['sha256'] == IPKS[name] and receipt['retained_ipk'] == {'path': 'output/' + name + '.ipk', 'sha256': IPKS[name]}, 'built/retained receipt differs')
    for key, (commit, tree) in PINS.items():
        need(receipt['pins'][key] == {'sha': commit, 'tree': tree, 'dirty': False}, 'source pin differs: ' + key)
    config = receipt['config']
    need(config['config_sha256'] == CONFIG and config['target'] == 'x86_64' and config['apk'] == 'disabled' and config['js_minification'] == 'CONFIG_LUCI_JSMIN=y' and config['css_tidy'] == 'CONFIG_LUCI_CSSTIDY=y', 'config receipt differs')
    control, members, outer = archive.read_ipk(ipk)
    fields = control_fields(control)
    need(fields == receipt['control'] == {'Package': name, 'Version': '26.284.22350~8125d12', 'Architecture': 'x86_64' if name == 'luci-mod-status' else 'all'}, 'package control differs')
    need(outer == receipt['outer_archive_hashes'] and archive.receipts(control) == receipt['control_archive_members'] and archive.receipts(members) == receipt['data_archive_members'], 'archive inventory differs')
    source_rows = [r for r in oracle['rows'] if r['package'] == name and r['classification'] != 'build_input_not_direct_member']
    mappings = receipt['source_mappings']
    need(len(mappings) == len(source_rows) and len({r['source_path'] for r in mappings}) == len(mappings), 'source mapping count differs')
    by_source = {r['source_path']: r for r in source_rows}
    transforms = Counter()
    for mapping in mappings:
        source = by_source.get(mapping['source_path'])
        need(source is not None and mapping['projected_member'] == source['projected_member'] and mapping['classification'] == source['classification'], 'source projection differs')
        data = file_bytes(root, 'source/' + source['source_path'])
        entry = members.get(source['projected_member'])
        need(entry and entry['type'] == 'file', 'projected package member missing')
        mode = format(entry['mode'], '04o')
        need(mapping['source_sha256'] == sha(data) and mapping['source_mode'] == source['git_mode'] and mapping['prepared_sha256'] == sha(data) and mapping['prepared_mode'] == '0' + source['git_mode'][-3:], 'source/prepared receipt differs')
        need(mapping['stage_sha256'] == mapping['ipk_sha256'] == sha(entry['bytes']) and mapping['stage_mode'] == mapping['ipk_mode'] == mode and entry['mode'] == int(source['projected_mode'], 8), 'stage/IPK receipt differs')
        transform = mapping['transform']
        expected = ('pinned-substitution-noop-projected' if source['source_path'].endswith('.ut') else 'minification-enabled-output-bytes-unknown' if source['classification'].startswith('auxiliary_htdocs') and source['source_path'].endswith('.js') else 'direct-copy-projection')
        need(transform == expected, 'transformation classification differs')
        if transform != 'minification-enabled-output-bytes-unknown':
            need(data == entry['bytes'], 'direct-copy bytes differ')
        else:
            need(data != entry['bytes'], 'observed JS change differs')
        transforms[transform] += 1
    build_rows = [r for r in oracle['rows'] if r['package'] == name and r['classification'] == 'build_input_not_direct_member']
    build_inputs = receipt['build_inputs']
    need(len(build_inputs) == len(build_rows), 'build input receipt count differs')
    expected_build = {r['source_path']: r for r in build_rows}
    need(len(expected_build) == len(build_rows), 'duplicate build input source')
    for record in build_inputs:
        source = expected_build.get(record['source_path'])
        need(source is not None and record['source_sha256'] == record['prepared_sha256'] == source['source_sha256'] and record['prepared_mode'] == '0' + source['git_mode'][-3:], 'build input receipt differs')
    extras = receipt['generated_or_unclassified_members']
    mapped = {r['projected_member'] for r in source_rows}
    actual_files = {path for path, entry in members.items() if entry['type'] == 'file'}
    need(actual_files - mapped == {r['path'] for r in extras}, 'unmapped package members differ')
    for row in extras:
        entry = members[row['path']]
        need(row['sha256'] == sha(entry['bytes']) and row['size'] == len(entry['bytes']) and row['mode'] == format(entry['mode'], '04o'), 'unmapped member receipt differs')
    if name == 'luci-mod-status':
        need(len(extras) == 1 and extras[0]['path'] == 'usr/bin/luci-bwc' and extras[0]['sha256'] == '5e709a137dc827f5863b0f460cb26c8ddd229a27529a470aa8bfbba5493ecc7d' and extras[0]['mode'] == '0755' and extras[0]['size'] == 20493 and members[extras[0]['path']]['bytes'][:6] == b'\x7fELF\x02\x01' and members[extras[0]['path']]['bytes'][18:20] == b'\x3e\x00', 'generated member differs')
    else:
        need(extras == [], 'unexpected unclassified member')
    return transforms

def verify(root):
    inventory(root)
    raw = obj(file_bytes(root, 'raw-manifest.json'))
    need(raw['source_artifact_sha256'] == '7432735425f220c12c0a51acc7cc2ef16ae68d14f157a7d33fdb239bd1d55dd2' and raw['original_run_log_sha256'] == 'd279f039d26e07db13dc4b21634e18d7c9ff5b59b311d3146fdf37617e472df5', 'raw artifact identity differs')
    actual_raw = {p.name for p in (root / 'raw').iterdir() if p.is_file()}
    need(actual_raw == set(raw['files']), 'raw evidence file set differs')
    for name, digest in raw['files'].items():
        need(sha(file_bytes(root, 'raw/' + name)) == digest, 'raw evidence differs: ' + name)
    oracle = obj(file_bytes(root, 'source-oracle.json'))
    need(oracle['luci_commit'] == PINS['luci'][0] and oracle['luci_tree'] == PINS['luci'][1], 'oracle source pin differs')
    validate_source(root, oracle)
    config = file_bytes(root, 'raw/config-final')
    need(sha(config) == CONFIG, 'final config hash differs')
    config_lines = config.decode('utf-8').splitlines()
    for symbol in ('CONFIG_TARGET_x86=y', 'CONFIG_TARGET_x86_64=y', 'CONFIG_PACKAGE_luci-mod-status=m', 'CONFIG_PACKAGE_luci-mod-network=m', 'CONFIG_PACKAGE_luci-mod-system=m', 'CONFIG_LUCI_JSMIN=y', 'CONFIG_LUCI_CSSTIDY=y'):
        need(config_lines.count(symbol) == 1, 'final config symbol differs: ' + symbol)
    transforms = Counter()
    for name in IPKS:
        transforms.update(verify_package(root, name, oracle))
        stage_paths = file_bytes(root, 'raw/' + name + '.stages.nul')
        ipk_paths = file_bytes(root, 'raw/' + name + '.ipks.nul')
        need(stage_paths == file_bytes(root, 'raw/' + name + '.stages-after.nul'), 'stage inventory changed')
        need(ipk_paths == file_bytes(root, 'raw/' + name + '.ipks-after.nul'), 'IPK inventory changed')
        receipt = obj(file_bytes(root, 'raw/' + name + '.json'))
        base = '/home/runner/work/_temp/issue173-core-module-batches/openwrt/'
        arch = 'x86_64' if name == 'luci-mod-status' else 'all'
        stage = base + 'build_dir/target-x86_64_musl/' + name + '/ipkg-' + arch + '/' + name
        need(stage_paths == stage.encode() + b'\0' and ipk_paths == (base + receipt['build_output']['path']).encode() + b'\0', 'package path inventory differs')
    need(transforms == Counter({'direct-copy-projection': 23, 'minification-enabled-output-bytes-unknown': 47, 'pinned-substitution-noop-projected': 1}), 'transform totals differ')
    diagnostic_lines = file_bytes(root, 'raw/diagnostic-lines.txt').splitlines()
    need(sum(b'warning:' in line.lower() for line in diagnostic_lines) == 2108, 'warning excerpt count differs')
    need(sum(b':error: recursive dependency detected!' in line for line in diagnostic_lines) == 6, 'Kconfig diagnostic count differs')
    need(sum(b'(ignored)' in line for line in diagnostic_lines) == 8, 'ignored error count differs')
    for path in (root / 'raw').glob('*.time'):
        need(b'Exit status: 0' in path.read_bytes(), 'nonzero recorded phase: ' + path.name)
    return {'status': 'retained_evidence_consistent', 'packages': 3, 'source_rows': 73, 'minified_js_provenance': 'unknown', 'runtime_or_codeql_claim': False}

if __name__ == '__main__':
    print(json.dumps(verify(ROOT), sort_keys=True))
