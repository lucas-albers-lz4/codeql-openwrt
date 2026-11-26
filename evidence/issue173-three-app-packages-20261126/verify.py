#!/usr/bin/env python3
"""Verify retained three-app package evidence without building."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path, PurePosixPath
import stat
ROOT = Path(__file__).resolve().parent
archive = None
ANCHORS = {'archive.py': '224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100', 'source-oracle.json': '05906176f0830f311e2872d9d4b7743825cb80dfe1cb89af22673feac212d72a', 'raw-manifest.json': 'ffd953a13651bb97d6f284ba6280696d280d6a5d7ea9faa37f6a34d483288d7b', 'diagnostics.log': '523aa866a71f522e85e58beec9416053e0e39f59301c6f39261a0e7cd05ded31'}
ANCHORS.update({'source/LICENSE':'43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1', 'source/NOTICE':'0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2', 'source/luci.mk':'9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d', 'source/LICENSE-AGPL-3.0.txt':'0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0'})
IPKS = {'luci-app-ddns':'cc54a30504d5936ad6c34919b815112cc4b05b02f517d856d2dee191e9c8fe38','luci-app-advanced-reboot':'0748aa14823d95241d52fb63a97c561beb3e3a4e9366c139ab0cd20226f7ee5b','luci-app-wifihistory':'1565f6d6616da36eaf97db27c3ec17ee13f23f5fa4e50dab6640a2508b41b673'}
VERSIONS = {'luci-app-ddns':'26.280.64158~a450f0d','luci-app-advanced-reboot':'1.1.2-r6','luci-app-wifihistory':'26.040.14621~ff57b23'}
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



def verify_package(root, name, oracle):
    load_archive(root)
    ipk = file_bytes(root, 'raw/' + name + '.ipk')
    receipt = obj(file_bytes(root, 'raw/' + name + '.json'))
    need(sha(ipk) == IPKS[name] == receipt['ipk_sha256'] == receipt['built_ipk_sha256'] == receipt['retained_ipk_sha256'], 'IPK digest differs')
    control, members, outer = archive.read_ipk(ipk)
    need(control_fields(control) == receipt['control'] == {'Package':name,'Version':VERSIONS[name],'Architecture':'all'}, 'package control differs')
    need(outer == receipt['outer_member_sha256'], 'outer member identity differs')
    need(archive.receipts(control) == sorted(receipt['archive_control_members'], key=lambda x:x['path']), 'control members differ')
    need(archive.receipts(members) == sorted(receipt['archive_data_members'], key=lambda x:x['path']), 'data members differ')
    regular = {p:r for p,r in members.items() if r['type'] == 'file'}
    rows = receipt['members']
    source_rows = {r['source_path']:r for r in oracle['packages'][name]['source_rows']}
    projected = {r['projected_member']:r for r in source_rows.values() if r['projected_member']}
    expected_paths = set(projected)
    if name == 'luci-app-advanced-reboot': expected_paths.add('usr/share/advanced-reboot/devices.json')
    need(len(rows) == len(regular) and {r['path'] for r in rows} == set(regular) == expected_paths, 'regular membership differs')
    for row in rows:
        member = regular[row['path']]
        need(sha(member['bytes']) == row['ipk_sha256'] == row['stage_sha256'] and format(member['mode'],'04o') == row['ipk_mode'] == row['stage_mode'], 'IPK/stage member differs')
        path = row['source_path']
        if path:
            source = file_bytes(root,'source/'+path)
            expected = source_rows[path]
            need(sha(source) == row['source_sha256'] == expected['source_sha256'] and blob(source) == row['source_git_blob'] == expected['git_blob'], 'source identity differs')
            need(row['source_git_mode'] == expected['git_mode'], 'source mode differs')
            need(projected.get(row['path']) == expected and row['classification'] == expected['classification'] and row['ipk_mode'] == expected['projected_mode'].zfill(4), 'source projection differs')
            need(row['prepared_sha256'] == row['source_sha256'] and row['prepared_mode'] == expected['projected_mode'].zfill(4), 'prepared source lineage differs')
            if row['classification'] != 'auxiliary_htdocs_js':
                need(sha(source) == row['ipk_sha256'], 'direct source bytes differ')
        else:
            need(row['classification'] == 'generated_advanced_devices' and row['ipk_sha256'] == oracle['packages'][name]['custom_prepare_projection']['projected_sha256_under_C_locale'], 'generated bytes differ')
            inputs = oracle['packages'][name]['custom_prepare_projection']['merge_inputs_filename_order']
            need(len(inputs) == 44 and [r['source_path'] for r in row['source_inputs']] == inputs, 'generated input order differs')
            for item in row['source_inputs']:
                source = source_rows[item['source_path']]
                need(all(item[key] == source[key] for key in ('source_sha256','git_blob','git_mode')), 'generated input lineage differs')
            generated = b'[' + b','.join(file_bytes(root, 'source/'+path) for path in inputs) + b']'
            need(member['bytes'] == generated and len(generated) == 25061 and row['prepared_sha256'] == row['ipk_sha256'] and row['prepared_mode'] == row['ipk_mode'] == '0644', 'generated input bytes differ')
            need(not any(p.startswith(('usr/share/advanced-reboot/devices/', 'usr/share/advanced-reboot/devices.disabled/')) or p in ('usr/share/advanced-reboot/devices','usr/share/advanced-reboot/devices.disabled') for p in members), 'removed device trees present')
    raw = root / 'raw'
    order = list(IPKS)
    triggers = order[order.index(name):]
    need({p.name for p in raw.glob(name + '-after-*.json')} == {name+'-after-'+trigger+'.json' for trigger in triggers}, 'serial receipt set differs')
    for after in sorted(raw.glob(name + '-after-*.json')):
        need(file_bytes(root, 'raw/'+after.name) == file_bytes(root, 'raw/'+name+'.json'), 'serial receipt differs')
    for kind in ('stage','ipk'):
        baseline = file_bytes(root, 'raw/'+name+'.'+kind+'-paths.nul')
        path = receipt['stage_path'] if kind == 'stage' else receipt['built_ipk_path']
        expected_path = ('build_dir/target-x86_64_musl/'+name+'/ipkg-all/'+name if kind == 'stage' else 'bin/packages/x86_64/luci/'+name+'_'+VERSIONS[name]+'_all.ipk')
        need(path == expected_path, 'receipt path differs')
        need(baseline == ('/home/runner/work/_temp/issue173-app-module-batches/openwrt/'+path+'\0').encode(), 'serial path differs')
        need({p.name for p in raw.glob(name+'.'+kind+'-paths-after-*.nul')} == {name+'.'+kind+'-paths-after-'+trigger+'.nul' for trigger in triggers}, 'serial path set differs')
        for after in sorted(raw.glob(name+'.'+kind+'-paths-after-*.nul')):
            need(file_bytes(root, 'raw/'+after.name) == baseline, 'serial path inventory differs')
    return len(rows)

def main():
    inventory(ROOT)
    manifest = obj(file_bytes(ROOT,'raw-manifest.json'))
    actual = {p.relative_to(ROOT/'raw').as_posix() for p in (ROOT/'raw').rglob('*') if p.is_file()}
    need(len(manifest) == 88 and set(manifest) == actual, 'raw artifact inventory differs')
    for path, expected in manifest.items():
        need(sha(file_bytes(ROOT,'raw/'+path)) == expected, 'raw artifact digest differs')
    verify_kernel(ROOT)
    oracle = obj(file_bytes(ROOT,'source-oracle.json'))
    for package in oracle['packages'].values():
        for row in package['source_rows'] + package['candidate_inventory_rows']:
            data = file_bytes(ROOT,'source/'+row['source_path'])
            need(sha(data) == row['source_sha256'] and blob(data) == row['git_blob'], 'oracle source differs')
            mode = stat.S_IMODE((ROOT/'source'/row['source_path']).stat().st_mode)
            need(mode == (0o755 if row['git_mode'] == '100755' else 0o644), 'oracle source mode differs')
        recipe = package['recipe']
        data = file_bytes(ROOT,'source/'+recipe['source_path'])
        need(sha(data) == recipe['sha256'] and blob(data) == recipe['git_blob'], 'recipe identity differs')
    for name in IPKS:
        print(name, verify_package(ROOT,name,oracle), 'regular members verified')
    print('Raw IPKs reopened; prepared and staged bytes are runner-attested.')

def verify_kernel(root):
    load_archive(root)
    config = file_bytes(root, 'raw/config-final')
    need(sha(config) == '80d8c0b67b7dfd176068b06ea3e0abb8c99cc93fdc365555e5a131e48056cbcb', 'build config differs')
    need(sha(file_bytes(root, 'raw/feeds-list-fs')) == '52b3e3c257411fc5de4caf088d2fab73a242ca33dfe182088113f217d0239848', 'feed mirror differs')
    kc = file_bytes(root, 'raw/kernel-evidence/.config')
    magic = file_bytes(root, 'raw/kernel-evidence/.vermagic')
    need(sha(kc) == 'adff086c399e48803aacc0b87838aacc89f582fc8bb52a5343a8d35cb8703fba' and magic == b'd06fc8e744142971fdfa96b50c6d006f\n', 'kernel identity differs')
    version = '6.12.116~d06fc8e744142971fdfa96b50c6d006f-r1'
    need(file_bytes(root, 'raw/kernel-evidence/kernel.version') == (version+'\n').encode(), 'kernel version differs')
    ipk = file_bytes(root,'raw/kernel-evidence/kernel.ipk')
    need(sha(ipk) == '3f45007bbdbad6d0c171adc06cb1b7e667ff1895d9ce909986fbe3f9a78ab25e', 'kernel IPK differs')
    candidate = 'raw/kernel-evidence/kernel-ipks/kernel_'+version+'_x86_64.ipk'
    need(file_bytes(root,candidate) == ipk, 'kernel candidate differs')
    control, members, outer = archive.read_ipk(ipk)
    receipt = obj(file_bytes(root,'raw/kernel-package-inventory.json'))
    need(control_fields(control) == {'Package':'kernel','Version':version,'Architecture':'x86_64'} == receipt['control'], 'kernel control differs')
    need(archive.receipts(control) == receipt['control_members'] and archive.receipts(members) == receipt['data_members'] and outer == receipt['outer_members'], 'kernel archive differs')
    builtin = file_bytes(root,'raw/kernel-evidence/modules.builtin')
    projected = b''.join(line.rsplit(b'/',1)[-1] for line in builtin.splitlines(keepends=True))
    need(members['lib/modules/6.12.116/modules.builtin']['bytes'] == projected, 'kernel builtin differs')
    before = obj(file_bytes(root,'raw/kernel-inventory-before-package.json'))
    after = obj(file_bytes(root,'raw/kernel-inventory-after-package.json'))
    need(before['inventory'] == after and before['config_sha256'] == sha(config), 'kernel inventories differ')
    warnings = [x.decode() for x in file_bytes(root,'raw/kernel-package-compile.stderr').splitlines() if re.fullmatch(rb'WARNING: .+ is not available in the kernel config - generating empty package',x)]
    disposition = obj(file_bytes(root,'raw/kernel-package-compile.diagnostics.json'))
    need(warnings == disposition['accepted_scoped_empty_warnings'] and set(warnings) == {'WARNING: kmod-drm-exec is not available in the kernel config - generating empty package','WARNING: kmod-drm-suballoc-helper is not available in the kernel config - generating empty package'} and len(warnings) == 2, 'kernel warnings differ')
    for phase in ('kernel-compile','kernel-package-compile'):
        for stream in ('stdout','stderr'):
            lines = file_bytes(root,'raw/'+phase+'.'+stream).splitlines()
            need(not any(re.fullmatch(rb"ERROR: module '.+' is missing\.",line) for line in lines), 'kernel missing-module error')
            if (phase,stream) != ('kernel-package-compile','stderr'):
                need(not any(re.fullmatch(rb'WARNING: .+ is not available in the kernel config - generating empty package',line) for line in lines), 'unexpected kernel empty warning')

if __name__ == '__main__': main()
