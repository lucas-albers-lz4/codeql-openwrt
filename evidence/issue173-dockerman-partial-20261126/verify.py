#!/usr/bin/env python3
"""Verify partial Dockerman source and fallback IPK evidence."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path, PurePosixPath
import stat
ROOT = Path(__file__).resolve().parent
archive = None
ANCHORS = {'archive.py':'224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100','projection.json':'f5d75916f57e399401ba25f8ceeb32c47f74230c586156427c7af4b222f501bb','provider-controls.json':'0ce71560e947244d8b5a3bf5baf506d07a9b6842989ea92741d345041ef89ce3','raw-manifest.json':'d13435ff850621ba9b7ea044cff3ed7b23446cc8c872f5172b2912bd34e3f69d','source/LICENSE':'43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1','source/NOTICE':'0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2','source/LICENSE-AGPL-3.0.txt':'0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0'}
ANCHORS['circular-go-excerpt.log'] = '80d1d416bd27c8e0d5b034bdfabb6d86c9e8d5d1a33764d3fa0d3059674f0899'
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




def verify_app(root):
    load_archive(root)
    projection = obj(file_bytes(root,'projection.json'))
    path = 'raw/luci-app-dockerman_26.134.50559~d5129a1_all.ipk'
    ipk = file_bytes(root,path)
    need(sha(ipk) == '16cc2dd37767f51be361a9b787d1c85fe83ab040c54394b5145a02caed92292d', 'fallback IPK differs')
    control, rows, _ = archive.read_ipk(ipk)
    need(control_fields(control) == {'Package':'luci-app-dockerman','Version':'26.134.50559~d5129a1','Architecture':'all'}, 'app control differs')
    actual = {name:row for name,row in rows.items() if row['type']=='file'}
    projected = {row['projected_member']:row for row in projection['projected']}
    need(len(actual)==len(projected)==22 and set(actual)==set(projected), 'projected member set differs')
    for name, expected in projected.items():
        source = file_bytes(root,'source/'+expected['source_path'])
        need(sha(source)==expected['sha256'] and blob(source)==expected['git_object'], 'source identity differs')
        need(format(stat.S_IMODE((root/'source'/expected['source_path']).stat().st_mode),'04o')==expected['source_mode_projected'], 'source mode differs')
        need(sha(actual[name]['bytes'])==expected['sha256'] and format(actual[name]['mode'],'04o')==expected['source_mode_projected'], 'IPK member differs')
    return len(actual)

def verify_controls(root, controls):
    load_archive(root)
    names = {'luci-app-dockerman','luci-base','containerd','docker-compose','docker','dockerd','runc','tini','ttyd','ucode-mod-socket','kernel','kmod-ipt-nat6','kmod-ipt-nat','kmod-ipt-physdev','kmod-nf-ipvs','kmod-veth'}
    observed = set()
    for row in controls:
        fields = {}
        for line in row['control'].splitlines():
            if ':' in line and not line.startswith((' ', '\t')):
                key, value = line.split(':',1)
                need(key not in fields, 'duplicate provider control field')
                fields[key] = value.strip()
        name, version, arch = (fields.get(k) for k in ('Package','Version','Architecture'))
        need(name in names and name not in observed and version and arch and row['retained_path'].endswith('/'+name+'_'+version+'_'+arch+'.ipk'), 'provider control identity differs')
        observed.add(name)
        if name.startswith('kmod-'):
            need('kernel (=6.12.116~7df1a98339a37dfe41af7485d026e004-r1)' in fields.get('Depends',''), 'kmod kernel dependency differs')
    need(observed == names, 'provider names differ')
    for name, path in [('kernel','raw/kernel-evidence/kernel.ipk'),('luci-app-dockerman','raw/luci-app-dockerman_26.134.50559~d5129a1_all.ipk')]:
        control = archive.read_ipk(file_bytes(root,path))[0]['control']['bytes']
        need(any(row['control'].encode()==control and row['retained_path'].split('/')[-1].startswith(name+'_') for row in controls), 'retained provider control differs')

def verify_kernel_and_logs(root, kernel, ctl, rows):
    receipt = obj(file_bytes(root,'raw/kernel-package-inventory.json'))
    kctl, krows, outer = archive.read_ipk(kernel)
    need(archive.receipts(kctl)==receipt['control_members'] and archive.receipts(krows)==receipt['data_members'] and outer==receipt['outer_members'], 'kernel archive receipt differs')
    version = '6.12.116~7df1a98339a37dfe41af7485d026e004-r1'
    need(file_bytes(root,'raw/kernel-evidence/kernel.version')==(version+'\n').encode() and file_bytes(root,'raw/kernel-evidence/.vermagic')==b'7df1a98339a37dfe41af7485d026e004\n', 'kernel version differs')
    need(sha(file_bytes(root,'raw/kernel-evidence/.config'))=='3723a6cb9153dc0683defc4fc724b92ddb69e534b66acf1afeb4dc7f39ec4492', 'kernel config differs')
    need(file_bytes(root,'raw/kernel-evidence/kernel-ipks/kernel_'+version+'_x86_64.ipk')==kernel, 'kernel candidate differs')
    before = obj(file_bytes(root,'raw/kernel-inventory-before-package.json'))
    after = obj(file_bytes(root,'raw/kernel-inventory-after-package.json'))
    need(before['inventory']==after, 'pre-app kernel inventories differ')
    phase = obj(file_bytes(root,'raw/dockerman-compile.receipt.json'))
    stderr = file_bytes(root,'raw/dockerman-compile.stderr')
    need(phase['exit']==0 and phase['stderr_sha256']==sha(stderr), 'app phase receipt differs')
    failure = obj(file_bytes(root,'raw/dockerman-compile-validation-failures.json'))
    need(set(failure)=={'cycle_parser','diagnostics'} and 'circular.go' in failure['cycle_parser'] and 'empty-package diagnostic' in failure['diagnostics'], 'wrapper failure differs')
    lines = stderr.decode().splitlines()
    cycles = [line for line in lines if re.fullmatch(r'make\[1\]: Circular .* dependency dropped\.',line)]
    need(cycles == ['make[1]: Circular package/feeds/packages/'+name+'/compile <- package/feeds/packages/dockerd/compile dependency dropped.' for name in ('containerd','runc','tini')], 'cycle warnings differ')
    for name in ('kmod-drm-exec','kmod-drm-suballoc-helper'):
        need(lines.count('WARNING: '+name+' is not available in the kernel config - generating empty package')==1, 'kernel warning differs')

def main():
    inventory(ROOT)
    manifest = obj(file_bytes(ROOT,'raw-manifest.json'))
    actual = {p.relative_to(ROOT/'raw').as_posix() for p in (ROOT/'raw').rglob('*') if p.is_file()}
    need(len(manifest)==34 and set(manifest)==actual, 'raw inventory differs')
    for path, expected in manifest.items(): need(sha(file_bytes(ROOT,'raw/'+path))==expected, 'raw digest differs')
    candidates = obj(file_bytes(ROOT,'raw/provider-candidates.json'))['members']
    controls = json.loads(file_bytes(ROOT,'provider-controls.json'))
    need(len(candidates)==len(controls)==16, 'provider control count differs')
    need(all((a['retained_path'],a['sha256'],a['size'])==(b['retained_path'],b['ipk_sha256'],b['ipk_size']) for a,b in zip(candidates,controls)), 'provider identities differ')
    verify_controls(ROOT, controls)
    config = file_bytes(ROOT,'raw/config-final')
    need(sha(config)=='4678b8d328391f97ba85b19020cbdcc077cccc528dc79553b99625627f25ae17' and b'# CONFIG_LUCI_JSMIN is not set' in config.splitlines() and b'# CONFIG_LUCI_CSSTIDY is not set' in config.splitlines(), 'config differs')
    kernel = file_bytes(ROOT,'raw/kernel-evidence/kernel.ipk')
    need(sha(kernel)=='88490a59d5be9be9bee9f6582efe8bf20fd6df4e52933abd324763cda96f1caa', 'kernel IPK differs')
    load_archive(ROOT); ctl, rows, _ = archive.read_ipk(kernel)
    need(control_fields(ctl)=={'Package':'kernel','Version':'6.12.116~7df1a98339a37dfe41af7485d026e004-r1','Architecture':'x86_64'}, 'kernel control differs')
    builtin = file_bytes(ROOT,'raw/kernel-evidence/modules.builtin')
    projected = b''.join(line.rsplit(b'/',1)[-1] for line in builtin.splitlines(keepends=True))
    need(rows['lib/modules/6.12.116/modules.builtin']['bytes']==projected, 'kernel builtin differs')
    verify_kernel_and_logs(ROOT, kernel, ctl, rows)
    print(verify_app(ROOT), 'fallback IPK members equal pinned source; prepared/stage comparison absent')

if __name__=='__main__': main()
