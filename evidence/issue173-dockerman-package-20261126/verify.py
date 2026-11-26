#!/usr/bin/env python3
"""Verify the retained Dockerman source/prepared/stage/IPK comparison."""
import hashlib
import json
import types
import re
from pathlib import Path, PurePosixPath
import stat
ROOT=Path(__file__).resolve().parent
archive=None
ANCHORS={'archive.py':'224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100','projection.json':'f5d75916f57e399401ba25f8ceeb32c47f74230c586156427c7af4b222f501bb','provider-controls.json':'d916e98049a9bf8276be8255324e80a2eae18aa1c94f3d0d7fb37df2dcc9dd17','raw-manifest.json':'3f515f6288aa580e180c259eb95a4f9bbcabe3d308a513800e69e0aa93080036','source/LICENSE':'43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1','source/NOTICE':'0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2','source/LICENSE-AGPL-3.0.txt':'0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0'}
ANCHORS.update({'source/luci.mk':'9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d','source/applications/luci-app-dockerman/Makefile':'2e6ac58f1f0bd579885d635a64e2451a03af7124279554376a7a315330edc647','offline-timing/invocation.json':'e7855aac43b3e28c0a1785a47555dcbae71e590a7d3fe26719362b349d37ffa6','offline-timing/time_dockerman_original.py':'8436570b8ffc327659ded365f7f14aa0af3a5061359d414f4e15530a13ea6256','offline-timing/comparison.receipt.json':'e081ff7c47e1e04229987919c75d67b8cb12772f5ea481755135dc6ede38108c','offline-timing/comparison.time-and-stderr':'fadb5a2220d585516671bb6677e44805c220669de6f477881a1e7a59def6063c','offline-timing/comparison.stdout':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','offline-timing/comparison.stderr':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'})
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
    source = file_bytes(root, 'archive.py')
    need(sha(source) == ANCHORS['archive.py'], 'archive parser digest differs')
    if archive is None:
        module = types.ModuleType('retained_base_archive')
        exec(compile(source, str(root/'archive.py'), 'exec'), module.__dict__)
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
    ipk=file_bytes(root,'raw/luci-app-dockerman.ipk')
    need(sha(ipk)=='7b17766175a32ad8ab533a7b01089a7f362d3d1dd2988fe1ce15aaa66480dcd3','IPK differs')
    receipt=obj(file_bytes(root,'raw/dockerman-package-comparison.json'))
    need(sha(file_bytes(root,'raw/dockerman-package-comparison.json'))=='e081ff7c47e1e04229987919c75d67b8cb12772f5ea481755135dc6ede38108c','comparison differs')
    ctl,rows,outer=archive.read_ipk(ipk)
    need(control_fields(ctl)==receipt['package']=={'Package':'luci-app-dockerman','Version':'26.134.50559~d5129a1','Architecture':'all'},'control differs')
    need(archive.receipts(ctl)==receipt['control_archive_members'] and archive.receipts(rows)==receipt['data_archive_members'] and outer==receipt['outer_members'],'archive receipts differ')
    projection=obj(file_bytes(root,'projection.json'))['projected']; projected={x['projected_member']:x for x in projection}
    regular={k:v for k,v in rows.items() if v['type']=='file'}; recorded={x['member']:x for x in receipt['members']}
    need(len(projected)==len(regular)==len(recorded)==22 and set(projected)==set(regular)==set(recorded),'member set differs')
    for name, row in projected.items():
        source=file_bytes(root,'source/'+row['source_path']); rel=row['source_path'].split('applications/luci-app-dockerman/',1)[1]
        prepared=file_bytes(root,'raw/dockerman-prepared/'+rel);stage=file_bytes(root,'raw/dockerman-stage/'+name);member=regular[name]; observed=recorded[name]
        need(sha(source)==row['sha256'] and blob(source)==row['git_object'] and sha(prepared)==sha(stage)==sha(member['bytes'])==sha(source),'source or package member differs')
        mode=row['source_mode_projected']
        for path in ('source/'+row['source_path'],'raw/dockerman-prepared/'+rel,'raw/dockerman-stage/'+name):
            need(format(stat.S_IMODE((root/path).stat().st_mode),'04o')==mode,'member mode differs')
        need(format(member['mode'],'04o')==mode==observed['ipk_mode']==observed['prepared_mode']==observed['stage_mode'] and observed['source_sha256']==observed['prepared_sha256']==observed['stage_sha256']==observed['ipk_sha256']==sha(source) and observed['source_path']==row['source_path'] and observed['git_blob']==row['git_object'] and observed['source_mode']==row['git_mode'],'comparison lineage differs')
    prepared_inventory=obj(file_bytes(root,'raw/dockerman-prepared-inventory.json'))['members']
    stage_inventory=obj(file_bytes(root,'raw/dockerman-stage-inventory.json'))['members']
    need(len(prepared_inventory)==22 and len(stage_inventory)==26,'retained tree inventory count differs')
    for row in prepared_inventory:
        data=file_bytes(root,'raw/dockerman-prepared/'+row['prepared_path']);need(row['status']=='captured' and sha(data)==row['sha256'] and len(data)==row['size'],'prepared inventory differs')
    for row in stage_inventory:
        data=file_bytes(root,'raw/dockerman-stage/'+row['path']);need(sha(data)==row['sha256'] and len(data)==row['size'],'stage inventory differs')
    prepared_paths={p.relative_to(root/'raw/dockerman-prepared').as_posix() for p in (root/'raw/dockerman-prepared').rglob('*') if p.is_file()}
    need(prepared_paths=={row['prepared_path'] for row in prepared_inventory},'prepared membership differs')
    stage_paths={p.relative_to(root/'raw/dockerman-stage').as_posix() for p in (root/'raw/dockerman-stage').rglob('*') if p.is_file()}
    control_paths={'CONTROL/'+p for p,row in ctl.items() if row['type']=='file'}
    need(stage_paths==set(projected)|control_paths,'stage membership differs')
    for path in control_paths:
        row=ctl[path.removeprefix('CONTROL/')];f=root/'raw/dockerman-stage'/path
        need(file_bytes(root,'raw/dockerman-stage/'+path)==row['bytes'] and stat.S_IMODE(f.stat().st_mode)==row['mode'],'stage control differs')
    return len(projected)

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
    for name, path in [('kernel','raw/kernel-evidence/kernel.ipk'),('luci-app-dockerman','raw/luci-app-dockerman.ipk')]:
        control = archive.read_ipk(file_bytes(root,path))[0]['control']['bytes']
        need(any(row['control'].encode()==control and row['retained_path'].split('/')[-1].startswith(name+'_') for row in controls), 'retained provider control differs')

def verify_kernel_and_diagnostics(root):
    load_archive(root)
    config=file_bytes(root,'raw/config-final');need(sha(config)=='4678b8d328391f97ba85b19020cbdcc077cccc528dc79553b99625627f25ae17','config differs')
    version='6.12.116~7df1a98339a37dfe41af7485d026e004-r1'
    ipk=file_bytes(root,'raw/kernel-evidence/kernel.ipk');need(sha(ipk)=='88490a59d5be9be9bee9f6582efe8bf20fd6df4e52933abd324763cda96f1caa','kernel IPK differs')
    ctl,rows,outer=archive.read_ipk(ipk);receipt=obj(file_bytes(root,'raw/kernel-package-inventory.json'))
    need(control_fields(ctl)==receipt['control']=={'Package':'kernel','Version':version,'Architecture':'x86_64'} and archive.receipts(ctl)==receipt['control_members'] and archive.receipts(rows)==receipt['data_members'] and outer==receipt['outer_members'],'kernel receipt differs')
    need(file_bytes(root,'raw/kernel-evidence/kernel.version')==(version+'\n').encode() and file_bytes(root,'raw/kernel-evidence/.vermagic')==b'7df1a98339a37dfe41af7485d026e004\n','kernel version differs')
    kernel_config=file_bytes(root,'raw/kernel-evidence/.config');need(sha(kernel_config)=='3723a6cb9153dc0683defc4fc724b92ddb69e534b66acf1afeb4dc7f39ec4492' and b'CONFIG_MODULE_STRIPPED=y' in kernel_config.splitlines(),'kernel config differs')
    builtin=file_bytes(root,'raw/kernel-evidence/modules.builtin');projected=b''.join(x.rsplit(b'/',1)[-1] for x in builtin.splitlines(keepends=True))
    need(rows['lib/modules/6.12.116/modules.builtin']['bytes']==projected,'kernel builtin differs')
    chunks=re.findall(rb'[\t\x20-\x7e]{4,}',file_bytes(root,'raw/kernel-evidence/modules.builtin.modinfo'))
    modinfo=b''.join(x+b'\0' for x in chunks if not re.search(rb'\.(file|parmtype)=',x))
    need(len(modinfo.split(b'\0'))-1==501 and rows['lib/modules/6.12.116/modules.builtin.modinfo']['bytes']==modinfo and rows['lib/modules/6.12.116/modules.builtin.modinfo']['mode']==0o644,'kernel modinfo differs')
    before=obj(file_bytes(root,'raw/kernel-inventory-before-package.json'));after=obj(file_bytes(root,'raw/kernel-inventory-after-package.json'));need(before['inventory']==after,'kernel inventory differs')
    final=obj(file_bytes(root,'raw/kernel-diagnostic-scope-final-disposition.json'))
    need(final['dockerman_comparison_sha256']=='e081ff7c47e1e04229987919c75d67b8cb12772f5ea481755135dc6ede38108c' and final['kernel_package_inventory_sha256']==sha(file_bytes(root,'raw/kernel-package-inventory.json')),'kernel disposition differs')
    expected={'WARNING: kmod-drm-exec is not available in the kernel config - generating empty package','WARNING: kmod-drm-suballoc-helper is not available in the kernel config - generating empty package'}
    for key in ('raw_warning_receipt','dockerman_repeated_warning_receipt'):
        need(sha(file_bytes(root,'raw/'+final[key]))==final[key+'_sha256'],'warning receipt link differs')
    for phase in ('kernel-package-compile','dockerman-compile'):
        lines=file_bytes(root,'raw/'+phase+'.stderr').decode().splitlines()
        warnings=[line for line in lines if re.fullmatch(r'WARNING: .+ is not available in the kernel config - generating empty package',line)]
        need(len(warnings)==2 and set(warnings)==expected,'kernel warnings differ')
        need(not any(line.startswith('ERROR: module ') and line.endswith(' is missing.') for line in lines),'missing kernel module')
        if phase=='dockerman-compile':
            cycles=[line for line in lines if re.match(r'make(?:\[\d+\])?: Circular(?:\s|$)',line)]
            receipt=json.loads(file_bytes(root,'raw/dockerman-compile-cycle-warnings.json'))
            need(cycles==[row['line'] for row in receipt] and len(cycles)==3,'cycle warnings differ')

def main():
    inventory(ROOT)
    raw=obj(file_bytes(ROOT,'raw-manifest.json'));actual={p.relative_to(ROOT/'raw').as_posix() for p in (ROOT/'raw').rglob('*') if p.is_file()}
    need(len(raw)==94 and set(raw)==actual,'raw inventory differs')
    for name,value in raw.items():need(sha(file_bytes(ROOT,'raw/'+name))==value,'raw digest differs')
    manifest=obj(file_bytes(ROOT,'raw/manifest.json'))
    need(manifest['status']=='dockerman_package_compared_review_required' and manifest['ipk_sha256']=='7b17766175a32ad8ab533a7b01089a7f362d3d1dd2988fe1ce15aaa66480dcd3' and manifest['comparison_sha256']=='e081ff7c47e1e04229987919c75d67b8cb12772f5ea481755135dc6ede38108c','run manifest differs')
    for name,value in raw.items():
        if name != 'manifest.json': need(manifest['output_sha256'].get(name)==value,'run raw output differs: '+name)
    go=file_bytes(ROOT,'raw/go-version.stdout');gorec=obj(file_bytes(ROOT,'raw/go-version.receipt.json'))
    need(go==b'go version go1.26.11 linux/amd64\n' and not file_bytes(ROOT,'raw/go-version.stderr') and gorec['exit']==0 and gorec['argv']==['/home/runner/work/_temp/issue173-dockerman-build/openwrt/staging_dir/hostpkg/lib/go-1.26/bin/go','version'] and gorec['stdout_sha256']==sha(go) and gorec['stderr_sha256']==sha(b''),'Go version differs')
    capture=obj(file_bytes(ROOT,'raw/dockerman-candidate-capture.json'))
    need(capture['ipk_copy']=='luci-app-dockerman.ipk' and capture['prepared_copy']=='dockerman-prepared' and capture['stage_copy']=='dockerman-stage' and not capture['errors'] and capture['provider_manifest_sha256']==sha(file_bytes(ROOT,'raw/provider-candidates.json')) and len(capture['dockerman_ipk_candidates'])==1 and capture['dockerman_ipk_candidates'][0]['sha256']==sha(file_bytes(ROOT,'raw/luci-app-dockerman.ipk')),'candidate capture differs')
    controls=json.loads(file_bytes(ROOT,'provider-controls.json')); candidates=obj(file_bytes(ROOT,'raw/provider-candidates.json'))['members']
    need(len(controls)==len(candidates)==16 and all((a['retained_path'],a['sha256'],a['size'])==(b['retained_path'],b['ipk_sha256'],b['ipk_size']) for a,b in zip(candidates,controls)),'provider identities differ')
    providers=obj(file_bytes(ROOT,'raw/dockerman-provider-inventory.json'))
    need(providers['provider_candidate_manifest_sha256']==sha(file_bytes(ROOT,'raw/provider-candidates.json')) and providers['go_version']=='go version go1.26.11 linux/amd64' and len(providers['ipks'])==16,'provider inventory differs')
    for row in candidates:
        matches=[item for item in providers['ipks'].values() if item['path']==row['path']]
        need(len(matches)==1 and all(matches[0][key]==row[key] for key in ('path','retained_path','sha256','size','mode')),'provider inventory row differs')
    verify_controls(ROOT,controls)
    verify_kernel_and_diagnostics(ROOT)
    timing=obj(file_bytes(ROOT,'offline-timing/invocation.json'))
    for name, value in timing['outputs'].items():need(sha(file_bytes(ROOT,'offline-timing/'+name))==value,'offline timing output differs')
    need(timing['exit']==0 and file_bytes(ROOT,'offline-timing/comparison.receipt.json')==file_bytes(ROOT,'raw/dockerman-package-comparison.json') and b'0.24 real' in file_bytes(ROOT,'offline-timing/comparison.time-and-stderr') and b'24231936  maximum resident set size' in file_bytes(ROOT,'offline-timing/comparison.time-and-stderr'),'offline timing differs')
    print(verify_app(ROOT),'Dockerman source/prepared/stage/IPK members verified')

if __name__=='__main__':main()
