#!/usr/bin/env python3
"""Verify retained Statistics package evidence without a build."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import re
import types
ROOT=Path(__file__).resolve().parent
archive=None
ANCHORS={'archive.py':'224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100','source-oracle.json':'a5ab0a2b8f0099073a040b57ec4be3324a874d2f67ec3951a62a18cfa886cf4f','graph_scope.py':'2a7cb2482b57f6e8b20148fca3911e3365a8bb9d449645067634272c3f53400a','raw-manifest.json':'959cd80cb2e5db81cca242f5a4f6c0c25b88dbadb313d5a62577fb0bb25a2814','source/LICENSE':'43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1','source/NOTICE':'0f815375cd41a2cd9f297bcd640eb174af287ba2f3ae0262382f4b0c3ee5c9f2','source/luci.mk':'9716c9a7a1c276b867df5887558e2b63b78f7d3695915adb7fcd0a7f0182ed0d'}
ANCHORS.update({'offline-timing/compare_retained.py':'07b523560e0a364a28d8699e86aa9925b9d7409434d865b444e94431bd4dedad','offline-timing/invocation.json':'dcd14839f03fb82273106fa256c1108fe2affa7b5ac7a744d228cf2b330f5cb1','offline-timing/comparison.stdout':'59342ad4f2cd04764a402b9e975f1c1294aa5b92d65bf209e3a48fe76351fc14','offline-timing/comparison.stderr':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','offline-timing/comparison.time-and-stderr':'91e824f7a08b4ceeec3f3e7dd447af19a4e459f9b1354543021e522c39228a93'})
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




def verify_package(root, oracle):
    load_archive(root)
    ipk=file_bytes(root,'raw/luci-app-statistics.ipk')
    need(sha(ipk)=='66d275801b8c28134891c20be92c79c243614107f3299270ebd9c1f56e4fc08a', 'IPK digest differs')
    need(file_bytes(root,'raw/candidate-luci-app-statistics_26.205.85817~58d43e5_all.ipk')==ipk,'candidate IPK differs')
    receipt=obj(file_bytes(root,'raw/statistics-comparison.json'))
    need(sha(file_bytes(root,'raw/statistics-comparison.json'))=='4fdcb1312dd7aeb9e757be5ff5a97d883b6772424c49e61cddba52c113b84ac4','comparison receipt differs')
    need(receipt['ipk_sha256']==sha(ipk) and receipt['config_sha256']=='cbff738c953271533651885c3759d6a5ba6b845c61b23a1e7aca7059f552d8ff' and receipt['oracle_sha256']==ANCHORS['source-oracle.json'] and receipt['graph_scope_sha256']=='4d8e05cff63f11484fdacdc7b0c0adfedd3340dbedcb7bef6929b0e982cfd7f9' and receipt['graph_scope_rows']==2781, 'comparison context differs')
    ctl,members,outer=archive.read_ipk(ipk)
    need(ctl['conffiles']['bytes']==b'/etc/config/luci_statistics\n','conffiles differs')
    candidates=json.loads(file_bytes(root,'raw/statistics-candidates.json'))
    need(candidates==[{'name':'luci-app-statistics_26.205.85817~58d43e5_all.ipk','sha256':sha(ipk),'size':len(ipk)}],'candidate inventory differs')
    need(control_fields(ctl)==receipt['package']=={'Package':'luci-app-statistics','Version':'26.205.85817~58d43e5','Architecture':'all'},'package control differs')
    need(archive.receipts(ctl)==receipt['archive_control_members'] and archive.receipts(members)==receipt['archive_data_members'] and outer==receipt['outer_member_sha256'],'archive receipts differ')
    rows=[x for x in oracle['entries'] if x['package']=='luci-app-statistics']
    need(len(rows)==175,'source inventory count differs')
    for row in rows:
        source=file_bytes(root,'source/'+row['source_path'])
        need(sha(source)==row['sha256'] and blob(source)==row['git_object'],'source identity differs')
        need(format(stat.S_IMODE((root/'source'/row['source_path']).stat().st_mode),'04o')==('0755' if row['git_mode']=='100755' else '0644'),'source mode differs')
    projected={row['projected_member']:row for row in rows if row['projected_member']}
    regular={name:row for name,row in members.items() if row['type']=='file'}
    need(len(projected)==len(regular)==126 and set(projected)==set(regular),'projected member set differs')
    receipt_rows={row['path']:row for row in receipt['members']}
    need(len(receipt_rows)==126 and set(receipt_rows)==set(regular),'comparison members differ')
    for name,row in projected.items():
        source=file_bytes(root,'source/'+row['source_path']); actual=regular[name]; recorded=receipt_rows[name]
        digest=sha(source); mode=row['source_mode_projected']
        need(sha(actual['bytes'])==digest==recorded['source_sha256']==recorded['prepared_sha256']==recorded['stage_sha256']==recorded['ipk_sha256'],'member bytes differ')
        need(format(actual['mode'],'04o')==mode==recorded['prepared_mode']==recorded['stage_mode']==recorded['ipk_mode'] and recorded['source_path']==row['source_path'] and recorded['source_git_mode']==row['git_mode'],'member mode or lineage differs')
    return len(regular)

def verify_kernel(root):
    load_archive(root)
    config=file_bytes(root,'raw/config-final'); need(sha(config)=='cbff738c953271533651885c3759d6a5ba6b845c61b23a1e7aca7059f552d8ff','config differs')
    need(file_bytes(root,'raw/metadata-pre-build-config')==config,'pre-build config differs')
    need(sha(file_bytes(root,'raw/kernel-config'))=='10bcab859188cc3602488c42507780a0de7c6336e537494a475db9526476591f' and file_bytes(root,'raw/kernel-vermagic')==b'd06fc8e744142971fdfa96b50c6d006f\n','kernel identity differs')
    version='6.12.116~d06fc8e744142971fdfa96b50c6d006f-r1'
    need(file_bytes(root,'raw/kernel-version')==(version+'\n').encode(),'kernel version differs')
    ipk=file_bytes(root,'raw/kernel.ipk');need(sha(ipk)=='3f45007bbdbad6d0c171adc06cb1b7e667ff1895d9ce909986fbe3f9a78ab25e','kernel IPK differs')
    ctl,rows,_=archive.read_ipk(ipk);need(control_fields(ctl)=={'Package':'kernel','Version':version,'Architecture':'x86_64'},'kernel control differs')
    builtin=file_bytes(root,'raw/kernel-modules.builtin');projected=b''.join(x.rsplit(b'/',1)[-1] for x in builtin.splitlines(keepends=True))
    need(rows['lib/modules/6.12.116/modules.builtin']['bytes']==projected,'kernel builtin differs')
    modinfo=file_bytes(root,'raw/kernel-modules.builtin.modinfo')
    chunks=re.findall(rb'[\t\x20-\x7e]{4,}',modinfo)
    projected_info=b''.join(chunk+b'\0' for chunk in chunks if not re.search(rb'\.(file|parmtype)=',chunk))
    need(b'CONFIG_MODULE_STRIPPED=y' in file_bytes(root,'raw/kernel-config').splitlines() and len(builtin.splitlines())==297 and len(projected_info.split(b'\0'))-1==501 and rows['lib/modules/6.12.116/modules.builtin.modinfo']['bytes']==projected_info,'kernel modinfo projection differs')
    packages=obj(file_bytes(root,'raw/kernel-packages.json')); package=packages['kernel_'+version+'_x86_64.ipk']
    need(package['sha256']==sha(ipk) and package['control']==control_fields(ctl),'kernel receipt differs')
    for name in ('modules.builtin','modules.builtin.modinfo'):
        path='lib/modules/6.12.116/'+name; row=rows[path]; expected=package['builtin_metadata'][path]
        need(row['mode']==0o644 and expected=={'mode':'0644','sha256':sha(row['bytes']),'size':len(row['bytes'])},'kernel metadata receipt differs')
    need(obj(file_bytes(root,'raw/kernel-inventory.json'))==obj(file_bytes(root,'raw/kernel-inventory-after.json')),'kernel inventory differs')
    prior=obj(file_bytes(root,'raw/kernel-warning-disposition.json')); app=obj(file_bytes(root,'raw/statistics-warning-disposition.json'))
    expected={'WARNING: kmod-drm-exec is not available in the kernel config - generating empty package','WARNING: kmod-drm-suballoc-helper is not available in the kernel config - generating empty package'}
    need(app['kernel_warning_disposition']==prior and set(prior['warnings'])==set(app['warnings'])==expected and len(app['warnings'])==len(prior['warnings'])==2,'warning disposition differs')
    for phase in ('kernel-package-compile','statistics-compile'):
        lines=file_bytes(root,'raw/'+phase+'.stderr').decode().splitlines()
        actual=[x for x in lines if re.fullmatch(r'WARNING: .+ is not available in the kernel config - generating empty package',x)]
        need(len(actual)==2 and set(actual)==expected,'actual kernel warnings differ')
        need(not any(re.fullmatch(r"ERROR: module '.+' is missing\.",x) for x in lines),'missing kernel module')

def verify_timing(root):
    invocation=obj(file_bytes(root,'offline-timing/invocation.json'))
    need(invocation['exit']==0 and invocation['cpu']=='arm64' and invocation['hosted_source']['run']==45800745811,'offline timing context differs')
    for name, value in invocation['outputs'].items():
        need(sha(file_bytes(root,'offline-timing/'+name))==value,'offline timing output differs')
    sample=obj(file_bytes(root,'offline-timing/comparison.stdout'))
    need(sample['compared_member_count']==126 and sample['ipk_sha256']=='66d275801b8c28134891c20be92c79c243614107f3299270ebd9c1f56e4fc08a','offline timing sample differs')
    report=file_bytes(root,'offline-timing/comparison.time-and-stderr')
    need(b'0.47 real' in report and b'22020096  maximum resident set size' in report,'offline timing metrics differ')

def main():
    inventory(ROOT)
    manifest=obj(file_bytes(ROOT,'raw-manifest.json')); actual={p.relative_to(ROOT/'raw').as_posix() for p in (ROOT/'raw').rglob('*') if p.is_file()}
    need(len(manifest)==34 and set(manifest)==actual,'raw inventory differs')
    for path,value in manifest.items():need(sha(file_bytes(ROOT,'raw/'+path))==value,'raw artifact differs')
    result=obj(file_bytes(ROOT,'raw/manifest.json'))
    for path, value in manifest.items():
        if path != 'manifest.json': need(result['output_sha256'].get(path)==value,'run manifest output differs')
    need(result['status']=='statistics_package_compared_review_required' and result['graph_scope_rows']==2781 and result['graph_scope_sha256']=='4d8e05cff63f11484fdacdc7b0c0adfedd3340dbedcb7bef6929b0e982cfd7f9','run status or scope differs')
    comparison=obj(file_bytes(ROOT,'raw/statistics-comparison.json'))
    need(comparison['graph_sha256']==result['locked_graph_sha256'] and comparison['kernel_inventory_sha256']==sha(file_bytes(ROOT,'raw/kernel-inventory.json')),'comparison run identity differs')
    labels=['pre-build','tools-install-before','tools-install-after','toolchain-install-before','toolchain-install-after','kernel-compile-before','kernel-compile-after','kernel-package-compile-before','kernel-package-compile-after','statistics-compile-before','statistics-compile-after','statistics-comparison','final']
    for label in labels:
        need(result['output_sha256'].get('metadata-'+label+'-config')=='cbff738c953271533651885c3759d6a5ba6b845c61b23a1e7aca7059f552d8ff' and result['output_sha256'].get('metadata-'+label+'-packagedeps')==result['locked_graph_sha256'],'run graph snapshot differs')
    graph=file_bytes(ROOT,'raw/metadata-pre-build-packagedeps'); config=file_bytes(ROOT,'raw/config-final')
    need(sha(graph)==result['locked_graph_sha256'],'graph lock differs')
    graph_source=file_bytes(ROOT,'graph_scope.py')
    need(sha(graph_source)==ANCHORS['graph_scope.py'],'graph parser differs')
    module=types.ModuleType('graph_scope');exec(compile(graph_source,str(ROOT/'graph_scope.py'),'exec'),module.__dict__)
    need(sha(module.scope(graph,config))==result['graph_scope_sha256'],'graph scope differs')
    verify_kernel(ROOT)
    verify_timing(ROOT)
    oracle=obj(file_bytes(ROOT,'source-oracle.json'));print(verify_package(ROOT,oracle),'Statistics members equal pinned source; stage/prepared runner-attested')

if __name__=='__main__':main()
