#!/usr/bin/env python3
"""Source-first comparator for three independently retained LuCI app IPKs."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path, PurePosixPath
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'luci-base-inventory'))
import archive
spec=importlib.util.spec_from_file_location('base_compare', Path(__file__).resolve().parent.parent/'luci-base-inventory'/'compare.py')
base=importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
ORACLE_SHA256='05906176f0830f311e2872d9d4b7743825cb80dfe1cb89af22673feac212d72a'
LUCI_SHA='cb87fe60e1e2e052af36a93647f2264577829e0a'
OPENWRT_SHA='4e9642517b48bae612ff10fb72fb9199e559500e'
PACKAGES_SHA='07e0d16305d2b5903b37ad7913e33e18795f81a4'
NAMES=('luci-app-ddns','luci-app-advanced-reboot','luci-app-wifihistory')
DDNS_RECIPE={'source_path':'net/ddns-scripts/Makefile','git_mode':'100644','git_blob':'c0f6aef5047bd4b07f1e1708557bdf41ff763c34','source_sha256':'eaf326cffdd5436c0fe039030b40279a24ab2b7104dc7ddd5fa014957c66177b'}

def digest(data): return hashlib.sha256(data).hexdigest()
def unique(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError('duplicate JSON key: '+k)
        out[k]=v
    return out

def load_oracle(path):
    data=path.read_bytes()
    if digest(data)!=ORACLE_SHA256: raise ValueError('source oracle digest differs')
    return json.loads(data,object_pairs_hook=unique)

def git_blob(repo,rev,row):
    path=row['source_path']; info=base.git(repo,'ls-tree',rev,'--',path).split('\t',1)
    if len(info)!=2 or info[1]!=path or info[0].split()!=[row['git_mode'],'blob',row['git_blob']]: raise ValueError('Git identity differs: '+path)
    body=subprocess.check_output(['git','-C',str(repo),'show',rev+':'+path])
    if digest(body)!=row.get('source_sha256',row.get('sha256')): raise ValueError('source hash differs: '+path)
    return body

def package_rows(package): return package['source_rows']
def generated_merge(pkg,luci):
    custom=pkg['custom_prepare_projection']
    bodies=[git_blob(luci,LUCI_SHA,{'source_path':p,'git_blob':next(r['git_blob'] for r in pkg['source_rows'] if r['source_path']==p),'git_mode':next(r['git_mode'] for r in pkg['source_rows'] if r['source_path']==p),'source_sha256':next(r['source_sha256'] for r in pkg['source_rows'] if r['source_path']==p)}) for p in custom['merge_inputs_filename_order']]
    return b'['+b','.join(bodies)+b']'

def prepare_expected(oracle,luci,packages):
    base.pinned_clean('luci',luci)
    base.pinned_clean('packages',packages)
    if base.git(luci,'rev-parse','HEAD')!=LUCI_SHA: raise ValueError('LuCI pin differs')
    if base.git(packages,'rev-parse','HEAD')!=PACKAGES_SHA: raise ValueError('packages feed pin differs')
    git_blob(packages,PACKAGES_SHA,DDNS_RECIPE)
    if digest(subprocess.check_output(['git','-C',str(luci),'show',LUCI_SHA+':luci.mk']))!=oracle['luci_mk']['sha256']: raise ValueError('luci.mk digest differs')
    for name,pkg in oracle['packages'].items():
        for row in pkg['source_rows']+pkg['candidate_inventory_rows']+pkg['excluded_test_fixture_candidates']:
            git_blob(luci,LUCI_SHA,row)
        git_blob(luci,LUCI_SHA,pkg['recipe'])
        if pkg.get('custom_prepare_projection'):
            merged=generated_merge(pkg,luci); projection=pkg['custom_prepare_projection']
            if digest(merged)!=projection['projected_sha256_under_C_locale'] or len(merged)!=projection['projected_bytes'] or b'\"device\"' not in merged:
                raise ValueError('advanced-reboot generated merge projection differs')
        if pkg['recipe']['projected_control_version'] is None: raise ValueError('unfrozen version projection: '+name)
    return True

def config_facts(root, package):
    facts=base.build_inputs(root); lines=(root/'.config').read_text().splitlines()
    for name in NAMES:
        symbol='CONFIG_PACKAGE_'+name
        seen=[x for x in lines if x.startswith(symbol+'=') or x=='# '+symbol+' is not set']
        expected=[symbol+'=m'] if name in package['batch']['packages'] else ['# '+symbol+' is not set']
        if seen!=expected: raise ValueError('selected package config differs: '+name)
    js=[x for x in lines if x.startswith('CONFIG_LUCI_JSMIN=') or x=='# CONFIG_LUCI_JSMIN is not set']
    if len(js)!=1 or js[0] not in ('CONFIG_LUCI_JSMIN=y','CONFIG_LUCI_JSMIN=n','# CONFIG_LUCI_JSMIN is not set'): raise ValueError('JS minification config missing/ambiguous')
    facts['js_minification']=js[0]=='CONFIG_LUCI_JSMIN=y'
    runtime=set()
    for name in NAMES:
        runtime.update(x[1:] for x in package['packages'][name]['recipe']['runtime_dependencies'].split() if x.startswith('+'))
    dependency_modes={}
    for dep in sorted(runtime-{'luci-base'}):
        symbol='CONFIG_PACKAGE_'+dep
        seen=[x for x in lines if x.startswith(symbol+'=') or x=='# '+symbol+' is not set']
        if len(seen)!=1 or seen[0] not in (symbol+'=m',symbol+'=y'): raise ValueError('runtime dependency config must resolve exactly once to m or y: '+dep)
        dependency_modes[dep]=seen[0].split('=',1)[1]
    if 'CONFIG_PER_FEED_REPO=y' not in lines: raise ValueError('per-feed package repository must be enabled')
    if 'CONFIG_USE_MUSL=y' not in lines: raise ValueError('musl target configuration is required')
    css=[x for x in lines if x.startswith('CONFIG_LUCI_CSSTIDY=') or x=='# CONFIG_LUCI_CSSTIDY is not set']
    if len(css)!=1 or css[0] not in ('CONFIG_LUCI_CSSTIDY=y','CONFIG_LUCI_CSSTIDY=n','# CONFIG_LUCI_CSSTIDY is not set'): raise ValueError('CSS minification config missing/ambiguous')
    facts['dependency_modes']=dependency_modes
    facts['css_minification']=css[0]=='CONFIG_LUCI_CSSTIDY=y'
    return facts

def safe_file(root,relative):
    cur=root
    if not relative or relative.startswith('/') or '\\' in relative or PurePosixPath(relative).as_posix()!=relative: raise ValueError('unsafe relative path: '+relative)
    for part in PurePosixPath(relative).parts:
        if part in ('','.','..'): raise ValueError('unsafe relative path: '+relative)
        cur=cur/part
        if cur.is_symlink(): raise ValueError('symlink in path: '+str(cur))
    if not cur.is_file(): raise ValueError('missing regular file: '+str(cur))
    return cur.read_bytes(),cur.stat().st_mode&0o7777

def stage_inventory(stage):
    result=set()
    for p in stage.rglob('*'):
        if p.is_symlink(): raise ValueError('stage symlink: '+str(p))
        if p.is_file(): result.add(p.relative_to(stage).as_posix())
        elif not p.is_dir(): raise ValueError('stage special file: '+str(p))
    return result

def expected_members(pkg):
    rows=package_rows(pkg); expected={}
    for row in rows:
        path=row['projected_member']
        if path:
            if path in expected: raise ValueError('duplicate projected path: '+path)
            expected[path]=row
    custom=pkg.get('custom_prepare_projection')
    if custom:
        path=custom['projected_output']
        if path in expected: raise ValueError('generated path collides')
        expected[path]={'classification':'generated_advanced_devices','projected_member':path,'projected_mode':custom['projected_mode_under_umask_022'],'source_path':None}
    return expected

def compare_one(name,pkg,luci,prepared,stage,ipk,js_minification):
    expected=expected_members(pkg); control,members,outer=archive.read_ipk(ipk)
    fields=base.control_from_rows(control); recipe=pkg['recipe']
    if fields!={'Package':name,'Version':recipe['projected_control_version'],'Architecture':'all'}: raise ValueError('IPK control identity differs: '+name)
    if any(p=='CONTROL' or p.startswith('CONTROL/') for p in members): raise ValueError('data archive uses reserved CONTROL namespace')
    actual={p for p,r in members.items() if r['type']=='file'}; stagefiles=stage_inventory(stage)
    cfiles={p for p,r in control.items() if r['type']=='file'}
    if stagefiles!=actual|{'CONTROL/'+p for p in cfiles}: raise ValueError('stage/IPK complete file set differs: '+name)
    for p in cfiles:
        data,mode=safe_file(stage,'CONTROL/'+p)
        if data!=control[p]['bytes'] or mode!=control[p]['mode']: raise ValueError('CONTROL mismatch: '+p)
    if actual!=set(expected): raise ValueError('package membership differs; missing=%r extra=%r'%(sorted(set(expected)-actual),sorted(actual-set(expected))))
    rows=[]
    for path,row in expected.items():
        item=members[path]; staged,smode=safe_file(stage,path); mode=int(row['projected_mode'],8) if isinstance(row['projected_mode'],str) else int(row['projected_mode'])
        if item['type']!='file' or item['mode']!=mode or smode!=mode or staged!=item['bytes']: raise ValueError('stage/IPK member bytes or mode differ: '+path)
        disposition=row['classification']; srcsha=None; prep_sha=None; prep_mode=None; provenance='observed_only'
        if row.get('source_path'):
            source=git_blob(luci,LUCI_SHA,row)
            srcsha=digest(source)
            local=row['source_path'].removeprefix(pkg['source_directory']+'/')
            # Normal root/htdocs copies are present under the package PKG_BUILD_DIR.
            if row['source_root']!='root' and row['source_root']!='htdocs': raise ValueError('unexpected direct source root')
            p_rel=local
            prepped,prep_mode=safe_file(prepared,p_rel)
            if prepped!=source or prep_mode!=int(row['git_mode'][-3:],8): raise ValueError('prepared source mismatch: '+row['source_path'])
            prep_sha=digest(prepped)
            if disposition=='auxiliary_htdocs_js' and js_minification:
                provenance='js_minification_unverified'
            elif digest(item['bytes'])==srcsha:
                provenance='source_equal'
            else: raise ValueError('source copy or configured transform differs: '+path)
        elif disposition=='generated_advanced_devices':
            custom=pkg['custom_prepare_projection']; expected_sha=custom['projected_sha256_under_C_locale']
            generated,generated_mode=safe_file(prepared,'root/'+custom['projected_output'])
            if digest(generated)!=expected_sha or len(generated)!=custom['projected_bytes'] or generated_mode!=int(custom['projected_mode_under_umask_022'],8): raise ValueError('prepared advanced-reboot merge differs')
            if digest(item['bytes'])!=expected_sha or len(item['bytes'])!=custom['projected_bytes']: raise ValueError('generated advanced-reboot stage/IPK merge differs')
            prep_sha=digest(generated); prep_mode=generated_mode
            provenance='recipe_generated_projection; individual inputs removed during Prepare'
        source_inputs=[]
        if disposition=='generated_advanced_devices':
            source_by_path={r['source_path']:r for r in pkg['source_rows']}
            source_inputs=[{'source_path':p,'git_blob':source_by_path[p]['git_blob'],'git_mode':source_by_path[p]['git_mode'],'source_sha256':source_by_path[p]['source_sha256']} for p in pkg['custom_prepare_projection']['merge_inputs_filename_order']]
        rows.append({'path':path,'classification':disposition,'source_path':row.get('source_path'),'source_git_blob':row.get('git_blob'),'source_git_mode':row.get('git_mode'),'source_sha256':srcsha,'source_inputs':source_inputs,'prepared_sha256':prep_sha,
                     'prepared_mode':format(prep_mode,'04o') if prep_mode is not None else None,
                     'stage_sha256':digest(staged),'stage_mode':format(smode,'04o'),
                     'ipk_sha256':digest(item['bytes']),'ipk_mode':format(item['mode'],'04o'),
                     'transform_provenance':provenance})
    if name=='luci-app-advanced-reboot':
        # This hook consumes and deletes the source directories; absence is the only post-Prepare fact.
        for removed in pkg['custom_prepare_projection']['removed_source_paths']:
            local=removed.removeprefix(pkg['source_directory']+'/')
            if (prepared/local).exists() or (prepared/local).is_symlink(): raise ValueError('removed source directory unexpectedly remains: '+local)
        for rel in ('root/usr/share/advanced-reboot/devices','root/usr/share/advanced-reboot/devices.disabled'):
            if (prepared/rel).exists() or (prepared/rel).is_symlink(): raise ValueError('recipe-removed directory remains: '+rel)
    return {'package':name,'control':fields,'ipk_sha256':digest(ipk),'outer_member_sha256':outer,'members':rows,
            'archive_data_members':archive.receipts(members),'archive_control_members':archive.receipts(control),
            'js_minification_enabled':js_minification}

def physical_under(path,root,label,must_exist=True):
    path=Path(path); root=Path(root).resolve(strict=True)
    lexical=Path(os.path.abspath(path))
    if not path.is_absolute() or lexical!=path: raise ValueError(label+' path must be absolute and canonical')
    try: lexical.relative_to(root)
    except ValueError as exc: raise ValueError(label+' outside trusted root') from exc
    cur=root
    for part in lexical.relative_to(root).parts:
        cur=cur/part
        if cur.is_symlink(): raise ValueError(label+' contains symlink component')
    if must_exist:
        resolved=lexical.resolve(strict=True)
        if resolved!=lexical: raise ValueError(label+' path is aliased')
    elif lexical.exists() or lexical.is_symlink(): raise ValueError(label+' output path already exists')
    return lexical

def verify_ipk_pair(built_arg,retained_arg,config_root,run_root,name,version):
    built=physical_under(built_arg,config_root,'built package IPK')
    retained=physical_under(retained_arg,run_root/'output','retained IPK')
    expected=config_root/'bin/packages/x86_64/luci'/f'{name}_{version}_all.ipk'
    if built!=expected: raise ValueError('built IPK must be the exact x86_64/luci feed artifact')
    if retained.parent!=run_root/'output' or retained.name!=name+'.ipk': raise ValueError('retained IPK path differs')
    if not retained.is_file() or retained.is_symlink() or not built.is_file() or built.is_symlink(): raise ValueError('built and retained IPKs must be regular files')
    if retained.read_bytes()!=built.read_bytes(): raise ValueError('retained IPK differs from exact built feed artifact')
    return built,retained

def main():
    p=argparse.ArgumentParser(); p.add_argument('--luci',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--run-root',type=Path,required=True);p.add_argument('--preflight',action='store_true')
    p.add_argument('--config-root',type=Path);p.add_argument('--config-sha256');p.add_argument('--package',choices=NAMES);p.add_argument('--prepared',type=Path);p.add_argument('--stage',type=Path);p.add_argument('--built-ipk',type=Path);p.add_argument('--ipk',type=Path);p.add_argument('--receipt',type=Path)
    a=p.parse_args(); oracle=load_oracle(Path(__file__).with_name('source-oracle.json')); run=physical_under(a.run_root,a.run_root,'run root')
    if a.luci.resolve(strict=True)!=run/'luci' or a.packages.resolve(strict=True)!=run/'packages': raise ValueError('source feeds must be run-owned pinned checkouts')
    physical_under(a.luci,run,'LuCI source'); physical_under(a.packages,run,'packages source')
    prepare_expected(oracle,a.luci,a.packages)
    facts=None
    if a.config_root is not None:
        config_root=physical_under(a.config_root,run,'OpenWrt source')
        if config_root!=run/'openwrt': raise ValueError('OpenWrt path must be run-owned')
        base.pinned_clean('openwrt',config_root)
        if base.git(config_root,'rev-parse','HEAD')!=OPENWRT_SHA: raise ValueError('OpenWrt pin differs')
        base.require_feed_links(config_root,a.luci,a.packages)
        for name in NAMES:
            link=config_root/'package/feeds/luci'/name
            if not link.is_symlink() or link.resolve(strict=True)!=a.luci/'applications'/name: raise ValueError('LuCI package recipe feed link differs: '+name)
        package_link=config_root/'package/feeds/packages/ddns-scripts'
        if not package_link.is_symlink() or package_link.resolve(strict=True)!=a.packages/'net/ddns-scripts': raise ValueError('ddns-scripts feed link differs')
        facts=config_facts(config_root,oracle)
        if not a.config_sha256 or facts['config']['sha256']!=a.config_sha256: raise ValueError('frozen config digest differs')
    elif a.config_sha256:
        raise ValueError('config digest requires its run-owned OpenWrt root')
    if a.preflight:
        if any((a.package,a.prepared,a.stage,a.built_ipk,a.ipk,a.receipt)): raise ValueError('preflight forbids package output arguments')
        return
    if not all((a.package,a.prepared,a.stage,a.built_ipk,a.ipk,a.receipt,a.config_root,a.config_sha256)) or facts is None: raise ValueError('comparison arguments incomplete')
    pkg=oracle['packages'][a.package]
    prepared=physical_under(a.prepared,config_root,'prepared package tree'); stage=physical_under(a.stage,config_root,'package stage')
    if not prepared.is_relative_to(config_root/'build_dir') or not stage.is_relative_to(config_root/'build_dir'): raise ValueError('prepared/stage path outside build_dir')
    expected_stage=config_root/'build_dir/target-x86_64_musl'/a.package/'ipkg-all'/a.package
    if prepared!=expected_stage.parent.parent or stage!=expected_stage: raise ValueError('build/stage layout differs')
    version=pkg['recipe']['projected_control_version']
    built_ipk,ipk=verify_ipk_pair(a.built_ipk,a.ipk,config_root,run,a.package,version)
    receipt_path=physical_under(a.receipt,run/'output','receipt path',must_exist=False)
    if not receipt_path.parent.is_dir() or receipt_path.exists() or receipt_path.is_symlink(): raise ValueError('receipt must be a fresh exclusive output path')
    result=compare_one(a.package,pkg,a.luci,prepared,stage,built_ipk.read_bytes(),facts['js_minification'])
    result.update({'oracle_sha256':ORACLE_SHA256,'config':facts,'source_pins':{'luci':LUCI_SHA,'openwrt':OPENWRT_SHA,'packages':PACKAGES_SHA,'ddns_scripts_recipe':DDNS_RECIPE},'prepared_path':prepared.relative_to(config_root).as_posix(),'stage_path':stage.relative_to(config_root).as_posix(),'built_ipk_path':built_ipk.relative_to(config_root).as_posix(),'retained_ipk_path':ipk.relative_to(run).as_posix(),'built_ipk_sha256':digest(built_ipk.read_bytes()),'retained_ipk_sha256':digest(ipk.read_bytes())})
    with receipt_path.open('x') as f: f.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
if __name__=='__main__': main()
