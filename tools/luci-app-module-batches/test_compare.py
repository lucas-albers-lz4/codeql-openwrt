import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import compare


def tar_gz(rows):
    b=io.BytesIO()
    with tarfile.open(fileobj=b,mode='w:gz') as tf:
        for name,data,mode in rows:
            x=tarfile.TarInfo(name); x.size=len(data); x.mode=mode; tf.addfile(x,io.BytesIO(data))
    return b.getvalue()

def make_ipk(name,version,entries):
    control=f'Package: {name}\nVersion: {version}\nArchitecture: all\n'.encode()
    outer=[('debian-binary',b'2.0\n',0o644),('control.tar.gz',tar_gz([('control',control,0o644)]),0o644),('data.tar.gz',tar_gz(entries),0o644)]
    return tar_gz(outer),control

def sha(b): return hashlib.sha256(b).hexdigest()

class FrozenOracleTests(unittest.TestCase):
    def test_digest_and_three_package_membership(self):
        oracle=compare.load_oracle(Path(__file__).with_name('source-oracle.json'))
        self.assertEqual(set(oracle['packages']),set(compare.NAMES))
        self.assertEqual(oracle['source']['commit'],compare.LUCI_SHA)
        self.assertEqual(compare.DDNS_RECIPE['git_blob'],'c0f6aef5047bd4b07f1e1708557bdf41ff763c34')
        self.assertEqual(compare.DDNS_RECIPE['source_sha256'],'eaf326cffdd5436c0fe039030b40279a24ab2b7104dc7ddd5fa014957c66177b')
        self.assertEqual([oracle['packages'][n]['source_row_count'] for n in compare.NAMES],[5,54,6])
        self.assertEqual(len(oracle['packages']['luci-app-advanced-reboot']['custom_prepare_projection']['merge_inputs_filename_order']),44)
        self.assertEqual(oracle['packages']['luci-app-advanced-reboot']['custom_prepare_projection']['projected_sha256_under_C_locale'],'83338e92781a1535df23cc255cf76fdafd2a3fbaf21c6a64b0ef6c93e735c548')
        self.assertEqual(sum(r['classification']=='auxiliary_acl' for p in oracle['packages'].values() for r in p['source_rows']),3)
        self.assertEqual(sum(r['classification']=='selected source candidate' for p in oracle['packages'].values() for r in p['source_rows']),4)
    def test_oracle_mutation_and_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'oracle.json';p.write_text('{}')
            with self.assertRaisesRegex(ValueError,'digest'): compare.load_oracle(p)
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'): compare.unique([('a',1),('a',2)])
    def test_config_requires_exact_apps_dependencies_and_transform_setting(self):
        oracle=compare.load_oracle(Path(__file__).with_name('source-oracle.json'))
        deps=sorted({x[1:] for p in oracle['packages'].values() for x in p['recipe']['runtime_dependencies'].split() if x.startswith('+')})
        lines=['CONFIG_TARGET_x86=y','CONFIG_TARGET_x86_64=y','CONFIG_USE_MUSL=y','CONFIG_PACKAGE_luci-base=m']+[f'CONFIG_PACKAGE_{n}=m' for n in compare.NAMES]+[f'CONFIG_PACKAGE_{d}=m' for d in deps if d!='luci-base']+['CONFIG_PER_FEED_REPO=y','CONFIG_USE_APK=n','# CONFIG_LUCI_JSMIN is not set','# CONFIG_LUCI_CSSTIDY is not set']
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'feeds.conf').write_text('src-link luci ../../luci\nsrc-link packages ../../packages\n');(root/'.config').write_text('\n'.join(lines)+'\n')
            self.assertFalse(compare.config_facts(root,oracle)['js_minification'])
            (root/'.config').write_text('\n'.join(lines+['CONFIG_PACKAGE_ddns-scripts=y'])+'\n')
            with self.assertRaisesRegex(ValueError,'runtime dependency config must resolve exactly once'): compare.config_facts(root,oracle)
            y_lines=[line.replace('CONFIG_PACKAGE_ddns-scripts=m','CONFIG_PACKAGE_ddns-scripts=y') for line in lines]
            (root/'.config').write_text('\n'.join(y_lines)+'\n')
            self.assertEqual(compare.config_facts(root,oracle)['dependency_modes']['ddns-scripts'],'y')

class PackageFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.prepared=self.root/'prepared';self.stage=self.root/'stage';self.prepared.mkdir();self.stage.mkdir()
        self.name='luci-app-ddns';self.data=b'#!/usr/bin/env ucode\nreturn {};\n';self.path='usr/share/rpcd/ucode/ddns.uc';self.local='root/usr/share/rpcd/ucode/ddns.uc'
        self.row={'source_path':'applications/luci-app-ddns/'+self.local,'git_blob':'blob','git_mode':'100644','source_sha256':sha(self.data),'source_root':'root','source_path': 'applications/luci-app-ddns/'+self.local,'projected_member':self.path,'projected_mode':'644','classification':'selected source candidate'}
        self.pkg={'source_directory':'applications/luci-app-ddns','source_rows':[self.row],'recipe':{'projected_control_version':'26.280.64158~a450f0d'}}
        (self.prepared/self.local).parent.mkdir(parents=True);(self.prepared/self.local).write_bytes(self.data);(self.prepared/self.local).chmod(0o644)
        self.archive,self.control=make_ipk(self.name,self.pkg['recipe']['projected_control_version'],[(self.path,self.data,0o644)])
        self.put('CONTROL/control',self.control,0o644);self.put(self.path,self.data,0o644)
        self.patch=patch.object(compare,'git_blob',return_value=self.data);self.patch.start();self.addCleanup(self.patch.stop)
    def put(self,path,data,mode):
        p=self.stage/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(mode)
    def run_compare(self,data=None): return compare.compare_one(self.name,self.pkg,Path('/unused'),self.prepared,self.stage,data or self.archive,False)
    def test_valid_observed_member_has_separate_lineage(self):
        got=self.run_compare(); row=got['members'][0]
        self.assertEqual(row['source_sha256'],sha(self.data));self.assertEqual(row['prepared_sha256'],sha(self.data));self.assertEqual(row['stage_sha256'],sha(self.data));self.assertEqual(row['ipk_sha256'],sha(self.data))
    def test_rejects_wrong_package_control(self):
        bad,_=make_ipk('luci-app-wifihistory',self.pkg['recipe']['projected_control_version'],[(self.path,self.data,0o644)])
        with self.assertRaisesRegex(ValueError,'control identity'): self.run_compare(bad)
    def test_rejects_missing_candidate_and_unexpected_member(self):
        bad,_=make_ipk(self.name,self.pkg['recipe']['projected_control_version'],[])
        (self.stage/self.path).unlink()
        with self.assertRaisesRegex(ValueError,'membership differs'): self.run_compare(bad)
        self.put(self.path,self.data,0o644)
        self.put('extra',b'x',0o644)
        bad,_=make_ipk(self.name,self.pkg['recipe']['projected_control_version'],[(self.path,self.data,0o644),('extra',b'x',0o644)])
        with self.assertRaisesRegex(ValueError,'membership differs'): self.run_compare(bad)
    def test_rejects_stage_ipk_mode_or_prepared_drift(self):
        self.put(self.path,self.data,0o755)
        with self.assertRaisesRegex(ValueError,'bytes or mode'): self.run_compare()
        self.put(self.path,self.data,0o644);(self.prepared/self.local).chmod(0o755)
        with self.assertRaisesRegex(ValueError,'prepared source mismatch'): self.run_compare()
    def test_rejects_duplicate_archive_paths(self):
        bad,_=make_ipk(self.name,self.pkg['recipe']['projected_control_version'],[(self.path,self.data,0o644),(self.path,self.data,0o644)])
        with self.assertRaisesRegex(ValueError,'duplicate archive path'): self.run_compare(bad)
    def test_rejects_reserved_control_archive_namespace(self):
        bad,_=make_ipk(self.name,self.pkg['recipe']['projected_control_version'],[('CONTROL',b'',0o755)])
        with self.assertRaisesRegex(ValueError,'reserved CONTROL namespace'): self.run_compare(bad)
    def test_rejects_special_stage_mode_bits(self):
        p=self.stage/self.path;p.chmod(0o4644)
        with self.assertRaisesRegex(ValueError,'bytes or mode'): self.run_compare()
    def test_js_minification_is_explicitly_unknown_when_enabled(self):
        source=b'const original = true;\n'; packaged=b'const original=true;'; path='www/luci-static/resources/view.js'; local='htdocs/luci-static/resources/view.js'
        row={'source_path':'applications/luci-app-ddns/'+local,'git_blob':'jsblob','git_mode':'100644','source_sha256':sha(source),'source_root':'htdocs','projected_member':path,'projected_mode':'644','classification':'auxiliary_htdocs_js'}
        self.pkg['source_rows'].append(row); p=self.prepared/local; p.parent.mkdir(parents=True); p.write_bytes(source); p.chmod(0o644); self.put(path,packaged,0o644)
        entries=[(self.path,self.data,0o644),(path,packaged,0o644)]; data,_=make_ipk(self.name,self.pkg['recipe']['projected_control_version'],entries)
        with patch.object(compare,'git_blob',side_effect=lambda _repo,_rev,row: source if row['source_path'].endswith('view.js') else self.data):
            got=compare.compare_one(self.name,self.pkg,Path('/unused'),self.prepared,self.stage,data,True)
        self.assertEqual(next(r['transform_provenance'] for r in got['members'] if r['path']==path),'js_minification_unverified')
        with patch.object(compare,'git_blob',side_effect=lambda _repo,_rev,row: source if row['source_path'].endswith('view.js') else self.data):
            with self.assertRaisesRegex(ValueError,'source copy or configured transform'): compare.compare_one(self.name,self.pkg,Path('/unused'),self.prepared,self.stage,data,False)

class AdvancedMergeTests(unittest.TestCase):
    def test_exact_recipe_merge_and_changed_input(self):
        paths=['applications/luci-app-advanced-reboot/root/usr/share/advanced-reboot/devices/a.json','applications/luci-app-advanced-reboot/root/usr/share/advanced-reboot/devices/b.json']
        rows=[];body={paths[0]:b'{"device":"a"}',paths[1]:b'{"device":"b"}'}
        for i,p in enumerate(paths): rows.append({'source_path':p,'git_blob':str(i),'git_mode':'100644','source_sha256':sha(body[p])})
        pkg={'source_rows':rows,'custom_prepare_projection':{'merge_inputs_filename_order':paths}}
        with patch.object(compare,'git_blob',side_effect=lambda _repo,_rev,row:body[row['source_path']]):
            merged=compare.generated_merge(pkg,Path('/unused'))
        self.assertEqual(merged,b'[{"device":"a"},{"device":"b"}]')
        self.assertEqual(sha(merged),compare.digest(merged))
        body[paths[0]]=b'changed'
        with patch.object(compare,'git_blob',side_effect=lambda _repo,_rev,row:body[row['source_path']]):
            self.assertNotEqual(sha(compare.generated_merge(pkg,Path('/unused'))),sha(merged))
    def test_generated_member_keeps_prepared_stage_ipk_boundaries(self):
        paths=['applications/luci-app-advanced-reboot/root/usr/share/advanced-reboot/devices/a.json','applications/luci-app-advanced-reboot/root/usr/share/advanced-reboot/devices/b.json']
        source_rows=[{'source_path':p,'git_blob':f'blob{i}','git_mode':'100644','source_sha256':sha(bytes([i])),'projected_member':None} for i,p in enumerate(paths)]
        custom={'projected_output':'usr/share/advanced-reboot/devices.json','projected_mode_under_umask_022':'0644','projected_sha256_under_C_locale':sha(b'[]'),'projected_bytes':2,'removed_source_paths':[],'merge_inputs_filename_order':paths}
        pkg={'source_directory':'applications/luci-app-advanced-reboot','source_rows':source_rows,'custom_prepare_projection':custom,'recipe':{'projected_control_version':'1.1.2-r6'}}
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); prepared=root/'prepared';stage=root/'stage';prepared.mkdir();stage.mkdir(); raw=b'[]'; path=custom['projected_output']
            pp=prepared/'root'/path;pp.parent.mkdir(parents=True);pp.write_bytes(raw);pp.chmod(0o644)
            sp=stage/path;sp.parent.mkdir(parents=True);sp.write_bytes(raw);sp.chmod(0o644)
            control=f'Package: luci-app-advanced-reboot\nVersion: 1.1.2-r6\nArchitecture: all\n'.encode();cp=stage/'CONTROL/control';cp.parent.mkdir();cp.write_bytes(control);cp.chmod(0o644)
            data,_=make_ipk('luci-app-advanced-reboot','1.1.2-r6',[(path,raw,0o644)])
            got=compare.compare_one('luci-app-advanced-reboot',pkg,Path('/unused'),prepared,stage,data,False)
            self.assertEqual(got['members'][0]['prepared_sha256'],sha(raw));self.assertEqual(len(got['members'][0]['source_inputs']),2);pp.write_bytes(b'[ ]')
            with self.assertRaisesRegex(ValueError,'prepared advanced-reboot merge'): compare.compare_one('luci-app-advanced-reboot',pkg,Path('/unused'),prepared,stage,data,False)
            pp.write_bytes(raw); removed=prepared/'root/usr/share/advanced-reboot/devices'; removed.parent.mkdir(parents=True,exist_ok=True); removed.symlink_to(root/'missing',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'recipe-removed directory remains'): compare.compare_one('luci-app-advanced-reboot',pkg,Path('/unused'),prepared,stage,data,False)

class PhysicalPathTests(unittest.TestCase):
    def test_exact_built_and_retained_ipk_identity(self):
        with tempfile.TemporaryDirectory() as t:
            run=Path(__import__('os').path.realpath(t));output=run/'output';output.mkdir();config=run/'openwrt';built=config/'bin/packages/x86_64/luci/luci-app-ddns_26.280.64158~a450f0d_all.ipk';built.parent.mkdir(parents=True);built.write_bytes(b'ipk')
            retained=output/'luci-app-ddns.ipk';retained.write_bytes(b'ipk')
            got=compare.verify_ipk_pair(built,retained,config,run,'luci-app-ddns','26.280.64158~a450f0d')
            self.assertEqual(got,(built,retained))
            retained.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'retained IPK differs'): compare.verify_ipk_pair(built,retained,config,run,'luci-app-ddns','26.280.64158~a450f0d')
            retained.write_bytes(b'ipk')
            with self.assertRaisesRegex(ValueError,'exact x86_64/luci'): compare.verify_ipk_pair(built,retained,config,run,'luci-app-ddns','wrong-version')
    def test_rejects_symlink_aliases_and_dangling_output_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(__import__('os').path.realpath(t)); real=root/'real';real.mkdir();(real/'file').write_text('x');alias=root/'alias';alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'outside trusted root|symlink component'): compare.physical_under(alias/'file',root,'file')
            dangling=root/'fresh';dangling.symlink_to(root/'absent')
            with self.assertRaisesRegex(ValueError,'outside trusted root|symlink component'): compare.physical_under(dangling,root,'output',must_exist=False)
            self.assertEqual(compare.physical_under(real/'file',root,'file').read_text(),'x')

if __name__=='__main__': unittest.main()
