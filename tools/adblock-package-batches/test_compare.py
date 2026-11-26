import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import compare


def pack(entries):
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w:gz') as tf:
        for name,body,mode in entries:
            x=tarfile.TarInfo(name);x.size=len(body);x.mode=mode;tf.addfile(x,io.BytesIO(body))
    return buf.getvalue()

def ipk(package, entries):
    c=b'Package: '+package.encode()+b'\nVersion: 1.2.4-r4\nArchitecture: all\n'
    control=pack([('control',c,0o644)])
    return pack([('debian-binary',b'2.0\n',0o644),('control.tar.gz',control,0o644),('data.tar.gz',pack(entries),0o644)]), c

class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.stage=self.root/'stage';self.stage.mkdir()
        self.data=b'version=1.2.4-r4\n';self.source=b'version=old\n'
        self.row={'source_path':'net/adblock-fast/files/lib/adblock-fast/adblock-fast.uc','git_blob':'blob','git_mode':'100644','source_sha256':compare.digest(self.source),'projected_member':'lib/adblock-fast/adblock-fast.uc','expected_member_mode':'0644','expected_member_sha256':compare.digest(self.data),'expected_member_size':len(self.data),'recipe_action':'version_sed'}
        self.oracle={'source_mapping':[self.row]}
        self.archive,self.control=ipk('adblock-fast',[(self.row['projected_member'],self.data,0o644)])
        self.put('CONTROL/control',self.control,0o644);self.put(self.row['projected_member'],self.data,0o644)
        self.mock=patch.object(compare,'git_blob',return_value=self.source);self.mock.start();self.addCleanup(self.mock.stop)
    def put(self,path,data,mode):
        p=self.stage/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(mode)
    def inspect(self, data=None): return compare.inspect_package('service',self.oracle,self.root,self.stage,data or self.archive)
    def test_expected_service_recipe_and_control(self):
        r=self.inspect();self.assertEqual(r['control']['Package'],'adblock-fast');self.assertEqual(r['source_mappings'][0]['staged_sha256'],compare.digest(self.data))
    def test_rejects_swapped_package(self):
        data,_=ipk('luci-app-adblock-fast',[(self.row['projected_member'],self.data,0o644)])
        with self.assertRaisesRegex(ValueError,'package control identity'): self.inspect(data)
    def test_rejects_wrong_transformed_bytes(self):
        self.row['expected_member_sha256']=compare.digest(b'wrong')
        with self.assertRaisesRegex(ValueError,'service recipe bytes differ'): self.inspect()
    def test_rejects_wrong_installed_mode(self):
        self.row['expected_member_mode']='0600'
        with self.assertRaisesRegex(ValueError,'member mode differs'): self.inspect()
    def test_rejects_extra_even_if_stage_matches(self):
        self.put('extra',b'x',0o644)
        data,_=ipk('adblock-fast',[(self.row['projected_member'],self.data,0o644),('extra',b'x',0o644)])
        with self.assertRaisesRegex(ValueError,'unexpected package files'): self.inspect(data)
    def test_rejects_stage_and_control_drift(self):
        self.put(self.row['projected_member'],b'changed',0o644)
        with self.assertRaisesRegex(ValueError,'stage/IPK bytes or mode differ'): self.inspect()
        self.put(self.row['projected_member'],self.data,0o644);self.put('CONTROL/control',b'bad',0o644)
        with self.assertRaisesRegex(ValueError,'stage/IPK control differs'): self.inspect()
    def test_edited_oracle_is_rejected(self):
        p=self.root/'oracle.json';p.write_text('{}')
        with self.assertRaisesRegex(ValueError,'oracle hash differs'): compare.load_oracle('service',p)
    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'): compare.base.unique_object([('x',1),('x',2)])


class ConfigTests(unittest.TestCase):
    def test_explicit_batches_and_per_feed_required(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/'feeds.conf').write_text('src-link luci ../../luci\nsrc-link packages ../../packages\n')
            config=('CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_luci-base=m\n'
                    'CONFIG_PACKAGE_luci-app-adblock-fast=m\nCONFIG_PACKAGE_adblock-fast=m\n'
                    'CONFIG_PER_FEED_REPO=y\nCONFIG_USE_APK=n\n# CONFIG_LUCI_JSMIN is not set\n')
            (root/'.config').write_text(config)
            self.assertFalse(compare.check_config(root)['js_minification'])
            for bad, reason in [(config.replace('CONFIG_PER_FEED_REPO=y','CONFIG_PER_FEED_REPO=n'),'per-feed'),
                                (config.replace('CONFIG_PACKAGE_adblock-fast=m','CONFIG_PACKAGE_adblock-fast=y'),'package configuration'),
                                (config+'CONFIG_PACKAGE_adblock-fast=y\n','package configuration'),
                                (config.replace('# CONFIG_LUCI_JSMIN is not set',''),'minification')]:
                (root/'.config').write_text(bad)
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason): compare.check_config(root)

class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.stage=self.root/'stage';self.prepared=self.root/'prepared';self.stage.mkdir();self.prepared.mkdir()
        self.src={'root/usr/share/rpcd/ucode/luci.adblock-fast':b'ucode', 'root/etc/uci-defaults/40_luci-adblock-fast':b'#!/bin/sh\n', 'htdocs/luci-static/x.js':b'js source'}
        self.rows=[];entries=[]
        for local,data in self.src.items():
            path=local[5:] if local.startswith('root/') else 'www/'+local[7:]
            kind='auxiliary_htdocs_js' if local.startswith('htdocs/') else 'excluded_shell_route_control' if 'uci-defaults' in local else 'selected_ucode_rpcd'
            row={'source_path':'applications/luci-app-adblock-fast/'+local,'git_blob':'x','git_mode':'100644','source_sha256':compare.digest(data),'projected_member_path':path,'projected_mode_bits':0o644,'disposition':kind}
            self.rows.append(row);entries.append((path,data,0o644));self.put(self.prepared,local,data);self.put(self.stage,path,data)
        self.archive,c=ipk('luci-app-adblock-fast',entries);self.put(self.stage,'CONTROL/control',c)
        self.oracle={'projected_files':self.rows}
        self.patcher=patch.object(compare,'git_blob',side_effect=lambda repo,rev,path,oid,dig:self.src[path.removeprefix('applications/luci-app-adblock-fast/')]);self.patcher.start();self.addCleanup(self.patcher.stop)
    def put(self,root,path,data):
        p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o644)
    def inspect(self,data=None,js=False): return compare.inspect_package('app',self.oracle,self.root,self.stage,data or self.archive,self.prepared,js)
    def test_app_root_and_shell_positive(self):
        r=self.inspect();self.assertEqual({x['disposition'] for x in r['source_mappings']},{'selected_ucode_rpcd','excluded_shell_route_control','auxiliary_htdocs_js'})
    def test_js_config_and_unknown_transform(self):
        js='www/luci-static/x.js';self.put(self.stage,js,b'minified')
        entries=[(r['projected_member_path'],b'minified' if r['disposition']=='auxiliary_htdocs_js' else self.src[r['source_path'].removeprefix('applications/luci-app-adblock-fast/')],0o644) for r in self.rows]
        data,_=ipk('luci-app-adblock-fast',entries)
        with self.assertRaisesRegex(ValueError,'app root copy differs'):self.inspect(data)
        r=self.inspect(data,True);self.assertEqual([x['transform_provenance'] for x in r['source_mappings'] if x['path']==js],['minification_unverified'])
    def test_missing_shell_control(self):
        shell=next(r for r in self.rows if r['disposition']=='excluded_shell_route_control');(self.stage/shell['projected_member_path']).unlink()
        entries=[(r['projected_member_path'],self.src[r['source_path'].removeprefix('applications/luci-app-adblock-fast/')],0o644) for r in self.rows if r is not shell]
        data,_=ipk('luci-app-adblock-fast',entries)
        with self.assertRaisesRegex(ValueError,'missing projected member'):self.inspect(data)
    def test_root_byte_and_prepared_mode_drift(self):
        rpc=next(r for r in self.rows if r['disposition']=='selected_ucode_rpcd')
        p=rpc['projected_member_path'];self.put(self.stage,p,b'bad')
        entries=[(r['projected_member_path'],b'bad' if r is rpc else self.src[r['source_path'].removeprefix('applications/luci-app-adblock-fast/')],0o644) for r in self.rows]
        data,_=ipk('luci-app-adblock-fast',entries)
        with self.assertRaisesRegex(ValueError,'app root copy differs'):self.inspect(data)
        self.put(self.stage,p,b'ucode');(self.prepared/'root/usr/share/rpcd/ucode/luci.adblock-fast').chmod(0o755)
        with self.assertRaisesRegex(ValueError,'app prepared source differs'):self.inspect()
    def test_parent_symlink_rejected(self):
        (self.stage/'www').rename(self.root/'outside');(self.stage/'www').symlink_to(self.root/'outside',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'stage symlink'):self.inspect()

if __name__=='__main__': unittest.main()
