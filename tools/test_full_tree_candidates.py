import hashlib, importlib.util, subprocess, tempfile, unittest
from pathlib import Path
MODULE=Path(__file__).with_name('full_tree_candidates.py')
spec=importlib.util.spec_from_file_location('full_tree_candidates',MODULE); selector=importlib.util.module_from_spec(spec);spec.loader.exec_module(selector)
class FullTreeControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'repo';self.root.mkdir();subprocess.run(['git','init','-q',str(self.root)],check=True)
  for k,v in [('user.email','test@example.invalid'),('user.name','Selector Test')]:subprocess.run(['git','-C',str(self.root),'config',k,v],check=True)
  self.policy={'schema':'mvp-bounded-corpus-v0.4','pins':{'openwrt':'0'*40},'selected':[{'repo':'openwrt','source_path':'selected/pkg.uc','package_owner':'fixture','proposed_installed_path':'usr/share/ucode/pkg.uc'}],'excluded':[{'repo':'openwrt','source_path':'twin-a/tool.ucode','reason':'control disposition'},{'repo':'openwrt','source_path':'twin-b/tool.ucode','reason':'control disposition'}]};self.raw=b'{}';selector.EXPECTED_MANIFEST_SHA256=hashlib.sha256(self.raw).hexdigest()
  self.put('selected/pkg.uc',b'old source\n');self.put('twin-a/tool.ucode',b'identical\n');self.put('twin-b/tool.ucode',b'identical\n');self.commit();self.base=self.sha()
 def tearDown(self):self.tmp.cleanup()
 def put(self,p,d):q=self.root/p;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(d)
 def commit(self):subprocess.run(['git','-C',str(self.root),'add','-A'],check=True);subprocess.run(['git','-C',str(self.root),'commit','-qm','fixture'],check=True)
 def sha(self):return subprocess.check_output(['git','-C',str(self.root),'rev-parse','HEAD'],text=True).strip()
 def result(self):return selector.compare(self.root,self.base,self.sha(),self.policy,self.raw,"openwrt")
 def test_edit_and_duplicate_identities(self):
  self.put('selected/pkg.uc',b'edited\n');self.commit();r=self.result();self.assertFalse(r['fail_closed']);self.assertEqual(sum(x['head'] and x['head']['sha256']==hashlib.sha256(b'identical\n').hexdigest() for x in r['events']),2);self.assertIn('selected_or_excluded_content_changed',next(x for x in r['events'] if x['source_path']=='selected/pkg.uc')['events'])
 def test_outside_candidate_shebang_and_extensionless(self):
  self.put('elsewhere/new.uc',b'x');self.put('bin/odd.py',b'#!/usr/bin/ucode\nprint(1)');self.put('usr/share/ucode/noext',b'x');self.commit();r=self.result();self.assertTrue(r['fail_closed']);self.assertEqual(r['head_unreviewed_count'],3);by={x['source_path']:x for x in r['events']};self.assertIn('ucode_suffix',by['elsewhere/new.uc']['head']['signals']);self.assertIn('first_line_ucode_shebang',by['bin/odd.py']['head']['signals']);self.assertIn('extensionless_installed_ucode_root',by['usr/share/ucode/noext']['head']['signals'])
 def test_rename_and_deletion(self):
  (self.root/'selected/pkg.uc').unlink();self.put('selected/renamed.uc',b'old source\n');self.commit();r=self.result();self.assertTrue(r['fail_closed']);by={x['source_path']:x for x in r['events']};self.assertIn('candidate_removed_or_signal_lost',by['selected/pkg.uc']['events']);self.assertIn('candidate_added',by['selected/renamed.uc']['events'])
 def test_changed_selection_signal(self):
  self.put('selected/pkg.uc',b'#!/usr/bin/ucode\n');self.commit();r=self.result();self.assertTrue(r['fail_closed']);self.assertIn('candidate_signal_changed',next(x for x in r['events'] if x['source_path']=='selected/pkg.uc')['events'])
if __name__=='__main__':unittest.main()
