import hashlib, importlib.util, json, subprocess, tempfile, unittest
from pathlib import Path
MODULE=Path(__file__).with_name('full_tree_candidates.py')
spec=importlib.util.spec_from_file_location('full_tree_candidates',MODULE); selector=importlib.util.module_from_spec(spec);spec.loader.exec_module(selector)
class FullTreeControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'repo';self.root.mkdir();subprocess.run(['git','init','-q',str(self.root)],check=True)
  for k,v in [('user.email','test@example.invalid'),('user.name','Selector Test')]:subprocess.run(['git','-C',str(self.root),'config',k,v],check=True)
  self.policy={'schema':'mvp-bounded-corpus-v0.4','pins':{'openwrt':'0'*40},'selected':[{'repo':'openwrt','source_path':'selected/pkg.uc','package_owner':'fixture','proposed_installed_path':'usr/share/ucode/pkg.uc'}],'excluded':[{'repo':'openwrt','source_path':'twin-a/tool.ucode','reason':'control disposition'},{'repo':'openwrt','source_path':'twin-b/tool.ucode','reason':'control disposition'}]};self.raw=json.dumps(self.policy,sort_keys=True).encode();selector.EXPECTED_MANIFESTS['mvp-bounded-corpus-v0.4']=hashlib.sha256(self.raw).hexdigest()
  self.put('selected/pkg.uc',b'old source\n');self.put('twin-a/tool.ucode',b'identical\n');self.put('twin-b/tool.ucode',b'identical\n');self.commit();self.base=self.sha()
 def tearDown(self):self.tmp.cleanup()
 def put(self,p,d):q=self.root/p;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(d)
 def commit(self):subprocess.run(['git','-C',str(self.root),'add','-A'],check=True);subprocess.run(['git','-C',str(self.root),'commit','-qm','fixture'],check=True)
 def sha(self):return subprocess.check_output(['git','-C',str(self.root),'rev-parse','HEAD'],text=True).strip()
 def result(self):
  raw=json.dumps(self.policy,sort_keys=True).encode();selector.EXPECTED_MANIFESTS[self.policy['schema']]=hashlib.sha256(raw).hexdigest();return selector.compare(self.root,self.base,self.sha(),self.policy,raw,"openwrt")
 def test_edit_and_duplicate_identities(self):
  self.put('selected/pkg.uc',b'edited\n');self.commit();r=self.result();self.assertFalse(r['fail_closed']);self.assertEqual(sum(x['head'] and x['head']['sha256']==hashlib.sha256(b'identical\n').hexdigest() for x in r['events']),2);self.assertIn('selected_content_changed_scan_eligible',next(x for x in r['events'] if x['source_path']=='selected/pkg.uc')['events'])
 def test_outside_candidate_shebang_and_extensionless(self):
  self.put('elsewhere/new.uc',b'x');self.put('bin/odd.py',b'#!/usr/bin/ucode\nprint(1)');self.put('bin/another.sh',b'#!/usr/bin/ucode\nprint(2)');self.put('usr/share/ucode/noext',b'x');self.put('applications/app/root/usr/share/rpcd/ucode/luci.mtk_hqos',b"'use strict';\nreturn {};\n");self.put('bin/luci.mtk_hqos',b'x');self.put('bin/late.py',b'# comment\n#!/usr/bin/ucode\n');self.commit();r=self.result();self.assertTrue(r['fail_closed']);self.assertEqual(r['head_unreviewed_count'],5);by={x['source_path']:x for x in r['events']};self.assertIn('ucode_suffix',by['elsewhere/new.uc']['head']['signals']);self.assertIn('first_line_ucode_shebang',by['bin/odd.py']['head']['signals']);self.assertIn('first_line_ucode_shebang',by['bin/another.sh']['head']['signals']);self.assertIn('extensionless_installed_ucode_root',by['usr/share/ucode/noext']['head']['signals']);self.assertIn('installed_ucode_root',by['applications/app/root/usr/share/rpcd/ucode/luci.mtk_hqos']['head']['signals']);self.assertNotIn('bin/luci.mtk_hqos',by);self.assertNotIn('bin/late.py',by)
 def test_excluded_content_change_requires_review(self):
  self.put('twin-a/tool.ucode',b'changed exclusion\n');self.commit();r=self.result();self.assertTrue(r['fail_closed'])
  row=next(x for x in r['events'] if x['source_path']=='twin-a/tool.ucode')
  self.assertEqual(row['status'],'excluded');self.assertIn('excluded_content_changed_review_required',row['events'])
 def test_reviewed_baseline_missing_from_both_trees_fails_closed(self):
  self.policy['selected'].append({'repo':'openwrt','source_path':'missing/selected.uc'})
  self.policy['excluded'].append({'repo':'openwrt','source_path':'missing/excluded.ut','reason':'reviewed exclusion'})
  r=self.result();self.assertTrue(r['fail_closed']);self.assertEqual(r['missing_baseline_count'],2)
  by={x['source_path']:x for x in r['events']}
  self.assertEqual(by['missing/selected.uc']['status'],'selected');self.assertEqual(by['missing/selected.uc']['baseline_policy']['repo'],'openwrt');self.assertIn('baseline_identity_missing_at_base_and_head',by['missing/selected.uc']['events'])
  self.assertEqual(by['missing/excluded.ut']['status'],'excluded');self.assertIn('baseline_identity_missing_at_base_and_head',by['missing/excluded.ut']['events'])
 def test_rename_and_deletion(self):
  (self.root/'selected/pkg.uc').unlink();self.put('selected/renamed.uc',b'old source\n');self.commit();r=self.result();self.assertTrue(r['fail_closed']);by={x['source_path']:x for x in r['events']};self.assertIn('candidate_removed_or_signal_lost',by['selected/pkg.uc']['events']);self.assertIn('candidate_added',by['selected/renamed.uc']['events'])
 def test_changed_selection_signal(self):
  self.put('selected/pkg.uc',b'#!/usr/bin/ucode\n');self.commit();r=self.result();self.assertTrue(r['fail_closed']);self.assertIn('candidate_signal_changed',next(x for x in r['events'] if x['source_path']=='selected/pkg.uc')['events'])

 def test_candidate_mode_change_requires_review(self):
  (self.root/'selected/pkg.uc').chmod(0o755);self.commit();r=self.result()
  self.assertTrue(r['fail_closed'])
  self.assertIn('candidate_mode_changed',next(x for x in r['events'] if x['source_path']=='selected/pkg.uc')['events'])

 def test_candidate_symlink_rejected(self):
  (self.root/'selected/pkg.uc').unlink()
  (self.root/'selected/pkg.uc').symlink_to('../twin-a/tool.ucode')
  self.commit()
  with self.assertRaisesRegex(selector.SelectorError,'not a regular tracked file'):
   self.result()

 def test_reviewed_luci_symlink_exclusions_and_target_change(self):
  for path in ('selected/pkg.uc','twin-a/tool.ucode','twin-b/tool.ucode'):
   (self.root/path).unlink()
  paths=[f'themes/luci-theme-bootstrap/ucode/template/themes/bootstrap-{theme}' for theme in ('dark','light')]
  pinned=json.loads((MODULE.parent.parent/'docs/current-corpus-source-v0.6.json').read_bytes())
  pinned_links={x['source_path']:x for x in pinned['excluded'] if x['repo']=='luci' and x.get('reason')=='tracked symlink; target not followed'}
  self.assertEqual(set(paths),set(pinned_links))
  for path in paths:
   target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to('bootstrap')
   self.policy['excluded'].append({'repo':'luci','source_path':path,'reason':'tracked symlink; target not followed'})
  self.commit();base=self.sha()
  def compare():
   raw=json.dumps(self.policy,sort_keys=True).encode()
   selector.EXPECTED_MANIFESTS[self.policy['schema']]=hashlib.sha256(raw).hexdigest()
   return selector.compare(self.root,base,self.sha(),self.policy,raw,'luci')
  initial=compare()
  self.assertFalse(initial['fail_closed'])
  self.assertEqual(initial['head_excluded_count'],2)
  self.assertEqual({x['head']['mode'] for x in initial['events']},{'120000'})
  (self.root/paths[0]).unlink();(self.root/paths[0]).symlink_to('changed-target');self.commit()
  changed=compare()
  self.assertTrue(changed['fail_closed'])
  self.assertIn('excluded_content_changed_review_required',next(x for x in changed['events'] if x['source_path']==paths[0])['events'])

 def test_suffix_gitlink_rejected_before_blob_read(self):
  target=self.sha()
  subprocess.run(['git','-C',str(self.root),'update-index','--add','--cacheinfo','160000',target,'new/module.uc'],check=True)
  subprocess.run(['git','-C',str(self.root),'commit','-qm','gitlink'],check=True)
  with self.assertRaisesRegex(selector.SelectorError,'not a regular tracked file'):
   self.result()

 def test_nested_openwrt_and_luci_roots_match_but_fakeusr_does_not(self):
  openwrt_path='package/example/files/usr/share/ucode/tool';luci_path='modules/luci-base/root/usr/share/rpcd/ucode/luci';fake_path='package/example/files/fakeusr/share/ucode/not-a-root'
  self.put(openwrt_path,b'return 1\n');self.put(luci_path,b'return 2\n');self.put(fake_path,b'return 3\n');self.commit()
  self.policy['selected'].extend([{'repo':'openwrt','source_path':openwrt_path},{'repo':'luci','source_path':luci_path}])
  oi=selector.make_inventory(self.root,self.sha(),self.policy,'openwrt');li=selector.make_inventory(self.root,self.sha(),self.policy,'luci')
  o={x['source_path']:x for x in oi};l={x['source_path']:x for x in li}
  self.assertIn('extensionless_installed_ucode_root',o[openwrt_path]['signals']);self.assertIn('extensionless_installed_ucode_root',l[luci_path]['signals']);self.assertNotIn(fake_path,o)

 def test_v05_pinned_manifest_accepts_selected_and_excluded_full_tree_paths(self):
  raw=(MODULE.parent.parent/'docs/current-corpus-source-v0.5.json').read_bytes();policy=json.loads(raw)
  self.assertEqual(hashlib.sha256(raw).hexdigest(),'70ba39e2307b7c5c9905d572d85b0cca320214e48c0dc64065bad668cddb08fc')
  self.assertEqual(policy['schema'],'mvp-bounded-corpus-v0.5-source-staged')
  selected=next(x for x in policy['selected'] if x['repo']=='openwrt' and 'package_or_target_condition' in x and x['source_path'].endswith('.uc'))
  excluded=next(x for x in policy['excluded'] if x['repo']=='openwrt' and x.get('source_commit')==policy['pins']['openwrt'])
  for path in (self.root/'selected/pkg.uc',self.root/'twin-a/tool.ucode',self.root/'twin-b/tool.ucode'):
   path.unlink()
  self.put(selected['source_path'],b'#!/usr/bin/ucode\nreturn 1\n');self.put(excluded['source_path'],b'#!/bin/sh\n');self.commit();rev=self.sha()
  result=selector.compare(self.root,rev,rev,policy,raw,'openwrt')
  self.assertEqual(result['policy_schema'],policy['schema']);self.assertEqual(result['policy_sha256'],hashlib.sha256(raw).hexdigest())
  by={x['source_path']:x for x in result['events']}
  self.assertEqual(by[selected['source_path']]['status'],'selected')
  self.assertEqual(by[excluded['source_path']]['status'],'excluded')
  self.assertTrue(result['fail_closed'])
  self.assertGreater(result['missing_baseline_count'],0)

 def test_v05_digest_and_schema_are_independently_fail_closed(self):
  raw=(MODULE.parent.parent/'docs/current-corpus-source-v0.5.json').read_bytes();policy=json.loads(raw)
  with self.assertRaisesRegex(selector.SelectorError,'manifest digest mismatch'):
   selector.compare(self.root,self.base,self.base,policy,raw+b' ','openwrt')
  changed=dict(policy);changed['schema']='mvp-bounded-corpus-v0.4'
  with self.assertRaisesRegex(selector.SelectorError,'manifest digest mismatch'):
   selector.compare(self.root,self.base,self.base,changed,raw,'openwrt')
 def test_v06_pinned_manifest_digest_schema_and_selected_excluded_paths(self):
  raw=(MODULE.parent.parent/'docs/current-corpus-source-v0.6.json').read_bytes();policy=json.loads(raw)
  self.assertEqual(hashlib.sha256(raw).hexdigest(),'9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490')
  self.assertEqual(policy['schema'],'mvp-bounded-corpus-v0.6')
  selected=next(x for x in policy['selected'] if x['repo']=='openwrt' and x['source_path'].endswith('proto-ucode.uc'))
  excluded=next(x for x in policy['excluded'] if x['repo']=='openwrt')
  for path in (self.root/'selected/pkg.uc',self.root/'twin-a/tool.ucode',self.root/'twin-b/tool.ucode'):
   path.unlink()
  self.put(selected['source_path'],b'#!/usr/bin/ucode\nreturn 1\n');self.put(excluded['source_path'],b'#!/bin/sh\n');self.commit();rev=self.sha()
  result=selector.compare(self.root,rev,rev,policy,raw,'openwrt')
  self.assertEqual(result['policy_schema'],policy['schema']);self.assertEqual(result['policy_sha256'],hashlib.sha256(raw).hexdigest())
  by={x['source_path']:x for x in result['events']}
  self.assertEqual(by[selected['source_path']]['status'],'selected')
  self.assertEqual(by[excluded['source_path']]['status'],'excluded')
  self.assertTrue(result['fail_closed'])
  self.assertGreater(result['missing_baseline_count'],0)

 def test_parsed_policy_must_match_pinned_bytes(self):
  raw=(MODULE.parent.parent/'docs/current-corpus-source-v0.6.json').read_bytes();policy=json.loads(raw)
  changed=dict(policy);changed['selected']=policy['selected'][:-1]
  with self.assertRaisesRegex(selector.SelectorError,'parsed policy differs from pinned manifest bytes'):
   selector.compare(self.root,self.base,self.base,changed,raw,'openwrt')

 def test_v06_digest_and_schema_are_independently_fail_closed(self):
  raw=(MODULE.parent.parent/'docs/current-corpus-source-v0.6.json').read_bytes();policy=json.loads(raw)
  with self.assertRaisesRegex(selector.SelectorError,'manifest digest mismatch'):
   selector.compare(self.root,self.base,self.base,policy,raw+b' ','openwrt')
  changed=dict(policy);changed['schema']='mvp-bounded-corpus-v0.5-source-staged'
  with self.assertRaisesRegex(selector.SelectorError,'manifest digest mismatch'):
   selector.compare(self.root,self.base,self.base,changed,raw,'openwrt')

 def test_v07_packages_feed_inventory_classifies_fixture_paths(self):
  raw=(MODULE.parent.parent/'docs/current-corpus-source-v0.7.json').read_bytes();policy=json.loads(raw)
  self.assertEqual(hashlib.sha256(raw).hexdigest(),'2ef4dc10e78b6c3aef873e3f0652b5102698cedb317c9cf96587806941c61d2e')
  self.assertEqual(policy['schema'],'mvp-bounded-corpus-v0.7')
  for path in (self.root/'selected/pkg.uc',self.root/'twin-a/tool.ucode',self.root/'twin-b/tool.ucode'):
   path.unlink()
  package_rows=[row for row in policy['selected']+policy['excluded'] if row['repo']=='packages']
  self.assertEqual(len(package_rows),37)
  for row in package_rows:
   target=self.root/row['source_path'];target.parent.mkdir(parents=True,exist_ok=True)
   route=row.get('expected_route',{})
   content=(b'#!/usr/bin/ucode\nfixture\n' if route.get('reason')=='ucode_shebang'
            else ('fixture '+row['source_path']+'\n').encode())
   target.write_bytes(content)
   if row.get('source_mode')=='100755': target.chmod(0o755)
  self.commit();rev=self.sha()
  expected={row['source_path'] for row in package_rows}
  natural=selector.make_inventory(self.root,rev,{'selected':[],'excluded':[]},'packages')
  self.assertEqual({row['source_path'] for row in natural},expected)
  self.assertTrue(all(row['status']=='unreviewed' for row in natural))
  inventory=selector.make_inventory(self.root,rev,policy,'packages')
  counts={status:sum(row['status']==status for row in inventory)
          for status in ('selected','excluded','unreviewed')}
  self.assertEqual(len(inventory),37)
  self.assertEqual(counts,{'selected':26,'excluded':11,'unreviewed':0})

if __name__=='__main__':unittest.main()
