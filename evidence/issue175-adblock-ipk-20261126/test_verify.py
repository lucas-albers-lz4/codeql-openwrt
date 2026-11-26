"""Portable retained-evidence checks and discriminating mutations."""
import copy,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
root=Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location('portable175',root/'verify.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class Tests(unittest.TestCase):
 def setUp(self):self.lock=v.obj(root/'provenance/run-lock.json');self.stage=self.lock['env']['CODEQL_UCODE_STAGED_ROOT'];self.oracle=v.obj(root/'source-first-oracle.json');self.baseline=v.obj(root/'raw/output/query.json');self.witness=v.obj(root/'raw/witness/output/witness.json')
 def test_packet(self):self.assertEqual(v.verify(root)['near_miss_added'],1)
 def test_missing_baseline_row_rejected(self):
  x=copy.deepcopy(self.baseline);x['#select']['tuples'].pop()
  with self.assertRaisesRegex(ValueError,'row multiset'):v.query(x,self.oracle,self.stage,False)
 def test_formal_shadow_missing_from_control_rejected(self):
  x=copy.deepcopy(self.witness);x['#select']['tuples']=[r for r in x['#select']['tuples'] if 'near-miss.uc' not in r[0]['url']['uri']]
  with self.assertRaisesRegex(ValueError,'row multiset'):v.query(x,self.oracle,self.stage,True)
 def test_entity_alias_rejected(self):
  x=copy.deepcopy(self.baseline);rows=x['#select']['tuples'];rows[1][0]['id']=rows[0][0]['id']
  with self.assertRaisesRegex(ValueError,'AST ID reused'):v.query(x,self.oracle,self.stage,False)
 def test_variant_log_alias_and_resolver_identity_rejected(self):
  plan=v.obj(root/'provenance/witness-plan.json');row=v.obj(root/'raw/witness/output/logs/resolve.receipt.json');directory=root/'raw/witness/output'
  bad=copy.deepcopy(row);bad['stdout_path']=plan['private_root']+'/output/../resolver.json'
  with self.assertRaisesRegex(ValueError,'log path'):v.control_log_path(bad,'resolve','stdout',plan,directory)
  data=v.obj(directory/'resolver.json');v.control_resolver(data,plan,self.lock);bad=copy.deepcopy(data);bad['compilationCache']=[]
  with self.assertRaisesRegex(ValueError,'resolver identity'):v.control_resolver(bad,plan,self.lock)
  bad=copy.deepcopy(data);bad['libraryPath']=bad['libraryPath'][:-1]
  with self.assertRaisesRegex(ValueError,'resolver identity'):v.control_resolver(bad,plan,self.lock)

 def test_nested_checksum_and_hardlink_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp).resolve()/'packet';shutil.copytree(root,target);(target/'nested').mkdir();(target/'nested/SHA256SUMS').write_text('extra')
   with self.assertRaisesRegex(ValueError,'inventory'):v.verify(target)
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp).resolve()/'packet';shutil.copytree(root,target);os.link(target/'raw/output/query.json',target/'alias')
   with self.assertRaisesRegex(ValueError,'hardlink'):v.verify(target)
 def test_inventory_omission_and_stage_mode_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp).resolve()/'packet';shutil.copytree(root,target);(target/'raw/output/query.json').unlink()
   with self.assertRaisesRegex(ValueError,'inventory'):v.verify(target)
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp).resolve()/'packet';shutil.copytree(root,target);(target/'stage'/v.APP).chmod(0o600)
   with self.assertRaisesRegex(ValueError,'stage identity'):v.verify(target)
if __name__=='__main__':unittest.main()
