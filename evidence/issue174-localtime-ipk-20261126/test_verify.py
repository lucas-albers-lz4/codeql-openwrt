import copy
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('issue174_evidence_verify',HERE/'verify.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.spec=v.obj(HERE/'source-first-oracle.json');self.data=v.obj(HERE/'raw/retry-output/query.json');lock=v.obj(HERE/'provenance/run-lock.json');self.uri='file://'+lock['run_root']+'/stage/'+v.MEMBER
    def test_retained_packet(self):
        result=v.validate(HERE);self.assertEqual(result['query_rows'],7);self.assertEqual(result['extraction_errors'],0)
    def test_tuple_multiplicity_and_near_miss(self):
        changed=copy.deepcopy(self.data);changed['#select']['tuples'].pop()
        with self.assertRaisesRegex(ValueError,'query tuple multiset differs'):v.validate_query(changed,self.spec,self.uri)
        changed=copy.deepcopy(self.data);changed['#select']['tuples'].append(copy.deepcopy(changed['#select']['tuples'][0]))
        with self.assertRaisesRegex(ValueError,'query tuple multiset differs'):v.validate_query(changed,self.spec,self.uri)
        changed=copy.deepcopy(self.data);sink=changed['#select']['tuples'][0][2];sink['url'].update(startLine=112,startColumn=5,endLine=112,endColumn=55)
        with self.assertRaisesRegex(ValueError,'query tuple multiset differs'):v.validate_query(changed,self.spec,self.uri)
    def test_retained_provider_mode_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'packet';shutil.copytree(HERE,root)
            (root/'stage'/v.MEMBER).chmod(0o755)
            with self.assertRaisesRegex(ValueError,'retained stage mode/size differs'):v.validate(root)
    def test_entity_identity_and_uri(self):
        changed=copy.deepcopy(self.data);changed['#select']['tuples'][1][0]['id']=changed['#select']['tuples'][0][0]['id']
        with self.assertRaisesRegex(ValueError,'AST identity inconsistency'):v.validate_query(changed,self.spec,self.uri)
        changed=copy.deepcopy(self.data);changed['#select']['tuples'][0][0]['url']['uri']='file:///unrelated'
        with self.assertRaisesRegex(ValueError,'query file URI differs'):v.validate_query(changed,self.spec,self.uri)
if __name__=='__main__':unittest.main()
