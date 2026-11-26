import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import io
import stat
import zipfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import check
import prepare
import controls

class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        self.rows = []
        for path, count in ((check.APP, 13), (check.POS, 1), (check.NEG, 1)):
            p = self.stage / path
            p.parent.mkdir(parents=True, exist_ok=True)
            data = b'system(x)\n' * count
            p.write_bytes(data)
            for n in range(count):
                self.rows.append({'path': path, 'byte_start_0': n*10, 'byte_end_exclusive_0': n*10+9,
                    'expression_sha256': check.digest(b'system(x)'), 'start':[n+1,1], 'end_inclusive':[n+1,9],
                    'source_line':n+1, 'expected_rows': 0 if path == check.NEG else 1})
        self.expected = {'schema':'issue175-source-first-call-spans-v1','expected_rows':14,'rows':self.rows}
        self.query = {'#select':{'tuples':[]}}
        for i, row in enumerate(self.rows):
            if row['expected_rows']:
                path = row['path']
                self.query['#select']['tuples'].append([{'id':i+1,'label':'CallExpression','url':{
                    'uri':(self.stage/path).as_uri(), 'startLine':row['start'][0], 'startColumn':row['start'][1],
                    'endLine':row['end_inclusive'][0], 'endColumn':row['end_inclusive'][1]}},
                    f"builtin system() in {Path(path).name} at line {row['source_line']}"])

    def test_exact_source_and_query(self):
        check.check_source_spans(self.stage,self.expected)
        self.assertEqual(check.validate_query(self.stage,self.query,self.expected)['total_rows'],14)

    def test_missing_call_and_false_near_miss_rejected(self):
        missing = copy.deepcopy(self.query); missing['#select']['tuples'].pop()
        with self.assertRaisesRegex(ValueError,'multiplicity'): check.validate_query(self.stage,missing,self.expected)
        extra = copy.deepcopy(self.query); extra['#select']['tuples'].append(copy.deepcopy(extra['#select']['tuples'][-1]))
        extra['#select']['tuples'][-1][0]['url']['uri'] = (self.stage/check.NEG).as_uri()
        with self.assertRaises(ValueError): check.validate_query(self.stage,extra,self.expected)

    def test_witness_and_mutant_add_only_shadowed_same_node(self):
        positive=copy.deepcopy(self.query);r=self.rows[-1];path=r['path']
        positive['#select']['tuples'].append([{'id':99,'label':'CallExpression','url':{'uri':(self.stage/path).as_uri(),'startLine':r['start'][0],'startColumn':r['start'][1],'endLine':r['end_inclusive'][0],'endColumn':r['end_inclusive'][1]}},f"builtin system() in {Path(path).name} at line {r['source_line']}"])
        self.assertEqual(controls.validate(self.stage,self.expected,self.query,positive,positive)['near_miss_added'],1)
        bad=copy.deepcopy(positive);bad['#select']['tuples'][0][0]['id']=500
        with self.assertRaisesRegex(ValueError,'baseline node IDs'):controls.validate(self.stage,self.expected,self.query,positive,bad)
        with self.assertRaisesRegex(ValueError,'multiplicity'):controls.validate(self.stage,self.expected,self.query,positive,self.query)

    def test_node_identity_cannot_alias_different_spans(self):
        value=copy.deepcopy(self.query);value['#select']['tuples'][1][0]['id']=value['#select']['tuples'][0][0]['id']
        with self.assertRaisesRegex(ValueError,'reused'):check.validate_query(self.stage,value,self.expected)

    def test_source_byte_and_position_mutations_rejected(self):
        value=copy.deepcopy(self.expected);value['rows'][0]['byte_end_exclusive_0']-=1
        with self.assertRaisesRegex(ValueError,'expression'):check.check_source_spans(self.stage,value)
        value=copy.deepcopy(self.expected);value['rows'][0]['start'][1]+=1
        with self.assertRaisesRegex(ValueError,'coordinates'):check.check_source_spans(self.stage,value)

    def test_route_and_diagnostic_controls(self):
        route={'input_count':3,'duplicate_input_count':0,'plain_count':3,'markup_count':0,'markup_inconclusive_count':0,'uncertain_count':0,'excluded_count':0,'decisions':[]}
        for path in check.PATHS:
            route['decisions'].append({'installed_path':path,'path':str(self.stage/path),'classification':'plain','reason':'rpcd_raw_mode_full_path' if path==check.APP else 'ucode_extension','status':'plain_route_selected','inconclusive_reason':None})
        check.validate_route(self.stage,route)
        bad=copy.deepcopy(route);bad['decisions'][0]['reason']='ucode_extension'
        with self.assertRaisesRegex(ValueError,'route identity'):check.validate_route(self.stage,bad)
        check.validate_errors({'#select':{'tuples':[]}})
        with self.assertRaisesRegex(ValueError,'errors present'):check.validate_errors({'#select':{'tuples':[['failure']]}})
        success={'#select':{'tuples':[[{'url':{'uri':(self.stage/p).as_uri()}},''] for p in check.PATHS]}}
        check.validate_success(self.stage,success)
        success['#select']['tuples'].pop()
        with self.assertRaisesRegex(ValueError,'successful-file'):check.validate_success(self.stage,success)

    def test_duplicate_json_and_unsafe_stage_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON'):check.load_json('{"x":1,"x":2}')
        (self.stage/'extra').write_text('extra')
        with self.assertRaisesRegex(ValueError,'inventory'):check.stage_inputs(self.stage,{path:check.digest((self.stage/path).read_bytes()) for path in check.PATHS})

    def test_extra_empty_stage_directory_rejected(self):
        expected={path:check.digest((self.stage/path).read_bytes()) for path in check.PATHS}
        check.stage_inputs(self.stage,expected)
        (self.stage/'unused').mkdir()
        with self.assertRaisesRegex(ValueError,'stage inventory'):check.stage_inputs(self.stage,expected)

    def test_source_archive_rejects_duplicate_and_wrong_mode(self):
        values={path:(self.stage/path).read_bytes() for path in check.PATHS}
        def archive(duplicate=False, bad_mode=False):
            result=io.BytesIO()
            with zipfile.ZipFile(result,'w') as out:
                for i,(path,data) in enumerate(values.items()):
                    info=zipfile.ZipInfo(str(self.stage/path).lstrip('/'));info.create_system=3
                    info.external_attr=(stat.S_IFREG | (0o600 if bad_mode and i==0 else 0o644)) << 16
                    out.writestr(info,data)
                if duplicate:out.writestr(info,data)
            p=self.root/'source.zip';p.write_bytes(result.getvalue());return p
        hashes={path:check.digest(data) for path,data in values.items()}
        with patch.object(check,'APP_SHA',hashes[check.APP]),patch.object(check,'CONTROL_SHA',{k:hashes[k] for k in (check.POS,check.NEG)}):
            check.validate_source_archive(self.stage,archive())
            with self.assertRaisesRegex(ValueError,'mode'):check.validate_source_archive(self.stage,archive(bad_mode=True))
            with self.assertRaisesRegex(ValueError,'count'):check.validate_source_archive(self.stage,archive(duplicate=True))

    def test_app_receipt_inventory_and_mode_are_required(self):
        from unittest.mock import patch
        raw=b'synthetic package'; app=b'synthetic rpc'; acl=b'synthetic acl'
        members={check.APP:{'type':'file','mode':0o644,'bytes':app},'usr/share/rpcd/acl.d/luci-app-adblock-fast.json':{'type':'file','mode':0o644,'bytes':acl}}
        control={};outer={'synthetic':'outer'}; fields={'Package':'luci-app-adblock-fast','Version':'1.2.4-r4','Architecture':'all'}
        apphash=check.digest(app);config={'config':{'sha256':'a'*64}}
        row={'path':check.APP,'disposition':'selected_ucode_rpcd','source_git_mode':'100644',**{k:apphash for k in ('source_sha256','prepared_sha256','staged_sha256','ipk_sha256')},**{k:'0644' for k in ('prepared_mode','staged_mode','ipk_mode')}}
        lock={'package_run_id':'123-1','artifact_url':'https://example.invalid/artifact','ipk_sha256':check.digest(raw),'config':config}
        receipt={'ipk_sha256':lock['ipk_sha256'],'package':'app','oracle_sha256':check.APP_ORACLE_SHA,'source_pins':check.base.PINS,'config':config,'outer_sha256':outer,'control':fields,'source_mappings':[row],'control_members':[], 'data_members':[]}
        # Mock archive decoding only; synthetic bytes are not package evidence.
        with patch.object(check,'APP_SHA',apphash),patch.object(check.archive,'read_ipk',return_value=(control,members,outer)),patch.object(check.archive,'receipts',return_value=[]),patch.object(check.base,'control_from_rows',return_value=fields),patch.object(check,'digest',side_effect=lambda b: 'af249e0610e568be8e7bac542c0ce9f402e1a95cd34d3c5eb9a9724aff46502d' if b==acl else __import__('hashlib').sha256(b).hexdigest()):
            self.assertEqual(check.validate_app_package(raw,receipt,lock),app)
            bad=copy.deepcopy(receipt);bad['outer_sha256']={}
            with self.assertRaisesRegex(ValueError,'archive inventory'):check.validate_app_package(raw,bad,lock)
            members[check.APP]['mode']=0o600
            with self.assertRaisesRegex(ValueError,'RPC member'):check.validate_app_package(raw,receipt,lock)

    def test_fresh_layout_guard(self):
        root=self.root
        lock={'run_root':str(root),'database_path':str(root/'db'),
          'output_paths':{n:str(root/'output'/(n+'.json')) for n in ('routing','successful','errors','query')},
          'bqrs_paths':{n:str(root/'output'/(n+'.bqrs')) for n in ('successful','errors','query')},
          'resolver_paths':{n:str(root/'output'/('resolve-'+n+'.json')) for n in ('query','successful','errors')},
          'raw_routing_path':str(root/'db/trap/ucode/routing.json'),'commands_path':str(root/'output/commands.json')}
        with self.assertRaisesRegex(ValueError,'not fresh'):prepare.layout(lock,self.stage,True)

if __name__=='__main__': unittest.main()
