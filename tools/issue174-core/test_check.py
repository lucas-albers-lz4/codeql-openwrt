import copy
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import check

class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.stage=Path(self.temp.name).resolve()/'stage';self.file=self.stage/check.IPK_SOURCE
        self.file.parent.mkdir(parents=True);self.file.write_bytes(b'synthetic test input, not package evidence\n');self.file.chmod(0o644)
        self.sha=patch.object(check,'SOURCE_SHA',check.digest(self.file.read_bytes()));self.sha.start();self.addCleanup(self.sha.stop)
        self.url=self.file.as_uri()
        self.route={'input_count':1,'duplicate_input_count':0,'plain_count':1,'markup_count':0,'markup_inconclusive_count':0,'uncertain_count':0,'excluded_count':0,
                    'decisions':[{'path':str(self.file),'installed_path':check.IPK_SOURCE,'classification':'plain','reason':'rpcd_raw_mode_full_path','status':'plain_route_selected'}]}
        self.success={'#select':{'tuples':[[{'url':{'uri':self.url}},'']]}}
        self.errors={'#select':{'tuples':[]}}
        self.spec=check.oracle();self.query={'#select':{'tuples':[]}}
        ids={}
        def entity(x):
            key=str(x); ident=ids.setdefault(key,len(ids)+1);_,sl,sc,el,ec=x['entity']
            return {'id':ident,'label':x['label'],'url':{'uri':self.url,'startLine':sl,'startColumn':sc,'endLine':el,'endColumn':ec}}
        for row in check.expected_rows(self.spec):
            self.query['#select']['tuples'].append([entity(row[0]),row[1],entity(row[2]),row[3]])
    def run_check(self):return check.check_observations(self.stage,self.route,self.success,self.errors,self.query,self.spec)
    def test_expected_seven_and_near_miss_absence(self):
        self.assertEqual(self.run_check()['query_rows'],7)
    def test_rejects_fixed_literal_near_miss_result(self):
        row=copy.deepcopy(self.query['#select']['tuples'][0]);row[2]['url'].update(startLine=112,startColumn=5,endLine=112,endColumn=55);row[2]['id']=999
        self.query['#select']['tuples'].append(row)
        with self.assertRaisesRegex(ValueError,'query tuple multiset differs'):self.run_check()
    def test_rejects_missing_duplicate_and_altered_ambient(self):
        baseline=copy.deepcopy(self.query)
        for variant in ('missing','duplicate','message','entity_id','id_alias'):
            self.query=copy.deepcopy(baseline);rows=self.query['#select']['tuples']
            if variant=='missing': rows.pop()
            elif variant=='duplicate': rows.append(copy.deepcopy(rows[0]))
            elif variant=='message': rows[-1][1]+=' changed'
            elif variant=='entity_id': rows[4][2]['id']=9999
            else: rows[-1][0]['id']=rows[0][0]['id']
            with self.subTest(variant=variant), self.assertRaises(ValueError):self.run_check()
    def test_route_and_success_and_diagnostic_failures(self):
        self.route['decisions'][0]['reason']='other'
        with self.assertRaisesRegex(ValueError,'route identity'):self.run_check()
        self.route['decisions'][0]['reason']='rpcd_raw_mode_full_path'
        self.success['#select']['tuples'].append(copy.deepcopy(self.success['#select']['tuples'][0]))
        with self.assertRaisesRegex(ValueError,'successful-file multiset'):self.run_check()
        self.success['#select']['tuples'].pop();self.errors['#select']['tuples'].append(['error'])
        with self.assertRaisesRegex(ValueError,'extraction errors'):self.run_check()
    def test_rejects_stage_extra_and_path_alias(self):
        extra=self.stage/'extra';extra.write_text('extra')
        with self.assertRaisesRegex(ValueError,'stage inventory'):self.run_check()
        extra.unlink();self.query['#select']['tuples'][0][0]['url']['uri']='file:///unselected'
        with self.assertRaises((ValueError,FileNotFoundError)):self.run_check()
    def test_rejects_duplicate_json_keys(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'):check.json_object('{"x": 1, "x": 2}')
        with self.assertRaisesRegex(ValueError,'invalid JSON constant'):check.json_object('{"x": NaN}')
class CommandContractTests(unittest.TestCase):
    def fixture(self):
        import verify
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name).resolve()
        cli=root/'tool/codeql';producer=root/'producer';pack=root/'extractor';deps=root/'deps';(deps/'util').mkdir(parents=True)
        stage=root/'run/stage';run=stage.parent;db=str(run/'db')
        outputs={n:str(run/'output'/(n+'.json')) for n in ('routing','successful','errors','query')}
        bqrs={n:str(run/'output'/(n+'.bqrs')) for n in ('successful','errors','query')}
        target=str(producer/'ql/src/m4/RequestArgsExec.ql');success=str(producer/'ql/src/diagnostics/SuccessfullyExtractedFiles.ql');errors=str(producer/'ql/src/diagnostics/ExtractionErrors.ql')
        search='--search-path='+':'.join(map(str,(pack,producer/'ql/lib',producer/'ql/src')));additional='--additional-packs='+str(deps/'util')
        argv={}
        for key,path in (('query',target),('success',success),('errors',errors)):
            argv['resolve-'+key]=[str(cli),'resolve','library-path','--query='+path,search,additional,'--format=json','--common-caches='+str(run/'cache/queries'),'--compilation-cache='+str(run/'cache/compile'),'--no-default-compilation-cache']
        argv.update({'database-init':[str(cli),'database','init',db,'--source-root='+str(stage),'--language=ucode','--search-path='+str(pack),'--common-caches='+str(run/'cache/database')],
                     'database-index':[str(cli),'database','index-files',db,'--working-dir='+str(stage),'--include=**/*','--language=ucode','--common-caches='+str(run/'cache/database')],
                     'database-finalize':[str(cli),'database','finalize',db,'--common-caches='+str(run/'cache/database')]})
        for prefix,path,name in (('success',success,'successful'),('errors',errors,'errors'),('target',target,'query')):
            argv[prefix+'-query']=[str(cli),'query','run',path,'--database='+db,'--output='+bqrs[name],search,additional,'--common-caches='+str(run/'cache/queries'),'--compilation-cache='+str(run/'cache/compile'),'--no-default-compilation-cache']
            argv[prefix+'-decode']=[str(cli),'bqrs','decode',bqrs[name],'--format=json','--entities=id,url,string','--output='+outputs[name]]
        env={'CODEQL_UCODE_STAGED_ROOT':str(stage),'HOME':str(run/'home'),'TMPDIR':str(run/'tmp'),'XDG_CACHE_HOME':str(run/'cache'),'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}
        lock={'phase_argv':argv,'bqrs_paths':bqrs,'output_paths':outputs,'database_path':db,'run_root':str(run),'cwd':str(producer),'env':env,'additional_packs':[str(deps/'util')],'resolver_paths':{'query':'q','successful':'s','errors':'e'}}
        commands={'commands':[{'label':name,'argv':argv[name].copy(),'cwd':str(producer),'env':env,'exit':0,'elapsed_seconds':0.1,'peak_rss_bytes':100} for name in verify.PHASES]}
        return verify,lock,commands,cli,producer,stage,pack,deps
    def test_frozen_command_contract(self):
        v,l,c,cli,p,s,pack,deps=self.fixture();self.assertEqual(len(v.validate_commands(l,c,cli,p,s,pack,deps)),12)
    def test_rejects_unbound_query_and_failed_phase_even_if_lock_is_mutated(self):
        for variant in ('query','decode','executable','exit','order'):
            v,l,c,cli,p,s,pack,deps=self.fixture()
            if variant=='query':
                i=v.PHASES.index('target-query');c['commands'][i]['argv'][3]='/other/query.ql';l['phase_argv']['target-query']=c['commands'][i]['argv']
            elif variant=='decode':
                i=v.PHASES.index('target-decode');c['commands'][i]['argv'][-1]='--output=/wrong';l['phase_argv']['target-decode']=c['commands'][i]['argv']
            elif variant=='executable':
                c['commands'][0]['argv'][0]='/other/codeql';l['phase_argv']['resolve-query']=c['commands'][0]['argv']
            elif variant=='exit':c['commands'][0]['exit']=1
            else:c['commands'][0],c['commands'][1]=c['commands'][1],c['commands'][0]
            with self.subTest(variant=variant),self.assertRaises(ValueError):v.validate_commands(l,c,cli,p,s,pack,deps)

    def test_recorded_logs_bind_bytes_and_reject_warning(self):
        v,lock,commands,cli,producer,stage,pack,deps=self.fixture()
        run=Path(lock['run_root']); (run/'output/logs').mkdir(parents=True)
        lock['resolver_paths']={n:str(run/'output'/('resolve-'+n+'.json')) for n in ('query','successful','errors')}
        names={'resolve-query':'query','resolve-success':'successful','resolve-errors':'errors'}
        for row in commands['commands']:
            for stream in ('stdout','stderr'):
                path=Path(lock['resolver_paths'][names[row['label']]]) if stream=='stdout' and row['label'] in names else run/'output/logs'/(row['label']+'.'+stream)
                path.write_bytes(b'clean\n');row[stream+'_path']=str(path);row[stream+'_sha256']=check.digest(path.read_bytes())
        self.assertEqual(len(v.validate_logs(lock,commands['commands'])),24)
        first=commands['commands'][0];stdout=Path(first['stdout_path']);stdout.write_text('FATAL: unexpected\n');first['stdout_sha256']=check.digest(stdout.read_bytes())
        with self.assertRaisesRegex(ValueError,'command error requires review'):v.validate_logs(lock,commands['commands'])
        stdout.write_bytes(b'clean\n');first['stdout_sha256']=check.digest(stdout.read_bytes())
        row=commands['commands'][0];p=Path(row['stderr_path']);p.write_bytes(b'WARNING: unexpected\n');row['stderr_sha256']=check.digest(p.read_bytes())
        with self.assertRaisesRegex(ValueError,'warning requires review'):v.validate_logs(lock,commands['commands'])
    def test_only_exact_performance_warning_in_query_phases(self):
        v,lock,commands,cli,producer,stage,pack,deps=self.fixture()
        run=Path(lock['run_root']);(run/'output/logs').mkdir(parents=True)
        lock['resolver_paths']={n:str(run/'output'/('resolve-'+n+'.json')) for n in ('query','successful','errors')}
        names={'resolve-query':'query','resolve-success':'successful','resolve-errors':'errors'}
        for row in commands['commands']:
            for stream in ('stdout','stderr'):
                path=Path(lock['resolver_paths'][names[row['label']]]) if stream=='stdout' and row['label'] in names else run/'output/logs'/(row['label']+'.'+stream)
                path.write_bytes(b'');row[stream+'_path']=str(path);row[stream+'_sha256']=check.digest(b'')
        row=next(r for r in commands['commands'] if r['label']=='success-query');p=Path(row['stderr_path'])
        p.write_text(v.KNOWN_CACHE_WARNING+'\n');row['stderr_sha256']=check.digest(p.read_bytes());row['classified_warnings']=[v.KNOWN_CACHE_WARNING]
        artifact=run/'output'/'success.bqrs';artifact.write_bytes(b'synthetic');row['artifacts']={str(artifact):check.digest(artifact.read_bytes())}
        v.validate_logs(lock,commands['commands'])
        p.write_text(v.KNOWN_CACHE_WARNING+'\nWARNING: unrelated\n');row['stderr_sha256']=check.digest(p.read_bytes());row['classified_warnings']=[v.KNOWN_CACHE_WARNING,'WARNING: unrelated']
        with self.assertRaisesRegex(ValueError,'warning requires review'):v.validate_logs(lock,commands['commands'])
        p.write_text(v.KNOWN_CACHE_WARNING+'\n');row['stderr_sha256']=check.digest(p.read_bytes());row['classified_warnings']=[]
        with self.assertRaisesRegex(ValueError,'warning classification differs'):v.validate_logs(lock,commands['commands'])
        row['classified_warnings']=[v.KNOWN_CACHE_WARNING]
        row=next(r for r in commands['commands'] if r['label']=='database-init');p=Path(row['stderr_path']);p.write_text(v.KNOWN_CACHE_WARNING+'\n');row['stderr_sha256']=check.digest(p.read_bytes());row['classified_warnings']=[v.KNOWN_CACHE_WARNING]
        with self.assertRaisesRegex(ValueError,'warning requires review'):v.validate_logs(lock,commands['commands'])

    def test_retained_route_must_match_raw_phase_hash(self):
        import verify
        with tempfile.TemporaryDirectory() as t:
            path=Path(t).resolve()/'routing.json';path.write_bytes(b'synthetic route')
            sha=check.digest(path.read_bytes());row={'artifacts':{str(path):sha},'raw_routing_sha256':sha}
            self.assertEqual(verify.validate_phase_artifact('database-index',row,str(path)),sha)
            row['raw_routing_sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'raw/retained routing digest differs'):verify.validate_phase_artifact('database-index',row,str(path))
            row['raw_routing_sha256']=sha;path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'phase artifact digest differs'):verify.validate_phase_artifact('database-index',row,str(path))

    def test_missing_rss_and_nonfinite_cost_rejected(self):
        v,l,c,cli,p,s,pack,deps=self.fixture()
        del c['commands'][0]['peak_rss_bytes']
        with self.assertRaisesRegex(ValueError,'peak RSS'):v.validate_commands(l,c,cli,p,s,pack,deps)
        c['commands'][0]['peak_rss_bytes']=100;c['commands'][0]['elapsed_seconds']=float('inf')
        with self.assertRaisesRegex(ValueError,'phase elapsed'):v.validate_commands(l,c,cli,p,s,pack,deps)

class PreflightControls(unittest.TestCase):
    def test_pack_tree_hash_detects_changes_and_aliases(self):
        import prepare
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve(); (root/'pack').mkdir(); p=root/'pack'/'file';p.write_bytes(b'synthetic test file')
            first=prepare.tree_digest(root/'pack');p.write_bytes(b'changed')
            self.assertNotEqual(first,prepare.tree_digest(root/'pack'))
            (root/'pack'/'link').symlink_to(p)
            with self.assertRaisesRegex(ValueError,'extractor pack symlink'):prepare.tree_digest(root/'pack')
    def test_fresh_run_layout_and_routing_identity(self):
        import prepare
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();stage=root/'stage'
            outputs={'routing':str(root/'output/routing.json'),**{n:str(root/'output'/(n+'.json')) for n in ('successful','errors','query')}}
            lock={'run_root':str(root),'database_path':str(root/'db'),'output_paths':outputs,
                  'bqrs_paths':{n:str(root/'output'/(n+'.bqrs')) for n in ('successful','errors','query')},
                  'resolver_paths':{n:str(root/'output'/('resolve-'+n+'.json')) for n in ('query','successful','errors')},
                  'commands_path':str(root/'output/commands.json'),'raw_routing_path':str(root/'db/trap/ucode/routing.json')}
            prepare.validate_layout(lock,stage,before=True)
            lock['output_paths']['routing']=str(root/'db/trap/ucode/routing.json')
            with self.assertRaisesRegex(ValueError,'output layout differs'):prepare.validate_layout(lock,stage,before=True)
            lock['output_paths']['routing']=str(root/'output/routing.json');(root/'db').mkdir()
            with self.assertRaisesRegex(ValueError,'not fresh'):prepare.validate_layout(lock,stage,before=True)
    def test_missing_and_invalid_run_pins_fail_before_io(self):
        import prepare
        for value in (None, '', '0'*64, 'G'*64):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'digest'):prepare.need_digest(value,'required')
    def test_create_stage_rejects_existing_and_alias(self):
        import prepare
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();existing=root/'stage';existing.mkdir()
            with self.assertRaisesRegex(ValueError,'stage must be new'):prepare.create_stage(b'not package',existing)
            alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'stage parent not physical'):prepare.create_stage(b'not package',alias/'stage2')

if __name__=="__main__":unittest.main()
