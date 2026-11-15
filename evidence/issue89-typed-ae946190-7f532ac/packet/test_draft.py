"""Unit tests only: synthetic data and harmless subprocesses, not live evidence."""
import copy
import csv
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent
OLD = HERE
CONSUMER = Path('/root/workspace/workflow-design/evidence/issue89-typed-ae946190-7f532ac-a3/consumer')

def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

class ComparatorTests(unittest.TestCase):
    def test_routing_and_source_archive_binding(self):
        import zipfile
        c=module('comparator')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            d=Path(t); src=d/'source'; src.write_bytes(b'fixture')
            route={'input_count':1,'plain_count':1,'markup_count':0,'markup_inconclusive_count':0,'uncertain_count':0,'excluded_count':0,'duplicate_input_count':0,'decisions':[{'path':str(src),'installed_path':'usr/share/rpcd/ucode/luci','classification':'plain','reason':'rpcd_raw_mode_full_path','status':'plain_route_selected'}]}
            p=d/'routing'; p.write_text(json.dumps(route)); c.check_routing(p,str(src),'usr/share/rpcd/ucode/luci')
            route['duplicate_input_count']=1; p.write_text(json.dumps(route))
            with self.assertRaises(ValueError): c.check_routing(p,str(src),'usr/share/rpcd/ucode/luci')
            z=d/'src.zip'
            with zipfile.ZipFile(z,'w') as f: f.writestr(str(src).lstrip('/'),b'fixture')
            c.check_archive(z,src)
            with zipfile.ZipFile(z,'a') as f: f.writestr('unexpected',b'x')
            with self.assertRaises(ValueError): c.check_archive(z,src)
    def setUp(self):
        self.c = module('comparator')
        self.tmp = tempfile.TemporaryDirectory(prefix='typed89-unit-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.b = Path(self.tmp.name)
        self.oracle = self.c.load(OLD/'oracle-csv-fixture.json')
        self.neutral = self.c.load(OLD/'oracle-neutral.json')
        self.retained = self.c.load(OLD/'oracle-retained.json')
        self.source = str(self.b / self.oracle['source_path'])
        self.csvwrite('effects.csv', [self.oracle['header']]+self.oracle['rows'])
        self.csvwrite('extracted.csv', [['f','col1'],[self.source,'']])
        self.csvwrite('errors.csv', [['error','col1','col2']])
        self.dump('typed.json', self.neutral)
        for i, path in enumerate(self.oracle['artifacts']):
            before = self.c.load(CONSUMER/path)
            after = [self.retained if r.get('record_id') == self.c.RID else r for r in before]
            self.dump('before-'+str(i)+'.json',before)
            self.dump('after-'+str(i)+'.json',after)
            self.dump('reimport-'+str(i)+'.json',after)
    def dump(self, name, obj):
        (self.b/name).write_text(json.dumps(obj, sort_keys=True), encoding='utf8')
    def csvwrite(self, name, rows):
        with (self.b/name).open('w', encoding='utf8', newline='') as f: csv.writer(f).writerows(rows)
    def reports(self): self.c.check_reports(self.b, CONSUMER, self.oracle, self.retained)
    def test_type_sensitive_equality(self):
        self.assertFalse(self.c.same({'n': 1}, {'n': 1.0}))
        self.assertFalse(self.c.same({'n': True}, {'n': 1}))
        self.assertTrue(self.c.same({'n': [1, 'x']}, {'n': [1, 'x']}))
    def test_synthetic_positive(self):
        self.c.check_csv(self.b, self.oracle, self.source)
        self.c.check_typed(self.b, self.neutral)
        self.reports()
    def test_csv_omission_substitution_duplicate_and_bad_quote(self):
        rows = [self.oracle['header']] + self.oracle['rows']
        for bad in ([rows[0]], [rows[0], rows[1], rows[1]], [rows[0], [*rows[1][:-1], '69']]):
            self.csvwrite('effects.csv',bad)
            with self.assertRaises(ValueError): self.c.check_csv(self.b,self.oracle,self.source)
        (self.b/'effects.csv').write_text('"unterminated', encoding='utf8')
        with self.assertRaises(ValueError): self.c.check_csv(self.b,self.oracle,self.source)
    def test_strict_csv_parser_rejects_permissive_recovery(self):
        import io
        payload='"known"junk,tail\n'
        self.assertEqual(list(csv.reader(io.StringIO(payload),strict=False)),[['knownjunk','tail']])
        (self.b/'malformed.csv').write_text(payload,encoding='utf8')
        with self.assertRaises(ValueError): self.c.readcsv(self.b/'malformed.csv')

    def test_diagnostics_and_neutral_unknown_mutations(self):
        diagnostics={
            'extracted.csv':[[['f','col1']],[['f','col1'],[self.source,''],[self.source,'']]],
            'errors.csv':[[['error','col1','col2'],['error','1','bad']],[['wrong','col1','col2']]],
        }
        for name, cases in diagnostics.items():
            original=(self.b/name).read_bytes()
            for rows in cases:
                self.csvwrite(name,rows)
                with self.subTest(name=name,rows=rows), self.assertRaises(ValueError):
                    self.c.check_csv(self.b,self.oracle,self.source)
            (self.b/name).write_bytes(original)
        for mutation in ('omit','duplicate','substitute'):
            bad=copy.deepcopy(self.neutral)
            unknowns=bad[0]['unknowns']
            if mutation=='omit': unknowns.pop()
            if mutation=='duplicate': unknowns.append(unknowns[0])
            if mutation=='substitute': unknowns[-1]='unreviewed replacement'
            self.dump('typed.json',bad)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.c.check_typed(self.b,self.neutral)

    def test_json_duplicate_key_and_nonfinite(self):
        # Last-value-wins parsers see the *exact* approved neutral oracle.
        raw=json.dumps(self.neutral,sort_keys=True)
        expected=json.dumps(self.neutral[0]['record_id'])
        field='"record_id": '+expected
        self.assertEqual(raw.count(field),1)
        for first in (expected,json.dumps('wrong-first')):
            payload=raw.replace(field,'"record_id": '+first+', '+field,1)
            self.assertTrue(self.c.same(json.loads(payload),self.neutral))
            (self.b/'typed.json').write_text(payload,encoding='utf8')
            with self.subTest(first=first), self.assertRaisesRegex(ValueError,'duplicate JSON key'):
                self.c.check_typed(self.b,self.neutral)
        (self.b/'typed.json').write_text('[NaN]',encoding='utf8')
        with self.assertRaises(ValueError): self.c.check_typed(self.b,self.neutral)
    def test_target_wrong_type_noop_and_unrelated_change(self):
        original = self.c.load(self.b/'after-0.json')
        for mutate in ('type', 'noop', 'unrelated', 'duplicate'):
            after = copy.deepcopy(original)
            if mutate == 'type': next(r for r in after if r.get('record_id')==self.c.RID)['source_location']['start_line']=532.0
            if mutate == 'noop': after=self.c.load(self.b/'before-0.json')
            if mutate == 'unrelated': next(r for r in after if r.get('record_id')!=self.c.RID)['test']=1
            if mutate == 'duplicate': after.append(copy.deepcopy(next(r for r in after if r.get('record_id')==self.c.RID)))
            self.dump('after-0.json',after); self.dump('reimport-0.json',after)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.reports()
    def test_malformed_extraction_and_coherent_omission(self):
        self.csvwrite('extracted.csv',[['f','col1'],['/wrong/source','']])
        with self.assertRaises(ValueError): self.c.check_csv(self.b,self.oracle,self.source)
        self.csvwrite('extracted.csv',[['f','col1'],[self.source,'']])
        self.csvwrite('effects.csv',[self.oracle['header']])
        self.dump('typed.json',[])
        with self.assertRaises(ValueError): self.c.check_csv(self.b,self.oracle,self.source)
        with self.assertRaises(ValueError): self.c.check_typed(self.b,self.neutral)
    def test_independent_prestate_validation_before_import(self):
        before0=self.c.load(self.b/'before-0.json'); before1=self.c.load(self.b/'before-1.json')
        self.c.check_prestates(before0,before1,self.oracle,self.retained)
        bad=copy.deepcopy(before1); next(r for r in bad if r.get('record_id')==self.c.RID)['method']='getBlockDevices'
        with self.assertRaises(ValueError): self.c.check_prestates(before0,bad,self.oracle,self.retained)
    def test_prestates_and_unknowns_are_exact(self):
        before = self.c.load(self.b/'before-0.json')
        next(r for r in before if r.get('record_id')==self.c.RID)['unknowns'].append('unreviewed unknown')
        self.dump('before-0.json', before)
        with self.assertRaises(ValueError): self.reports()
    def test_grant_and_deny_mutations_rejected(self):
        import shutil
        synthetic=self.b/'consumer'; (synthetic/'policy').mkdir(parents=True)
        for name in ('grants.json','policy_decisions.json'): shutil.copyfile(CONSUMER/'policy'/name,synthetic/'policy'/name)
        grants=self.c.load(synthetic/'policy/grants.json')
        next(g for g in grants if g.get('record_id')==self.oracle['grants'][0]['record_id'])['expectation_id']='root-administration'
        (synthetic/'policy/grants.json').write_text(json.dumps(grants))
        with self.assertRaises(ValueError): self.c.check_reports(self.b,synthetic,self.oracle,self.retained)
        shutil.copyfile(CONSUMER/'policy/grants.json',synthetic/'policy/grants.json')
        decisions=self.c.load(synthetic/'policy/policy_decisions.json')
        next(d for d in decisions['decisions'] if d.get('record_id')==self.oracle['deny_id'])['grant_emitted']=1
        (synthetic/'policy/policy_decisions.json').write_text(json.dumps(decisions))
        with self.assertRaises(ValueError): self.c.check_reports(self.b,synthetic,self.oracle,self.retained)
    def test_first_import_checked_before_reimport(self):
        (self.b/'reimport-0.json').unlink(); (self.b/'reimport-1.json').unlink()
        self.c.check_reports(self.b,CONSUMER,self.oracle,self.retained, require_reimport=False)
        bad=self.c.load(self.b/'after-0.json'); next(r for r in bad if r.get('record_id')==self.c.RID)['unknowns']=[]
        self.dump('after-0.json',bad)
        with self.assertRaises(ValueError): self.c.check_reports(self.b,CONSUMER,self.oracle,self.retained, require_reimport=False)
    def test_reimport_byte_difference_rejected(self):
        with (self.b/'reimport-0.json').open('ab') as f: f.write(b' ')
        with self.assertRaises(ValueError): self.reports()

class OrchestratorTests(unittest.TestCase):
    def test_exact_source_root_layout(self):
        o=module('orchestrator')
        self.assertTrue(o.valid_source_root(Path('/tmp/ql/test/extractor-smoke')))
        self.assertFalse(o.valid_source_root(Path('/tmp/other/extractor-smoke')))
    def test_executables_must_be_in_frozen_roots(self):
        o=module('orchestrator')
        exe=str(Path('/usr/bin/python3').resolve())
        cmd={'x':{'argv':['/usr/bin/python3']}}
        with self.assertRaises(ValueError): o.check_executable_pins(cmd, ['/not-the-interpreter'])
        o.check_executable_pins(cmd, [exe])
    def test_complete_synthetic_pipeline_with_real_stub_processes(self):
        self._exercise_synthetic_pipeline()

    def test_invalid_command_specs_stop_before_attempt(self):
        for mutation in ('extra-field','string-argv','relative-cwd','nonstring-env',
                         'nul-later-argv','nul-env-key','nul-env-value','nul-cwd',
                         'bad-env-key','unencodable-argv','python-without-E'):
            with self.subTest(mutation=mutation): self._exercise_synthetic_pipeline(mutation)

    def test_poisoned_cache_cannot_bypass_wrong_pins(self):
        self._exercise_synthetic_pipeline('poison-cache')

    def test_isolated_bootstrap_ignores_poisoned_cache_with_valid_pins(self):
        for mutation in ('poison-valid','poison-local'):
            with self.subTest(mutation=mutation): self._exercise_synthetic_pipeline(mutation)

    def test_bootstrap_requires_isolated_startup(self):
        import subprocess
        for flags in (['-S','-B'], ['-I','-B'], ['-I','-S']):
            p=subprocess.run(['/usr/bin/python3',*flags,str(HERE/'bootstrap.py')],capture_output=True,text=True)
            with self.subTest(flags=flags):
                self.assertNotEqual(p.returncode,0)
                self.assertIn('requires python -I -S -B',p.stderr)

    def test_bootstrap_rejects_valid_shaped_duplicate_approval_json(self):
        for mutation in ('duplicate-manifest-equal','duplicate-manifest-wrong',
                         'duplicate-ack-equal','duplicate-ack-wrong',
                         'duplicate-input-equal','duplicate-input-wrong'):
            with self.subTest(mutation=mutation): self._exercise_synthetic_pipeline(mutation)

    def test_input_inventory_types_stop_before_attempt(self):
        self._exercise_synthetic_pipeline('input-float')

    def test_packet_tampering_stops_before_attempt(self):
        for mutation in ('packet-tamper','source-tamper-comparator','source-tamper-recorder','source-tamper-orchestrator'):
            with self.subTest(mutation=mutation): self._exercise_synthetic_pipeline(mutation)

    def _exercise_synthetic_pipeline(self, mutation=None):
        import hashlib, shutil, subprocess, sys
        flags=['-E','-S','-B']+(['-O'] if sys.flags.optimize else [])
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); packet=root/'packet'; packet.mkdir(); producer=root/'producer'; producer.mkdir(); consumer=root/'consumer'
            shutil.copytree(CONSUMER,consumer,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            source_root=root/'ql/test/extractor-smoke'; source=source_root/'usr/share/rpcd/ucode/luci'; source.parent.mkdir(parents=True); source.write_bytes(b'synthetic unit source')
            distro=root/'dummy-distribution'; distro.mkdir(); (distro/'dummy').write_text('not CodeQL')
            for name in ('comparator.py','recorder.py','orchestrator.py'): shutil.copyfile(HERE/name,packet/name)
            for name in ('oracle-csv-fixture.json','oracle-neutral.json','oracle-retained.json'): shutil.copyfile(OLD/name,packet/name)
            oracle=json.loads((packet/'oracle-csv-fixture.json').read_text()); oracle['source_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
            (packet/'oracle-csv-fixture.json').write_text(json.dumps(oracle))
            stub=producer/'harmless_stub.py'
            stub.write_text('''import csv, io, json, pathlib, sys, zipfile\nact, attempt, source, consumer, packet = sys.argv[1:]\na=pathlib.Path(attempt); s=pathlib.Path(source); k=pathlib.Path(consumer); p=pathlib.Path(packet); db=a/'database'; art=a/'artifacts'\no=json.loads((p/'oracle-csv-fixture.json').read_text())\nif act.endswith('-resolve'): print(json.dumps({'synthetic':act}))\nelif act=='init': db.mkdir()\nelif act=='index':\n q=db/'trap/ucode'; q.mkdir(parents=True)\n (q/'routing.json').write_text(json.dumps({'input_count':1,'plain_count':1,'markup_count':0,'markup_inconclusive_count':0,'uncertain_count':0,'excluded_count':0,'duplicate_input_count':0,'decisions':[{'path':str(s),'installed_path':o['source_path'],'classification':'plain','reason':'rpcd_raw_mode_full_path','status':'plain_route_selected'}]}))\nelif act=='finalize':\n with zipfile.ZipFile(db/'src.zip','w') as z: z.writestr(str(s).lstrip('/'),s.read_bytes())\nelif act.endswith('-query'):\n n=act[:-6]; rows={'effects':[o['header']]+o['rows'],'extracted':[['f','col1'],[str(s),'']],'errors':[['error','col1','col2']]}[n]\n with (art/(n+'.bqrs')).open('w',newline='') as f: csv.writer(f).writerows(rows)\nelif act.endswith('-decode'): sys.stdout.buffer.write((art/(act[:-7]+'.bqrs')).read_bytes())\nelif act=='export': sys.stdout.buffer.write((p/'oracle-neutral.json').read_bytes())\nelif act=='import':\n target=json.loads((p/'oracle-retained.json').read_text())\n for path in o['artifacts']:\n  f=k/path; rows=json.loads(f.read_text()); rows=[target if x.get('record_id')==target['record_id'] else x for x in rows]; f.write_text(json.dumps(rows,sort_keys=True))\nelse: raise RuntimeError(act)\n''')
            attempt=root/'attempt'; env={'HOME':str(attempt/'home'),'TMPDIR':str(attempt/'tmp'),'XDG_CACHE_HOME':str(attempt/'cache'),'XDG_CONFIG_HOME':str(attempt/'config'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','PATH':'/usr/bin:/bin'}
            names=['init','index','finalize','export','import','reimport']+[n+'-'+s for n in ('effects','extracted','errors') for s in ('query','decode','resolve')]
            commands={}
            for name in names:
                action='import' if name=='reimport' else name
                commands[name]={'argv':['/usr/bin/python3',*flags,str(stub),action,str(attempt),str(source),str(consumer),str(packet)],'cwd':str(producer),'env':env}
                if name.endswith('-resolve'): (packet/(name[:-8]+'-resolution.json')).write_text(json.dumps({'synthetic':name}))
            if mutation=='extra-field': commands['export']['unreviewed']='field'
            if mutation=='string-argv': commands['errors-resolve']['argv']='/usr/bin/python3'
            if mutation=='relative-cwd': commands['errors-resolve']['cwd']='relative'
            if mutation=='nonstring-env': env['LANG']=1
            if mutation=='nul-later-argv': commands['export']['argv'].append('embedded\0nul')
            if mutation=='nul-env-key': env['BAD\0KEY']='value'
            if mutation=='nul-env-value': env['LANG']='bad\0value'
            if mutation=='nul-cwd': commands['export']['cwd']='/bad\0cwd'
            if mutation=='bad-env-key': env['BAD=KEY']='value'
            if mutation=='unencodable-argv': commands['export']['argv'].append('\ud800')
            if mutation=='python-without-E': commands['export']['argv'].remove('-E')
            config={'attempt':str(attempt),'producer':str(producer),'consumer':str(consumer),'source':str(source),'source_root':str(source_root),'codeql_root':str(distro),'commands':commands}
            (packet/'config.json').write_text(json.dumps(config))
            inputs={str(p):r.inventory(p) for p in (producer,consumer,source_root,distro,Path('/usr/bin/python3').resolve())}
            if mutation=='input-float': inputs[str(producer)]['harmless_stub.py']['size']=float(inputs[str(producer)]['harmless_stub.py']['size'])
            raw_inputs=json.dumps(inputs)
            if mutation and mutation.startswith('duplicate-input-'):
                key=str(producer); field=json.dumps(key)+': '
                first=json.dumps(inputs[key]) if mutation.endswith('equal') else '{}'
                raw_inputs=raw_inputs.replace(field,field+first+', '+field,1)
                self.assertEqual(json.loads(raw_inputs),inputs)
            (packet/'input-inventories.json').write_text(raw_inputs)
            marker=root/'unapproved-code-ran'
            if mutation=='poison-local':
                import py_compile
                injected=root/'injected.py'
                injected.write_text((packet/'recorder.py').read_text()+f'\ndef verify_approval(*args, **kwargs):\n    Path({str(marker)!r}).write_text("injected")\n')
                old_prefix=sys.pycache_prefix
                try:
                    sys.pycache_prefix=None
                    cache=Path(importlib.util.cache_from_source(str(packet/'recorder.py'),optimization='1' if sys.flags.optimize else ''))
                finally: sys.pycache_prefix=old_prefix
                cache.parent.mkdir(parents=True)
                py_compile.compile(str(injected),cfile=str(cache),dfile=str(packet/'recorder.py'),doraise=True,optimize=1 if sys.flags.optimize else 0,invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
            manifest=root/'manifest.json'; manifest.write_text(json.dumps({k:v for k,v in r.inventory(packet).items() if k!='.'}))
            md=r.sha(manifest); ack=root/'ack.json'; ack.write_text(json.dumps({'approved_manifest_sha256':md,'decision':'approve'})); ad=r.sha(ack)
            if mutation and mutation.startswith('duplicate-manifest-'):
                data=json.loads(manifest.read_text()); raw=manifest.read_text()
                field='"config.json": '
                first=json.dumps(data['config.json']) if mutation.endswith('equal') else '{}'
                raw=raw.replace(field,field+first+', '+field,1)
                self.assertEqual(json.loads(raw),data)
                manifest.write_text(raw); md=r.sha(manifest)
                ack.write_text(json.dumps({'approved_manifest_sha256':md,'decision':'approve'})); ad=r.sha(ack)
            if mutation and mutation.startswith('duplicate-ack-'):
                data=json.loads(ack.read_text()); raw=ack.read_text()
                first='"approve"' if mutation.endswith('equal') else '"deny"'
                raw=raw.replace('"decision": "approve"','"decision": '+first+', "decision": "approve"',1)
                self.assertEqual(json.loads(raw),data)
                ack.write_text(raw); ad=r.sha(ack)
            if mutation and mutation.startswith('source-tamper-'):
                target=packet/(mutation.removeprefix('source-tamper-')+'.py')
                with target.open('a') as f: f.write(f'\nopen({str(marker)!r}, "w").write("injected")\n')
            if mutation=='packet-tamper': (packet/'unapproved-file').write_bytes(b'unapproved')
            process_env=os.environ.copy()
            if mutation in ('poison-cache','poison-valid'):
                import py_compile
                injected=root/'injected.py'
                injected.write_text((packet/'recorder.py').read_text()+f'\ndef verify_approval(*args, **kwargs):\n    Path({str(marker)!r}).write_text("injected")\n')
                prefix=root/'external-bytecode'; old_prefix=sys.pycache_prefix
                try:
                    sys.pycache_prefix=str(prefix)
                    cache=Path(importlib.util.cache_from_source(str(packet/'recorder.py'),optimization='1' if sys.flags.optimize else ''))
                finally: sys.pycache_prefix=old_prefix
                cache.parent.mkdir(parents=True)
                py_compile.compile(str(injected),cfile=str(cache),dfile=str(packet/'recorder.py'),doraise=True,optimize=1 if sys.flags.optimize else 0,invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
                process_env['PYTHONPYCACHEPREFIX']=str(prefix)
                if mutation=='poison-cache': md='0'*64; ad='1'*64
            entry = (['/usr/bin/python3',*[f for f in flags if f!='-E'],str(packet/'orchestrator.py')] if mutation=='poison-cache'
                     else ['/usr/bin/python3','-I',*flags,str(HERE/'bootstrap.py')])
            proc=subprocess.run([*entry,'--packet',str(packet),'--manifest',str(manifest),'--manifest-sha256',md,'--ack',str(ack),'--ack-sha256',ad],text=True,capture_output=True,env=process_env)
            self.assertFalse(marker.exists(),'unapproved recorder cache ran')
            if mutation and mutation not in ('poison-valid','poison-local'):
                self.assertNotEqual(proc.returncode,0,proc.stdout+'\\n'+proc.stderr)
                self.assertFalse(attempt.exists(),proc.stdout+'\\n'+proc.stderr)
                return
            self.assertEqual(proc.returncode,0,proc.stdout+'\\n'+proc.stderr)
            self.assertTrue(module('comparator').same(json.loads((attempt/'complete.json').read_text()),{'status':'consistent_observed_boundaries','coverage':'partial','attestation':False}))
            receipts=list((attempt/'logs').glob('*.receipt.json')); self.assertEqual(len(receipts),15)
            self.assertEqual(json.loads((attempt/'logs/import.receipt.json').read_text())['exit_code'],0)
            self.assertEqual((attempt/'artifacts/after-0.json').read_bytes(),(attempt/'artifacts/reimport-0.json').read_bytes())

    def test_unapproved_packet_never_creates_attempt(self):
        o=module('orchestrator')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); packet=root/'packet'; packet.mkdir(); attempt=root/'attempt'
            (packet/'config.json').write_text(json.dumps({'attempt':str(attempt)}))
            manifest=root/'manifest'; manifest.write_text('{}')
            ack=root/'ack'; ack.write_text('{}')
            with self.assertRaises(ValueError): o.run(packet,manifest,'0'*64,ack,'1'*64)
            self.assertFalse(attempt.exists())

class RecorderTests(unittest.TestCase):
    def test_valid_shaped_duplicate_manifest_and_ack_rejected(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); packet=root/'packet'; packet.mkdir(); (packet/'recipe').write_bytes(b'fixture')
            expected={k:v for k,v in r.inventory(packet).items() if k!='.'}
            manifest=root/'manifest'; ack=root/'ack'
            for which in ('manifest','ack'):
                for wrong in (False,True):
                    raw=json.dumps(expected,sort_keys=True)
                    field='"recipe": '
                    if which=='manifest':
                        first=json.dumps({'wrong':'first'}) if wrong else json.dumps(expected['recipe'],sort_keys=True)
                        raw=raw.replace(field,field+first+', '+field,1)
                        self.assertEqual(json.loads(raw),expected)
                    manifest.write_text(raw); digest=r.sha(manifest)
                    approved={'approved_manifest_sha256':digest,'decision':'approve'}
                    a=json.dumps(approved,sort_keys=True)
                    if which=='ack':
                        first='"deny"' if wrong else '"approve"'
                        a=a.replace('"decision": "approve"','"decision": '+first+', "decision": "approve"',1)
                        self.assertEqual(json.loads(a),approved)
                    ack.write_text(a)
                    with self.subTest(which=which,wrong=wrong), self.assertRaisesRegex(ValueError,'duplicate JSON key'):
                        r.verify_approval(packet,manifest,digest,ack,r.sha(ack))

    def test_approval_manifest_is_utf8_and_type_sensitive(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); packet=root/'packet'; packet.mkdir(); (packet/'recipe').write_bytes(b'fixture')
            expected={k:v for k,v in r.inventory(packet).items() if k!='.'}
            manifest=root/'manifest'; ack=root/'ack'
            for mutation in ('float-size','bool-mode','utf16'):
                bad=copy.deepcopy(expected)
                if mutation=='float-size': bad['recipe']['size']=float(bad['recipe']['size'])
                if mutation=='bool-mode':
                    (packet/'recipe').chmod(0o1)
                    bad['recipe']=r.inventory(packet/'recipe')['.']; bad['recipe']['mode']=True
                encoding='utf-16' if mutation=='utf16' else 'utf-8'
                manifest.write_bytes(json.dumps(bad).encode(encoding))
                digest=r.sha(manifest)
                ack.write_text(json.dumps({'approved_manifest_sha256':digest,'decision':'approve'}),encoding='utf8')
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    r.verify_approval(packet,manifest,digest,ack,r.sha(ack))
                (packet/'recipe').chmod(0o600)
                expected={k:v for k,v in r.inventory(packet).items() if k!='.'}

    def test_approval_digest_and_manifest_fail_closed(self):
        r=module('recorder')
        import hashlib
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); packet=root/'packet'; packet.mkdir(); (packet/'recipe').write_text('approved bytes')
            manifest=root/'manifest.json'
            manifest.write_text(json.dumps({'recipe':r.inventory(packet/'recipe')['.']}))
            digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
            ack=root/'ack.json'; ack.write_text(json.dumps({'approved_manifest_sha256':digest,'decision':'approve'}))
            ack_digest=hashlib.sha256(ack.read_bytes()).hexdigest()
            r.verify_approval(packet,manifest,digest,ack,ack_digest)
            (packet/'extra').write_text('unapproved')
            with self.assertRaises(ValueError): r.verify_approval(packet,manifest,digest,ack,ack_digest)
            (packet/'extra').unlink(); (packet/'recipe').write_text('changed')
            with self.assertRaises(ValueError): r.verify_approval(packet,manifest,digest,ack,ack_digest)
            with self.assertRaises(ValueError): r.verify_approval(packet,manifest,'0'*64,ack,ack_digest)
            with self.assertRaises(ValueError): r.verify_approval(packet,manifest,digest,ack,'0'*64)

    def test_symlink_inventory_and_missing_output_are_rejected(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); logs=root/'logs'; logs.mkdir(); target=root/'target'; target.write_bytes(b'fixture')
            link=root/'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): r.inventory(link)
            with self.assertRaises(ValueError): r.inventory(root)
            cmd={'argv':['/usr/bin/python3','-S','-B','-c','pass'],'cwd':t,'env':{},'inputs':[],'outputs':[str(root/'missing')]}
            with self.assertRaises(r.StageError): r.run_stage('missing-output',cmd,logs)
            receipt=json.loads((logs/'missing-output.receipt.json').read_text())
            self.assertEqual(receipt['exit_code'],0)
            self.assertEqual(len(receipt['boundary_errors']),1)
            self.assertEqual(receipt['outputs'],{})

    def test_value_and_encoding_launch_errors_leave_structured_receipts(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); logs=root/'logs'; logs.mkdir()
            for name, arg, error in [('nul','bad\0arg','ValueError'),('encoding','\ud800','UnicodeEncodeError')]:
                cmd={'argv':['/usr/bin/python3',arg],'cwd':t,'env':{},'inputs':[],'outputs':[]}
                with self.subTest(name=name):
                    with self.assertRaises(r.StageError): r.run_stage(name,cmd,logs)
                    receipt=json.loads((logs/(name+'.receipt.json')).read_text())
                    self.assertIsNone(receipt['exit_code']); self.assertIn(error,receipt['launch_error'])
                    self.assertGreaterEqual(receipt['elapsed_ns'],0)
                    self.assertEqual(receipt['inputs_before'],receipt['inputs_after'])
                    self.assertEqual(receipt['stdout_sha256'],r.sha(logs/(name+'.stdout')))
                    self.assertEqual(receipt['stderr_sha256'],r.sha(logs/(name+'.stderr')))

    def test_launch_error_is_retained_not_success(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); logs=root/'logs'; logs.mkdir()
            cmd={'argv':[str(root/'nonexistent-executable')],'cwd':t,'env':{},'inputs':[],'outputs':[]}
            with self.assertRaises(r.StageError): r.run_stage('launch-error',cmd,logs)
            receipt=json.loads((logs/'launch-error.receipt.json').read_text())
            self.assertIsNone(receipt['exit_code']); self.assertIn('FileNotFoundError',receipt['launch_error'])
            self.assertIsInstance(receipt['elapsed_ns'],int); self.assertGreaterEqual(receipt['elapsed_ns'],0)
            self.assertEqual(receipt['stdout_sha256'],r.sha(logs/'launch-error.stdout'))
            self.assertEqual(receipt['stderr_sha256'],r.sha(logs/'launch-error.stderr'))

    def test_mutable_and_stdout_artifact_boundaries(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); logs=root/'logs'; logs.mkdir(); mutable=root/'state'; mutable.write_text('before')
            artifact=root/'out'
            cmd={'argv':['/usr/bin/python3','-S','-B','-c','from pathlib import Path; Path("state").write_text("after"); print("bytes")'],'cwd':t,'env':{},'inputs':[],'mutables':[str(mutable)],'outputs':[],'stdout_artifact':str(artifact)}
            receipt=r.run_stage('mutable',cmd,logs)
            self.assertNotEqual(receipt['mutables_before'],receipt['mutables_after'])
            self.assertEqual(artifact.read_bytes(),b'bytes\n')
            self.assertEqual(receipt['stdout_sha256'], r.sha(artifact))

    def test_existing_output_stops_before_process_and_input_mutation_fails(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            root=Path(t); logs=root/'logs'; logs.mkdir(); inp=root/'input'; inp.write_text('before'); out=root/'out'; out.write_text('existing'); marker=root/'marker'
            cmd={'argv':['/usr/bin/python3','-S','-B','-c',f'from pathlib import Path; Path({str(marker)!r}).write_text("ran")'], 'cwd':t,'env':{},'inputs':[str(inp)],'outputs':[str(out)]}
            with self.assertRaises(FileExistsError): r.run_stage('existing',cmd,logs)
            self.assertFalse(marker.exists()); self.assertEqual(out.read_text(),'existing')
            cmd['outputs']=[]; cmd['argv']=['/usr/bin/python3','-S','-B','-c',f'from pathlib import Path; Path({str(inp)!r}).write_text("changed")']
            with self.assertRaises(r.StageError): r.run_stage('mutated',cmd,logs)
            receipt=json.loads((logs/'mutated.receipt.json').read_text()); self.assertEqual(receipt['exit_code'],0)
            self.assertNotEqual(receipt['inputs_before'],receipt['inputs_after'])
    def test_success_failure_and_real_receipts(self):
        r=module('recorder')
        with tempfile.TemporaryDirectory(prefix='typed89-unit-',dir=os.environ['TMPDIR']) as t:
            d=Path(t); inp=d/'input'; inp.write_bytes(b'unit input')
            logs=d/'logs'; logs.mkdir()
            cmd={'argv':['/usr/bin/python3','-S','-B','-c','import os,sys; print(os.getenv("UNIT")); print("stderr",file=sys.stderr)'], 'cwd':t,'env':{'UNIT':'fixture'},'inputs':[str(inp)],'outputs':[]}
            got=r.run_stage('unit',cmd,logs)
            self.assertEqual(got['exit_code'],0); self.assertEqual(got['argv'],cmd['argv'])
            self.assertEqual(got['environment'],cmd['env'])
            self.assertEqual((logs/'unit.stdout').read_bytes(),b'fixture\n')
            self.assertEqual((logs/'unit.stderr').read_bytes(),b'stderr\n')
            self.assertEqual(got['inputs_before'],got['inputs_after'])
            bad=dict(cmd,argv=['/usr/bin/python3','-S','-B','-c','import sys; sys.exit(7)'])
            with self.assertRaises(r.StageError): r.run_stage('bad',bad,logs)
            self.assertEqual(json.loads((logs/'bad.receipt.json').read_text())['exit_code'],7)
            with self.assertRaises(FileExistsError): r.run_stage('unit',cmd,logs)

if __name__ == '__main__': unittest.main()
