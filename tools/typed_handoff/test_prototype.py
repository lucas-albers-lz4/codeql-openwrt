#!/usr/bin/env python3
"""Synthetic smoke only; not evidence of a CodeQL or policy execution."""
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PY = str(Path(sys.executable).resolve()); GIT = str(Path(shutil.which('git')).resolve())
STAGES = ('init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode','export','import','reimport')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p, obj): p.write_text(json.dumps(obj))
class Prototype(unittest.TestCase):
    def test_synthetic_transition_and_mutation(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve(); consumer = root/'consumer'; consumer.mkdir()
            source = root/'source'; source.mkdir()
            original = HERE.parent.parent/'evidence/typed-handoff-d398198-1f01e0a'
            source_file = source/'usr/share/rpcd/ucode/luci'; source_file.parent.mkdir(parents=True)
            shutil.copyfile(original/'source/usr/share/rpcd/ucode/luci', source_file)
            family = json.loads((original/'oracle-expanded.json').read_text())
            lock = consumer/'corpus/lock.json'; lock.parent.mkdir(); shutil.copyfile(HERE.parent.parent/'corpus/lock.json',lock)
            reports = ['reports/handler_effects.json','reports/m4-block-device-exec.json']
            report = consumer/reports[0]; report.parent.mkdir()
            before = [{'record_id':'m4:effect:luci-setBlockDetect-system','value':'before'}, {'record_id':'keep'}]
            after = [{'record_id':'m4:effect:luci-setBlockDetect-system','value':'after'}, {'record_id':'keep'}]
            dump(report, before)
            second = consumer/reports[1]; dump(second, before)
            producer = root/'producer'; producer.mkdir()
            (producer/'marker').write_text('pinned producer')
            pins = {}
            for name, checkout in [('producer',producer),('consumer',consumer)]:
                subprocess.run(['git','init','--quiet','--separate-git-dir',str(root/(name+'-git')),str(checkout)],check=True)
                subprocess.run(['git','add','.'],cwd=checkout,check=True)
                subprocess.run(['git','-c','user.name=Synthetic','-c','user.email=synthetic@example.invalid','commit','--quiet','-m','fixture'],cwd=checkout,check=True)
                pins[name] = subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()
            script = root/'stage.py'
            script.write_text('''import json, os, pathlib, sys\ns=sys.argv[1]; r=pathlib.Path(os.environ["RUN"]); c=pathlib.Path(os.environ["CONSUMER"])\nif s=="init":\n (r/"db/log").mkdir(parents=True)\n (r/"db/data").write_text("database")\n (r/"db/db-ucode/default/cache").mkdir(parents=True)\n (r/"runtime/approved").mkdir()\n (r/"runtime/approved/data").write_text("cache")\nif s=="extracted_query":\n for name in ["pages","predicates","relations"]: (r/("db/db-ucode/default/cache/"+name)).mkdir()\nif s.endswith("_query"):\n (r/(s[:-6]+".bqrs")).write_text("bqrs")\n (r/("db/log/query-run-"+s+".log")).write_text("query log")\n (r/("db/log/execute-queries-"+s+".log")).write_text("query log")\nif s.endswith("_decode"):\n import csv\n csv.writer(sys.stdout,lineterminator="\\n").writerows(json.loads(pathlib.Path(os.environ["ORACLE"]).read_text())[s[:-7]+"_rows"])\nif s=="export": print(json.dumps(json.loads(pathlib.Path(os.environ["ORACLE"]).read_text())["neutral_typed_payload"]))\nif s=="import":\n for name in ["reports/handler_effects.json","reports/m4-block-device-exec.json"]: (c/name).write_text(json.dumps([{"record_id":"m4:effect:luci-setBlockDetect-system","value":"after"},{"record_id":"keep"}]))\n''')
            run = root/'run'; oracle = root/'oracle.json'; context = root/'context.json'
            dump(oracle, {'source':'usr/share/rpcd/ucode/luci', 'source_sha256':family['source_sha256'], 'lock_sha256':family['lock_sha256'], 'extracted_rows':[['f','col1'],[str(source_file),'']], 'errors_rows':family['errors_rows'], 'effects_rows':family['effects_rows'], 'neutral_typed_payload':family['neutral_typed_payload'], 'expected_effects':reports, 'prestate_provenance':{name:{'target_index':0} for name in reports}, 'expected_complete_targets':{name:[after[0]] for name in reports}})
            commands = {s:{'argv':[PY,str(script),s], 'cwd':str(root), 'env':{'RUN':str(run),'CONSUMER':str(consumer),'ORACLE':str(oracle)}} for s in STAGES}
            initial = {'reports':{'directory':True}, 'corpus':{'directory':True}, '.git':{'sha256':sha(consumer/'.git'),'size':(consumer/'.git').stat().st_size}} | {name:{'sha256':sha(consumer/name),'size':(consumer/name).stat().st_size} for name in reports} | {'corpus/lock.json':{'sha256':sha(lock),'size':lock.stat().st_size}}
            dump(context, {'oracle_sha256':sha(oracle),'commands':commands,'inputs':{'consumer':str(consumer),'producer':str(producer),'source':str(source)},'run':str(run),'initial':{'consumer':initial,'producer':{name:{'sha256':sha(producer/name),'size':(producer/name).stat().st_size} for name in ('.git','marker')},'source':{**{d:{'directory':True} for d in ('usr','usr/share','usr/share/rpcd','usr/share/rpcd/ucode')},'usr/share/rpcd/ucode/luci':{'sha256':sha(source_file),'size':source_file.stat().st_size}}},'git':pins,'runtime_directories':['home','tmp'],'runtime_transitions':{s:(['approved'] if s=='init' else []) for s in STAGES},'required_absent':['runtime/empty-pycache'],'git_executable':GIT,'git_env':{'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null'},'runner_sha256':sha(HERE/'runner.py'),'verifier_sha256':sha(HERE/'verify.py'),'executables':{PY:sha(Path(PY)),GIT:sha(Path(GIT))},'outputs':{k:k+'.csv' for k in ('extracted','errors','effects')}|{'typed':'typed.json','database':'db','runtime':'runtime'}|{k+'_bqrs':k+'.bqrs' for k in ('extracted','errors','effects')}})
            bad_context = root/'bad-context.json'; bad = json.loads(context.read_text()); bad['runner_sha256'] = '0'*64; dump(bad_context,bad)
            digest_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(digest_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('implementation digest mismatch',result.stderr)
            bad = json.loads(context.read_text()); bad['executables'][PY] = '0'*64; dump(bad_context,bad)
            result = subprocess.run(digest_cmd[:-1]+[sha(bad_context)],capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('executable digest mismatch',result.stderr)
            bad = json.loads(context.read_text()); bad['git']['producer'] = '0'*40; dump(bad_context,bad)
            bad_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(bad_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('unclean or wrong git input: producer',result.stderr)
            bad = json.loads(context.read_text()); bad['commands']['init']['argv'][0] = 'python3'; bad['executables']['python3'] = sha(Path(PY)); dump(bad_context,bad)
            relative_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(relative_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('absolute and normalized',result.stderr)
            bad_oracle = root/'bad-oracle.json'; wrong_family = json.loads(oracle.read_text()); wrong_family['effects_rows'][1][3] = 'other'; dump(bad_oracle,wrong_family)
            bad = json.loads(context.read_text()); bad['oracle_sha256'] = sha(bad_oracle); dump(bad_context,bad)
            bad_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(bad_oracle),sha(bad_context)]
            result = subprocess.run(bad_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('family oracle: effects_rows',result.stderr)
            link = root/'source-hardlink'; os.link(source_file,link)
            result = subprocess.run([sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(context),str(oracle),sha(context)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0); self.assertIn('hardlinked input',result.stderr); link.unlink()
            source_link = root/'source-link'; source_link.symlink_to(source, target_is_directory=True)
            symlinked = json.loads(context.read_text()); symlinked['inputs']['source'] = str(source_link)
            linked_oracle = json.loads(oracle.read_text()); linked_oracle['extracted_rows'][1][0] = str(source_link/'usr/share/rpcd/ucode/luci'); dump(bad_oracle,linked_oracle)
            symlinked['oracle_sha256'] = sha(bad_oracle); dump(bad_context,symlinked)
            link_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(bad_oracle),sha(bad_context)]
            result = subprocess.run(link_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('symlink path component',result.stderr)
            aliased = json.loads(context.read_text()); aliased['run'] = str(root/'alias-run'); aliased['outputs']['errors'] = aliased['outputs']['effects']; dump(bad_context,aliased)
            alias_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(alias_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('overlapping output paths',result.stderr)
            failed = json.loads(context.read_text()); failed['run'] = str(root/'failed-run'); failed['commands']['init']['argv'] = [PY, '-c', 'raise SystemExit(7)']; dump(bad_context,failed)
            failed_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(failed_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('stage failed: init',result.stderr)
            self.assertEqual(json.loads((root/'failed-run/init.receipt.json').read_text())['exit_code'],7)
            self.assertFalse((root/'failed-run/index.receipt.json').exists())
            conflict = json.loads(context.read_text()); conflict['run'] = str(root/'conflict'); conflict['runtime_directories'] = ['empty-pycache']; dump(bad_context,conflict)
            conflict_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(conflict_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('required absence conflicts',result.stderr)
            invalid = json.loads(context.read_text()); invalid['run'] = str(root/'invalid-allowlist'); invalid['runtime_transitions']['reimport'] = ['../escape']; dump(bad_context,invalid)
            invalid_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(invalid_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('invalid runtime allowlist',result.stderr); self.assertFalse((root/'invalid-allowlist').exists())
            failed = json.loads(context.read_text()); failed['run'] = str(root/'runtime-failure'); failed['commands']['init']['env']['RUN'] = failed['run']
            failed['commands']['init']['argv'] = [PY,'-c',"import os,pathlib; p=pathlib.Path(os.environ['RUN']); (p/'db').mkdir(); (p/'runtime/unexpected').write_text('x')"]
            dump(bad_context,failed); runtime_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(runtime_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('unexpected runtime transition',result.stderr)
            failed = json.loads(context.read_text()); failed['run'] = str(root/'snapshot-failure'); failed['commands']['init']['env']['RUN'] = failed['run']
            failed['commands']['init']['argv'] = [PY,'-c',"import os,pathlib; p=pathlib.Path(os.environ['RUN'])/'db'; p.mkdir(); (p/'link').symlink_to('/dev/null')"]
            dump(bad_context,failed); failure_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(oracle),sha(bad_context)]
            result = subprocess.run(failure_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('stage artifact or snapshot failed: init',result.stderr)
            self.assertIn('symlink',json.loads((root/'snapshot-failure/init.failure.json').read_text())['snapshot_error'])
            bad_target = json.loads(oracle.read_text()); bad_target['expected_complete_targets'][reports[0]][0]['value'] = 'wrong'; dump(bad_oracle,bad_target)
            target_context = json.loads(context.read_text()); target_context['oracle_sha256'] = sha(bad_oracle); target_context['run'] = str(root/'target-run')
            for cfg in target_context['commands'].values(): cfg['env']['RUN'] = target_context['run']; cfg['env']['ORACLE'] = str(bad_oracle)
            dump(bad_context,target_context)
            target_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(bad_context),str(bad_oracle),sha(bad_context)]
            result = subprocess.run(target_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('import target mismatch',result.stderr)
            self.assertFalse((root/'target-run/reimport.receipt.json').exists())
            for name in reports: dump(consumer/name,before)
            marker = producer/'marker'; marker.write_text('changed')
            clean_cmd = [sys.executable,str(HERE/'runner.py'),'--synthetic-only',str(context),str(oracle),sha(context)]
            result = subprocess.run(clean_cmd,capture_output=True,text=True); self.assertNotEqual(result.returncode,0); self.assertIn('input inventory mismatch: producer',result.stderr)
            marker.write_text('pinned producer')
            env = [sys.executable, str(HERE/'runner.py'), '--synthetic-only', str(context),str(oracle),sha(context)]
            p = subprocess.run(env, capture_output=True, text=True); self.assertEqual(p.returncode,0,p.stderr)
            cmd = [sys.executable,str(HERE/'verify.py'),str(run),str(context),str(oracle),sha(context),sha(oracle)]
            p = subprocess.run(cmd,capture_output=True,text=True); self.assertEqual(p.returncode,0,p.stderr)
            repeated = subprocess.run(env,capture_output=True,text=True)
            self.assertNotEqual(repeated.returncode,0); self.assertIn('fresh and absolute',repeated.stderr)
            runtime_file = root/'runtime-file'; shutil.copytree(run,runtime_file)
            for stage, edge in [('errors_query','after'),('errors_decode','before')]:
                path = runtime_file/(stage+'.receipt.json'); rec = json.loads(path.read_text()); rec[edge]['runtime'] = {'sha256':'0'*64,'size':1}; dump(path,rec)
            runtime_file_cmd = [*cmd]; runtime_file_cmd[2] = str(runtime_file)
            p = subprocess.run(runtime_file_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('runtime directory state: errors_query',p.stderr)
            boolean = root/'boolean'; shutil.copytree(run,boolean); path = boolean/'init.receipt.json'; rec = json.loads(path.read_text()); rec['before']['consumer'][reports[0]]['size'] = True; dump(path,rec)
            boolean_cmd = [*cmd]; boolean_cmd[2] = str(boolean)
            p = subprocess.run(boolean_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('inventory schema: init',p.stderr)
            missing_db = root/'missing-db'; shutil.copytree(run, missing_db); shutil.rmtree(missing_db/'db')
            missing_cmd = [*cmd]; missing_cmd[2] = str(missing_db)
            p = subprocess.run(missing_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('database directory',p.stderr)
            extra = root/'extra'; shutil.copytree(run,extra); (extra/'unexpected').write_text('x')
            extra_cmd = [*cmd]; extra_cmd[2] = str(extra)
            p = subprocess.run(extra_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('packet inventory',p.stderr)
            symlink = root/'packet-link'; shutil.copytree(run,symlink); log = next((symlink/'db/log').iterdir()); log.unlink(); log.symlink_to(root/'oracle.json')
            symlink_cmd = [*cmd]; symlink_cmd[2] = str(symlink)
            p = subprocess.run(symlink_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('symlink:',p.stderr)
            fifo = root/'fifo'; shutil.copytree(run,fifo); (fifo/'init.stdout').unlink(); os.mkfifo(fifo/'init.stdout')
            fifo_cmd = [*cmd]; fifo_cmd[2] = str(fifo)
            p = subprocess.run(fifo_cmd,capture_output=True,text=True,timeout=5); self.assertNotEqual(p.returncode,0); self.assertIn('special entry',p.stderr)
            bad_size = root/'bad-size'; shutil.copytree(run,bad_size)
            for index, stage in enumerate(STAGES):
                path = bad_size/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > STAGES.index('effects_decode') or (stage == 'effects_decode' and edge == 'after'): rec[edge]['effects']['size'] = 0
                dump(path,rec)
            size_cmd = [*cmd]; size_cmd[2] = str(bad_size)
            p = subprocess.run(size_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('output binding: effects',p.stderr)
            altered_stream = root/'altered-stream'; shutil.copytree(run, altered_stream)
            (altered_stream/'errors_decode.stdout').write_text('corrupt')
            stream_cmd = [*cmd]; stream_cmd[2] = str(altered_stream)
            p = subprocess.run(stream_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('stream: errors_decode',p.stderr)
            altered = root/'altered'; shutil.copytree(run, altered)
            for index, stage in enumerate(STAGES):
                path = altered/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > 0 or edge == 'after':
                        rec[edge]['consumer']['injected'] = {'sha256':'0'*64, 'size':1}
                dump(path, rec)
            altered_cmd = [*cmd]; altered_cmd[2] = str(altered)
            p = subprocess.run(altered_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('early consumer change',p.stderr)
            altered_bqrs = root/'altered-bqrs'; shutil.copytree(run, altered_bqrs)
            (altered_bqrs/'effects.bqrs').write_bytes(b'wrong')
            bqrs_cmd = [*cmd]; bqrs_cmd[2] = str(altered_bqrs)
            p = subprocess.run(bqrs_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('bqrs: effects',p.stderr)
            runtime_mut = root/'runtime-mut'; shutil.copytree(run,runtime_mut); (runtime_mut/'runtime/injected').write_text('x')
            for index, stage in enumerate(STAGES):
                path = runtime_mut/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > 0 or edge == 'after': rec[edge]['runtime']['injected'] = {'sha256':sha(runtime_mut/'runtime/injected'),'size':1}
                dump(path,rec)
            runtime_mut_cmd = [*cmd]; runtime_mut_cmd[2] = str(runtime_mut)
            p = subprocess.run(runtime_mut_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('runtime transition: init',p.stderr)
            duplicate = root/'duplicate'; shutil.copytree(run,duplicate)
            duplicate_bytes = b'[{"record_id":"m4:effect:luci-setBlockDetect-system","record_id":"m4:effect:luci-setBlockDetect-system","value":"after"},{"record_id":"keep"}]'
            for phase in ('import','reimport'): (duplicate/'reports'/phase/reports[0]).write_bytes(duplicate_bytes)
            for stage in ('import','reimport'):
                path = duplicate/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in (('after',) if stage == 'import' else ('before','after')):
                    rec[edge]['consumer'][reports[0]] = {'sha256':hashlib.sha256(duplicate_bytes).hexdigest(),'size':len(duplicate_bytes)}
                dump(path,rec)
            duplicate_cmd = [*cmd]; duplicate_cmd[2] = str(duplicate)
            p = subprocess.run(duplicate_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('duplicate key',p.stderr)
            cache_child = root/'cache-child'; shutil.copytree(run,cache_child)
            cache_path = cache_child/'db/db-ucode/default/cache/pages/injected'; cache_path.write_text('x')
            for index, stage in enumerate(STAGES):
                path = cache_child/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > STAGES.index('extracted_query') or (stage == 'extracted_query' and edge == 'after'):
                        rec[edge]['database']['db-ucode/default/cache/pages/injected'] = {'sha256':sha(cache_path),'size':1}
                dump(path,rec)
            cache_cmd = [*cmd]; cache_cmd[2] = str(cache_child)
            p = subprocess.run(cache_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('query log transition: extracted_query',p.stderr)
            cache_missing = root/'cache-missing'; shutil.copytree(run,cache_missing); (cache_missing/'db/db-ucode/default/cache/pages').rmdir()
            for index, stage in enumerate(STAGES):
                path = cache_missing/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > STAGES.index('extracted_query') or (stage == 'extracted_query' and edge == 'after'): del rec[edge]['database']['db-ucode/default/cache/pages']
                dump(path,rec)
            missing_cache_cmd = [*cmd]; missing_cache_cmd[2] = str(cache_missing)
            p = subprocess.run(missing_cache_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('query log transition: extracted_query',p.stderr)
            db_mutation = root/'db-mutation'; shutil.copytree(run, db_mutation)
            (db_mutation/'db/data').write_text('corrupted')
            mutated_db_hash = sha(db_mutation/'db/data')
            for index, stage in enumerate(STAGES):
                path = db_mutation/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > STAGES.index('effects_query') or (stage == 'effects_query' and edge == 'after'):
                        rec[edge]['database']['data'] = {'sha256':mutated_db_hash,'size':len('corrupted')}
                dump(path,rec)
            db_cmd = [*cmd]; db_cmd[2] = str(db_mutation)
            p = subprocess.run(db_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('query log transition: effects_query',p.stderr)
            coherent = root/'coherent'; shutil.copytree(run, coherent)
            wrong = b'name\nwrong\n'
            (coherent/'effects.csv').write_bytes(wrong)
            (coherent/'effects_decode.stdout').write_bytes(wrong)
            wrong_hash = hashlib.sha256(wrong).hexdigest()
            for index, stage in enumerate(STAGES):
                path = coherent/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                if stage == 'effects_decode': rec['stdout_sha256'] = wrong_hash
                for edge in ('before','after'):
                    if index > STAGES.index('effects_decode') or (stage == 'effects_decode' and edge == 'after'):
                        rec[edge]['effects'] = {'sha256':wrong_hash,'size':len(wrong)}
                dump(path, rec)
            coherent_cmd = [*cmd]; coherent_cmd[2] = str(coherent)
            p = subprocess.run(coherent_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('rows: effects',p.stderr)
            (run/'effects.csv').write_text('name\nwrong\n')
            p = subprocess.run(cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('rows: effects',p.stderr)
            p = subprocess.run([sys.executable,'-O',*cmd[1:]],capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('rows: effects',p.stderr)
if __name__ == '__main__': unittest.main()
