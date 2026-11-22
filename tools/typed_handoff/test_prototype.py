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
STAGES = ('init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode','export','import','reimport')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p, obj): p.write_text(json.dumps(obj))
class Prototype(unittest.TestCase):
    def test_synthetic_transition_and_mutation(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); consumer = root/'consumer'; consumer.mkdir()
            source = root/'source'; source.mkdir()
            original = HERE.parent.parent/'evidence/typed-handoff-d398198-1f01e0a'
            source_file = source/'usr/share/rpcd/ucode/luci'; source_file.parent.mkdir(parents=True)
            shutil.copyfile(original/'source/usr/share/rpcd/ucode/luci', source_file)
            family = json.loads((original/'oracle-expanded.json').read_text())
            report = consumer/'report.json'
            before = [{'record_id':'m4:effect:luci-setBlockDetect-system','value':'before'}, {'record_id':'keep'}]
            after = [{'record_id':'m4:effect:luci-setBlockDetect-system','value':'after'}, {'record_id':'keep'}]
            dump(report, before)
            script = root/'stage.py'
            script.write_text('''import json, os, pathlib, sys\ns=sys.argv[1]; r=pathlib.Path(os.environ["RUN"]); c=pathlib.Path(os.environ["CONSUMER"])\nif s=="init": (r/"db").write_text("database")\nif s.endswith("_query"): (r/(s[:-6]+".bqrs")).write_text("bqrs")\nif s.endswith("_decode"):\n import csv\n csv.writer(sys.stdout,lineterminator="\\n").writerows(json.loads(pathlib.Path(os.environ["ORACLE"]).read_text())[s[:-7]+"_rows"])\nif s=="export": print(json.dumps(json.loads(pathlib.Path(os.environ["ORACLE"]).read_text())["neutral_typed_payload"]))\nif s=="import": (c/"report.json").write_text(json.dumps([{"record_id":"m4:effect:luci-setBlockDetect-system","value":"after"},{"record_id":"keep"}]))\n''')
            run = root/'run'; oracle = root/'oracle.json'; context = root/'context.json'
            dump(oracle, {'source':'usr/share/rpcd/ucode/luci', 'source_sha256':family['source_sha256'], 'lock_sha256':family['lock_sha256'], 'extracted_rows':[['f','col1'],[str(source_file),'']], 'errors_rows':family['errors_rows'], 'effects_rows':family['effects_rows'], 'neutral_typed_payload':family['neutral_typed_payload'], 'expected_effects':['report.json'], 'prestate_provenance':{'report.json':{'target_index':0}}, 'expected_complete_targets':{'report.json':[after[0]]}})
            commands = {s:{'argv':[sys.executable,str(script),s], 'cwd':str(root), 'env':{'RUN':str(run),'CONSUMER':str(consumer),'ORACLE':str(oracle)}} for s in STAGES}
            initial = {'report.json':{'sha256':sha(report),'size':report.stat().st_size}}
            dump(context, {'oracle_sha256':sha(oracle),'commands':commands,'inputs':{'consumer':str(consumer),'source':str(source)},'run':str(run),'initial':{'consumer':initial,'source':{'usr/share/rpcd/ucode/luci':{'sha256':sha(source_file),'size':source_file.stat().st_size}}},'git':{},'outputs':{k:k+'.csv' for k in ('extracted','errors','effects')}|{'typed':'typed.json','database':'db'}|{k+'_bqrs':k+'.bqrs' for k in ('extracted','errors','effects')}})
            env = [sys.executable, str(HERE/'runner.py'), '--synthetic-only', str(context),str(oracle),sha(context)]
            p = subprocess.run(env, capture_output=True, text=True); self.assertEqual(p.returncode,0,p.stderr)
            cmd = [sys.executable,str(HERE/'verify.py'),str(run),str(context),str(oracle),sha(context),sha(oracle)]
            p = subprocess.run(cmd,capture_output=True,text=True); self.assertEqual(p.returncode,0,p.stderr)
            repeated = subprocess.run(env,capture_output=True,text=True)
            self.assertNotEqual(repeated.returncode,0); self.assertIn('fresh and absolute',repeated.stderr)
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
