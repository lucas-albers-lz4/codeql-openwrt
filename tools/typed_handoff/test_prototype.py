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
            report = consumer/'report.json'
            before = [{'record_id':'m4:effect:luci-setBlockDetect-system','value':'before'}, {'record_id':'keep'}]
            after = [{'record_id':'m4:effect:luci-setBlockDetect-system','value':'after'}, {'record_id':'keep'}]
            dump(report, before)
            script = root/'stage.py'
            script.write_text('''import json, os, pathlib, sys\ns=sys.argv[1]; r=pathlib.Path(os.environ["RUN"]); c=pathlib.Path(os.environ["CONSUMER"])\nif s.endswith("_decode"): print("name\\nvalue")\nif s=="export": print(json.dumps({"neutral":True}))\nif s=="import": (c/"report.json").write_text(json.dumps([{"record_id":"m4:effect:luci-setBlockDetect-system","value":"after"},{"record_id":"keep"}]))\n''')
            run = root/'run'; oracle = root/'oracle.json'; context = root/'context.json'
            dump(oracle, {'extracted_rows':[['name'],['value']], 'errors_rows':[['name'],['value']], 'effects_rows':[['name'],['value']], 'neutral_typed_payload':{'neutral':True}, 'expected_effects':['report.json'], 'prestate_provenance':{'report.json':{'target_index':0}}, 'expected_complete_targets':{'report.json':[after[0]]}})
            commands = {s:{'argv':[sys.executable,str(script),s], 'cwd':str(root), 'env':{'RUN':str(run),'CONSUMER':str(consumer)}} for s in STAGES}
            initial = {'report.json':{'sha256':sha(report),'size':report.stat().st_size}}
            dump(context, {'oracle_sha256':sha(oracle),'commands':commands,'inputs':{'consumer':str(consumer)},'run':str(run),'initial':{'consumer':initial},'git':{},'outputs':{k:k+'.csv' for k in ('extracted','errors','effects')}|{'typed':'typed.json'}})
            env = [sys.executable, str(HERE/'runner.py'), '--synthetic-only', str(context),str(oracle),sha(context)]
            p = subprocess.run(env, capture_output=True, text=True); self.assertEqual(p.returncode,0,p.stderr)
            cmd = [sys.executable,str(HERE/'verify.py'),str(run),str(context),str(oracle),sha(context),sha(oracle)]
            p = subprocess.run(cmd,capture_output=True,text=True); self.assertEqual(p.returncode,0,p.stderr)
            altered = root/'altered'; shutil.copytree(run, altered)
            for index, stage in enumerate(STAGES):
                path = altered/(stage+'.receipt.json'); rec = json.loads(path.read_text())
                for edge in ('before','after'):
                    if index > 0 or edge == 'after':
                        rec[edge]['consumer']['injected'] = {'sha256':'0'*64, 'size':1}
                dump(path, rec)
            altered_cmd = [*cmd]; altered_cmd[2] = str(altered)
            p = subprocess.run(altered_cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('early consumer change',p.stderr)
            (run/'effects.csv').write_text('name\nwrong\n')
            p = subprocess.run(cmd,capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('rows: effects',p.stderr)
            p = subprocess.run([sys.executable,'-O',*cmd[1:]],capture_output=True,text=True); self.assertNotEqual(p.returncode,0); self.assertIn('rows: effects',p.stderr)
if __name__ == '__main__': unittest.main()
