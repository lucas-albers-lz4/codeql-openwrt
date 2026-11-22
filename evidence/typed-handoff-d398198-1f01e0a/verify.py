#!/usr/bin/env python3
"""Check packaged bytes and bounded claims; does not authenticate execution."""
import csv,hashlib,json,pathlib
p=pathlib.Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
for line in (p/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split('  ',1); assert sha((p/name).read_bytes())==digest,name
ctx=json.loads((p/'context-frozen.json').read_text()); oracle=json.loads((p/'oracle-expanded.json').read_text()); run=p/'run'; stages=['init','index','finalize','extracted_query','extracted_decode','errors_query','errors_decode','effects_query','effects_decode','export','import','reimport']; receipts={s:json.loads((run/(s+'.receipt.json')).read_text()) for s in stages}
for s,rec in receipts.items():
 assert rec['exit_code']==0 and rec['context_sha256']==sha((p/'context-frozen.json').read_bytes())
 assert rec['argv']==ctx['commands'][s]['argv'] and rec['cwd']==ctx['commands'][s]['cwd'] and rec['environment']==ctx['commands'][s]['env']
 for stream in ['stdout','stderr']:
  f=run/pathlib.Path(rec[stream]['path']).name; assert sha(f.read_bytes())==rec[stream]['sha256'],(s,stream)
for name,key in [('effects','effects_rows'),('extracted','extracted_rows'),('errors','errors_rows')]:
 with (run/(name+'.csv')).open(newline='') as f: assert list(csv.reader(f))==oracle[key]
assert json.loads((run/'typed.json').read_text())==oracle['neutral_typed_payload']
for n in ['source','ql_src','ql_lib','extractor','packs']:
 snapshots=[v for s in stages for v in [receipts[s]['before'][n],receipts[s]['after'][n]]]; assert all(v==snapshots[0] for v in snapshots)
imp=receipts['import']; replay=receipts['reimport']; assert imp['after']['consumer']==replay['before']['consumer']==replay['after']['consumer']; assert imp['before']['typed']==imp['after']['typed']==replay['after']['typed']; before,after=imp['before']['consumer'],imp['after']['consumer']; changed=sorted(k for k in set(before)|set(after) if before.get(k)!=after.get(k)); assert changed==sorted(oracle['expected_effects'])
for name in oracle['expected_effects']:
 files=[p/'report-artifacts'/stage/name for stage in ['before','after','replay']]; raw=[f.read_bytes() for f in files]; assert sha(raw[0])==before[name]['sha256'] and sha(raw[1])==after[name]['sha256'] and raw[1]==raw[2]; rows=[json.loads(x) for x in raw]; match=lambda x:x.get('record_id')=='m4:effect:luci-setBlockDetect-system'; positions=[[i for i,x in enumerate(a) if match(x)] for a in rows]; assert positions[0]==positions[1]==positions[2]==[oracle['prestate_provenance'][name]['target_index']]; assert rows[1][positions[1][0]]==oracle['expected_complete_targets'][name][0]; assert [x for x in rows[0] if not match(x)]==[x for x in rows[1] if not match(x)]
print('Packaged bytes, receipt bindings, reviewed rows and bounded report transitions verified; execution is not authenticated.')
