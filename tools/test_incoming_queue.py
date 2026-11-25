import json
import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from incoming_poll import PollError
from incoming_queue import open_queue, transition, apply_attested, encoded, identity


def event(repo, number, sha):
    return {'repository':repo,'kind':'pull_request','number':number,'head_repository':repo,'head_fork':False,'head_ref':'head','base_ref':'main','base_commit':'b'*40,'base':{'commit':'b'*40,'tree':None},'source':{'commit':sha*40,'tree':None}}


def snapshot(path, events):
    path.write_text(json.dumps({'schema':'incoming-poll-v3','status':'complete','observed_at':'2026-01-01T00:00:00Z','capacity':0,'previous_sha256':None,'genesis':True,'requests':[],'http_errors':[],'decisions':[{'event':e,'status':'pending','decision':'backlog','reason':'new'} for e in events],'limitations':[]}))

class QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name); self.db = open_queue(self.path/'queue.db'); self.addCleanup(self.db.close)
        self.snap = self.path/'snapshot.json'
        self.events = [event('openwrt/openwrt',1,'a'),event('openwrt/luci',2,'c'),event('openwrt/openwrt',3,'d')]
        snapshot(self.snap,self.events)
    def advance(self, pred, capacity=1):
        result, digest = transition(self.db,pred,self.snap,capacity,'2026-01-01T00:00:00Z')
        return result,(result['sequence'],digest)
    def test_first_attempts_before_retries_and_stale_cas(self):
        a,p = self.advance(None); b,q = self.advance(p); c,r = self.advance(q)
        self.assertEqual(len(set(a['selected']+b['selected']+c['selected'])),3)
        with self.assertRaises(PollError): self.advance(p)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0],3)
        d,_ = self.advance(r); self.assertEqual(d['selected'], [])
    def test_reconcile_supersession_and_absence(self):
        _,p = self.advance(None,0)
        replacement = event('openwrt/openwrt',1,'e')
        snapshot(self.snap,[replacement,self.events[1]])
        state,_ = self.advance(p,0)
        bysha = {r['event']['source']['commit'][0]:r for r in state['events']}
        self.assertEqual(bysha['a']['reason'],'superseded')
        self.assertEqual(bysha['d']['reason'],'not_observed')
        self.assertEqual(bysha['e']['status'],'pending')
    def attested(self, predecessor, payload, key=b'x'*32):
        mac = hmac.new(key,encoded(payload),hashlib.sha256).hexdigest()
        result,digest = apply_attested(self.db,predecessor,payload,mac,key,'2026-01-01T00:00:00Z')
        return result,(result['sequence'],digest)
    def test_authenticated_completion_and_stale_competitor(self):
        a,p = self.advance(None)
        eid = a['selected'][0]
        start = {'kind':'start','event_id':eid,'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'run-1'}
        _,q = self.attested(p,start)
        with self.assertRaises(PollError): self.attested(p,start)
        event = next(r['event'] for r in a['events'] if identity(r['event']) == eid)
        complete = {'kind':'complete','event_id':eid,'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'run-1','source':{'commit':event['source']['commit'],'tree':'f'*40},'release_lock_sha256':'1'*64,'manifest_sha256':'2'*64,'extraction_sha256':'3'*64,'sarif_sha256':'4'*64,'consumer_disposition':'alert_triage','control_sha256':'5'*64}
        bad = dict(complete,source={'commit':'9'*40,'tree':'f'*40})
        with self.assertRaises(PollError): self.attested(q,bad)
        _,r = self.attested(q,complete)
        with self.assertRaises(PollError): self.attested(r,complete)
        with self.assertRaises(PollError): apply_attested(self.db,r,start,'0'*64,b'x'*32,'2026-01-01T00:00:00Z')
    def test_failure_retry_does_not_starve_unstarted(self):
        a,p = self.advance(None)
        eid = a['selected'][0]
        start = {'kind':'start','event_id':eid,'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'run-1'}
        _,p = self.attested(p,start)
        failure = dict(start,kind='failure',failure='tool')
        _,p = self.attested(p,failure)
        b,p = self.advance(p)
        self.assertNotEqual(b['selected'][0],eid)
        c,_ = self.advance(p)
        self.assertNotIn(eid,c['selected'])
    def test_queue_and_reservation_binding_and_recovery(self):
        a,p = self.advance(None)
        start = {'kind':'start','event_id':a['selected'][0],'reservation':0,'reservation_digest':p[1], 'queue_id':a['queue_id'],'run_id':'run'}
        with self.assertRaises(PollError): self.attested(p,dict(start,queue_id='0'*32))
        with self.assertRaises(PollError): self.attested(p,dict(start,reservation_digest='0'*64))
        _,q = self.attested(p,dict(start,kind='recover'))
        with self.assertRaises(PollError): self.attested(q,start)
        b,r = self.advance(q)
        self.assertEqual(b['selected'][0],start['event_id'])
        self.assertNotEqual(r[1],start['reservation_digest'])
    def test_base_move_retains_started_attempt_fairness(self):
        a,p = self.advance(None)
        start = {'kind':'start','event_id':a['selected'][0],'reservation':0,'reservation_digest':p[1], 'queue_id':a['queue_id'],'run_id':'run'}
        _,p = self.attested(p,start)
        selected = next(e for e in self.events if identity(e)==start['event_id'])
        changed = dict(selected,base_commit='f'*40,base={'commit':'f'*40,'tree':None})
        snapshot(self.snap,[changed if identity(e)==start['event_id'] else e for e in self.events])
        b,p = self.advance(p)
        self.assertNotEqual(b['selected'][0],start['event_id'])
        row = next(r for r in b['events'] if identity(r['event']) == start['event_id'])
        self.assertEqual(row['attempts'],1)
        self.assertEqual(row['reason'],'base_changed')
        with self.assertRaises(PollError): self.attested(p,dict(start,kind='failure',failure='tool'))
    def test_reserved_unstarted_blocks_retries_until_recovered(self):
        a,p = self.advance(None)
        first = {'kind':'start','event_id':a['selected'][0],'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'run'}
        _,p = self.attested(p,first)
        _,p = self.attested(p,dict(first,kind='failure',failure='tool'))
        b,p = self.advance(p,2)
        self.assertEqual(len(b['selected']),2)
        c,p = self.advance(p,2)
        self.assertEqual(c['selected'],[])
        recover = {'kind':'recover','event_id':b['selected'][0],'reservation':b['sequence'],'reservation_digest':p[1], 'queue_id':b['queue_id'],'run_id':'recover'}
        recover['reservation_digest'] = self.db.execute('SELECT reservation_digest FROM events WHERE id=?',(b['selected'][0],)).fetchone()[0]
        _,p = self.attested(p,recover)
        d,_ = self.advance(p,1)
        self.assertEqual(d['selected'],[recover['event_id']])
    def test_duplicate_subject_rolls_back(self):
        _,p = self.advance(None,0)
        snapshot(self.snap,[self.events[0],event('openwrt/openwrt',1,'e')])
        with self.assertRaises(PollError): self.advance(p)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0],1)
    def test_reappearance_preserves_attempts(self):
        a,p = self.advance(None,3)
        snapshot(self.snap,[]); _,p = self.advance(p,0)
        snapshot(self.snap,self.events); b,_ = self.advance(p,0)
        self.assertTrue(all(r['attempts']==0 and r['status']=='pending' for r in b['events']))

if __name__ == '__main__': unittest.main()
