import json
import tempfile
import unittest
from pathlib import Path
from incoming_poll import PollError
from incoming_queue import open_queue, transition


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
        d,_ = self.advance(r); self.assertIn(d['selected'][0],a['selected']+b['selected']+c['selected'])
    def test_reconcile_supersession_and_absence(self):
        _,p = self.advance(None,0)
        replacement = event('openwrt/openwrt',1,'e')
        snapshot(self.snap,[replacement,self.events[1]])
        state,_ = self.advance(p,0)
        bysha = {r['event']['source']['commit'][0]:r for r in state['events']}
        self.assertEqual(bysha['a']['reason'],'superseded')
        self.assertEqual(bysha['d']['reason'],'not_observed')
        self.assertEqual(bysha['e']['status'],'pending')
    def test_duplicate_subject_rolls_back(self):
        _,p = self.advance(None,0)
        snapshot(self.snap,[self.events[0],event('openwrt/openwrt',1,'e')])
        with self.assertRaises(PollError): self.advance(p)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0],1)
    def test_reappearance_preserves_attempts(self):
        a,p = self.advance(None,3)
        snapshot(self.snap,[]); _,p = self.advance(p,0)
        snapshot(self.snap,self.events); b,_ = self.advance(p,0)
        self.assertTrue(all(r['attempts']==1 and r['status']=='pending' for r in b['events']))

if __name__ == '__main__': unittest.main()
