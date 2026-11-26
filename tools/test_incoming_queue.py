import json
import base64
import hashlib
import hmac
import tempfile
import sqlite3
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import unittest
from unittest.mock import patch
from pathlib import Path
from incoming_poll import PollError, replay_observed
from incoming_queue import open_queue, transition, apply_attested, encoded, identity


def event(repo, number, sha):
    return {'repository':repo,'kind':'pull_request','number':number,'head_repository':repo,'head_fork':False,'head_ref':'head','base_ref':'main','base_commit':'b'*40,'base':{'commit':'b'*40,'tree':None},'source':{'commit':sha*40,'tree':None}}


def snapshot(path, events):
    path.write_text(json.dumps({'schema':'incoming-poll-v3','status':'complete','observed_at':'2026-01-01T00:00:00Z','capacity':0,'previous_sha256':None,'genesis':True,'requests':[],'http_errors':[],'decisions':[{'event':e,'status':'pending','decision':'backlog','reason':'new'} for e in events],'limitations':[]}))


def retained_requests():
    result = []
    for repo in ('openwrt/openwrt', 'openwrt/luci'):
        pulls = ([{'number': 17, 'state': 'open',
                   'base': {'sha': 'b'*40, 'ref': 'main', 'repo': {'full_name': repo}},
                   'head': {'sha': 'a'*40, 'ref': 'head',
                            'repo': {'full_name': repo, 'fork': False}}}]
                 if repo == 'openwrt/openwrt' else [])
        values = [(f'/repos/{repo}', {'id': 100 if repo == 'openwrt/openwrt' else 101,
                                     'full_name': repo, 'default_branch': 'main'}),
                  (f'/repos/{repo}/commits/main', {'sha': 'b'*40}),
                  (f'/repos/{repo}/git/commits/{"b"*40}', {'sha': 'b'*40,
                                                            'tree': {'sha': 'c'*40}}),
                  (f'/repos/{repo}/pulls?state=open&per_page=25&page=1', pulls)]
        for path, data in values:
            raw = json.dumps(data).encode()
            result.append({'path': path, 'status': 200,
                           'time': '2026-01-01T00:00:00Z', 'link': '',
                           'rate_remaining': '100',
                           'sha256': hashlib.sha256(raw).hexdigest(),
                           'body_base64': base64.b64encode(raw).decode()})
    return result

class QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve(); self.db = open_queue(self.path/'queue.db', create=True); self.addCleanup(self.db.close)
        self.snap = self.path/'snapshot.json'
        self.events = [event('openwrt/openwrt',1,'a'),event('openwrt/luci',2,'c'),event('openwrt/openwrt',3,'d')]
        snapshot(self.snap,self.events)
        self.last_snapshot_hash = None
        self.replay_patch = patch('incoming_queue.replay_observed',
                                  side_effect=lambda path, digest:
                                  [row['event'] for row in json.loads(Path(path).read_text())['decisions']])
        self.replay_patch.start(); self.addCleanup(self.replay_patch.stop)
    def advance(self, pred, capacity=1, preserve=False):
        if pred is not None and not preserve:
            doc = json.loads(self.snap.read_text())
            doc['genesis'] = False
            doc['previous_sha256'] = self.last_snapshot_hash
            self.snap.write_text(json.dumps(doc))
        result, digest = transition(self.db,pred,self.snap,capacity,'2026-01-01T00:00:00Z')
        self.last_snapshot_hash = result['snapshot_sha256']
        return result,(result['sequence'],digest)
    def test_first_attempts_before_retries_and_stale_cas(self):
        a,p = self.advance(None,3); b,q = self.advance(p,3); c,r = self.advance(q,3)
        self.assertEqual(len(set(a['selected']+b['selected']+c['selected'])),3)
        with self.assertRaises(PollError): self.advance(p)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0],3)
        d,_ = self.advance(r,3); self.assertEqual(d['selected'], [])
    def test_repeated_genesis_rejected_without_mutating_queue(self):
        _, predecessor = self.advance(None, 0)
        before = self.db.execute('SELECT id,status,reason FROM events ORDER BY id').fetchall()
        with self.assertRaises(PollError): self.advance(predecessor, 0, preserve=True)
        self.assertEqual(self.db.execute('SELECT id,status,reason FROM events ORDER BY id').fetchall(), before)
        self.assertEqual(self.db.execute('SELECT count(*) FROM history').fetchone()[0], 1)
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
        if payload['kind'] in ('start', 'failure') and 'job' not in payload:
            payload = dict(payload, job=self.job())
        mac = hmac.new(key,encoded(payload),hashlib.sha256).hexdigest()
        result,digest = apply_attested(self.db,predecessor,payload,mac,key,'2026-01-01T00:00:00Z')
        return result,(result['sequence'],digest)
    def job(self):
        return {'workflow':'incoming.yml@protected-revision','job':'scan','run_id':101,'attempt':1}
    def complete(self, start, event):
        return dict(start,kind='complete',schema='incoming-queue-completion-v2',job=self.job(),
                    issuer_receipt_sha256='6'*64,source={'commit':event['source']['commit'],'tree':'f'*40},
                    release_lock_sha256='1'*64,manifest_sha256='2'*64,extraction_sha256='3'*64,
                    sarif_sha256='4'*64,consumer_disposition='alert_triage',control_sha256='5'*64)
    def test_authenticated_completion_and_stale_competitor(self):
        a,p = self.advance(None)
        eid = a['selected'][0]
        start = {'kind':'start','event_id':eid,'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'run-1','job':self.job()}
        _,q = self.attested(p,start)
        with self.assertRaises(PollError): self.attested(p,start)
        event = next(r['event'] for r in a['events'] if identity(r['event']) == eid)
        complete = self.complete(start,event)
        bad = dict(complete,source={'commit':'9'*40,'tree':'f'*40})
        with self.assertRaises(PollError): self.attested(q,bad)
        _,r = self.attested(q,complete)
        with self.assertRaises(PollError): self.attested(r,complete)
        with self.assertRaises(PollError): apply_attested(self.db,r,start,'0'*64,b'x'*32,'2026-01-01T00:00:00Z')
    def test_completion_receipt_and_job_controls(self):
        a,p = self.advance(None)
        eid = a['selected'][0]
        start = {'kind':'start','event_id':eid,'reservation':0,'reservation_digest':p[1],
                 'queue_id':a['queue_id'],'run_id':'run-1','job':self.job()}
        _,q = self.attested(p,start)
        event = next(r['event'] for r in a['events'] if identity(r['event']) == eid)
        complete = self.complete(start,event)
        for field in ('schema','issuer_receipt_sha256','job'):
            bad = dict(complete); bad.pop(field)
            with self.subTest(missing=field), self.assertRaises(PollError): self.attested(q,bad)
        for bad in (dict(complete, job=dict(self.job(),attempt=2)),
                    dict(complete, job=dict(self.job(),run_id=102)),
                    dict(complete, schema='incoming-queue-completion-v1')):
            with self.assertRaises(PollError): self.attested(q,bad)
        with self.assertRaises(PollError): apply_attested(self.db,q,complete,'0'*64,b'x'*32,'2026-01-01T00:00:00Z')
        recover = dict(start,kind='recover'); recover.pop('job')
        _,r = self.attested(q,recover)
        with self.assertRaises(PollError): self.attested(r,complete)
    def test_legacy_store_rejected_without_migration(self):
        path = self.path/'old.db'
        old = sqlite3.connect(path)
        old.execute('CREATE TABLE events (id TEXT PRIMARY KEY, reservation_digest TEXT)')
        old.commit(); old.close()
        with self.assertRaises(PollError): open_queue(path)
    def test_populated_v1_store_rejected_before_schema_ddl(self):
        path = self.path/'populated-v1.db'
        old = sqlite3.connect(path)
        old.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        old.execute('CREATE TABLE history (seq INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, document BLOB NOT NULL)')
        old.execute('CREATE TABLE events (id TEXT PRIMARY KEY, reservation_digest TEXT)')
        old.execute("INSERT INTO metadata VALUES ('queue_id', 'old-queue')")
        old.execute("INSERT INTO history VALUES (0, 'old-digest', x'00')")
        old.commit()
        before = old.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
        old.close()
        with self.assertRaises(PollError): open_queue(path)
        old = sqlite3.connect(path)
        self.assertEqual(old.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall(), before)
        self.assertEqual(old.execute('SELECT count(*) FROM history').fetchone()[0], 1)
        self.assertIsNone(old.execute("SELECT value FROM metadata WHERE key='schema'").fetchone())
        old.close()
    def test_concurrent_fresh_open_has_one_store_identity(self):
        path = self.path/'concurrent.db'
        barrier = Barrier(2)
        def open_after_barrier():
            barrier.wait()
            try:
                db = open_queue(path, create=True)
            except FileExistsError:
                return None
            try:
                return db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
            finally:
                db.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            ids = list(pool.map(lambda _: open_after_barrier(), range(2)))
        self.assertEqual(sum(x is not None for x in ids), 1)
        db = open_queue(path)
        self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0], next(x for x in ids if x))
        self.assertEqual(db.execute("SELECT count(*) FROM metadata WHERE key='schema'").fetchone()[0], 1)
        db.close()
    def test_store_path_requires_explicit_create_and_private_unaliased_file(self):
        missing = self.path/'missing.db'
        with self.assertRaises(FileNotFoundError): open_queue(missing)
        self.assertFalse(missing.exists())
        with self.assertRaises((OSError, PollError)): open_queue(':memory:', create=True)
        with self.assertRaises(FileExistsError): open_queue(self.path/'queue.db', create=True)
        alias = self.path/'alias.db'; alias.symlink_to(self.path/'queue.db')
        with self.assertRaises(PollError): open_queue(alias)
        link = self.path/'hardlink.db'; os.link(self.path/'queue.db', link)
        with self.assertRaises(PollError): open_queue(link)
        link.unlink()
        alias.unlink()
        fifo = self.path/'pipe.db'; os.mkfifo(fifo)
        with self.assertRaises(PollError): open_queue(fifo)
        fifo.unlink()
        sidecar = self.path/'queue.db-wal'; sidecar.symlink_to(self.path/'queue.db')
        with self.assertRaises(PollError): open_queue(self.path/'queue.db')
        sidecar.unlink()
        linked_parent = self.path/'alias-parent'; linked_parent.symlink_to(self.path)
        with self.assertRaises(PollError): open_queue(linked_parent/'queue.db')
    def test_uninitialized_and_wal_stores_reject_before_sqlite_open(self):
        empty = self.path/'empty.db'; empty.write_bytes(b'')
        with self.assertRaises(PollError): open_queue(empty)
        self.assertEqual(empty.read_bytes(), b'')
        wal = self.path/'wal.db'
        old = sqlite3.connect(wal)
        old.execute('PRAGMA journal_mode=WAL')
        old.execute('CREATE TABLE old (value TEXT)')
        old.commit(); old.close()
        before = wal.read_bytes()
        with self.assertRaises(PollError): open_queue(wal)
        self.assertEqual(wal.read_bytes(), before)
    def test_nonprivate_parent_rejected_before_create(self):
        parent = self.path/'shared'; parent.mkdir(mode=0o755)
        path = parent/'queue.db'
        with self.assertRaises(PollError): open_queue(path, create=True)
        self.assertFalse(path.exists())
        untrusted = self.path/'writable-ancestor'; untrusted.mkdir(mode=0o700)
        private = untrusted/'private'; private.mkdir(mode=0o700)
        untrusted.chmod(0o777)
        self.addCleanup(lambda: untrusted.chmod(0o700))
        with self.assertRaises(PollError): open_queue(private/'queue.db', create=True)
        self.assertFalse((private/'queue.db').exists())
    def test_private_store_under_root_owned_sticky_tmp(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temp:
            path = Path(temp).resolve()/'queue.db'
            db = open_queue(path, create=True)
            queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
            db.close()
            reopened = open_queue(path)
            self.assertEqual(reopened.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0], queue_id)
            reopened.close()
    def test_queue_cannot_authenticate_fabricated_receipt(self):
        a,p = self.advance(None)
        eid = a['selected'][0]
        start = {'kind':'start','event_id':eid,'reservation':0,'reservation_digest':p[1],
                 'queue_id':a['queue_id'],'run_id':'run-1','job':self.job()}
        _,q = self.attested(p,start)
        event = next(r['event'] for r in a['events'] if identity(r['event']) == eid)
        fabricated = dict(self.complete(start,event),issuer_receipt_sha256='7'*64)
        result,_ = self.attested(q,fabricated)
        self.assertEqual(result['attestation']['issuer_receipt_sha256'],'7'*64)
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
        with self.assertRaises(PollError): self.advance(p)
        _,p = self.attested(p,dict(start,kind='recover'))
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
        d,_ = self.advance(p,2)
        self.assertEqual(d['selected'],[recover['event_id']])
    def test_capacity_bounds_reservations_and_started_runs(self):
        a,p = self.advance(None,1)
        b,p = self.advance(p,1)
        self.assertEqual(b['selected'],[])
        start = {'kind':'start','event_id':a['selected'][0],'reservation':0,'reservation_digest':a and self.db.execute('SELECT reservation_digest FROM events WHERE id=?',(a['selected'][0],)).fetchone()[0], 'queue_id':a['queue_id'],'run_id':'run'}
        _,p = self.attested(p,start)
        c,p = self.advance(p,1)
        self.assertEqual(c['selected'],[])
        with self.assertRaises(PollError): self.advance(p,0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE status IN ('started','reserved')").fetchone()[0],1)
    def test_retry_cannot_start_before_same_batch_fresh_reservation(self):
        a,p = self.advance(None,1)
        start = {'kind':'start','event_id':a['selected'][0],'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'first'}
        _,p = self.attested(p,start)
        _,p = self.attested(p,dict(start,kind='failure',failure='tool'))
        b,p = self.advance(p,3)
        self.assertEqual(len(b['selected']),3)
        retry = dict(start,reservation=b['sequence'],reservation_digest=p[1],run_id='retry')
        with self.assertRaises(PollError): self.attested(p,retry)
        for eid in b['selected']:
            if eid != start['event_id']:
                _,p = self.attested(p,dict(retry,event_id=eid,run_id=eid))
        _,p = self.attested(p,retry)
        self.assertEqual(self.db.execute('SELECT status FROM events WHERE id=?',(retry['event_id'],)).fetchone()[0],'started')
    def test_new_discovery_preempts_unstarted_retry_at_capacity_one(self):
        snapshot(self.snap,[self.events[0]])
        a,p = self.advance(None,1)
        start = {'kind':'start','event_id':a['selected'][0],'reservation':0,'reservation_digest':p[1],'queue_id':a['queue_id'],'run_id':'first'}
        _,p = self.attested(p,start)
        _,p = self.attested(p,dict(start,kind='failure',failure='tool'))
        retry,p = self.advance(p,1)
        self.assertEqual(retry['selected'],[start['event_id']])
        retry_claim = dict(start,reservation=retry['sequence'],reservation_digest=p[1],run_id='retry')
        snapshot(self.snap,[self.events[0],self.events[1]])
        fresh,p = self.advance(p,1)
        self.assertEqual(fresh['preempted'],[start['event_id']])
        self.assertEqual(fresh['selected'],[identity(self.events[1])])
        with self.assertRaises(PollError): self.attested(p,retry_claim)
        row = next(r for r in fresh['events'] if identity(r['event'])==start['event_id'])
        self.assertEqual((row['status'],row['reason'],row['attempts']),('pending','retry_preempted',1))
        first_b = dict(start,event_id=identity(self.events[1]),reservation=fresh['sequence'],reservation_digest=p[1],run_id='first-b')
        _,p = self.attested(p,first_b)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE status IN ('reserved','started')").fetchone()[0],1)
    def test_duplicate_subject_rolls_back(self):
        _,p = self.advance(None,0)
        snapshot(self.snap,[self.events[0],event('openwrt/openwrt',1,'e')])
        with self.assertRaises(PollError): self.advance(p)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0],1)
    def test_reappearance_preserves_attempts(self):
        a,p = self.advance(None,3)
        digest = p[1]
        for eid in a['selected']:
            _,p = self.attested(p,{'kind':'recover','event_id':eid,'reservation':0,'reservation_digest':digest,'queue_id':a['queue_id'],'run_id':'recover'})
        snapshot(self.snap,[]); _,p = self.advance(p,0)
        snapshot(self.snap,self.events); b,_ = self.advance(p,0)
        self.assertTrue(all(r['attempts']==0 and r['status']=='pending' for r in b['events']))

    def test_successor_replays_current_requests_and_checks_snapshot_chain(self):
        old = event('openwrt/openwrt', 17, 'e')
        snapshot(self.snap, [old])
        _, predecessor = self.advance(None, 0)
        genesis_hash = hashlib.sha256(self.snap.read_bytes()).hexdigest()
        successor = {'schema': 'incoming-poll-v3', 'status': 'complete',
                     'observed_at': '2026-01-01T00:00:01Z', 'capacity': 1,
                     'previous_sha256': genesis_hash, 'genesis': False,
                     'requests': retained_requests(), 'http_errors': [],
                     'decisions': [{'event': old, 'status': 'pending',
                                    'decision': 'selected', 'reason': 'retry'},
                                   {'event': event('openwrt/openwrt', 17, 'a'), 'status': 'pending',
                                    'decision': 'backlog', 'reason': 'new'}],
                     'limitations': []}
        self.snap.write_text(json.dumps(successor))
        observed = replay_observed(self.snap, hashlib.sha256(self.snap.read_bytes()).hexdigest())
        successor['decisions'].extend({'event': item, 'status': 'pending',
                                       'decision': 'backlog', 'reason': 'new'}
                                      for item in observed if item['kind'] == 'default_branch')
        self.snap.write_text(json.dumps(successor))
        self.replay_patch.stop()
        missing = dict(successor, decisions=[row for row in successor['decisions']
                                             if row['event'] != event('openwrt/openwrt', 17, 'a')])
        self.snap.write_text(json.dumps(missing))
        with self.assertRaises(PollError): self.advance(predecessor, 0, preserve=True)
        self.snap.write_text(json.dumps(successor))
        state, next_head = self.advance(predecessor, 0, preserve=True)
        rows = {identity(row['event']): row for row in state['events']}
        self.assertEqual(rows[identity(old)]['status'], 'inactive')
        self.assertEqual(rows[identity(event('openwrt/openwrt', 17, 'a'))]['status'], 'pending')
        self.assertEqual(len([row for row in state['events'] if row['status'] == 'pending']), 3)
        self.assertEqual(state['snapshot_sha256'], hashlib.sha256(self.snap.read_bytes()).hexdigest())
        before_rows = self.db.execute('SELECT id,status,reason FROM events ORDER BY id').fetchall()
        with self.assertRaises(PollError): self.advance(next_head, 0, preserve=True)
        successor['previous_sha256'] = state['snapshot_sha256']
        successor['observed_at'] = '2025-12-31T23:59:59Z'
        self.snap.write_text(json.dumps(successor))
        with self.assertRaises(PollError): self.advance(next_head, 0, preserve=True)
        successor['observed_at'] = '2026-01-01T00:00:01Z'
        successor['previous_sha256'] = '0' * 64
        self.snap.write_text(json.dumps(successor))
        with self.assertRaises(PollError): self.advance(next_head, 0, preserve=True)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0], 2)
        self.assertEqual(self.db.execute('SELECT id,status,reason FROM events ORDER BY id').fetchall(), before_rows)

    def test_successor_without_retained_requests_fails_before_queue_change(self):
        snapshot(self.snap, [])
        _, predecessor = self.advance(None, 0)
        genesis_hash = hashlib.sha256(self.snap.read_bytes()).hexdigest()
        self.snap.write_text(json.dumps({'schema': 'incoming-poll-v3', 'status': 'complete',
            'observed_at': '2026-01-01T00:00:01Z', 'capacity': 1,
            'previous_sha256': genesis_hash, 'genesis': False, 'requests': [],
            'http_errors': [], 'decisions': [], 'limitations': []}))
        self.replay_patch.stop()
        with self.assertRaises(PollError): self.advance(predecessor, 0, preserve=True)
        self.assertEqual(self.db.execute('select count(*) from history').fetchone()[0], 1)

    def test_old_queue_history_requires_exact_previous_checkpoint(self):
        snapshot(self.snap, [])
        prior_bytes = self.snap.read_bytes()
        self.advance(None, 0)
        prior_file = self.path / 'prior.json'; prior_file.write_bytes(prior_bytes)
        old = json.loads(self.db.execute('SELECT document FROM history WHERE seq=0').fetchone()[0])
        old.pop('discovery_observed_at')
        raw_old = encoded(old); old_digest = hashlib.sha256(raw_old).hexdigest()
        self.db.execute('UPDATE history SET digest=?,document=? WHERE seq=0', (old_digest, raw_old))
        successor = {'schema': 'incoming-poll-v3', 'status': 'complete',
                     'observed_at': '2026-01-01T00:00:01Z', 'capacity': 0,
                     'previous_sha256': hashlib.sha256(prior_bytes).hexdigest(),
                     'genesis': False, 'requests': retained_requests(),
                     'http_errors': [], 'decisions': [], 'limitations': []}
        self.snap.write_text(json.dumps(successor))
        current = replay_observed(self.snap, hashlib.sha256(self.snap.read_bytes()).hexdigest())
        successor['decisions'] = [{'event': item, 'status': 'pending',
                                   'decision': 'backlog', 'reason': 'new'} for item in current]
        self.snap.write_text(json.dumps(successor))
        self.replay_patch.stop()
        with self.assertRaises(PollError):
            transition(self.db, (0, old_digest), self.snap, 0, '2026-01-01T00:00:01Z')
        wrong = self.path / 'wrong.json'; wrong.write_bytes(prior_bytes + b' ')
        with self.assertRaises(PollError):
            transition(self.db, (0, old_digest), self.snap, 0,
                       '2026-01-01T00:00:01Z', wrong)
        state, _ = transition(self.db, (0, old_digest), self.snap, 0,
                              '2026-01-01T00:00:01Z', prior_file)
        self.assertEqual(state['sequence'], 1)
        self.assertEqual(len([row for row in state['events'] if row['status'] == 'pending']), 3)

if __name__ == '__main__': unittest.main()
