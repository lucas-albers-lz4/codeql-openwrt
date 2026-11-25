#!/usr/bin/env python3
"""Local transactional incoming queue prototype with signer-bound claims."""
import hashlib
import hmac
import re
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from incoming_poll import PollError, check, key, plan, read_checkpoint, unique_object, MAX_EVENTS


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def identity(event):
    return json.dumps((event['repository'], event['kind'], event.get('number', event.get('ref')), event['source']['commit']), separators=(',', ':'))


def subject(event):
    return json.dumps((event['repository'], event['kind'], event.get('number', event.get('ref'))), separators=(',', ':'))


def open_queue(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS history (seq INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, document BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, subject TEXT NOT NULL, event TEXT NOT NULL, first_seen TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, last_attempt INTEGER, reason TEXT NOT NULL, reservation INTEGER, reservation_digest TEXT);''')
    columns = [row[1] for row in db.execute('PRAGMA table_info(events)')]
    check('reservation_digest' in columns, 'old queue schema requires explicit migration')
    db.execute("INSERT OR IGNORE INTO metadata VALUES ('queue_id', ?)", (uuid.uuid4().hex,))
    return db


def transition(db, expected, snapshot, capacity, now):
    """Atomically reconcile a complete snapshot and reserve first attempts before retries.

    expected is None only for genesis; otherwise (sequence, digest). A reservation
    does not itself count as a start or establish that a scanner ran.
    """
    check(type(capacity) is int and 0 <= capacity <= 1000, 'invalid capacity')
    timestamp = datetime.fromisoformat(now.replace('Z', '+00:00'))
    check(timestamp.tzinfo is not None, 'timestamp needs timezone')
    rows, snapshot_hash = read_checkpoint(Path(snapshot))
    raw_snapshot = Path(snapshot).read_bytes()
    check(hashlib.sha256(raw_snapshot).hexdigest() == snapshot_hash, 'snapshot changed while reading')
    doc = json.loads(raw_snapshot, object_pairs_hook=unique_object)
    check(doc['genesis'] and doc['previous_sha256'] is None, 'snapshot must be a complete genesis discovery')
    plan(rows, [], 0)
    events = [r['event'] for r in rows]
    check(len({subject(e) for e in events}) == len(events), 'duplicate snapshot subject')
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head == expected, 'stale or missing predecessor')
        seq = 0 if head is None else head[0] + 1
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        if head is not None:
            previous = json.loads(db.execute('SELECT document FROM history WHERE seq=?', (head[0],)).fetchone()[0])
            check(timestamp >= datetime.fromisoformat(previous['observed_at'].replace('Z', '+00:00')), 'timestamp moved backwards')
        active = {subject(e): identity(e) for e in events}
        for eid, subj, status in db.execute('SELECT id,subject,status FROM events').fetchall():
            if status in ('pending', 'reserved', 'started') and active.get(subj) != eid:
                reason = 'superseded' if subj in active else 'not_observed'
                db.execute('UPDATE events SET status=?,reason=? WHERE id=?', ('inactive', reason, eid))
        for event in events:
            eid, subj, text = identity(event), subject(event), encoded(event).decode()
            old = db.execute('SELECT event FROM events WHERE id=?', (eid,)).fetchone()
            if old is not None and old[0] != text:
                prior = json.loads(old[0]); updated = dict(event)
                check(event['kind'] == 'pull_request', 'event metadata changed for same identity')
                for field in ('base', 'base_commit', 'base_ref'):
                    prior.pop(field); updated.pop(field)
                check(prior == updated, 'non-base metadata changed for same identity')
                db.execute("UPDATE events SET event=?,status='pending',reason='base_changed',reservation=NULL,reservation_digest=NULL WHERE id=?", (text,eid))
            if old is None:
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)', (eid, subj, text, now, 'pending', 0, None, 'new', None, None))
            else:
                db.execute("UPDATE events SET status='pending',reason='reappeared',reservation=NULL,reservation_digest=NULL WHERE id=? AND status='inactive'", (eid,))
        check(db.execute('SELECT count(*) FROM events').fetchone()[0] <= MAX_EVENTS, 'history bound exceeded')
        # Global first-attempt priority prevents retries starving fresh work; round
        # robin by repository/kind within each attempt count via SQL row numbers.
        unstarted_inflight = db.execute("SELECT count(*) FROM events WHERE status='reserved' AND attempts=0").fetchone()[0]
        selected = db.execute('''SELECT id FROM (SELECT id, attempts, last_attempt,
            row_number() OVER (PARTITION BY attempts, json_extract(event,'$.repository'), json_extract(event,'$.kind') ORDER BY coalesce(last_attempt,-1),id) AS slot
            FROM events WHERE status='pending' AND (? = 0 OR attempts = 0)) ORDER BY attempts,slot,last_attempt,id LIMIT ?''', (unstarted_inflight, capacity)).fetchall()
        for (eid,) in selected:
            db.execute("UPDATE events SET status='reserved',reservation=?,reason='reserved' WHERE id=?", (seq, eid))
        records = [{'event': json.loads(e), 'first_seen': first, 'status': status, 'attempts': attempts, 'last_attempt': last, 'reason': reason}
                   for e, first, status, attempts, last, reason in db.execute('SELECT event,first_seen,status,attempts,last_attempt,reason FROM events ORDER BY id')]
        result = {'schema':'incoming-queue-v1', 'sequence':seq, 'previous_sha256':None if head is None else head[1],
                  'queue_id':queue_id, 'snapshot_sha256':snapshot_hash, 'observed_at':now, 'capacity':capacity,
                  'selected':[x[0] for x in selected], 'events':records}
        raw = encoded(result)
        digest = hashlib.sha256(raw).hexdigest()
        db.execute('INSERT INTO history VALUES (?,?,?)', (seq,digest,raw))
        db.executemany('UPDATE events SET reservation_digest=? WHERE id=?', [(digest, eid) for (eid,) in selected])
        db.execute('COMMIT')
        return result, digest
    except BaseException:
        db.execute('ROLLBACK')
        raise



def apply_attested(db, expected, payload, mac, secret, now):
    """Apply a trusted signer's start or outcome. MAC authenticates the issuer,
    not the truth of its claims; production needs a reviewed same-job signer.
    """
    check(isinstance(secret, bytes) and len(secret) >= 32, 'invalid signer key')
    check(isinstance(mac, str) and hmac.compare_digest(hmac.new(secret, encoded(payload), hashlib.sha256).hexdigest(), mac), 'invalid attestation')
    check(isinstance(payload, dict) and payload.get('kind') in ('start', 'failure', 'complete', 'recover'), 'invalid attestation kind')
    common = {'kind','queue_id','event_id','reservation','reservation_digest','run_id'}
    extra = set() if payload['kind'] in ('start', 'recover') else ({'failure'} if payload['kind'] == 'failure' else {'source','release_lock_sha256','manifest_sha256','extraction_sha256','sarif_sha256','consumer_disposition','control_sha256'})
    check(set(payload) == common | extra, 'invalid attestation fields')
    check(isinstance(payload['run_id'], str) and 1 <= len(payload['run_id']) <= 128, 'invalid run id')
    check(type(payload['reservation']) is int and payload['reservation'] >= 0 and isinstance(payload['event_id'], str), 'invalid reservation identity')
    if payload['kind'] == 'failure':
        check(payload['failure'] in ('tool','api','coverage','consumer'), 'invalid failure category')
    if payload['kind'] == 'complete':
        check(payload['consumer_disposition'] in ('clean','alert_triage'), 'invalid consumer disposition')
        for field in ('release_lock_sha256','manifest_sha256','extraction_sha256','sarif_sha256','control_sha256'):
            check(isinstance(payload[field], str) and re.fullmatch(r'[0-9a-f]{64}', payload[field]), 'invalid digest')
        source = payload['source']
        check(isinstance(source, dict) and set(source) == {'commit','tree'} and all(isinstance(source[x], str) and re.fullmatch(r'[0-9a-f]{40}', source[x]) for x in source), 'invalid resolved source')
    timestamp = datetime.fromisoformat(now.replace('Z','+00:00'))
    check(timestamp.tzinfo is not None, 'timestamp needs timezone')
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and head == expected, 'stale or missing predecessor')
        previous = json.loads(db.execute('SELECT document FROM history WHERE seq=?',(head[0],)).fetchone()[0])
        check(timestamp >= datetime.fromisoformat(previous['observed_at'].replace('Z','+00:00')), 'timestamp moved backwards')
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        check(payload['queue_id'] == queue_id, 'wrong queue identity')
        row = db.execute('SELECT event,status,reservation,reason,reservation_digest FROM events WHERE id=?',(payload['event_id'],)).fetchone()
        check(row is not None and row[2] == payload['reservation'] and row[4] == payload['reservation_digest'], 'unknown or stale reservation')
        event = json.loads(row[0]); kind = payload['kind']
        if kind == 'start':
            check(row[1] == 'reserved', 'reservation is not available')
            db.execute("UPDATE events SET status='started',attempts=attempts+1,last_attempt=?,reason=? WHERE id=?", (head[0]+1,payload['run_id'],payload['event_id']))
        elif kind == 'recover':
            check(row[1] == 'reserved' or (row[1] == 'started' and row[3] == payload['run_id']), 'recovery does not match active reservation')
            db.execute("UPDATE events SET status='pending',reason='recovered',reservation=NULL,reservation_digest=NULL WHERE id=?", (payload['event_id'],))
        else:
            check(row[1] == 'started' and row[3] == payload['run_id'], 'outcome does not match active run')
            if kind == 'complete':
                check(payload['source']['commit'] == event['source']['commit'], 'source commit mismatch')
                check(event['source']['tree'] is None or payload['source']['tree'] == event['source']['tree'], 'source tree mismatch')
            db.execute('UPDATE events SET status=?,reason=?,reservation=NULL,reservation_digest=NULL WHERE id=?', ('completed' if kind == 'complete' else 'pending', kind if kind == 'complete' else payload['failure'],payload['event_id']))
        result = {'schema':'incoming-queue-action-v1','sequence':head[0]+1,'previous_sha256':head[1],'observed_at':now,'attestation':payload,'mac':mac}
        raw = encoded(result); digest = hashlib.sha256(raw).hexdigest()
        db.execute('INSERT INTO history VALUES (?,?,?)',(head[0]+1,digest,raw)); db.execute('COMMIT')
        return result,digest
    except BaseException:
        db.execute('ROLLBACK'); raise


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--expected-sequence', required=True, type=int, help='-1 only for a new queue')
    parser.add_argument('--expected-sha256', help='required except for genesis')
    parser.add_argument('--capacity', required=True, type=int)
    args = parser.parse_args()
    try:
        check((args.expected_sequence == -1 and args.expected_sha256 is None) or
              (args.expected_sequence >= 0 and isinstance(args.expected_sha256, str) and len(args.expected_sha256) == 64), 'invalid predecessor')
        expected = None if args.expected_sequence == -1 else (args.expected_sequence, args.expected_sha256)
        db = open_queue(args.database)
        try:
            result, digest = transition(db, expected, args.snapshot, args.capacity, datetime.now(timezone.utc).isoformat())
        finally:
            db.close()
        print(json.dumps({'sequence': result['sequence'], 'sha256': digest, 'selected': result['selected'],
                          'pending': sum(r['status'] in ('pending', 'reserved', 'started') for r in result['events']),
                          'unattempted': sum(r['status'] in ('pending', 'reserved', 'started') and r['attempts'] == 0 for r in result['events'])}))
        return 0
    except (PollError, ValueError, OSError, sqlite3.Error) as exc:
        print('queue rejected: ' + str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
