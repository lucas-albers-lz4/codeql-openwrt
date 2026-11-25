#!/usr/bin/env python3
"""Local transactional incoming queue prototype. No scan or completion authentication."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from incoming_poll import PollError, check, key, plan, read_checkpoint, unique_object, MAX_EVENTS


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def identity(event):
    return json.dumps(key(event), separators=(',', ':'))


def subject(event):
    return json.dumps((event['repository'], event['kind'], event.get('number', event.get('ref'))), separators=(',', ':'))


def open_queue(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''CREATE TABLE IF NOT EXISTS history (seq INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, document BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, subject TEXT NOT NULL, event TEXT NOT NULL, first_seen TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, last_attempt INTEGER, reason TEXT NOT NULL);''')
    return db


def transition(db, expected, snapshot, capacity, now):
    """Atomically reconcile a complete snapshot and reserve first attempts before retries.

    expected is None only for genesis; otherwise (sequence, digest). A reservation
    is an attempt for fairness, not evidence a scanner ran. No completion API exists.
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
        if head is not None:
            previous = json.loads(db.execute('SELECT document FROM history WHERE seq=?', (head[0],)).fetchone()[0])
            check(timestamp >= datetime.fromisoformat(previous['observed_at'].replace('Z', '+00:00')), 'timestamp moved backwards')
        active = {subject(e): identity(e) for e in events}
        for eid, subj, status in db.execute('SELECT id,subject,status FROM events').fetchall():
            if status == 'pending' and active.get(subj) != eid:
                reason = 'superseded' if subj in active else 'not_observed'
                db.execute('UPDATE events SET status=?,reason=? WHERE id=?', ('inactive', reason, eid))
        for event in events:
            eid, subj, text = identity(event), subject(event), encoded(event).decode()
            old = db.execute('SELECT event FROM events WHERE id=?', (eid,)).fetchone()
            check(old is None or old[0] == text, 'event metadata changed for same identity')
            if old is None:
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)', (eid, subj, text, now, 'pending', 0, None, 'new'))
            else:
                db.execute("UPDATE events SET status='pending',reason='observed' WHERE id=?", (eid,))
        check(db.execute('SELECT count(*) FROM events').fetchone()[0] <= MAX_EVENTS, 'history bound exceeded')
        # Global first-attempt priority prevents retries starving fresh work; round
        # robin by repository/kind within each attempt count via SQL row numbers.
        selected = db.execute('''SELECT id FROM (SELECT id, attempts, last_attempt,
            row_number() OVER (PARTITION BY attempts, json_extract(event,'$.repository'), json_extract(event,'$.kind') ORDER BY coalesce(last_attempt,-1),id) AS slot
            FROM events WHERE status='pending') ORDER BY attempts,slot,last_attempt,id LIMIT ?''', (capacity,)).fetchall()
        for (eid,) in selected:
            db.execute('UPDATE events SET attempts=attempts+1,last_attempt=?,reason=? WHERE id=?', (seq, 'reserved', eid))
        records = [{'event': json.loads(e), 'first_seen': first, 'status': status, 'attempts': attempts, 'last_attempt': last, 'reason': reason}
                   for e, first, status, attempts, last, reason in db.execute('SELECT event,first_seen,status,attempts,last_attempt,reason FROM events ORDER BY id')]
        result = {'schema':'incoming-queue-v1', 'sequence':seq, 'previous_sha256':None if head is None else head[1],
                  'snapshot_sha256':snapshot_hash, 'observed_at':now, 'capacity':capacity,
                  'selected':[x[0] for x in selected], 'events':records}
        raw = encoded(result)
        digest = hashlib.sha256(raw).hexdigest()
        db.execute('INSERT INTO history VALUES (?,?,?)', (seq,digest,raw))
        db.execute('COMMIT')
        return result, digest
    except BaseException:
        db.execute('ROLLBACK')
        raise


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
                          'pending': sum(r['status'] == 'pending' for r in result['events']),
                          'unattempted': sum(r['status'] == 'pending' and r['attempts'] == 0 for r in result['events'])}))
        return 0
    except (PollError, ValueError, OSError, sqlite3.Error) as exc:
        print('queue rejected: ' + str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
