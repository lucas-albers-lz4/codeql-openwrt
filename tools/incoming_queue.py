#!/usr/bin/env python3
"""Local transactional incoming queue prototype with signer-bound claims."""
import hashlib
import hmac
import re
import json
import os
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from incoming_poll import PollError, check, verify_checkpoint_decisions, unique_object, MAX_EVENTS


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def identity(event):
    return json.dumps((event['repository'], event['kind'], event.get('number', event.get('ref')), event['source']['commit']), separators=(',', ':'))


def subject(event):
    return json.dumps((event['repository'], event['kind'], event.get('number', event.get('ref'))), separators=(',', ':'))


def _store_path(path, *, create):
    path = Path(path)
    check(path.is_absolute() and path.name not in ('', '.', '..', ':memory:'), 'queue path must be an absolute file path')
    parent = path.parent
    check(parent == parent.resolve(strict=True), 'queue parent must not contain symlinks')
    for ancestor in (parent, *parent.parents):
        boundary = ancestor.stat()
        protected_sticky = boundary.st_uid == 0 and bool(boundary.st_mode & stat.S_ISVTX)
        check(stat.S_ISDIR(boundary.st_mode) and boundary.st_uid in (0, os.getuid()) and
              (boundary.st_mode & 0o022 == 0 or protected_sticky),
              'queue ancestor is writable or owned outside the trusted operator boundary')
    parent_info = parent.stat()
    check(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid() and
          parent_info.st_mode & 0o077 == 0 and parent_info.st_mode & 0o700 == 0o700,
          'queue parent must be an operator-owned private directory')
    def checked_file(name):
        info = (parent / name).lstat()
        check(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              info.st_nlink == 1 and info.st_mode & 0o077 == 0,
              'queue store or sidecar is not a private unaliased regular file')
        return info
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = parent / (path.name + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            check(not create, 'new queue has preexisting sidecar')
            checked_file(sidecar.name)
    if create:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
    info = checked_file(path.name)
    if not create:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        try:
            opened = os.fstat(descriptor)
            check((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                  'queue store changed before header read')
            header = os.read(descriptor, 20)
        finally:
            os.close(descriptor)
        check(header[:16] == b'SQLite format 3\x00' and header[18:20] == b'\x01\x01',
              'queue store is missing, uninitialized, or uses unsupported WAL mode')
    return path, (info.st_dev, info.st_ino)


def open_queue(path, *, create=False):
    path, file_identity = _store_path(path, create=create)
    # mode=rw prevents SQLite from silently recreating a disappeared store.
    db = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=10, isolation_level=None)
    try:
        current = path.lstat()
        check((current.st_dev, current.st_ino) == file_identity and current.st_nlink == 1,
              'queue store changed before SQLite open')
        check(db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete',
              'unsupported queue journal mode')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('BEGIN IMMEDIATE')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not create:
            # Reject old or partial stores before creating or altering any table.
            check(tables == {'metadata', 'history', 'events'}, 'unsupported queue store schema')
            version = db.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()
            check(version is not None and version[0] == 'incoming-queue-store-v2',
                  'old queue history requires explicit migration')
            columns = {row[1] for row in db.execute('PRAGMA table_info(events)')}
            check({'reservation_digest', 'started_job'} <= columns, 'unsupported queue store schema')
            check(db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone() is not None,
                  'missing queue identity')
        else:
            check(not tables, 'new queue filename contains an existing store')
            db.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute('CREATE TABLE history (seq INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, document BLOB NOT NULL)')
            db.execute('CREATE TABLE events (id TEXT PRIMARY KEY, subject TEXT NOT NULL, event TEXT NOT NULL, first_seen TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, last_attempt INTEGER, reason TEXT NOT NULL, reservation INTEGER, reservation_digest TEXT, started_job TEXT)')
            db.execute("INSERT INTO metadata VALUES ('schema','incoming-queue-store-v2')")
            db.execute("INSERT INTO metadata VALUES ('queue_id', ?)", (uuid.uuid4().hex,))
        db.execute('COMMIT')
        return db
    except BaseException:
        if db.in_transaction:
            db.execute('ROLLBACK')
        db.close()
        raise


def transition(db, expected, snapshot, capacity, now, previous_snapshot=None):
    """Atomically reconcile a complete snapshot and reserve first attempts before retries.

    expected is None only for genesis; otherwise (sequence, digest). A reservation
    does not itself count as a start or establish that a scanner ran.
    """
    check(type(capacity) is int and 0 <= capacity <= 1000, 'invalid capacity')
    timestamp = datetime.fromisoformat(now.replace('Z', '+00:00'))
    check(timestamp.tzinfo is not None, 'timestamp needs timezone')
    # Reconstruct both current observations and the poller's complete decision
    # plan. Pending rows in a successor include superseded heads; only current
    # replayed observations are reconciled into the queue.
    doc, snapshot_hash, events, prior_hash, prior_time = verify_checkpoint_decisions(
        Path(snapshot), previous_snapshot)
    check(len({subject(e) for e in events}) == len(events), 'duplicate snapshot subject')
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head == expected, 'stale or missing predecessor')
        check(doc['genesis'] == (head is None),
              'genesis is valid only for an empty queue')
        if not doc['genesis']:
            prior_snapshot = None
            for (raw_history,) in db.execute('SELECT document FROM history ORDER BY seq DESC'):
                history = json.loads(raw_history, object_pairs_hook=unique_object)
                if history.get('schema') == 'incoming-queue-v1':
                    prior_snapshot = history
                    break
            check(prior_snapshot is not None and prior_snapshot.get('snapshot_sha256') == prior_hash,
                  'successor discovery does not follow last queued snapshot')
            earlier_time = prior_snapshot.get('discovery_observed_at', prior_time)
            check(earlier_time == prior_time,
                  'previous observation time differs from queued history')
            check(isinstance(earlier_time, str) and
                  datetime.fromisoformat(doc['observed_at'].replace('Z', '+00:00')) >=
                  datetime.fromisoformat(earlier_time.replace('Z', '+00:00')),
                  'discovery observation time moved backwards')
        seq = 0 if head is None else head[0] + 1
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        if head is not None:
            previous = json.loads(db.execute('SELECT document FROM history WHERE seq=?', (head[0],)).fetchone()[0])
            check(timestamp >= datetime.fromisoformat(previous['observed_at'].replace('Z', '+00:00')), 'timestamp moved backwards')
        active = {subject(e): identity(e) for e in events}
        for eid, subj, status in db.execute('SELECT id,subject,status FROM events').fetchall():
            if status in ('pending', 'reserved', 'started') and active.get(subj) != eid:
                check(status == 'pending', 'in-flight event changed or disappeared; recover first')
                reason = 'superseded' if subj in active else 'not_observed'
                db.execute('UPDATE events SET status=?,reason=? WHERE id=?', ('inactive', reason, eid))
        for event in events:
            eid, subj, text = identity(event), subject(event), encoded(event).decode()
            old = db.execute('SELECT event FROM events WHERE id=?', (eid,)).fetchone()
            if old is not None and old[0] != text:
                status = db.execute('SELECT status FROM events WHERE id=?', (eid,)).fetchone()[0]
                check(status not in ('reserved', 'started'), 'in-flight metadata changed; recover first')
                prior = json.loads(old[0]); updated = dict(event)
                check(event['kind'] == 'pull_request', 'event metadata changed for same identity')
                for field in ('base', 'base_commit', 'base_ref'):
                    prior.pop(field); updated.pop(field)
                check(prior == updated, 'non-base metadata changed for same identity')
                db.execute("UPDATE events SET event=?,status='pending',reason='base_changed',reservation=NULL,reservation_digest=NULL,started_job=NULL WHERE id=?", (text,eid))
            if old is None:
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)', (eid, subj, text, now, 'pending', 0, None, 'new', None, None, None))
            else:
                db.execute("UPDATE events SET status='pending',reason='reappeared',reservation=NULL,reservation_digest=NULL,started_job=NULL WHERE id=? AND status='inactive'", (eid,))
        check(db.execute('SELECT count(*) FROM events').fetchone()[0] <= MAX_EVENTS, 'history bound exceeded')
        # Global first-attempt priority prevents retries starving fresh work; round
        # robin by repository/kind within each attempt count via SQL row numbers.
        inflight = db.execute("SELECT count(*) FROM events WHERE status IN ('reserved','started')").fetchone()[0]
        check(inflight <= capacity, 'capacity below outstanding work; recover or finish work first')
        # Free only the slots needed by first attempts. A started run cannot be
        # preempted; its owner must stop and recover it before another can start.
        first_pending = db.execute("SELECT count(*) FROM events WHERE status='pending' AND attempts=0").fetchone()[0]
        needed = max(0, min(first_pending, capacity) - (capacity - inflight))
        preempted = db.execute("SELECT id FROM events WHERE status='reserved' AND attempts>0 ORDER BY id LIMIT ?", (needed,)).fetchall()
        for (eid,) in preempted:
            db.execute("UPDATE events SET status='pending',reason='retry_preempted',reservation=NULL,reservation_digest=NULL WHERE id=?", (eid,))
        inflight -= len(preempted)
        available = capacity - inflight
        unstarted_inflight = db.execute("SELECT count(*) FROM events WHERE status='reserved' AND attempts=0").fetchone()[0]
        selected = db.execute('''SELECT id FROM (SELECT id, attempts, last_attempt,
            row_number() OVER (PARTITION BY attempts, json_extract(event,'$.repository'), json_extract(event,'$.kind') ORDER BY coalesce(last_attempt,-1),id) AS slot
            FROM events WHERE status='pending' AND (? = 0 OR attempts = 0)) ORDER BY attempts,slot,last_attempt,id LIMIT ?''', (unstarted_inflight, available)).fetchall()
        for (eid,) in selected:
            db.execute("UPDATE events SET status='reserved',reservation=?,reason='reserved' WHERE id=?", (seq, eid))
        records = [{'event': json.loads(e), 'first_seen': first, 'status': status, 'attempts': attempts, 'last_attempt': last, 'reason': reason}
                   for e, first, status, attempts, last, reason in db.execute('SELECT event,first_seen,status,attempts,last_attempt,reason FROM events ORDER BY id')]
        result = {'schema':'incoming-queue-v1', 'sequence':seq, 'previous_sha256':None if head is None else head[1],
                  'queue_id':queue_id, 'snapshot_sha256':snapshot_hash, 'observed_at':now, 'capacity':capacity,
                  'discovery_observed_at':doc['observed_at'],
                  'selected':[x[0] for x in selected], 'preempted':[x[0] for x in preempted], 'events':records}
        raw = encoded(result)
        digest = hashlib.sha256(raw).hexdigest()
        db.execute('INSERT INTO history VALUES (?,?,?)', (seq,digest,raw))
        db.executemany('UPDATE events SET reservation_digest=? WHERE id=?', [(digest, eid) for (eid,) in selected])
        db.execute('COMMIT')
        return result, digest
    except BaseException:
        db.execute('ROLLBACK')
        raise



def reserve_exact_pr(db, expected, prepared, now):
    """Reserve one exact current PR for an operator-owned, one-item pilot.

    This is an offline queue transition, not a scan dispatch or completion.
    """
    check(isinstance(prepared, dict) and prepared.get('schema') == 'incoming-pr-dispatch-inputs-v1' and
          prepared.get('status') == 'prepared_only', 'unsupported prepared input')
    upstream = prepared.get('upstream')
    check(isinstance(upstream, str), 'invalid prepared upstream')
    repo = 'openwrt/' + upstream
    number, source_sha = prepared.get('pr_number'), prepared.get('source_sha')
    snapshot_sha = prepared.get('discovery_checkpoint_sha256')
    control_sha = prepared.get('control_sha')
    check(repo in ('openwrt/openwrt', 'openwrt/luci') and type(number) is int and number > 0 and
          isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{40}', source_sha) and
          isinstance(control_sha, str) and re.fullmatch(r'[0-9a-f]{40}', control_sha) and
          isinstance(snapshot_sha, str) and re.fullmatch(r'[0-9a-f]{64}', snapshot_sha),
          'invalid prepared PR identity')
    check(isinstance(now, str), 'invalid reservation time')
    timestamp = datetime.fromisoformat(now.replace('Z', '+00:00'))
    check(timestamp.tzinfo is not None, 'reservation time needs timezone')
    eid = json.dumps((repo, 'pull_request', number, source_sha), separators=(',', ':'))
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and (head[0], head[1]) == expected,
              'stale or missing queue predecessor')
        previous = json.loads(head[2], object_pairs_hook=unique_object)
        check(timestamp >= datetime.fromisoformat(previous['observed_at'].replace('Z', '+00:00')),
              'reservation time moved backwards')
        latest_snapshot = None
        for (raw_history,) in db.execute('SELECT document FROM history ORDER BY seq DESC'):
            history = json.loads(raw_history, object_pairs_hook=unique_object)
            if history.get('schema') == 'incoming-queue-v1':
                latest_snapshot = history.get('snapshot_sha256')
                break
        check(latest_snapshot == snapshot_sha, 'prepared candidate is not from latest queued discovery')
        check(db.execute("SELECT count(*) FROM events WHERE status IN ('reserved','started')").fetchone()[0] == 0,
              'pilot capacity is occupied')
        subj = json.dumps((repo, 'pull_request', number), separators=(',', ':'))
        check(db.execute("SELECT count(*) FROM events WHERE subject=? AND status='pending'", (subj,)).fetchone()[0] == 1,
              'PR subject is not uniquely current and pending')
        row = db.execute('SELECT event,status,attempts FROM events WHERE id=?', (eid,)).fetchone()
        check(row is not None and row[1] == 'pending' and row[2] == 0,
              'exact PR head is not an unattempted pending event')
        event = json.loads(row[0], object_pairs_hook=unique_object)
        check(event.get('kind') == 'pull_request' and event['source']['commit'] == source_sha and
              event['base_commit'] == control_sha and source_sha != control_sha,
              'queued event differs from prepared PR')
        seq = head[0] + 1
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        result = {'schema': 'incoming-queue-manual-reservation-v1', 'sequence': seq,
                  'previous_sha256': head[1], 'observed_at': now,
                  'queue_id': queue_id, 'snapshot_sha256': snapshot_sha,
                  'event_id': eid, 'source': event['source'],
                  'control_sha': control_sha,
                  'prepared_sha256': hashlib.sha256(encoded(prepared)).hexdigest(),
                  'capacity': 1, 'status': 'reserved_only'}
        raw = encoded(result)
        digest = hashlib.sha256(raw).hexdigest()
        changed = db.execute("UPDATE events SET status='reserved',reservation=?,reservation_digest=?,reason='manual_reserved' WHERE id=? AND status='pending' AND attempts=0",
                             (seq, digest, eid)).rowcount
        check(changed == 1, 'PR reservation changed during transaction')
        db.execute('INSERT INTO history VALUES (?,?,?)', (seq, digest, raw))
        db.execute('COMMIT')
        return result, digest
    except BaseException:
        db.execute('ROLLBACK'); raise


def recover_stale_reserved_pr(db, expected, raw_files, now):
    """Operator-only recovery of an unstarted PR reservation after head/base drift.

    The supplied hosted API files are checked for internal consistency, not
    authenticated by this offline queue. This never signs or completes a scan.
    """
    check(isinstance(raw_files, dict) and set(raw_files) == {'pull', 'run', 'jobs', 'dispatch'} and
          all(isinstance(value, bytes) and 0 < len(value) <= 65_536
              for value in raw_files.values()), 'invalid recovery evidence bytes')
    pull, run, jobs, dispatch = (json.loads(raw_files[key], object_pairs_hook=unique_object)
                                 for key in ('pull', 'run', 'jobs', 'dispatch'))
    evidence = {key + '_sha256': hashlib.sha256(value).hexdigest()
                for key, value in raw_files.items()}
    timestamp = datetime.fromisoformat(now.replace('Z', '+00:00'))
    check(timestamp.tzinfo is not None, 'recovery time needs timezone')
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and head[:2] == expected and
              hashlib.sha256(head[2]).hexdigest() == head[1],
              'stale or invalid queue predecessor')
        reservation = json.loads(head[2], object_pairs_hook=unique_object)
        check(reservation.get('schema') == 'incoming-queue-manual-reservation-v1' and
              reservation.get('status') == 'reserved_only',
              'queue head is not a manual exact PR reservation')
        check(timestamp >= datetime.fromisoformat(reservation['observed_at'].replace('Z', '+00:00')),
              'recovery time moved backwards')
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()[0]
        check(reservation['queue_id'] == queue_id, 'queue identity mismatch')
        row = db.execute('SELECT event,status,attempts,reservation,reservation_digest,started_job FROM events WHERE id=?',
                         (reservation['event_id'],)).fetchone()
        check(row is not None and row[1:] == ('reserved', 0, head[0], head[1], None),
              'reservation has started or changed')
        queued = json.loads(row[0], object_pairs_hook=unique_object)
        event_id = json.loads(reservation['event_id'])
        check(isinstance(event_id, list) and len(event_id) == 4 and event_id[1] == 'pull_request' and
              event_id[0] in ('openwrt/openwrt', 'openwrt/luci') and
              event_id[3] == queued['source']['commit'] == reservation['source']['commit'] and
              queued['base_commit'] == reservation['control_sha'],
              'invalid queued PR reservation')
        repo, _, number, old_head = event_id
        new_head, new_base = pull.get('head', {}).get('sha'), pull.get('base', {}).get('sha')
        check(pull.get('number') == number and pull.get('state') == 'open' and
              pull.get('base', {}).get('repo', {}).get('full_name') == repo and
              all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value)
                  for value in (new_head, new_base)) and
              (new_head, new_base) != (old_head, reservation['control_sha']),
              'canonical PR response does not show head/base drift')
        check(run.get('repository', {}).get('full_name') == 'lucas-albers-lz4/codeql-openwrt' and
              type(run.get('id')) is int and run['id'] > 0 and
              type(run.get('run_attempt')) is int and run['run_attempt'] > 0 and
              run.get('path') == '.github/workflows/incoming-event-preflight.yml' and
              run.get('event') == 'workflow_dispatch' and run.get('status') == 'completed' and
              run.get('conclusion') == 'failure',
              'invalid failed workflow identity')
        started_at = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
        check(started_at.tzinfo is not None and
              started_at >= datetime.fromisoformat(reservation['observed_at'].replace('Z', '+00:00')) and
              timestamp >= started_at, 'failed run predates reservation or recovery')
        check(dispatch.get('schema') == 'incoming-dispatch-inputs-v1' and
              dispatch.get('status') == 'claimed_unverified' and
              dispatch.get('run_id') == str(run['id']) + '-' + str(run['run_attempt']) and
              dispatch.get('upstream') == repo.split('/')[1] and
              dispatch.get('pr_number') == number and
              dispatch.get('source_sha') == old_head and
              dispatch.get('control_sha') == reservation['control_sha'] and
              dispatch.get('queue_id') == queue_id and
              dispatch.get('reservation_sequence') == head[0] and
              dispatch.get('reservation_sha256') == head[1],
              'failed workflow dispatch does not match reservation')
        listed = jobs.get('jobs')
        check(isinstance(listed, list) and jobs.get('total_count') == len(listed) == 3 and
              {job.get('name'): (job.get('status'), job.get('conclusion')) for job in listed} ==
              {'contract': ('completed', 'success'), 'resolve-pins': ('completed', 'failure'),
               'released-event-scan': ('completed', 'skipped')} and
              all(job.get('run_id') == run['id'] and
                  job.get('run_attempt') == run['run_attempt'] and
                  job.get('head_sha') == run.get('head_sha') for job in listed) and
              [step.get('name') for job in listed if job.get('name') == 'resolve-pins'
               for step in job.get('steps', []) if step.get('conclusion') == 'failure'] ==
              ['Fetch exact GitHub pull API response'],
              'failed run did not stop before released scan')
        sequence = head[0] + 1
        result = {'schema': 'incoming-queue-manual-stale-recovery-v1',
                  'status': 'recovered_unstarted', 'authority': 'local_operator',
                  'sequence': sequence, 'previous_sha256': head[1],
                  'queue_id': queue_id, 'event_id': reservation['event_id'],
                  'reservation_sequence': head[0], 'reservation_sha256': head[1],
                  'observed_at': now, 'old_head': old_head,
                  'old_base': reservation['control_sha'], 'observed_head': new_head,
                  'observed_base': new_base,
                  'failed_run_id': run['id'], 'failed_run_attempt': run['run_attempt'],
                  'evidence': evidence,
                  'evidence_source': {
                      'pull_artifact': 'incoming-event-' + str(run['id']) + '-' + str(run['run_attempt']) + '/pull-api-response.json',
                      'dispatch_artifact': 'incoming-event-' + str(run['id']) + '-' + str(run['run_attempt']) + '/dispatch-inputs.json',
                      'run_api': 'repos/lucas-albers-lz4/codeql-openwrt/actions/runs/' + str(run['id']),
                      'jobs_api': 'repos/lucas-albers-lz4/codeql-openwrt/actions/runs/' + str(run['id']) + '/jobs'},
                  'limitations': ['Operator-supplied API files are not authenticated by this queue.']}
        raw = encoded(result)
        digest = hashlib.sha256(raw).hexdigest()
        changed = db.execute("UPDATE events SET status='inactive',reason='manual_stale_head_recovery',reservation=NULL,reservation_digest=NULL,started_job=NULL WHERE id=? AND status='reserved' AND attempts=0 AND reservation=? AND reservation_digest=?",
                             (reservation['event_id'], head[0], head[1])).rowcount
        check(changed == 1, 'stale reservation changed before recovery')
        db.execute('INSERT INTO history VALUES (?,?,?)', (sequence, digest, raw))
        db.execute('COMMIT')
        return result, digest
    except BaseException:
        db.execute('ROLLBACK'); raise


def apply_attested(db, expected, payload, mac, secret, now):
    """Apply a trusted signer's start or outcome. MAC authenticates the issuer,
    not the truth of its claims; production needs a reviewed same-job signer.
    """
    check(isinstance(secret, bytes) and len(secret) >= 32, 'invalid signer key')
    check(isinstance(mac, str) and hmac.compare_digest(hmac.new(secret, encoded(payload), hashlib.sha256).hexdigest(), mac), 'invalid attestation')
    check(isinstance(payload, dict) and payload.get('kind') in ('start', 'failure', 'complete', 'recover'), 'invalid attestation kind')
    common = {'kind','queue_id','event_id','reservation','reservation_digest','run_id'}
    extra = set() if payload['kind'] == 'recover' else ({'job'} if payload['kind'] == 'start' else ({'job','failure'} if payload['kind'] == 'failure' else {'schema','job','issuer_receipt_sha256','source','release_lock_sha256','manifest_sha256','extraction_sha256','sarif_sha256','consumer_disposition','control_sha256'}))
    check(set(payload) == common | extra, 'invalid attestation fields')
    check(isinstance(payload['run_id'], str) and 1 <= len(payload['run_id']) <= 128, 'invalid run id')
    check(type(payload['reservation']) is int and payload['reservation'] >= 0 and isinstance(payload['event_id'], str), 'invalid reservation identity')
    if payload['kind'] != 'recover':
        job = payload['job']
        check(isinstance(job, dict) and set(job) == {'workflow','job','run_id','attempt'}, 'invalid job identity')
        check(all(isinstance(job[x], str) and 1 <= len(job[x]) <= 256 for x in ('workflow','job')), 'invalid job identity')
        check(type(job['run_id']) is int and job['run_id'] > 0 and type(job['attempt']) is int and job['attempt'] > 0, 'invalid job identity')
    if payload['kind'] == 'failure':
        check(payload['failure'] in ('tool','api','coverage','consumer'), 'invalid failure category')
    if payload['kind'] == 'complete':
        check(payload['schema'] == 'incoming-queue-completion-v2', 'invalid completion schema')
        check(payload['consumer_disposition'] in ('clean','alert_triage'), 'invalid consumer disposition')
        for field in ('issuer_receipt_sha256','release_lock_sha256','manifest_sha256','extraction_sha256','sarif_sha256','control_sha256'):
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
        row = db.execute('SELECT event,status,reservation,reason,reservation_digest,started_job FROM events WHERE id=?',(payload['event_id'],)).fetchone()
        check(row is not None and row[2] == payload['reservation'] and row[4] == payload['reservation_digest'], 'unknown or stale reservation')
        event = json.loads(row[0]); kind = payload['kind']
        if kind == 'start':
            check(row[1] == 'reserved', 'reservation is not available')
            attempts = db.execute('SELECT attempts FROM events WHERE id=?', (payload['event_id'],)).fetchone()[0]
            if attempts > 0:
                unstarted = db.execute("SELECT count(*) FROM events WHERE status IN ('pending','reserved') AND attempts=0").fetchone()[0]
                check(unstarted == 0, 'first attempts remain pending or reserved')
            db.execute("UPDATE events SET status='started',attempts=attempts+1,last_attempt=?,reason=?,started_job=? WHERE id=?", (head[0]+1,payload['run_id'],encoded(payload['job']).decode(),payload['event_id']))
        elif kind == 'recover':
            check(row[1] == 'reserved' or (row[1] == 'started' and row[3] == payload['run_id']), 'recovery does not match active reservation')
            db.execute("UPDATE events SET status='pending',reason='recovered',reservation=NULL,reservation_digest=NULL,started_job=NULL WHERE id=?", (payload['event_id'],))
        else:
            check(row[1] == 'started' and row[3] == payload['run_id'], 'outcome does not match active run')
            check(row[5] == encoded(payload['job']).decode(), 'outcome does not match active job')
            if kind == 'complete':
                check(payload['source']['commit'] == event['source']['commit'], 'source commit mismatch')
                check(event['source']['tree'] is None or payload['source']['tree'] == event['source']['tree'], 'source tree mismatch')
            db.execute('UPDATE events SET status=?,reason=?,reservation=NULL,reservation_digest=NULL,started_job=NULL WHERE id=?', ('completed' if kind == 'complete' else 'pending', kind if kind == 'complete' else payload['failure'],payload['event_id']))
        result = {'schema':'incoming-queue-action-v2','sequence':head[0]+1,'previous_sha256':head[1],'observed_at':now,'attestation':payload,'mac':mac}
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
    parser.add_argument('--create', action='store_true', help='exclusively create a new queue store')
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--expected-sequence', required=True, type=int, help='-1 only for a new queue')
    parser.add_argument('--expected-sha256', help='required except for genesis')
    parser.add_argument('--capacity', required=True, type=int)
    parser.add_argument('--previous-snapshot',
                        help='exact prior discovery checkpoint required for every successor')
    args = parser.parse_args()
    try:
        check((args.expected_sequence == -1 and args.expected_sha256 is None) or
              (args.expected_sequence >= 0 and isinstance(args.expected_sha256, str) and len(args.expected_sha256) == 64), 'invalid predecessor')
        check(args.create == (args.expected_sequence == -1), 'create mode must match genesis predecessor')
        expected = None if args.expected_sequence == -1 else (args.expected_sequence, args.expected_sha256)
        db = open_queue(args.database, create=args.create)
        try:
            result, digest = transition(db, expected, args.snapshot, args.capacity,
                                        datetime.now(timezone.utc).isoformat(),
                                        args.previous_snapshot)
        finally:
            db.close()
        print(json.dumps({'sequence': result['sequence'], 'sha256': digest, 'selected': result['selected'],
                          'pending': sum(r['status'] in ('pending', 'reserved', 'started') for r in result['events']),
                          'unattempted': sum(r['status'] in ('pending', 'reserved', 'started') and r['attempts'] == 0 for r in result['events'])}))
        return 0
    except (PollError, ValueError, OSError, sqlite3.Error, RecursionError) as exc:
        print('queue rejected: ' + str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
