"""Transactional queue records for a separately verified local issuer.

These shape/MAC/CAS checks do not authenticate GitHub evidence themselves.
Only an operator command that verifies canonical live/final bytes may call
them with its private key. Legacy v2 actions remain a separate prototype.
"""
import hashlib
import hmac
import json
import re
from datetime import datetime

from incoming_poll import check, unique_object
from incoming_queue import encoded

WORKFLOW = '.github/workflows/incoming-event-preflight.yml'
JOB = 'released-event-scan'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')


def _digest(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _job(job, run_id):
    check(type(job) is dict and set(job) == {'workflow', 'job', 'run_id',
          'attempt', 'id', 'consumer_commit'} and
          job['workflow'] == WORKFLOW and job['job'] == JOB and
          type(job['run_id']) is int and job['run_id'] > 0 and
          type(job['attempt']) is int and job['attempt'] > 0 and
          type(job['id']) is int and job['id'] > 0 and
          isinstance(job['consumer_commit'], str) and
          HEX40.fullmatch(job['consumer_commit']) and
          run_id == f"{job['run_id']}-{job['attempt']}",
          'invalid issued job identity')


def _common(payload):
    check(type(payload) is dict and
          isinstance(payload.get('queue_id'), str) and
          re.fullmatch(r'[0-9a-f]{32}', payload['queue_id']) and
          isinstance(payload.get('event_id'), str) and
          type(payload.get('reservation')) is int and payload['reservation'] >= 0 and
          _digest(payload.get('reservation_digest')) and
          isinstance(payload.get('run_id'), str), 'invalid issued reservation')
    _job(payload.get('job'), payload['run_id'])


def _start_shape(payload):
    fields = {'schema', 'kind', 'queue_id', 'event_id', 'reservation',
              'reservation_digest', 'run_id', 'job', 'source_sha', 'control_sha',
              'policy_sha256',
              'early_artifact', 'observation_sha256', 'run_api_sha256',
              'jobs_api_sha256', 'artifacts_api_sha256',
              'recheck_run_api_sha256', 'recheck_jobs_api_sha256'}
    check(type(payload) is dict and set(payload) == fields and
          payload['schema'] == 'incoming-issued-start-v1' and
          payload['kind'] == 'start', 'invalid issued start schema')
    _common(payload)
    check(all(isinstance(payload[name], str) and HEX40.fullmatch(payload[name])
              for name in ('source_sha', 'control_sha')) and
          all(_digest(payload[name]) for name in fields if name.endswith('_sha256') and
              name not in ('reservation_digest',)) and
          type(payload['early_artifact']) is dict and
          set(payload['early_artifact']) == {'id', 'sha256'} and
          type(payload['early_artifact']['id']) is int and
          payload['early_artifact']['id'] > 0 and
          _digest(payload['early_artifact']['sha256']),
          'invalid issued start evidence digests')


def _completion_shape(payload):
    fields = {'schema', 'kind', 'queue_id', 'event_id', 'reservation',
              'reservation_digest', 'run_id', 'job', 'start_sequence',
              'start_sha256', 'final_artifact', 'custody_sha256',
              'early_final_sha256', 'source', 'release_lock_sha256',
              'manifest_sha256', 'extraction_sha256', 'sarif_sha256',
              'control_sha256', 'freeze_inventory_sha256', 'control_commit', 'consumer_disposition',
              'result_count'}
    check(type(payload) is dict and set(payload) == fields and
          payload['schema'] == 'incoming-issued-completion-v1' and
          payload['kind'] == 'complete', 'invalid issued completion schema')
    _common(payload)
    check(type(payload['start_sequence']) is int and
          payload['start_sequence'] == payload['reservation'] + 1 and
          all(_digest(payload[name]) for name in fields if name.endswith('_sha256') and
              name != 'reservation_digest') and
          type(payload['final_artifact']) is dict and
          set(payload['final_artifact']) == {'id', 'sha256'} and
          type(payload['final_artifact']['id']) is int and
          payload['final_artifact']['id'] > 0 and
          _digest(payload['final_artifact']['sha256']) and
          type(payload['source']) is dict and
          set(payload['source']) == {'commit', 'tree'} and
          all(isinstance(payload['source'][name], str) and
              HEX40.fullmatch(payload['source'][name]) for name in ('commit', 'tree')) and
          isinstance(payload['control_commit'], str) and
          HEX40.fullmatch(payload['control_commit']) and
          payload['consumer_disposition'] in ('clean', 'alert_triage') and
          type(payload['result_count']) is int and payload['result_count'] >= 0 and
          ((payload['consumer_disposition'] == 'clean') ==
           (payload['result_count'] == 0)), 'invalid issued completion fields')


def _failure_shape(payload):
    fields = {'schema', 'kind', 'queue_id', 'event_id', 'reservation',
              'reservation_digest', 'run_id', 'job', 'start_sequence',
              'start_sha256', 'run_api_sha256', 'jobs_api_sha256',
              'run_conclusion', 'job_conclusion'}
    check(type(payload) is dict and set(payload) == fields and
          payload['schema'] == 'incoming-issued-failure-v1' and
          payload['kind'] == 'failure', 'invalid issued failure schema')
    _common(payload)
    check(type(payload['start_sequence']) is int and
          payload['start_sequence'] == payload['reservation'] + 1 and
          all(_digest(payload[name]) for name in
              ('start_sha256', 'run_api_sha256', 'jobs_api_sha256')) and
          payload['run_conclusion'] in ('failure', 'cancelled', 'timed_out') and
          payload['job_conclusion'] in ('failure', 'cancelled', 'timed_out'),
          'invalid issued failure fields')


def _time(now, prior):
    current = datetime.fromisoformat(now.replace('Z', '+00:00'))
    previous = datetime.fromisoformat(prior.replace('Z', '+00:00'))
    check(current.tzinfo is not None and previous.tzinfo is not None and
          current >= previous, 'issued timestamp invalid or moved backwards')


def _append(db, sequence, predecessor_digest, now, payload, key):
    check(isinstance(key, bytes) and len(key) >= 32, 'invalid local issuer key')
    mac = hmac.new(key, encoded(payload), hashlib.sha256).hexdigest()
    document = {'schema': 'incoming-queue-issued-action-v1',
                'sequence': sequence, 'previous_sha256': predecessor_digest,
                'observed_at': now, 'attestation': payload, 'mac': mac}
    raw = encoded(document)
    digest = hashlib.sha256(raw).hexdigest()
    db.execute('INSERT INTO history VALUES (?,?,?)', (sequence, digest, raw))
    return document, digest


def issue_start(db, expected, payload, key, now):
    """Append a start only for the exact current unstarted manual reservation."""
    _start_shape(payload)
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and head[:2] == expected and
              hashlib.sha256(head[2]).hexdigest() == head[1],
              'stale or corrupt issued-start predecessor')
        reservation = json.loads(head[2], object_pairs_hook=unique_object)
        check(reservation.get('schema') == 'incoming-queue-manual-reservation-v1' and
              reservation.get('status') == 'reserved_only' and
              reservation.get('sequence') == head[0] == payload['reservation'] and
              reservation.get('queue_id') == payload['queue_id'] and
              reservation.get('event_id') == payload['event_id'] and
              reservation.get('source', {}).get('commit') == payload['source_sha'] and
              reservation.get('control_sha') == payload['control_sha'] and
              payload['reservation_digest'] == head[1],
              'issued start differs from exact reservation')
        queue_id = db.execute("SELECT value FROM metadata WHERE key='queue_id'").fetchone()
        check(queue_id == (payload['queue_id'],), 'issued queue ID mismatch')
        event = db.execute('SELECT status,attempts,reservation,reservation_digest,started_job '
                           'FROM events WHERE id=?', (payload['event_id'],)).fetchone()
        attempts_before = reservation.get('attempts_before', 0)
        check(type(attempts_before) is int and attempts_before >= 0 and
              event == ('reserved', attempts_before, head[0], head[1], None),
              'issued reservation attempt differs from queue')
        if attempts_before > 0:
            unattempted = db.execute("SELECT count(*) FROM events WHERE status IN ('pending','reserved') AND attempts=0").fetchone()[0]
            check(unattempted == 0, 'first attempts remain before issued retry')
        _time(now, reservation['observed_at'])
        changed = db.execute("UPDATE events SET status='started',attempts=attempts+1,"
                             "last_attempt=?,reason=?,started_job=? WHERE id=? AND status='reserved' "
                             "AND attempts=? AND reservation=? AND reservation_digest=?",
                             (head[0] + 1, payload['run_id'], encoded(payload['job']).decode(),
                              payload['event_id'], attempts_before, head[0], head[1])).rowcount
        check(changed == 1, 'issued start event changed')
        result = _append(db, head[0] + 1, head[1], now, payload, key)
        db.execute('COMMIT')
        return result
    except BaseException:
        db.execute('ROLLBACK')
        raise


def issue_complete(db, expected, payload, key, now):
    """Append a completion only for its immediately preceding issued start."""
    _completion_shape(payload)
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and head[:2] == expected and
              hashlib.sha256(head[2]).hexdigest() == head[1],
              'stale or corrupt issued-completion predecessor')
        start = json.loads(head[2], object_pairs_hook=unique_object)
        att = start.get('attestation', {})
        check(start.get('schema') == 'incoming-queue-issued-action-v1' and
              start.get('sequence') == head[0] == payload['start_sequence'] and
              start.get('previous_sha256') == payload['reservation_digest'] and
              payload['start_sha256'] == head[1] and
              att.get('schema') == 'incoming-issued-start-v1' and
              att.get('kind') == 'start' and
              all(att.get(name) == payload[name] for name in
                  ('queue_id', 'event_id', 'reservation', 'reservation_digest',
                   'run_id', 'job')) and
              att.get('source_sha') == payload['source']['commit'] and
              att.get('control_sha') == payload['control_commit'],
              'completion does not match issued start')
        check(hmac.compare_digest(start.get('mac', ''),
              hmac.new(key, encoded(att), hashlib.sha256).hexdigest()),
              'issued start MAC mismatch')
        reservation_row = db.execute('SELECT digest,document FROM history WHERE seq=?',
                                     (payload['reservation'],)).fetchone()
        check(reservation_row is not None and
              reservation_row[0] == payload['reservation_digest'] and
              hashlib.sha256(reservation_row[1]).hexdigest() == reservation_row[0],
              'retained reservation mismatch')
        reservation = json.loads(reservation_row[1], object_pairs_hook=unique_object)
        check(reservation.get('event_id') == payload['event_id'] and
              reservation.get('source', {}).get('commit') == payload['source']['commit'] and
              reservation.get('control_sha') == payload['control_commit'] and
              (reservation['source']['tree'] is None or
               reservation['source']['tree'] == payload['source']['tree']),
              'completion source differs from reservation')
        event = db.execute('SELECT status,reason,reservation,reservation_digest,started_job '
                           'FROM events WHERE id=?', (payload['event_id'],)).fetchone()
        check(event == ('started', payload['run_id'], payload['reservation'],
                        payload['reservation_digest'], encoded(payload['job']).decode()),
              'started event differs from completion')
        _time(now, start['observed_at'])
        changed = db.execute("UPDATE events SET status='completed',reason='issued_complete',"
                             "reservation=NULL,reservation_digest=NULL,started_job=NULL "
                             "WHERE id=? AND status='started' AND reason=? AND reservation=? "
                             "AND reservation_digest=? AND started_job=?",
                             (payload['event_id'], payload['run_id'], payload['reservation'],
                              payload['reservation_digest'], encoded(payload['job']).decode())).rowcount
        check(changed == 1, 'issued completion event changed')
        result = _append(db, head[0] + 1, head[1], now, payload, key)
        db.execute('COMMIT')
        return result
    except BaseException:
        db.execute('ROLLBACK')
        raise


def issue_failure(db, expected, payload, key, now):
    """Return a terminal failed/cancelled issued run to pending for retry."""
    _failure_shape(payload)
    db.execute('BEGIN IMMEDIATE')
    try:
        head = db.execute('SELECT seq,digest,document FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        check(head is not None and head[:2] == expected and
              hashlib.sha256(head[2]).hexdigest() == head[1],
              'stale or corrupt issued-failure predecessor')
        start = json.loads(head[2], object_pairs_hook=unique_object)
        att = start.get('attestation', {})
        check(start.get('schema') == 'incoming-queue-issued-action-v1' and
              start.get('sequence') == head[0] == payload['start_sequence'] and
              start.get('previous_sha256') == payload['reservation_digest'] and
              payload['start_sha256'] == head[1] and
              att.get('schema') == 'incoming-issued-start-v1' and
              att.get('kind') == 'start' and
              all(att.get(name) == payload[name] for name in
                  ('queue_id', 'event_id', 'reservation', 'reservation_digest',
                   'run_id', 'job')) and
              hmac.compare_digest(start.get('mac', ''),
                  hmac.new(key, encoded(att), hashlib.sha256).hexdigest()),
              'failure does not match authenticated issued start')
        event = db.execute('SELECT status,reason,reservation,reservation_digest,started_job '
                           'FROM events WHERE id=?', (payload['event_id'],)).fetchone()
        check(event == ('started', payload['run_id'], payload['reservation'],
                        payload['reservation_digest'], encoded(payload['job']).decode()),
              'started event differs from failure')
        _time(now, start['observed_at'])
        changed = db.execute("UPDATE events SET status='pending',reason=?,"
                             "reservation=NULL,reservation_digest=NULL,started_job=NULL "
                             "WHERE id=? AND status='started' AND reason=? AND reservation=? "
                             "AND reservation_digest=? AND started_job=?",
                             (payload['job_conclusion'], payload['event_id'],
                              payload['run_id'], payload['reservation'],
                              payload['reservation_digest'],
                              encoded(payload['job']).decode())).rowcount
        check(changed == 1, 'issued failure event changed')
        result = _append(db, head[0] + 1, head[1], now, payload, key)
        db.execute('COMMIT')
        return result
    except BaseException:
        db.execute('ROLLBACK')
        raise
