#!/usr/bin/env python3
"""Read-only GitHub discovery. No scans, dispatches, or mutable shared state.

The checkpoint is the previous successful output supplied by the operator.
It tracks observed snapshots only, not every upstream transition between polls.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import json
import hashlib
from http.client import HTTPException
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

SHA = re.compile(r'[0-9a-f]{40}\Z')
REPOS = ('openwrt/openwrt', 'openwrt/luci')
API = 'https://api.github.com'
REQUEST_LOG = []
HTTP_ERRORS = []
MAX_HTTP_ERRORS = 20_000
MAX_RESPONSE = 2_000_000
MAX_RECORD = 128_000_000
MAX_REQUEST_HISTORY = 96_000_000
MAX_EVENTS = 10_000
PAGE_SIZE = 25

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PollError('API redirect refused')

OPENER = build_opener(NoRedirect())

class PollError(ValueError):
    def __init__(self, message, detail=None):
        super().__init__(message)
        self.detail = detail

MAX_ERROR_BODY = 8192
SAFE_MESSAGES = {'Bad credentials', 'Requires authentication', 'API rate limit exceeded', 'Resource not accessible by integration', 'Not Found', 'Forbidden'}

def http_failure(path, exc):
    # Do not retain arbitrary server text, which could reflect request credentials.
    try:
        raw = exc.read(MAX_ERROR_BODY + 1)
    except (OSError, HTTPException):
        raw = b''
    finally:
        exc.close()
    truncated = len(raw) > MAX_ERROR_BODY
    raw = raw[:MAX_ERROR_BODY]
    message = '[unrecognized or unavailable response omitted]'
    if not truncated:
        try:
            obj = json.loads(raw, object_pairs_hook=unique_object)
            if isinstance(obj, dict) and isinstance(obj.get('message'), str) and obj['message'] in SAFE_MESSAGES:
                message = obj['message']
        except (ValueError, UnicodeError, RecursionError):
            pass
    safe_headers = {}
    for name in ('X-GitHub-Request-Id', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-RateLimit-Used', 'Retry-After'):
        value = exc.headers.get(name, '') if exc.headers else ''
        token = os.environ.get('GITHUB_TOKEN', '')
        if isinstance(value, str) and len(value) <= 128 and re.fullmatch(r'[A-Za-z0-9:._-]+', value) and (not token or token not in value):
            safe_headers[name] = value
    return {'path': path, 'status': exc.code, 'time': datetime.now(timezone.utc).isoformat(),
            'body_prefix_sha256': hashlib.sha256(raw).hexdigest(), 'body_prefix_bytes': len(raw),
            'body_truncated': truncated, 'safe_message': message, 'headers': safe_headers}


def check(ok, msg):
    if not ok: raise PollError(msg)

def full_sha(value):
    check(isinstance(value, str) and bool(SHA.fullmatch(value)), 'invalid full SHA')
    return value

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def fetch(path):
    check(path.startswith('/repos/'), 'invalid API path')
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'codeql-openwrt-incoming-poll'}
    if os.environ.get('GITHUB_TOKEN'): headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    retried_401 = False
    for attempt in range(3):
        try:
            with OPENER.open(Request(API + path, headers=headers), timeout=30) as response:
                check(response.status == 200, 'non-200 API response')
                check(response.headers.get('X-RateLimit-Remaining', '').isdigit() and int(response.headers['X-RateLimit-Remaining']) > 0, 'missing or exhausted rate limit')
                raw = response.read(MAX_RESPONSE + 1)
                check(len(raw) <= MAX_RESPONSE, 'API response exceeds byte limit')
                check(sum(len(r['body_base64']) for r in REQUEST_LOG) + len(raw) * 4 // 3 + 4 <= MAX_REQUEST_HISTORY, 'request history exceeds byte limit')
                data = json.loads(raw, object_pairs_hook=unique_object)
                link = ', '.join(response.headers.get_all('Link', [])) if hasattr(response.headers, 'get_all') else response.headers.get('Link', '')
                REQUEST_LOG.append({'path': path, 'status': response.status, 'time': datetime.now(timezone.utc).isoformat(), 'link': link, 'rate_remaining': response.headers['X-RateLimit-Remaining'], 'sha256': hashlib.sha256(raw).hexdigest(), 'body_base64': base64.b64encode(raw).decode('ascii')})
                return data, link
        except HTTPError as exc:
            detail = http_failure(path, exc)
            check(len(HTTP_ERRORS) < MAX_HTTP_ERRORS, 'HTTP failure history exceeds limit')
            HTTP_ERRORS.append(detail)
            if exc.headers and exc.headers.get('Retry-After') is not None:
                raise PollError('GitHub API requested deferred retry', detail) from exc
            remaining = detail['headers'].get('X-RateLimit-Remaining')
            if remaining == '0':
                raise PollError('GitHub API rate limit exhausted', detail) from exc
            retryable = exc.code in (502, 503, 504) or (exc.code == 401 and not retried_401)
            if exc.code == 401: retried_401 = True
            if not retryable or attempt == 2:
                raise PollError('GitHub API returned an HTTP error', detail) from exc
            time.sleep(attempt + 1)
        except (URLError, HTTPException, TimeoutError, OSError, json.JSONDecodeError, RecursionError) as exc:
            raise PollError('API request failed (' + type(exc).__name__ + ')', {'path': path}) from exc

def link_values(header):
    """Parse a bounded, conservative Link subset; unsupported syntax fails closed."""
    parts, start, quoted, angle = [], 0, False, False
    for i, char in enumerate(header):
        if char == '"' and not angle:
            quoted = not quoted
        elif not quoted and char == '<':
            check(not angle, 'malformed pagination link'); angle = True
        elif not quoted and char == '>':
            check(angle, 'malformed pagination link'); angle = False
        elif char == ',' and not quoted and not angle:
            parts.append(header[start:i].strip()); start = i + 1
    check(not quoted and not angle, 'malformed pagination link')
    if header: parts.append(header[start:].strip())
    values = []
    for part in parts:
        match = re.fullmatch(r'<([^>]+)>((?:\s*;\s*[A-Za-z][A-Za-z0-9_-]*\s*=\s*(?:"[^"\\]*"|[A-Za-z0-9._~-]+))*)', part)
        check(match is not None, 'unsupported pagination link syntax')
        attrs = re.findall(r';\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*("[^"\\]*"|[A-Za-z0-9._~-]+)', match.group(2))
        rels = [v.strip('"').split() for k, v in attrs if k.lower() == 'rel']
        check(len(rels) == 1 and bool(rels[0]), 'missing or duplicate link relation')
        values.append((match.group(1), [relation.lower() for relation in rels[0]]))
    return values

def pull_pages(repo, get, max_pages, repo_id=None):
    rows = []
    expect_empty = False
    for page in range(1, max_pages + 1):
        data, link = get(f'/repos/{repo}/pulls?state=open&per_page={PAGE_SIZE}&page={page}')
        check(isinstance(data, list) and len(data) <= PAGE_SIZE, 'invalid pull page')
        if expect_empty:
            check(not data and not any('next' in relations for _, relations in link_values(link)), 'missing next link on nonterminal full page')
            return rows
        rows.extend(data)
        # Validate links semantically; never follow arbitrary URLs or query parameters.
        next_urls = [url for url, relations in link_values(link) if 'next' in relations]
        check(len(next_urls) <= 1, 'ambiguous next link')
        if next_urls:
            url = urlsplit(next_urls[0])
            query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            check(url.scheme == 'https' and url.netloc == 'api.github.com' and url.path in ({f'/repos/{repo}/pulls', f'/repositories/{repo_id}/pulls'} if repo_id is not None else {f'/repos/{repo}/pulls'}) and not url.fragment and query == {'state': ['open'], 'per_page': [str(PAGE_SIZE)], 'page': [str(page + 1)]}, 'unexpected next link')
        else:
            if len(data) < PAGE_SIZE: return rows
            # Verify a full terminal page with one bounded empty-page request.
            expect_empty = True
    raise PollError('pagination bound exceeded')

def identity(repo, sha, get):
    data, link = get(f'/repos/{repo}/git/commits/{full_sha(sha)}')
    check(not link and isinstance(data, dict) and data.get('sha') == sha, 'invalid commit response')
    tree = data.get('tree')
    check(isinstance(tree, dict), 'missing tree')
    return {'commit': sha, 'tree': full_sha(tree.get('sha'))}

def snapshot(repo, get, max_pages):
    meta, link = get(f'/repos/{repo}')
    check(not link and isinstance(meta, dict) and meta.get('full_name') == repo, 'invalid repository metadata')
    repo_id = meta.get('id')
    check(type(repo_id) is int and repo_id > 0, 'invalid repository numeric ID')
    branch = meta.get('default_branch')
    check(isinstance(branch, str) and re.fullmatch(r'[A-Za-z0-9._/-]+', branch) and '..' not in branch, 'invalid default branch')
    tip, link = get(f'/repos/{repo}/commits/{branch}')
    check(not link and isinstance(tip, dict), 'invalid default tip')
    default = identity(repo, full_sha(tip.get('sha')), get)
    pulls = pull_pages(repo, get, max_pages, repo_id)
    events = [{'repository': repo, 'kind': 'default_branch', 'ref': branch, 'source': default}]
    numbers = set()
    for pr in pulls:
        check(isinstance(pr, dict) and pr.get('state') == 'open', 'invalid pull entry')
        number = pr.get('number')
        check(type(number) is int and number > 0 and number not in numbers, 'duplicate or invalid PR')
        numbers.add(number)
        base, head = pr.get('base'), pr.get('head')
        check(isinstance(base, dict) and isinstance(head, dict) and isinstance(base.get('repo'), dict) and base['repo'].get('full_name') == repo, 'invalid PR base')
        check(isinstance(head.get('repo'), dict) and isinstance(head['repo'].get('full_name'), str) and type(head['repo'].get('fork')) is bool, 'invalid PR head repository')
        base_sha = full_sha(base.get('sha'))
        base_ref, head_ref = base.get('ref'), head.get('ref')
        check(isinstance(base_ref, str) and base_ref and isinstance(head_ref, str) and head_ref, 'missing PR refs')
        head_repo = head['repo']['full_name']
        check(head_repo == repo or head['repo']['fork'], 'invalid cross-repository head')
        check(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', head_repo)), 'invalid head repository name')
        # Discovery binds API-reported commits only. The event resolver must
        # revalidate membership and obtain trees before any scan.
        source = {'commit': full_sha(head.get('sha')), 'tree': None}
        base_identity = {'commit': base_sha, 'tree': None}
        events.append({'repository': repo, 'kind': 'pull_request', 'number': number, 'head_repository': head_repo, 'head_fork': head['repo']['fork'], 'head_ref': head_ref, 'base_ref': base_ref, 'base_commit': base_sha, 'base': base_identity, 'source': source})
    return events

def key(event):
    return (event['repository'], event['kind'], str(event.get('number', event.get('ref'))), event['source']['commit'], event.get('base_commit', ''), event.get('base_ref', ''))

def validate_event(event):
    check(isinstance(event, dict) and event.get('repository') in REPOS, 'invalid event repository')
    source = event.get('source')
    check(isinstance(source, dict) and set(source) == {'commit', 'tree'}, 'invalid source identity')
    full_sha(source['commit'])
    if event.get('kind') == 'default_branch':
        full_sha(source['tree'])
        check(set(event) == {'repository', 'kind', 'ref', 'source'} and isinstance(event['ref'], str) and bool(event['ref']), 'invalid default event')
    elif event.get('kind') == 'pull_request':
        check(set(event) == {'repository', 'kind', 'number', 'head_repository', 'head_fork', 'head_ref', 'base_ref', 'base_commit', 'base', 'source'}, 'invalid PR event fields')
        check(type(event['number']) is int and event['number'] > 0, 'invalid PR number')
        check(isinstance(event['head_repository'], str) and bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', event['head_repository'])), 'invalid head repository')
        check(type(event['head_fork']) is bool and (event['head_repository'] == event['repository'] or event['head_fork']), 'invalid head fork')
        check(all(isinstance(event[x], str) and event[x] for x in ('head_ref', 'base_ref')), 'invalid PR refs')
        base = event['base']
        check(isinstance(base, dict) and set(base) == {'commit', 'tree'}, 'invalid base identity')
        full_sha(event['base_commit'])
        check(source['tree'] is None and base['tree'] is None, 'PR discovery trees must remain unresolved')
        check(event['base_commit'] == base['commit'], 'base commit mismatch')
    else:
        raise PollError('invalid event kind')

def read_checkpoint(path):
    with path.open('rb') as handle:
        raw = handle.read(MAX_RECORD + 1)
    check(len(raw) <= MAX_RECORD, 'checkpoint exceeds byte limit')
    doc = json.loads(raw, object_pairs_hook=unique_object)
    check(isinstance(doc, dict) and set(doc) == {'schema', 'status', 'observed_at', 'capacity', 'previous_sha256', 'genesis', 'requests', 'http_errors', 'decisions', 'limitations'} and doc.get('schema') == 'incoming-poll-v3' and doc.get('status') == 'complete' and isinstance(doc.get('decisions'), list), 'invalid checkpoint')
    check(type(doc['genesis']) is bool and type(doc['capacity']) is int and 0 <= doc['capacity'] <= 1000 and isinstance(doc['requests'], list) and isinstance(doc['limitations'], list) and isinstance(doc['observed_at'], str), 'invalid checkpoint metadata')
    try:
        timestamp = datetime.fromisoformat(doc['observed_at'].replace('Z', '+00:00'))
    except (ValueError, AttributeError) as exc:
        raise PollError('invalid checkpoint timestamp') from exc
    check(timestamp.tzinfo is not None, 'checkpoint timestamp missing timezone')
    check(all(isinstance(x, str) for x in doc['limitations']), 'invalid checkpoint limitations')
    check(isinstance(doc['http_errors'], list) and len(doc['http_errors']) <= MAX_HTTP_ERRORS, 'invalid HTTP failure history')
    for error in doc['http_errors']:
        check(isinstance(error, dict) and set(error) == {'path', 'status', 'time', 'body_prefix_sha256', 'body_prefix_bytes', 'body_truncated', 'safe_message', 'headers'}, 'invalid HTTP failure record')
        check(isinstance(error['path'], str) and error['path'].startswith('/repos/') and type(error['status']) is int and 400 <= error['status'] <= 599 and isinstance(error['time'], str) and isinstance(error['headers'], dict) and isinstance(error['safe_message'], str) and type(error['body_prefix_bytes']) is int and 0 <= error['body_prefix_bytes'] <= MAX_ERROR_BODY and type(error['body_truncated']) is bool and isinstance(error['body_prefix_sha256'], str) and bool(re.fullmatch(r'[0-9a-f]{64}', error['body_prefix_sha256'])), 'invalid HTTP failure fields')
    for request in doc['requests']:
        check(isinstance(request, dict) and set(request) == {'path', 'status', 'time', 'link', 'rate_remaining', 'sha256', 'body_base64'}, 'invalid checkpoint request')
        check(isinstance(request['path'], str) and request['path'].startswith('/repos/') and request['status'] == 200 and all(isinstance(request[x], str) for x in ('time', 'link', 'rate_remaining', 'sha256', 'body_base64')), 'invalid checkpoint request fields')
        try:
            raw_body = base64.b64decode(request['body_base64'], validate=True)
        except ValueError as exc:
            raise PollError('invalid checkpoint response encoding') from exc
        check(len(raw_body) <= MAX_RESPONSE and hashlib.sha256(raw_body).hexdigest() == request['sha256'], 'invalid checkpoint response digest')
    check((doc['genesis'] and doc['previous_sha256'] is None) or (not doc['genesis'] and isinstance(doc['previous_sha256'], str) and bool(re.fullmatch(r'[0-9a-f]{64}', doc['previous_sha256']))), 'invalid checkpoint predecessor')
    return doc['decisions'], hashlib.sha256(raw).hexdigest()

def atomic_write(path, value):
    raw = (json.dumps(value, indent=2) + '\n').encode()
    check(len(raw) <= MAX_RECORD, 'output exceeds byte limit')
    name = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name + '.', delete=False) as handle:
            name = handle.name
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        name = None
    finally:
        if name is not None:
            try: os.unlink(name)
            except FileNotFoundError: pass

def plan(previous, discovered, capacity):
    check(type(capacity) is int and 0 <= capacity <= 1000, 'invalid capacity')
    check(isinstance(previous, list) and isinstance(discovered, list), 'invalid event list')
    check(len(previous) <= MAX_EVENTS and len(discovered) <= MAX_EVENTS, 'event bound exceeded')
    identities = {}
    def remember(event):
        for identity in (event['source'], event.get('base')):
            if identity is not None:
                sha, tree = identity['commit'], identity['tree']
                if tree is None: continue
                check(sha not in identities or identities[sha] == tree, 'commit has inconsistent tree')
                identities[sha] = tree
    old = {}
    for row in previous:
        check(isinstance(row, dict) and set(row) == {'event', 'status', 'decision', 'reason'} and row.get('status') == 'pending' and row.get('decision') in ('selected', 'backlog') and row.get('reason') in ('new', 'retry'), 'invalid previous record; completion is not implemented')
        event = row.get('event'); validate_event(event); remember(event)
        try: k = key(event)
        except (KeyError, TypeError): raise PollError('malformed previous event')
        check(k not in old, 'duplicate previous event'); old[k] = row
    fresh = {}
    for event in discovered:
        validate_event(event); remember(event)
        k = key(event); check(k not in fresh, 'duplicate observed event')
        check(k not in old or old[k]['event'] == event, 'identity metadata changed for same event key')
        fresh[k] = event
    # Prior pending work is retained even when a PR closes or changes head.
    pending = [(k, r['event'], 'retry') for k, r in old.items() if r['status'] == 'pending']
    pending += [(k, e, 'new') for k, e in fresh.items() if k not in old]
    check(len(pending) <= MAX_EVENTS, 'backlog bound exceeded')
    pending.sort(key=lambda item: (0 if item[2] == 'retry' else 1, item[0]))
    decisions = []
    for i, (k, event, origin) in enumerate(pending):
        decisions.append({'event': event, 'decision': 'selected' if i < capacity else 'backlog', 'reason': origin, 'status': 'pending'})
    return decisions

def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--previous', type=Path, help='previous successful decision record')
    source.add_argument('--genesis', action='store_true', help='explicitly start a new observation history')
    p.add_argument('--capacity', type=int, required=True)
    p.add_argument('--max-pages', type=int, default=401)
    p.add_argument('--output-dir', type=Path, required=True, help='new run-owned directory')
    a = p.parse_args()
    created = False
    try:
        a.output_dir.mkdir(parents=True, exist_ok=False)
        created = True
        check(1 <= a.max_pages <= 401, 'invalid page bound')
        previous = []
        previous_hash = None
        if a.previous:
            previous, previous_hash = read_checkpoint(a.previous)
            plan(previous, [], 0)  # Reject malformed history before any network request.
        observed = []
        for repo in REPOS: observed.extend(snapshot(repo, fetch, a.max_pages))
        decisions = plan(previous, observed, a.capacity)
        result = {'schema': 'incoming-poll-v3', 'status': 'complete', 'observed_at': datetime.now(timezone.utc).isoformat(), 'capacity': a.capacity, 'previous_sha256': previous_hash, 'genesis': a.genesis, 'requests': REQUEST_LOG, 'http_errors': HTTP_ERRORS, 'decisions': decisions, 'limitations': ['Observed snapshots only; intermediate PR heads and default-branch commits between polls are not enumerated.', 'PR discovery trees are unresolved; selections are not scan-ready and require independent event resolver verification.', 'PR and default branch discovery is not an atomic upstream snapshot.']}
        atomic_write(a.output_dir / 'decisions.json', result)
        return 0
    except (PollError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        if created:
            try:
                atomic_write(a.output_dir / 'failure.json', {'status': 'failed', 'error': str(exc), 'failed_request': exc.detail if isinstance(exc, PollError) else None, 'requests': REQUEST_LOG, 'http_errors': HTTP_ERRORS})
            except (PollError, OSError) as failure_exc:
                print('failure record could not be written: ' + str(failure_exc), file=sys.stderr)
        print('incoming poll failed: ' + str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__': sys.exit(main())
