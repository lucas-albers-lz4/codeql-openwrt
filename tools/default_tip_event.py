#!/usr/bin/env python3
"""Independently resolve a discovered default-branch tip and a control.

Creates fresh checkouts under a new run directory. This is identity preflight,
not a scan or proof that the control is clean of findings.
"""
from __future__ import annotations
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

from tools.incoming_event import REPOSITORIES, SHA, InvalidEvent, require
from tools.event_corpus_manifest import POLICY_SHA256

REPO_ALIASES = {'openwrt/openwrt': 'openwrt', 'openwrt/luci': 'luci'}
BRANCH = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]*\Z')


def api(url: str) -> dict:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise InvalidEvent('API redirect rejected')
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                                     'User-Agent': 'codeql-openwrt-default-tip-resolver'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        data = response.read(2_000_001)
    require(len(data) <= 2_000_000, 'API response too large')
    result = json.loads(data)
    require(isinstance(result, dict), 'API response must be an object')
    return result


def validate_run_path(run: Path) -> None:
    require(run.is_absolute() and all(part not in ('.', '..') and not part.startswith('-')
                                      for part in run.parts[1:]), 'unsafe run path')
    current = Path(run.anchor)
    for part in run.parts[1:]:
        current = current / part
        require(not current.is_symlink(), 'run path contains symlink')
    require(not run.exists(), 'run path already exists')


def resolve(event: dict, control: dict, run: Path) -> dict:
    validate_run_path(run)
    require(isinstance(event, dict) and set(event) == {'repository', 'kind', 'ref', 'source'}, 'invalid discovered event')
    repo = event['repository']
    require(isinstance(repo, str) and repo in REPO_ALIASES and event['kind'] == 'default_branch', 'unsupported event')
    alias = REPO_ALIASES[repo]
    branch = event['ref']
    require(isinstance(branch, str) and bool(BRANCH.fullmatch(branch)) and '..' not in branch
            and not branch.endswith(('/', '.', '.lock')) and '//' not in branch
            and all(not part.startswith('.') and not part.endswith('.lock') for part in branch.split('/')),
            'invalid branch')
    source = event['source']
    require(isinstance(source, dict) and set(source) == {'commit', 'tree'} and
            all(isinstance(source[k], str) and SHA.fullmatch(source[k]) for k in source), 'invalid discovered identity')
    require(isinstance(control, dict) and set(control) == {'commit', 'tree'} and
            all(isinstance(control[k], str) and SHA.fullmatch(control[k]) for k in control) and
            control['commit'] != source['commit'], 'invalid or identical control identity')
    control_sha = control['commit']
    policy_raw = (Path(__file__).resolve().parents[1] / 'docs/current-corpus-source-v0.6.json').read_bytes()
    require(hashlib.sha256(policy_raw).hexdigest() == POLICY_SHA256, 'policy digest drift')
    policy_pin = json.loads(policy_raw)['pins'][alias]
    require(isinstance(policy_pin, str) and bool(SHA.fullmatch(policy_pin)), 'invalid policy pin')
    full_name = REPOSITORIES[alias].split('github.com/')[1].removesuffix('.git')
    base = 'https://api.github.com/repos/' + full_name
    meta = api(base)
    require(isinstance(meta.get('full_name'), str) and meta['full_name'].lower() == full_name
            and meta.get('default_branch') == branch,
            'default branch or repository drift')
    commit = api(base + '/commits/' + source['commit'])
    require(commit.get('sha') == source['commit'] and isinstance(commit.get('commit'), dict) and
            isinstance(commit['commit'].get('tree'), dict) and
            commit['commit']['tree'].get('sha') == source['tree'], 'API commit/tree drift')
    run.mkdir(parents=True, exist_ok=False)
    home = run / 'home'
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(HOME=str(home.resolve()), TMPDIR=str(home.resolve()),
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
               GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.followRedirects', GIT_CONFIG_VALUE_0='false')
    def git(*args: str) -> str:
        return subprocess.check_output(['git', *args], stderr=subprocess.PIPE, env=env, text=True).strip()
    def identity(path: Path, expected: str) -> dict:
        commit = git('-C', str(path), 'rev-parse', '--verify', expected + '^{commit}')
        require(commit == expected and git('-C', str(path), 'rev-parse', 'HEAD') == expected,
                'fetched checkout commit drift')
        require(not git('-C', str(path), 'status', '--porcelain=v1'), 'fetched checkout dirty')
        return {'commit': commit, 'tree': git('-C', str(path), 'rev-parse', expected + '^{tree}')}
    identities = {}
    for label, ref, expected in [('source', 'refs/heads/' + branch, source['commit']),
                                 ('control', control_sha, control_sha)]:
        path = run / label
        git('init', '-q', str(path))
        git('-C', str(path), 'remote', 'add', 'origin', REPOSITORIES[alias])
        git('-C', str(path), 'fetch', '--no-tags', '--depth=1', 'origin', ref)
        git('-C', str(path), 'checkout', '-q', '--detach', 'FETCH_HEAD')
        identities[label] = identity(path, expected)
        git('-C', str(path), 'fetch', '--no-tags', '--depth=1', 'origin', policy_pin)
        require(git('-C', str(path), 'rev-parse', '--verify', policy_pin + '^{commit}') == policy_pin,
                'frozen policy pin missing')
    require(identities['source'] == source, 'fetched default branch commit/tree drift')
    require(identities['control'] == control, 'fetched control commit/tree drift')
    return {'schema': 'incoming-event-receipt-v1', 'repository': alias, 'discovery_repository': repo,
            'repository_url': REPOSITORIES[alias], 'event_type': 'default_branch',
            'ref': branch, 'source': identities['source'], 'control': identities['control'],
            'status': 'identities_resolved_only', 'policy_pin': policy_pin,
            'limitations': ['Fresh Git ref and API checks are observations, not an atomic snapshot.',
                            'Control identity is not a clean scan; no source selection or CodeQL scan ran.']}


def checkpoint_event(path: Path, index: int) -> tuple[dict, dict]:
    with path.open('rb') as handle:
        raw = handle.read(128_000_001)
    require(len(raw) <= 128_000_000, 'checkpoint exceeds byte limit')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate checkpoint JSON key')
            result[key] = value
        return result
    checkpoint = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(checkpoint, dict) and checkpoint.get('schema') == 'incoming-poll-v3'
            and checkpoint.get('status') == 'complete' and isinstance(checkpoint.get('decisions'), list),
            'invalid discovery checkpoint')
    observed = checkpoint.get('observed_at')
    require(isinstance(observed, str), 'invalid checkpoint observed time')
    try:
        parsed = datetime.fromisoformat(observed.replace('Z', '+00:00'))
    except ValueError as exc:
        raise InvalidEvent('invalid checkpoint observed time') from exc
    require(parsed.tzinfo is not None, 'checkpoint observed time missing timezone')
    decisions = checkpoint['decisions']
    require(type(index) is int and 0 <= index < len(decisions), 'invalid decision index')
    decision = decisions[index]
    require(isinstance(decision, dict) and decision.get('decision') == 'selected'
            and decision.get('status') == 'pending' and isinstance(decision.get('event'), dict),
            'decision is not a selected pending event')
    event = decision['event']
    require(event.get('kind') == 'default_branch' and isinstance(event.get('source'), dict),
            'selected event is not a default tip')
    key = [event.get('repository'), 'default_branch', event.get('ref'), event['source'].get('commit'), '', '']
    require(sum(isinstance(d, dict) and isinstance(d.get('event'), dict) and
                [d['event'].get('repository'), d['event'].get('kind'), d['event'].get('ref'),
                 d['event'].get('source', {}).get('commit') if isinstance(d['event'].get('source'), dict) else None,
                 '', ''] == key for d in decisions) == 1, 'duplicate discovery event key')
    return event, {'checkpoint_sha256': hashlib.sha256(raw).hexdigest(), 'observed_at': observed,
                   'decision_index': index, 'event_key': key}


def validate_pair(event: dict, binding: dict, control_event: dict, control_binding: dict) -> None:
    require(event.get('repository') == control_event.get('repository') and
            event.get('ref') == control_event.get('ref'), 'control repository or branch differs')
    require(datetime.fromisoformat(control_binding['observed_at'].replace('Z', '+00:00')) <
            datetime.fromisoformat(binding['observed_at'].replace('Z', '+00:00')),
            'control observation must precede event')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('checkpoint', type=Path)
    p.add_argument('decision_index', type=int)
    p.add_argument('control_checkpoint', type=Path)
    p.add_argument('control_index', type=int)
    p.add_argument('run_dir', type=Path)
    a = p.parse_args()
    try:
        event, binding = checkpoint_event(a.checkpoint, a.decision_index)
        control_event, control_binding = checkpoint_event(a.control_checkpoint, a.control_index)
        validate_pair(event, binding, control_event, control_binding)
        receipt = resolve(event, control_event['source'], a.run_dir)
        receipt['discovery'] = binding
        receipt['control_discovery'] = control_binding
        receipt['limitations'].append('Checkpoint digest binds supplied bytes; it does not authenticate discovery or prove selection freshness.')
        (a.run_dir / 'identity-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        print('default tip rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
