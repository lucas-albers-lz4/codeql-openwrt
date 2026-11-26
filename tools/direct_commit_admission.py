#!/usr/bin/env python3
"""Check one frozen historical source-policy admission input; do not scan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from tools import default_branch_event as event
from tools import incoming_poll as poll
from tools.event_corpus_manifest import source_route

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / 'docs/direct-commit-openvpn-admission-v1.json'
ORACLE_SHA256 = '28e74f60ebc0dc8076ea3e92c8f5795817caf0f23aae03845a9d78c6cb77c1bd'
MAX_BLOB = 1_048_576


def read_regular_bounded(path, limit):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as handle:
        info = os.fstat(handle.fileno())
        poll.check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                   'input must be a bounded single-link regular file')
        raw = handle.read(limit + 1)
    poll.check(len(raw) <= limit and len(raw) == info.st_size,
               'input changed or exceeds byte limit')
    return raw


def git_bytes(checkout, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    try:
        result = subprocess.run(['git', '-C', str(checkout), *args], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=20, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise poll.PollError('admission local Git command failed') from exc
    poll.check(len(result.stdout) <= MAX_BLOB, 'admission Git output exceeds byte limit')
    return result.stdout


def frozen_oracle():
    raw = read_regular_bounded(ORACLE, MAX_BLOB)
    poll.check(hashlib.sha256(raw).hexdigest() == ORACLE_SHA256, 'admission oracle digest differs')
    doc = json.loads(raw, object_pairs_hook=poll.unique_object)
    poll.check(doc.get('schema') == 'openvpn-direct-commit-policy-admission-source-v1' and
               doc.get('repository') == 'openwrt/luci', 'admission oracle schema differs')
    return doc


def object_at(checkout, commit, path):
    poll.full_sha(commit)
    poll.check(path and not path.startswith('/') and '..' not in Path(path).parts,
               'unsafe admission path')
    raw = git_bytes(checkout, 'ls-tree', '-z', commit, '--', path)
    if not raw:
        return {'state': 'absent'}, b''
    poll.check(raw.endswith(b'\0') and raw.count(b'\0') == 1,
               'admission tree path is ambiguous')
    meta, selected = raw[:-1].split(b'\t', 1)
    poll.check(selected == path.encode() and re.fullmatch(rb'100644 blob [0-9a-f]{40}', meta),
               'admission tree entry differs')
    mode, _, blob = meta.decode().split()
    size = event.safe_git(checkout, 'cat-file', '-s', blob)
    poll.check(size.isdecimal() and int(size) <= MAX_BLOB, 'admission blob exceeds byte limit')
    data = git_bytes(checkout, 'cat-file', 'blob', blob)
    poll.check(len(data) == int(size), 'admission blob size differs')
    return {'state': 'tracked_blob', 'mode': mode, 'git_blob': blob,
            'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}, data


def verify(identity, source_checkout, control_checkout):
    oracle = frozen_oracle()
    commits = oracle['commits']
    poll.check(isinstance(identity, dict), 'direct-commit receipt is not an object')
    live = (identity.get('schema') == 'default-branch-event-identity-v1' and
            identity.get('status') == 'identities_resolved_only' and
            all(isinstance(identity.get(key), str) and
                re.fullmatch(r'[0-9a-f]{64}', identity[key]) for key in
                ('gap_sha256', 'previous_checkpoint_sha256', 'current_checkpoint_sha256')))
    historical = (identity.get('schema') == 'historical-direct-commit-source-identity-v1' and
                  identity.get('status') == 'historical_objects_resolved_only' and
                  not any(key in identity for key in
                          ('gap_sha256', 'previous_checkpoint_sha256', 'current_checkpoint_sha256')))
    poll.check((live or historical) and identity.get('repository') == 'openwrt/luci' and
               identity.get('ref') == 'master', 'direct-commit receipt differs')
    for role, name in (('source', 'introduced'), ('base', 'absent_parent'), ('control', 'fixed')):
        item = identity.get(role)
        poll.check(isinstance(item, dict) and set(item) == {'commit', 'tree'} and
                   item.get('commit') == commits[name] and
                   isinstance(item.get('tree'), str) and re.fullmatch(r'[0-9a-f]{40}', item['tree']),
                   role + ' commit differs from frozen admission')
    url = event.incoming_event.REPOSITORIES['luci']
    for checkout, role in ((source_checkout, 'source'), (control_checkout, 'control')):
        poll.check(event.checkout_identity(checkout, url, identity[role]['commit']) == identity[role],
                   role + ' checkout differs from identity receipt')
    poll.check(event.safe_git(source_checkout, 'rev-parse',
                             commits['absent_parent'] + '^{tree}') == identity['base'].get('tree'),
               'admission base tree differs from identity receipt')
    poll.check(event.first_parent_from_object(source_checkout, commits['introduced']) == commits['absent_parent'],
               'admission source first parent differs')
    for name, commit in commits.items():
        checkout = control_checkout if name == 'fixed' else source_checkout
        for kind, path in oracle['paths'].items():
            found, data = object_at(checkout, commit, path)
            poll.check(found == oracle['identities'][name][kind],
                       f'admission {name} {kind} identity differs')
            if name == 'introduced' and kind == 'package_recipe':
                poll.check(b'include ../../luci.mk' in data and b'LUCI_DEPENDS:=+openvpn' in data,
                           'admission package recipe syntax differs')
            if name == 'introduced' and kind == 'shared_recipe':
                poll.check(b'cp -pR $(PKG_BUILD_DIR)/root/* $(1)/' in data,
                           'admission root install rule differs')
            if name == 'introduced' and kind == 'ucode_source':
                path_suffix = path.split('/root/', 1)
                poll.check(len(path_suffix) == 2 and path_suffix[1] == oracle['proposed_installed_path'],
                           'admission installed projection differs')
                poll.check(source_route(path, path_suffix[1], data) == oracle['proposed_route'],
                           'admission source route differs')
    for checkout, role in ((source_checkout, 'source'), (control_checkout, 'control')):
        poll.check(event.checkout_identity(checkout, url, identity[role]['commit']) == identity[role],
                   role + ' checkout changed during admission')
    return {'schema': 'direct-commit-admission-check-v1',
            'status': 'source_policy_input_verified_only',
            'repository': 'openwrt/luci', 'source': identity['source'],
            'base': identity['base'], 'control': identity['control'],
            'admission_oracle_sha256': ORACLE_SHA256,
            'limitations': ['No selector policy override, full candidate inventory, installed IPK, CodeQL scan, SARIF or clean-control assertion occurred.',
                            'Gap and checkpoint digests in the input identity receipt were not replayed by this checker.',
                            'Historical Git object verification does not establish live default-branch checkpoint custody.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--source-checkout', type=Path, required=True)
    parser.add_argument('--control-checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        for checkout in (args.source_checkout.resolve(), args.control_checkout.resolve()):
            poll.check(not args.output.resolve().is_relative_to(checkout),
                       'admission output must be outside checkouts')
        raw = read_regular_bounded(args.identity, MAX_BLOB)
        identity = json.loads(raw, object_pairs_hook=poll.unique_object)
        receipt = verify(identity, args.source_checkout, args.control_checkout)
        receipt['identity_receipt_sha256'] = hashlib.sha256(raw).hexdigest()
        event.write_receipt_exclusive(args.output, receipt)
        return 0
    except (poll.PollError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('direct-commit admission rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
