#!/usr/bin/env python3
"""Prepare policy-pinned source-first default-tip and prior-tip control oracles.

This performs no scan. Run only on the fresh resolver-owned checkouts.
"""
import argparse
from datetime import datetime
import re
import hashlib
import json
import os
from pathlib import Path
import sys

from tools.event_corpus_manifest import build, POLICY_SHA256, POLICY_SCHEMA
from tools.full_tree_candidates import compare, git
from tools.incoming_event import SHA, require

ROOT = Path(__file__).resolve().parents[1]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare(receipt_path: Path, run: Path, output: Path) -> None:
    raw_receipt = receipt_path.read_bytes()
    receipt = json.loads(raw_receipt)
    require(receipt.get('schema') == 'incoming-event-receipt-v1' and
            receipt.get('event_type') == 'default_branch' and
            receipt.get('status') == 'identities_resolved_only', 'invalid default-tip receipt')
    repo = receipt.get('repository')
    require(repo in ('openwrt', 'luci') and receipt.get('discovery_repository') == 'openwrt/' + repo,
            'invalid receipt repository')
    source, control = receipt.get('source'), receipt.get('control')
    for identity in (source, control):
        require(isinstance(identity, dict) and set(identity) == {'commit', 'tree'} and
                all(isinstance(v, str) and SHA.fullmatch(v) for v in identity.values()), 'invalid identity')
    require(source['commit'] != control['commit'], 'identical source and control')
    for field, identity in (('discovery', source), ('control_discovery', control)):
        binding = receipt.get(field)
        require(isinstance(binding, dict) and isinstance(binding.get('checkpoint_sha256'), str) and
                bool(re.fullmatch(r'[0-9a-f]{64}', binding['checkpoint_sha256'])) and
                binding.get('event_key') == ['openwrt/' + repo, 'default_branch', receipt.get('ref'), identity['commit'], '', ''],
                'invalid checkpoint identity binding')
    times = []
    for field in ('control_discovery', 'discovery'):
        observed = receipt[field].get('observed_at')
        require(isinstance(observed, str), 'invalid observation time')
        try:
            parsed = datetime.fromisoformat(observed.replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError('invalid observation time') from exc
        require(parsed.tzinfo is not None, 'observation time missing timezone')
        times.append(parsed)
    require(times[0] < times[1], 'control observation must precede event')
    raw = (ROOT / 'docs/current-corpus-source-v0.6.json').read_bytes()
    require(digest(raw) == POLICY_SHA256, 'policy digest drift')
    policy = json.loads(raw)
    require(policy.get('schema') == POLICY_SCHEMA and receipt.get('policy_pin') == policy['pins'][repo],
            'policy pin mismatch')
    output.mkdir(parents=True, exist_ok=False)
    records = {}
    for role, identity in (('event', source), ('control', control)):
        checkout = run / ('source' if role == 'event' else 'control')
        require(git(checkout, 'rev-parse', 'HEAD') == identity['commit'] and
                git(checkout, 'rev-parse', 'HEAD^{tree}') == identity['tree'] and
                not git(checkout, 'status', '--porcelain=v1'), role + ' checkout drift')
        base = policy['pins'][repo]
        derived = dict(receipt, source=identity, base={'commit': base})
        inventory = compare(checkout, base, identity['commit'], policy, raw, repo)
        manifest = build(policy, derived, inventory, checkout)
        def write(name, obj):
            data = (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()
            (output / name).write_bytes(data)
            return digest(data)
        derived_digest = write(role + '-derived-receipt.json', derived)
        inventory_digest = write(role + '-inventory.json', inventory)
        manifest['event'].update(identity_receipt_sha256=derived_digest,
                                 candidate_inventory_sha256=inventory_digest,
                                 route_oracle_script_sha256=digest((ROOT / 'tools/event_corpus_manifest.py').read_bytes()))
        if role == 'control':
            manifest['event']['source_role'] = 'clean_control'
        manifest_digest = write(role + '-manifest.json', manifest)
        records[role] = {'identity': identity, 'derived_receipt_sha256': derived_digest,
                         'inventory_sha256': inventory_digest, 'manifest_sha256': manifest_digest}
    binding = {'schema': 'default-tip-source-first-binding-v1', 'receipt_sha256': digest(raw_receipt),
               'policy_sha256': digest(raw), 'policy_pin': policy['pins'][repo], 'repository': repo,
               'discovery': receipt['discovery'], 'control_discovery': receipt['control_discovery'],
               'outputs': records, 'status': 'source_first_oracles_only',
               'limitations': ['Recorded prior tip is a control candidate, not evidence of a clean scan.',
                               'Checkpoint bytes do not authenticate GitHub history or establish immediate predecessor.',
                               'Installation projections are policy assumptions; no installed-byte or scan result is established.']}
    (output / 'binding.json').write_text(json.dumps(binding, sort_keys=True, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('run', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    # Selector helpers use subprocess without explicit env; isolate them before any Git call.
    for key in list(os.environ):
        if key.startswith('GIT_'):
            del os.environ[key]
    home = (args.run / 'home').resolve()
    require(home.is_dir(), 'resolver run home missing')
    os.environ.update(HOME=str(home), TMPDIR=str(home), GIT_CONFIG_NOSYSTEM='1',
                      GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    try:
        prepare(args.receipt, args.run, args.output)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('default-tip oracle rejected: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
