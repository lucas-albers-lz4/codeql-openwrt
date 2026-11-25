#!/usr/bin/env python3
"""Non-issuing same-job artifact freeze after both scans and graph replay.

Only run this after all artifact writers have exited. The inventory is a local
receipt, not proof that an uploaded artifact came from a trusted runner.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from tools.current_corpus_linux import REPOSITORIES as SCAN_REPOSITORIES, validate_event_manifest
from tools.incoming_event import REPOSITORIES, canonical_repository
from tools.r3_linux_handoff import ROOT, need, write_json


INPUT_FILES = {
    'pull-api-response.json', 'incoming-event.json', 'incoming-event-receipt.json',
    'source-policy-drift.json', 'full-tree-candidates.json', 'event-corpus-manifest.json',
    'scan-pull-api-response.json', 'replayed-receipt.json', 'replayed-inventory.json',
    'replayed-manifest.json', 'consumer-graph.json',
    *(f'control-oracle/{name}' for name in ('control-derived-receipt.json',
      'control-inventory.json', 'control-manifest.json', 'control-binding.json')),
}
SCAN_OUT = {'routing.json', 'successful.bqrs', 'successful.json', 'errors.bqrs',
            'errors.json', 'coverage-event.json', 'default-suite.sarif',
            'event-triage-input.json', 'producer-receipt.json', 'triage.json'}
R3_OUT = {'source-first-manifest.json', 'routing.json', 'successful.bqrs',
          'successful.json', 'errors.bqrs', 'errors.json', 'default-suite.sarif',
          'producer-receipt.json', 'accepted.json'}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def _safe_file(path: Path, seen: set[tuple[int, int]]) -> dict:
    mode = path.lstat()
    need(stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1, 'artifact is an alias or not regular: ' + str(path))
    identity = (mode.st_dev, mode.st_ino)
    need(identity not in seen, 'duplicate artifact inode')
    seen.add(identity)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    after = path.lstat()
    need((mode.st_dev, mode.st_ino, mode.st_size, mode.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'artifact changed while hashing')
    return {'sha256': digest.hexdigest(), 'bytes': mode.st_size}


def _inventory(root: Path, expected: set[str], seen: set[tuple[int, int]]) -> dict:
    need(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'unsafe artifact root')
    actual = set()
    for base, dirs, files in os.walk(root, followlinks=False):
        parent = Path(base)
        for name in dirs:
            child = parent / name
            need(not child.is_symlink(), 'symlink directory in artifacts')
            need(any(item.startswith(child.relative_to(root).as_posix() + '/') for item in expected),
                 'unexpected artifact directory: ' + str(child))
        for name in files:
            actual.add((parent / name).relative_to(root).as_posix())
    need(actual == expected, 'missing or unexpected artifacts: ' + repr(sorted(actual ^ expected)))
    return {name: _safe_file(root / name, seen) for name in sorted(expected)}


def _command_files(root: Path) -> set[str]:
    commands = json.loads((root / 'commands.json').read_text())
    need(isinstance(commands, list) and commands, 'missing commands')
    names = {row[key] for row in commands for key in ('stdout', 'stderr', 'time')}
    need(all(isinstance(name, str) and len(Path(name).parts) == 2 and
             Path(name).parts[0] == 'commands' and
             Path(name).parts[1] not in ('.', '..') for name in names), 'unsafe command artifact path')
    return names


def _root_entries(root: Path, files: set[str], dirs: set[str]) -> None:
    need(root.is_dir() and not root.is_symlink(), 'unsafe run root')
    entries = {p.name: p for p in root.iterdir()}
    need(set(entries) == files | dirs, 'unexpected or missing run-root entry')
    need(all(entries[name].is_file() and not entries[name].is_symlink() for name in files) and
         all(entries[name].is_dir() and not entries[name].is_symlink() for name in dirs),
         'run-root alias or unexpected entry type')


def _source_recheck(source: Path, control: Path, inputs: Path, run: Path) -> dict:
    receipt = json.loads((inputs / 'replayed-receipt.json').read_text())
    result = {}
    for role, checkout, identity, manifest, derived, inventory, scan in (
        ('event', source, receipt['source'], inputs / 'replayed-manifest.json',
         inputs / 'replayed-receipt.json', inputs / 'replayed-inventory.json', run / 'event-corpus'),
        ('control', control, receipt['control'], inputs / 'control-oracle/control-manifest.json',
         inputs / 'control-oracle/control-derived-receipt.json',
         inputs / 'control-oracle/control-inventory.json', run / 'control-corpus')):
        need(not checkout.is_symlink() and checkout.is_dir(), 'unsafe source checkout')
        canonical_repository(checkout, REPOSITORIES[receipt['repository']])
        need(_git(checkout, 'rev-parse', 'HEAD') == identity['commit'] and
             _git(checkout, 'rev-parse', 'HEAD^{tree}') == identity['tree'] and
             not _git(checkout, 'status', '--porcelain=v1'), role + ' checkout drift')
        oracle = validate_event_manifest(manifest, derived, inventory, checkout,
                                         source_role='incoming_pr_head' if role == 'event' else 'clean_control')
        scan_pins = {}
        for repo, pin in oracle['pins'].items():
            staged_repo = scan / 'sources' / repo
            need(not staged_repo.is_symlink() and staged_repo.is_dir(), 'unsafe scan source checkout')
            canonical_repository(staged_repo, SCAN_REPOSITORIES[repo])
            need(_git(staged_repo, 'rev-parse', 'HEAD') == pin and
                 not _git(staged_repo, 'status', '--porcelain=v1'), 'scan source Git drift: ' + repo)
            scan_pins[repo] = {'commit': pin, 'tree': _git(staged_repo, 'rev-parse', 'HEAD^{tree}')}
        for row in oracle['selected']:
            source_file = scan / 'sources' / row['repo'] / row['source_path']
            stage_file = scan / 'stage' / row['proposed_installed_path']
            need(not source_file.is_symlink() and not stage_file.is_symlink(), 'source or stage alias')
            for path in (source_file, stage_file):
                need(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == row['source_sha256'],
                     role + ' source/stage byte drift: ' + row['source_path'])
            need(_git(scan / 'sources' / row['repo'], 'rev-parse', row['source_commit'] + ':' + row['source_path']) == row['git_blob'],
                 role + ' Git blob drift')
        for row in oracle['excluded']:
            source_file = scan / 'sources' / row['repo'] / row['source_path']
            need(not source_file.is_symlink() and source_file.is_file() and
                 hashlib.sha256(source_file.read_bytes()).hexdigest() == row['sha256'],
                 role + ' excluded source drift: ' + row['source_path'])
        result[role] = {'checkout': identity, 'scan_sources': scan_pins}
    base = receipt['base']
    need(_git(source, 'rev-parse', base['commit'] + '^{commit}') == base['commit'] and
         _git(source, 'rev-parse', base['commit'] + '^{tree}') == base['tree'], 'base Git identity drift')
    result['base'] = base
    return result


def freeze(temp: Path, run_id: str) -> dict:
    need(temp.is_absolute() and run_id and all(c.isdigit() or c == '-' for c in run_id), 'invalid run paths')
    inputs, run = temp / ('event-input-' + run_id), temp / ('r3-event-' + run_id)
    source, control = temp / ('event-source-' + run_id), temp / ('event-control-' + run_id)
    graph = json.loads((inputs / 'consumer-graph.json').read_text())
    need(graph.get('schema') == 'incoming-consumer-graph-workflow-v1' and graph.get('status') == 'checked',
         'consumer graph did not pass')
    need(not _git(ROOT, 'status', '--porcelain=v1'), 'trusted consumer checkout drift')
    identities = _source_recheck(source, control, inputs, run)
    _root_entries(run, {'preflight.json', 'receipt.json', 'commands.json'},
                  {'home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db', 'out',
                   'commands', 'cli', 'bundle', 'event-corpus', 'control-corpus'})
    _root_entries(run / 'event-corpus', {'preflight.json', 'receipt.json', 'commands.json'},
                  {'home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db', 'out', 'commands', 'bundle'})
    _root_entries(run / 'control-corpus', {'preflight.json', 'receipt.json', 'commands.json', 'control-assertion.json'},
                  {'home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db', 'out', 'commands', 'bundle'})
    _root_entries(run / 'out', set(), {'openvpn-parent', 'openvpn-fixed'})
    seen: set[tuple[int, int]] = set()
    records = {'inputs': _inventory(inputs, INPUT_FILES, seen)}
    for role, scan in (('event', run / 'event-corpus'), ('control', run / 'control-corpus')):
        expected = {'preflight.json', 'receipt.json', 'commands.json'}
        if role == 'control':
            expected.add('control-assertion.json')
        expected |= {'out/' + name for name in SCAN_OUT}
        expected |= _command_files(scan)
        # The scan root also contains databases, copied release code and caches.
        # Freeze the exact retained evidence subtrees, without traversing those work areas.
        records[role] = {}
        for prefix in ('', 'out', 'commands'):
            names = {name for name in expected if ('/' not in name if not prefix else name.startswith(prefix + '/'))}
            if prefix:
                names = {name[len(prefix) + 1:] for name in names}
            records[role][prefix or 'root'] = _inventory(scan / prefix, names, seen) if prefix else {
                name: _safe_file(scan / name, seen) for name in sorted(names)}
    r3 = {'preflight.json', 'receipt.json', 'commands.json'}
    records['r3'] = {'root': {name: _safe_file(run / name, seen) for name in sorted(r3)},
                     'commands': _inventory(run / 'commands', {name.removeprefix('commands/') for name in _command_files(run)}, seen)}
    for case in ('openvpn-parent', 'openvpn-fixed'):
        records['r3'][case] = _inventory(run / 'out' / case, R3_OUT, seen)
    return {'schema': 'incoming-artifact-freeze-v1', 'status': 'frozen', 'run_id': run_id,
            'consumer_commit': _git(ROOT, 'rev-parse', 'HEAD'), 'source_identities': identities,
            'artifacts': records, 'limitations': ['Non-issuing same-job inventory; no queue or signer.']}


def snapshot(temp: Path, run_id: str, inventory: dict) -> None:
    """Copy the inventoried bytes to a separate read-only attempt directory."""
    inputs, run = temp / ('event-input-' + run_id), temp / ('r3-event-' + run_id)
    destination = temp / ('issuer-freeze-' + run_id) / 'snapshot'
    need(not destination.exists(), 'freeze snapshot already exists')
    for group, root in (('inputs', inputs), ('event', run / 'event-corpus'),
                        ('control', run / 'control-corpus'), ('r3', run)):
        record = inventory['artifacts'][group]
        sections = {'': record} if group == 'inputs' else {
            ('' if key == 'root' else ('out/' + key if group == 'r3' and key.startswith('openvpn-') else key)): value
            for key, value in record.items()}
        for prefix, files in sections.items():
            for name, metadata in files.items():
                source = root / prefix / name
                target = destination / group / prefix / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open('rb') as reader, target.open('xb') as writer:
                    shutil.copyfileobj(reader, writer)
                need(hashlib.sha256(target.read_bytes()).hexdigest() == metadata['sha256'],
                     'artifact changed during freeze copy: ' + str(source))
                target.chmod(0o444)


if __name__ == '__main__':
    temp = Path(os.environ['RUNNER_TEMP'])
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    output = temp / ('issuer-freeze-' + run_id) / 'inventory.json'
    try:
        inventory = freeze(temp, run_id)
        snapshot(temp, run_id, inventory)
        write_json(output, inventory)
    except Exception as exc:
        write_json(output, {'schema': 'incoming-artifact-freeze-v1', 'status': 'failed', 'error': repr(exc)})
        raise
