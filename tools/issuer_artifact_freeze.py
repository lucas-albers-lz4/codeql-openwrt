#!/usr/bin/env python3
"""Non-issuing same-job artifact freeze after both scans and graph replay.

Only run this after all artifact writers have exited. The inventory is a local
receipt, not proof that an uploaded artifact came from a trusted runner.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from contextlib import contextmanager, ExitStack

from tools.current_corpus_linux import REPOSITORIES as SCAN_REPOSITORIES, validate_event_manifest
from tools.incoming_event import REPOSITORIES, canonical_repository
from tools.r3_linux_handoff import ROOT, need, write_json
from tools import issuer_workflow_graph


INPUT_FILES = {
    'pull-api-response.json', 'incoming-event.json', 'incoming-event-receipt.json',
    'source-policy-drift.json', 'full-tree-candidates.json', 'event-corpus-manifest.json',
    'scan-pull-api-response.json', 'replayed-receipt.json', 'replayed-inventory.json',
    'replayed-manifest.json', 'consumer-graph.json', 'reservation-claim.json',
    'dispatch-inputs.json',
    *(f'control-oracle/{name}' for name in ('control-derived-receipt.json',
      'control-inventory.json', 'control-manifest.json', 'control-binding.json')),
}
SCAN_OUT = {'routing.json', 'successful.bqrs', 'successful.json', 'errors.bqrs',
            'errors.json', 'coverage-event.json', 'default-suite.sarif',
            'event-triage-input.json', 'producer-receipt.json', 'triage.json'}
R3_OUT = {'source-first-manifest.json', 'routing.json', 'successful.bqrs',
          'successful.json', 'errors.bqrs', 'errors.json', 'default-suite.sarif',
          'producer-receipt.json', 'accepted.json',
          'historical-event-manifest.json', 'historical-event-triage.json'}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def _no_alias(root: Path, relative: str, *, tracked_link: bool = False) -> Path:
    need(not root.is_symlink() and root.is_dir(), 'unsafe source root')
    parts = Path(relative).parts
    need(parts and all(part not in ('', '.', '..') for part in parts) and not Path(relative).is_absolute(),
         'unsafe source path')
    path = root
    for index, part in enumerate(parts):
        path = path / part
        need(not path.is_symlink() or (tracked_link and index == len(parts) - 1), 'source or stage alias')
    return path


@contextmanager
def _open_regular(path: Path, anchor: Path | None = None):
    """Open a regular file beneath a checked directory without following links."""
    anchor = path.parent if anchor is None else anchor
    need(anchor.is_absolute() and anchor.is_dir() and not anchor.is_symlink(),
         'unsafe artifact anchor')
    try:
        parts = path.relative_to(anchor).parts
    except ValueError as exc:
        raise RuntimeError('artifact escaped anchor: ' + str(path)) from exc
    need(parts and all(part not in ('', '.', '..') for part in parts),
         'unsafe artifact relative path')
    with ExitStack() as stack:
        anchor_info = anchor.lstat()
        directory = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, directory)
        opened_anchor = os.fstat(directory)
        need((anchor_info.st_dev, anchor_info.st_ino, anchor_info.st_mode) ==
             (opened_anchor.st_dev, opened_anchor.st_ino, opened_anchor.st_mode),
             'artifact anchor changed')
        for part in parts[:-1]:
            directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            stack.callback(os.close, directory)
        mode = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        need(stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1,
             'artifact is an alias or not regular: ' + str(path))
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        stack.callback(os.close, descriptor)
        opened = os.fstat(descriptor)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
             identity(mode) == identity(opened),
             'artifact changed before open: ' + str(path))
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            yield stream, opened
        after = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        need(identity(opened) == identity(after) == identity(current),
             'artifact changed while reading: ' + str(path))


def _safe_file(path: Path, seen: set[tuple[int, int]], anchor: Path | None = None) -> dict:
    digest = hashlib.sha256()
    with _open_regular(path, anchor) as (stream, opened):
        identity = (opened.st_dev, opened.st_ino)
        need(identity not in seen, 'duplicate artifact inode')
        seen.add(identity)
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return {'sha256': digest.hexdigest(), 'bytes': opened.st_size}


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
    return {name: _safe_file(root / name, seen, root) for name in sorted(expected)}


def _command_files(root: Path) -> set[str]:
    with _open_regular(root / 'commands.json', root) as (stream, opened):
        need(opened.st_size <= 64 * 1024 * 1024, 'command receipt exceeds byte limit')
        raw = stream.read(64 * 1024 * 1024 + 1)
        need(len(raw) <= 64 * 1024 * 1024, 'command receipt exceeds byte limit')
        commands = json.loads(raw)
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


def _stage_precheck(root: Path) -> None:
    need(root.is_dir() and not root.is_symlink(), 'unsafe stage root')
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(base) / name
            need(path.is_dir() and not path.is_symlink(), 'stage directory alias')
        for name in files:
            _safe_file(Path(base) / name, set(), root)


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
            source_file = _no_alias(scan / 'sources' / row['repo'], row['source_path'])
            stage_file = _no_alias(scan / 'stage', row['proposed_installed_path'])
            for path in (source_file, stage_file):
                anchor = scan / 'stage' if path == stage_file else scan / 'sources' / row['repo']
                need(_safe_file(path, set(), anchor)['sha256'] == row['source_sha256'],
                     role + ' source/stage byte drift: ' + row['source_path'])
            need(_git(scan / 'sources' / row['repo'], 'rev-parse', row['source_commit'] + ':' + row['source_path']) == row['git_blob'],
                 role + ' Git blob drift')
        for row in oracle['excluded']:
            repo_root = scan / 'sources' / row['repo']
            tracked_link = row.get('reason') == 'tracked symlink; target not followed'
            source_file = _no_alias(repo_root, row['source_path'], tracked_link=tracked_link)
            if tracked_link:
                need(source_file.is_symlink(), role + ' excluded tracked link missing')
                entry = subprocess.check_output(['git', '-C', str(repo_root), 'ls-tree', '-z',
                                                 oracle['pins'][row['repo']], '--', row['source_path']])
                need(entry.startswith(b'120000 blob ') and entry.count(b'\0') == 1,
                     role + ' excluded Git link mode drift')
                link_bytes = os.fsencode(os.readlink(source_file))
                git_bytes = subprocess.check_output(['git', '-C', str(repo_root), 'show',
                                                     oracle['pins'][row['repo']] + ':' + row['source_path']])
                need(link_bytes == git_bytes and hashlib.sha256(link_bytes).hexdigest() == row['sha256'],
                     role + ' excluded link bytes drift')
            else:
                need(_safe_file(source_file, set(), repo_root)['sha256'] == row['sha256'],
                     role + ' excluded source drift: ' + row['source_path'])
        result[role] = {'checkout': identity, 'scan_sources': scan_pins,
                        'stage_files': [row['proposed_installed_path'] for row in oracle['selected']]}
    base = receipt['base']
    need(_git(source, 'rev-parse', base['commit'] + '^{commit}') == base['commit'] and
         _git(source, 'rev-parse', base['commit'] + '^{tree}') == base['tree'], 'base Git identity drift')
    result['base'] = base
    return result


def precheck(temp: Path, run_id: str, *, graph_ready: bool) -> None:
    need(temp.is_absolute() and run_id and all(c.isdigit() or c == '-' for c in run_id), 'invalid run paths')
    inputs, run = temp / ('event-input-' + run_id), temp / ('r3-event-' + run_id)
    need(temp.is_dir() and not temp.is_symlink(), 'unsafe attempt parent')
    for name in ('event-source-' + run_id, 'event-control-' + run_id):
        checkout = temp / name
        need(checkout.is_dir() and not checkout.is_symlink() and
             (checkout / '.git').is_dir() and not (checkout / '.git').is_symlink(),
             'unsafe event/control checkout root')
    _root_entries(run, {'preflight.json', 'receipt.json', 'commands.json'},
                  {'home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db', 'out',
                   'commands', 'cli', 'bundle', 'event-corpus', 'control-corpus'})
    _root_entries(run / 'event-corpus', {'preflight.json', 'receipt.json', 'commands.json'},
                  {'home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db', 'out', 'commands', 'bundle'})
    _root_entries(run / 'control-corpus', {'preflight.json', 'receipt.json', 'commands.json', 'control-assertion.json'},
                  {'home', 'tmp', 'cache', 'downloads', 'sources', 'stage', 'db', 'out', 'commands', 'bundle'})
    _root_entries(run / 'out', set(), {'openvpn-parent', 'openvpn-fixed'})
    _inventory(inputs, INPUT_FILES if graph_ready else INPUT_FILES - {'consumer-graph.json'}, set())
    for scan, root_files in ((run / 'event-corpus', {'preflight.json', 'receipt.json', 'commands.json'}),
                             (run / 'control-corpus', {'preflight.json', 'receipt.json', 'commands.json', 'control-assertion.json'})):
        for name in root_files:
            _safe_file(scan / name, set())
        _inventory(scan / 'out', SCAN_OUT, set())
        _inventory(scan / 'commands', {name.removeprefix('commands/') for name in _command_files(scan)}, set())
        _stage_precheck(scan / 'stage')
    for name in ('preflight.json', 'receipt.json', 'commands.json'):
        _safe_file(run / name, set())
    _inventory(run / 'commands', {name.removeprefix('commands/') for name in _command_files(run)}, set())
    for case in ('openvpn-parent', 'openvpn-fixed'):
        _inventory(run / 'out' / case, R3_OUT, set())
    _safe_file(ROOT / 'docs/r3-release-lock.json', set())


def freeze(temp: Path, run_id: str) -> dict:
    precheck(temp, run_id, graph_ready=True)
    inputs, run = temp / ('event-input-' + run_id), temp / ('r3-event-' + run_id)
    source, control = temp / ('event-source-' + run_id), temp / ('event-control-' + run_id)
    seen: set[tuple[int, int]] = set()
    graph = json.loads((inputs / 'consumer-graph.json').read_text())
    need(graph.get('schema') == 'incoming-consumer-graph-workflow-v1' and graph.get('status') == 'checked',
         'consumer graph did not pass')
    consumer_sha = _git(ROOT, 'rev-parse', 'HEAD')
    need(consumer_sha == os.environ['GITHUB_SHA'] and graph.get('run_id') == run_id and
         graph.get('consumer_sha') == consumer_sha and
         not _git(ROOT, 'status', '--porcelain=v1'), 'trusted consumer checkout or graph drift')
    identities = _source_recheck(source, control, inputs, run)
    for role, scan in (('event', run / 'event-corpus'), ('control', run / 'control-corpus')):
        _safe_file(scan / 'commands.json', set())
        _inventory(scan / 'out', SCAN_OUT, set())
        _inventory(scan / 'commands', {name.removeprefix('commands/') for name in _command_files(scan)}, set())
        _inventory(scan / 'stage', set(identities[role]['stage_files']), set())
    _safe_file(run / 'commands.json', set())
    _inventory(run / 'commands', {name.removeprefix('commands/') for name in _command_files(run)}, set())
    for case in ('openvpn-parent', 'openvpn-fixed'):
        _inventory(run / 'out' / case, R3_OUT, set())
    # Re-run the graph check after source verification into an exclusive
    # attempt-owned report, leaving the first report unchanged.
    recheck_path = temp / ('issuer-freeze-' + run_id) / 'graph-recheck.json'
    issuer_workflow_graph.run(temp, run_id, 'success', 'success', recheck_path)
    recheck = json.loads(recheck_path.read_text())
    need(recheck.get('status') == 'checked' and recheck.get('run_id') == run_id and
         recheck.get('consumer_sha') == consumer_sha, 'graph recheck drift')
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
        records[role]['stage'] = _inventory(scan / 'stage', set(identities[role]['stage_files']), seen)
    r3 = {'preflight.json', 'receipt.json', 'commands.json'}
    records['r3'] = {'root': {name: _safe_file(run / name, seen) for name in sorted(r3)},
                     'commands': _inventory(run / 'commands', {name.removeprefix('commands/') for name in _command_files(run)}, seen)}
    for case in ('openvpn-parent', 'openvpn-fixed'):
        records['r3'][case] = _inventory(run / 'out' / case, R3_OUT, seen)
    lock_path = ROOT / 'docs/r3-release-lock.json'
    lock = _safe_file(lock_path, seen)
    preflight = json.loads((run / 'preflight.json').read_text())
    need(preflight.get('lock_sha256') == lock['sha256'] and preflight.get('consumer_sha') == consumer_sha,
         'R3 lock or consumer pin drift')
    return {'schema': 'incoming-artifact-freeze-v1', 'status': 'frozen', 'run_id': run_id,
            'consumer_commit': consumer_sha, 'source_identities': identities,
            'release_lock': lock, 'graph_recheck': _safe_file(recheck_path, seen), 'artifacts': records,
            'limitations': ['Non-issuing same-job inventory; no queue or signer.']}


def snapshot(temp: Path, run_id: str, inventory: dict) -> None:
    """Copy the inventoried bytes to a separate read-only attempt directory."""
    inputs, run = temp / ('event-input-' + run_id), temp / ('r3-event-' + run_id)
    output_root = temp / ('issuer-freeze-' + run_id)
    need(output_root.is_dir() and not output_root.is_symlink(), 'unsafe freeze output root')
    destination = output_root / 'snapshot'
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
                with _open_regular(source, root) as (reader, opened), target.open('xb') as writer:
                    need(opened.st_size == metadata['bytes'],
                         'artifact size changed before freeze copy: ' + str(source))
                    digest = hashlib.sha256()
                    size = 0
                    while block := reader.read(1024 * 1024):
                        writer.write(block)
                        digest.update(block)
                        size += len(block)
                    need(size == metadata['bytes'] and digest.hexdigest() == metadata['sha256'],
                         'artifact changed during freeze copy: ' + str(source))
                    writer.flush()
                    os.fchmod(writer.fileno(), 0o444)
    lock_source = ROOT / 'docs/r3-release-lock.json'
    lock_target = destination / 'release-lock.json'
    with _open_regular(lock_source, ROOT) as (reader, opened), lock_target.open('xb') as writer:
        need(opened.st_size == inventory['release_lock']['bytes'],
             'release lock size changed before freeze copy')
        digest = hashlib.sha256()
        size = 0
        while block := reader.read(1024 * 1024):
            writer.write(block)
            digest.update(block)
            size += len(block)
        need(size == inventory['release_lock']['bytes'] and
             digest.hexdigest() == inventory['release_lock']['sha256'],
             'release lock changed during freeze copy')
        writer.flush()
        os.fchmod(writer.fileno(), 0o444)


def create_output_root(temp: Path, run_id: str) -> Path:
    need(temp.is_absolute() and temp.is_dir() and not temp.is_symlink(), 'unsafe attempt parent')
    need(run_id and all(c.isdigit() or c == '-' for c in run_id), 'invalid run identity')
    output_root = temp / ('issuer-freeze-' + run_id)
    output_root.mkdir(mode=0o700)
    need(not output_root.is_symlink(), 'unsafe freeze output root')
    return output_root


if __name__ == '__main__':
    temp = Path(os.environ['RUNNER_TEMP'])
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    if sys.argv[1:] == ['--precheck']:
        precheck(temp, run_id, graph_ready=False)
        raise SystemExit(0)
    output_root = create_output_root(temp, run_id)
    output = output_root / 'inventory.json'
    try:
        inventory = freeze(temp, run_id)
        snapshot(temp, run_id, inventory)
        write_json(output, inventory)
    except Exception as exc:
        write_json(output, {'schema': 'incoming-artifact-freeze-v1', 'status': 'failed', 'error': repr(exc)})
        raise
