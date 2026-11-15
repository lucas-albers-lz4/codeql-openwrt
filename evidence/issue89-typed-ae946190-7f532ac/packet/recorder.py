#!/usr/bin/python3
"""Boundary receipt primitive. A receipt records subprocess observations, not attestation."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from comparator import load, same

class StageError(RuntimeError):
    pass

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''): h.update(chunk)
    return h.hexdigest()

def inventory(path):
    """Exact regular file/directory path set, bytes, executable modes; no symlinks."""
    root = Path(path)
    def entry(p):
        s = p.lstat()
        mode = stat.S_IMODE(s.st_mode)
        if stat.S_ISREG(s.st_mode): return {'type':'file','size':s.st_size,'mode':mode,'sha256':sha(p)}
        if stat.S_ISDIR(s.st_mode): return {'type':'directory','mode':mode}
        raise ValueError('unsupported input type: '+str(p))
    result = {'.': entry(root)}
    if result['.']['type'] == 'directory':
        for p in sorted(root.rglob('*')): result[p.relative_to(root).as_posix()] = entry(p)
    return result

def verify_approval(packet, manifest, manifest_sha256, ack, ack_sha256):
    """Caller supplies both digest pins externally; files are outside packet."""
    packet = Path(packet).resolve(strict=True)
    manifest = Path(manifest).resolve(strict=True)
    ack = Path(ack).resolve(strict=True)
    if packet in manifest.parents or packet in ack.parents: raise ValueError('manifest and ack must be external to packet')
    if manifest == ack: raise ValueError('manifest and ack must differ')
    if sha(manifest) != manifest_sha256 or sha(ack) != ack_sha256: raise ValueError('approval digest mismatch')
    expected = load(manifest)
    approval = load(ack)
    if not same(approval, {'approved_manifest_sha256':manifest_sha256,'decision':'approve'}): raise ValueError('ack does not approve manifest')
    actual = inventory(packet)
    if actual.pop('.') is None: raise ValueError('invalid packet')
    if not same(actual, expected): raise ValueError('packet path set or bytes differ')

def run_stage(name, command, logs):
    """Run exactly once; inputs immutable during the child, outputs must be created."""
    if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in name): raise ValueError('invalid stage name')
    argv, cwd, env = command['argv'], command['cwd'], command['env']
    if not argv or not all(type(x) is str and x for x in argv) or not os.path.isabs(argv[0]): raise ValueError('absolute argv required')
    if not os.path.isabs(cwd) or not all(type(k) is str and type(v) is str for k,v in env.items()): raise ValueError('invalid cwd/environment')
    inputs, outputs = command['inputs'], command['outputs']
    mutables = command.get('mutables', [])
    artifact = command.get('stdout_artifact')
    before = {p: inventory(p) for p in inputs}
    mutable_before = {p: inventory(p) for p in mutables}
    for p in outputs + ([artifact] if artifact else []):
        if os.path.lexists(p): raise FileExistsError('output exists: '+p)
    logs = Path(logs)
    # Open all three exclusively before launch; an existing attempt never gets overwritten.
    with (logs/(name+'.receipt.json')).open('x', encoding='utf8') as receipt, (logs/(name+'.stdout')).open('xb') as out, (logs/(name+'.stderr')).open('xb') as err:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tick = time.monotonic_ns()
        code = None; launch_error = None
        try:
            code = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, check=False).returncode
        except Exception as e:
            launch_error = repr(e)
        finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
        elapsed = time.monotonic_ns() - tick
        out.flush(); err.flush()
        after = {}; produced = {}; errors = []
        for p in inputs:
            try: after[p] = inventory(p)
            except (OSError, ValueError) as e: errors.append('input '+p+': '+str(e))
        mutable_after = {}
        for p in mutables:
            try: mutable_after[p] = inventory(p)
            except (OSError, ValueError) as e: errors.append('mutable '+p+': '+str(e))
        for p in outputs:
            try: produced[p] = inventory(p)
            except (OSError, ValueError) as e: errors.append('output '+p+': '+str(e))
        if artifact is not None:
            try:
                with open(artifact, 'xb') as f: f.write((logs/(name+'.stdout')).read_bytes())
                produced[artifact] = inventory(artifact)
            except OSError as e: errors.append('stdout artifact '+artifact+': '+str(e))
        record = {'stage':name,'argv':argv,'cwd':cwd,'environment':env,'started_utc':started,'finished_utc':finished,'elapsed_ns':elapsed,'exit_code':code,'launch_error':launch_error,'inputs_before':before,'inputs_after':after,'mutables_before':mutable_before,'mutables_after':mutable_after,'outputs':produced,'stdout_sha256':sha(logs/(name+'.stdout')),'stderr_sha256':sha(logs/(name+'.stderr')),'boundary_errors':errors}
        json.dump(record, receipt, sort_keys=True, indent=2); receipt.write('\n'); receipt.flush(); os.fsync(receipt.fileno())
    if code != 0 or errors or before != after:
        raise StageError('stage failed or boundary changed: '+name)
    return record
