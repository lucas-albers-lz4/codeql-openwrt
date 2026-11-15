#!/usr/bin/python3
"""Trusted, independently reviewed bootstrap; invoke only with python -I -S -B.

This bootstrap is a trust anchor, not authenticated by the packet it loads.
It compiles captured source bytes only after validating their manifest hashes.
"""
import sys
if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    raise SystemExit('bootstrap requires python -I -S -B')

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types


def pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def load(raw):
    def bad(value): raise ValueError('non-JSON number: ' + value)
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=bad)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('packet', 'manifest', 'manifest-sha256', 'ack', 'ack-sha256'):
        parser.add_argument('--'+arg, required=True)
    a = parser.parse_args()
    packet = Path(a.packet).resolve(strict=True)
    manifest = Path(a.manifest).resolve(strict=True)
    ack = Path(a.ack).resolve(strict=True)
    if packet in manifest.parents or packet in ack.parents or manifest == ack:
        raise ValueError('manifest and ack must be distinct and external to packet')
    raw_manifest, raw_ack = manifest.read_bytes(), ack.read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != a.manifest_sha256 or hashlib.sha256(raw_ack).hexdigest() != a.ack_sha256:
        raise ValueError('approval digest mismatch')
    expected, approval = load(raw_manifest), load(raw_ack)
    if type(approval) is not dict or approval != {'approved_manifest_sha256':a.manifest_sha256, 'decision':'approve'}:
        raise ValueError('ack does not approve manifest')
    snapshots = {}
    for name in ('comparator', 'recorder', 'orchestrator'):
        path = packet/(name+'.py')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode): raise ValueError('runner source is not a regular file')
        data = path.read_bytes()
        entry = {'type':'file','size':len(data),'mode':stat.S_IMODE(info.st_mode),'sha256':hashlib.sha256(data).hexdigest()}
        target = expected.get(name+'.py') if type(expected) is dict else None
        if type(target) is not dict or set(target) != set(entry) or any(type(target[k]) is not type(v) or target[k] != v for k,v in entry.items()):
            raise ValueError('runner source differs from approved manifest: '+name)
        snapshots[name] = (path, data)
    # Never use Python's source/bytecode import machinery for runner modules.
    for name in ('comparator', 'recorder', 'orchestrator'):
        path, data = snapshots[name]
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(data, str(path), 'exec', dont_inherit=True), module.__dict__)
    sys.modules['orchestrator'].run(packet, manifest, a.manifest_sha256, ack, a.ack_sha256)


if __name__ == '__main__': main()
