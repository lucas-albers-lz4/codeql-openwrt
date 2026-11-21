#!/usr/bin/env python3
"""Bounded experimental glob witness search; failure is never disjointness."""
import itertools
import json
import subprocess
import sys

# Deliberately tiny, deterministic grammar and candidate alphabet.
SUBSTITUTIONS = ('eth0', '', 'mtu', 'eth0/mtu')

def expand(pattern):
    atoms = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == '*':
            atoms.append(SUBSTITUTIONS)
        elif c == '[':
            end = pattern.find(']', i + 1)
            chars = pattern[i + 1:end] if end != -1 else ''
            if not chars or any(ch in chars for ch in '!^-[' + chr(92)):
                raise ValueError('unsupported bracket expression')
            atoms.append(tuple(chars))
            i = end
        elif c in '?\\]':
            raise ValueError('unsupported pattern form')
        else:
            atoms.append((c,))
        i += 1
    return (''.join(parts) for parts in itertools.product(*atoms))

def search(provenance_a, pattern_a, provenance_b, pattern_b, checker, budget=256):
    # Full source identity is required; ubus_function also requires an object.
    required = {'group', 'verb', 'scope', 'ubus_object'}
    def valid(p):
        return (isinstance(p, dict) and set(p) == required and
                all(isinstance(p[k], str) and p[k] for k in ('group', 'verb', 'scope')) and
                p['verb'] in {'read', 'write'} and
                p['scope'] in {'file', 'ubus_object', 'ubus_function'} and
                ((p['scope'] == 'ubus_function' and isinstance(p['ubus_object'], str) and p['ubus_object']) or
                 (p['scope'] != 'ubus_function' and p['ubus_object'] is None)))
    if not valid(provenance_a) or not valid(provenance_b) or provenance_a != provenance_b:
        return {'status': 'scope_mismatch', 'checked': 0}
    if budget < 1:
        return {'status': 'inconclusive', 'reason': 'budget', 'checked': 0}
    try:
        # Grammar validation happens before either returned iterator is consumed.
        expand(pattern_b)
        candidates = expand(pattern_a)
    except ValueError as exc:
        return {'status': 'inconclusive', 'reason': str(exc), 'checked': 0}
    checked = 0
    for candidate in candidates:
        if checked == budget:
            return {'status': 'inconclusive', 'reason': 'budget', 'checked': checked}
        checked += 1
        result = subprocess.run([checker, pattern_a, pattern_b, candidate], capture_output=True, text=True)
        if result.returncode == 0:
            return {'status': 'witness', 'value': candidate, 'checked': checked}
        if result.returncode != 1:
            raise RuntimeError('libc checker failed: ' + result.stderr)
    return {'status': 'inconclusive', 'reason': 'candidates_exhausted', 'checked': checked}

if __name__ == '__main__':
    if len(sys.argv) != 6:
        sys.exit('usage: search.py CHECKER PROVENANCE_A_JSON PATTERN_A PROVENANCE_B_JSON PATTERN_B')
    try:
        provenance_a, provenance_b = json.loads(sys.argv[2]), json.loads(sys.argv[4])
    except json.JSONDecodeError:
        sys.exit('error: provenance must be valid JSON')
    print(json.dumps(search(provenance_a, sys.argv[3], provenance_b, sys.argv[5], sys.argv[1]), sort_keys=True))
