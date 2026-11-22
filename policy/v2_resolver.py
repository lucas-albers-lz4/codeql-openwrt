"""In-memory expectation resolution for the experimental read-only v2 pilot.

This module does not establish evidence, select policy authorities, or validate a
v2 artifact context. Callers must do those separately before using a result.
It intentionally has no file or network access and no persistence API.
"""


class ResolutionError(ValueError):
    """Invalid policy input or invalid submitted assessed reference."""


import re

_SCOPE = ('caller', 'profile', 'ingress', 'entrypoint', 'packages')
_PROFILE = re.compile(r'sha256:[0-9a-f]{64}\Z')
_PACKAGE = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.+-]+@sha256:[0-9a-f]{64}\Z')


def _string(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _identity(value):
    if not _string(value):
        return False
    components = re.split(r'[/@:]', value.lower())
    return not any(part in {'unknown', 'unspecified', 'none', 'placeholder'}
                   or (len(part) >= 32 and set(part) == {'0'}) for part in components)


def _scope(value):
    if not isinstance(value, dict) or set(value) != set(_SCOPE):
        raise ResolutionError('invalid scope')
    if not all(_identity(value[k]) for k in _SCOPE[:-1]) or not _PROFILE.fullmatch(value['profile']):
        raise ResolutionError('invalid scope identity')
    packages = value['packages']
    if (not isinstance(packages, dict) or not packages
            or any(not _identity(k) or not _identity(v) or not _PACKAGE.fullmatch(v)
                   for k, v in packages.items())):
        raise ResolutionError('invalid package identities')
    return value


def _pairs(value):
    if (not isinstance(value, list) or not value
            or any(not isinstance(p, dict) or set(p) != {'target', 'operation'}
                   or not _string(p['target']) or not _string(p['operation']) for p in value)):
        raise ResolutionError('invalid target/operation pairs')
    pairs = [(p['target'], p['operation']) for p in value]
    if len(set(pairs)) != len(pairs):
        raise ResolutionError('duplicate target/operation pair')
    return set(pairs)


def resolve(*, scope, pairs, authorities, reference=None, verdict=None):
    """Resolve an exact caller question against explicitly selected candidates.

    ``authorities`` maps candidate namespaces to definition lists. It is not a
    policy catalog: pass only authorities selected as candidates for this exact
    question. An explicit reviewed choice is represented by a single entry.
    Selection and approval are the caller's responsibility. Each definition contains exactly
    ``id``, ``scope`` and ``pairs``. No omitted scope field is a wildcard. The
    result is a resolution only, not a finding or proof of a modeled gate.
    This core is not a consumer boundary: adapters must bind context to scope,
    independently bind the selected registry, and establish gate evidence.
    A submitted assessment requires an explicit namespace/id and the sole
    currently supported verdict. Invalid assessed references are errors.
    """
    scope = _scope(scope)
    pairs = _pairs(pairs)
    if not isinstance(authorities, dict) or not authorities:
        raise ResolutionError('missing selected policy')
    definitions = {}
    for authority, entries in authorities.items():
        if not _string(authority) or not isinstance(entries, list):
            raise ResolutionError('invalid authority')
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {'id', 'scope', 'pairs'} or not _string(entry['id']):
                raise ResolutionError('invalid definition')
            if entry['id'] in seen:
                raise ResolutionError('duplicate definition')
            seen.add(entry['id'])
            definitions[(authority, entry['id'])] = (_scope(entry['scope']), _pairs(entry['pairs']))
    if (reference is None) != (verdict is None):
        raise ResolutionError('reference and verdict required together')
    if reference is not None:
        if (not isinstance(reference, dict) or set(reference) != {'authority', 'id'}
                or not all(_string(reference[k]) for k in ('authority', 'id'))):
            raise ResolutionError('invalid reference')
        if verdict != 'intended_access':
            raise ResolutionError('unsupported verdict')
    applicable = {key for key, (candidate_scope, candidate_pairs) in definitions.items()
                  if candidate_scope == scope and pairs <= candidate_pairs}
    if reference is not None:
        key = (reference['authority'], reference['id'])
        if key not in definitions:
            raise ResolutionError('missing reference')
        if key not in applicable:
            raise ResolutionError('inapplicable reference')
    # A candidate with no matching definition is still a selected authority.
    # Only an independently reviewed choice can reduce candidates to one.
    # Invalid submitted references are rejected before reporting conflict.
    if len(authorities) > 1:
        return {'status': 'conflict'}
    if reference is None:
        return {'status': 'unassessed'}
    return {'status': 'matched', 'verdict': verdict, 'reference': dict(reference)}


def validate_context(expected, envelope):
    """Bind a v2 envelope to a separately selected context.

    This helper is not a consumer boundary. This comparison is not verification
    of the selected inputs or evidence;
    adapters must independently validate the identities and their source bytes.
    No v1 record or producer analysis revision selects this consumer boundary.
    """
    def valid_context(value):
        if not isinstance(value, dict) or set(value) != {'corpus', 'profile', 'policy', 'inputs'}:
            return False
        if not all(_string(value[k]) for k in ('corpus', 'profile', 'policy')):
            return False
        inputs = value['inputs']
        return (isinstance(inputs, dict) and bool(inputs)
                and all(_string(k) and _string(v) for k, v in inputs.items()))

    if not valid_context(expected):
        raise ResolutionError('invalid selected context')
    if (not isinstance(envelope, dict) or set(envelope) != {'kind', 'version', 'context'}
            or envelope['kind'] != 'readonly-assessment'
            or type(envelope['version']) is not int or envelope['version'] != 2
            or not valid_context(envelope['context']) or envelope['context'] != expected):
        raise ResolutionError('v2 context mismatch')
