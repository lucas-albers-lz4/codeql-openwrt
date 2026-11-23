"""Synthetic-only in-memory multi-primary experiment.

This module is deliberately not a production adapter. Inputs are caller-selected
synthetic assumptions; results establish no real policy or runtime behavior.
There is no persistence or serialization interface.
"""

from .v2_resolver import ResolutionError, resolve


def _structural_observation(observation, selected_identity):
    if (not isinstance(observation, dict)
            or set(observation) != {'kind', 'version', 'identity'}
            or observation['kind'] != 'synthetic-observation'
            or type(observation['version']) is not int or observation['version'] != 1
            or not isinstance(observation['identity'], dict)
            or set(observation['identity']) != {'id', 'source', 'start', 'end'}
            or any(not isinstance(observation['identity'][k], str)
                   or not observation['identity'][k].strip()
                   for k in ('id', 'source'))
            or type(observation['identity']['start']) is not int
            or type(observation['identity']['end']) is not int
            or observation['identity']['start'] < 0
            or observation['identity']['end'] < observation['identity']['start']):
        raise ResolutionError('invalid shared observation')
    if (not isinstance(selected_identity, dict)
            or selected_identity != observation['identity']):
        raise ResolutionError('shared observation selection mismatch')


def _binding(key, observation_identity, scope, context, pairs):
    # Bind the complete independently selected question, including role-labeled
    # packages and every context input, to each evidence record.
    return {'claim_key': key, 'observation': observation_identity,
            'scope': scope, 'context': context, 'pairs': pairs}


def _validate_context(context):
    if (not isinstance(context, dict)
            or set(context) != {'corpus', 'profile', 'policy', 'inputs'}
            or any(not isinstance(context[k], str) or not context[k].strip()
                   for k in ('corpus', 'profile', 'policy'))
            or not isinstance(context['inputs'], dict) or not context['inputs']
            or any(not isinstance(k, str) or not k.strip()
                   or not isinstance(v, str) or not v.strip()
                   for k, v in context['inputs'].items())):
        raise ResolutionError('invalid selected context')


def _assess_claim(claim, selection, observation_id):
    required = {'key', 'family', 'scope', 'context', 'pairs', 'authorities',
                'gate', 'effect', 'supplementary'}
    optional = {'reference', 'verdict'}
    if (not isinstance(claim, dict) or not required <= set(claim)
            or set(claim) - required - optional
            or (('reference' in claim) != ('verdict' in claim))):
        raise ResolutionError('invalid claim shape')
    key = claim['key']
    if not isinstance(key, str) or not key.strip() or key != key.strip():
        raise ResolutionError('invalid claim key')
    if claim['family'] != 'synthetic_access':
        raise ResolutionError('unsupported family')
    selected_fields = {'key', 'family', 'scope', 'context', 'pairs', 'authorities',
                       'reference', 'verdict', 'gate', 'effect'}
    if (not isinstance(selection, dict) or set(selection) != selected_fields
            or any(claim.get(k) != selection[k] for k in
                   selected_fields - {'reference', 'verdict'})):
        raise ResolutionError('claim differs from independent selection')
    if (selection['reference'] is None) != (selection['verdict'] is None):
        raise ResolutionError('selected reference and verdict required together')
    asserted = 'reference' in claim
    if asserted and (claim['reference'] != selection['reference']
                     or claim['verdict'] != selection['verdict']):
        raise ResolutionError('claim differs from independently selected reference')
    scope, context, pairs = selection['scope'], selection['context'], selection['pairs']
    _validate_context(context)
    if (not isinstance(scope, dict)
            or set(scope) != {'caller', 'profile', 'ingress', 'entrypoint', 'packages'}
            or not isinstance(scope.get('packages'), dict)
            or set(scope['packages']) != {'caller', 'provider'}):
        raise ResolutionError('invalid caller/provider roles')
    if context['profile'] != scope['profile']:
        raise ResolutionError('scope/context profile mismatch')
    # Validate the independently selected candidate reference even when this
    # claim elects to leave its judgment unassessed.
    if selection['reference'] is not None:
        resolve(scope=scope, pairs=pairs, authorities=selection['authorities'],
                reference=selection['reference'], verdict=selection['verdict'])
    policy = resolve(scope=scope, pairs=pairs, authorities=selection['authorities'],
                     reference=claim.get('reference') if asserted else None,
                     verdict=claim.get('verdict') if asserted else None)
    binding = _binding(key, observation_id, scope, context, pairs)
    gate_record, effect_record = selection['gate'], selection['effect']
    gate_ok = (isinstance(gate_record, dict)
               and set(gate_record) == set(binding) | {'allowed'}
               and all(gate_record.get(k) == v for k, v in binding.items())
               and gate_record.get('allowed') is True)
    effect_ok = (isinstance(effect_record, dict)
                 and set(effect_record) == set(binding) | {'available'}
                 and all(effect_record.get(k) == v for k, v in binding.items())
                 and effect_record.get('available') is True)
    # Supplementary evidence is recorded as an input only. It never completes
    # either the primary gate or the provider effect obligation.
    if gate_ok and effect_ok:
        state = 'assessed' if policy['status'] == 'matched' else (
            'conflict' if policy['status'] == 'conflict' else 'allow_unassessed')
    else:
        state = 'unknown'
    return {'key': key, 'state': state, 'gate': 'allow' if gate_ok else 'unknown',
            'effect': 'available' if effect_ok else 'unknown', 'policy': policy['status']}


def assess(observation, selections, claims, *, selected_observation):
    """Return one in-memory result for each independently selected claim.

    Duplicate claim keys and malformed shared identity reject the request.
    Expected contract failures are isolated to their claim. Unexpected Python
    exceptions intentionally propagate as implementation failures.
    """
    _structural_observation(observation, selected_observation)
    if not isinstance(selections, list) or not isinstance(claims, list):
        raise ResolutionError('selections and claims must be lists')

    def keyed(rows, label):
        result = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('key'), str) or not row['key'].strip():
                raise ResolutionError(f'{label} key unavailable')
            if row['key'] in result:
                raise ResolutionError(f'duplicate {label} key')
            result[row['key']] = row
        return result

    selected_by_key = keyed(selections, 'selection')
    claims_by_key = keyed(claims, 'claim')
    def freeze(value):
        if isinstance(value, dict):
            return tuple(sorted((k, freeze(v)) for k, v in value.items()))
        if isinstance(value, list):
            items = [freeze(v) for v in value]
            return tuple(sorted(items, key=repr))
        return value

    observation_id = selected_observation
    results = []
    semantic = []
    # Process claims by their unique keys. A missing independently selected
    # input is local to that claim; a malformed B cannot suppress valid A.
    for claim in claims:
        selection = selected_by_key.get(claim['key'])
        if selection is None:
            results.append({'key': claim['key'], 'state': 'contract_error',
                            'gate': 'unknown', 'effect': 'unknown',
                            'error': 'missing independent selection'})
            continue
        try:
            results.append(_assess_claim(claim, selection, observation_id))
            semantic.append(freeze({k: selection.get(k) for k in
                                    ('family', 'scope', 'context', 'pairs')}))
        except ResolutionError as exc:
            results.append({'key': claim['key'], 'state': 'contract_error',
                            'gate': 'unknown', 'effect': 'unknown',
                            'error': str(exc)})
    for key in selected_by_key.keys() - claims_by_key.keys():
        results.append({'key': key, 'state': 'contract_error', 'gate': 'unknown',
                        'effect': 'unknown', 'error': 'missing claim envelope'})
    if len(set(semantic)) != len(semantic):
        raise ResolutionError('duplicate semantic primary claim')
    return results
