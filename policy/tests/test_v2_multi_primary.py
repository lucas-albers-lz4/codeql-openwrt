import copy
import unittest
from unittest.mock import patch

from policy import v2_multi_primary
from policy.v2_multi_primary import assess
from policy.v2_resolver import ResolutionError


def fixture_claim(key, caller, tag):
    scope = {'caller': caller, 'profile': 'sha256:' + tag * 64,
             'ingress': 'synthetic-ingress-' + caller,
             'entrypoint': 'synthetic.entry-' + caller,
             'packages': {'caller': f'feed/{caller}/1@sha256:{tag * 64}',
                         'provider': f'feed/provider-{caller}/1@sha256:{tag * 64}'}}
    context = {'corpus': 'synthetic-corpus-' + caller,
               'profile': scope['profile'], 'policy': 'synthetic-policy-' + caller,
               'inputs': {'fixture': 'synthetic-input-' + caller}}
    pairs = [{'target': 'synthetic:resource-' + caller, 'operation': 'read'}]
    authority = 'synthetic-authority-' + caller
    ref = {'authority': authority, 'id': 'expectation-' + caller}
    definition = {'id': ref['id'], 'scope': copy.deepcopy(scope),
                  'pairs': copy.deepcopy(pairs)}
    binding = {'claim_key': key, 'observation': copy.deepcopy(OBSERVATION['identity']),
               'scope': scope, 'context': context, 'pairs': pairs}
    return {'key': key, 'family': 'synthetic_access',
            'scope': scope, 'context': context, 'pairs': pairs,
            'authorities': {authority: [definition]}, 'reference': ref,
            'verdict': 'intended_access',
            'gate': dict(binding, allowed=True), 'effect': dict(binding, available=True),
            'supplementary': []}


OBSERVATION = {'kind': 'synthetic-observation', 'version': 1,
               'identity': {'id': 'synthetic-shared-observation', 'source': 'fixture.uc',
                            'start': 0, 'end': 1}}


class MultiPrimaryTests(unittest.TestCase):
    def setUp(self):
        self.a = fixture_claim('claim-a', 'caller-a', 'a')
        self.b = fixture_claim('claim-b', 'caller-b', 'b')

    def run_claims(self, *claims):
        selected = [self.selection(c) for c in claims]
        return assess(copy.deepcopy(OBSERVATION), selected, list(claims),
                      selected_observation=copy.deepcopy(OBSERVATION['identity']))

    @staticmethod
    def selection(claim):
        return {k: copy.deepcopy(claim[k]) for k in
                ('key', 'family', 'scope', 'context', 'pairs', 'authorities',
                 'reference', 'verdict', 'gate', 'effect')}

    def test_independent_callers_assess_separately(self):
        self.assertEqual([r['state'] for r in self.run_claims(self.a, self.b)],
                         ['assessed', 'assessed'])

    def test_allow_without_assertion_is_unassessed_and_peer_assesses(self):
        b = copy.deepcopy(self.b)
        b.update(reference=None, verdict=None)
        results = self.run_claims(self.a, b)
        self.assertEqual([r['state'] for r in results], ['assessed', 'allow_unassessed'])
        self.assertEqual(results[1]['gate'], 'allow')

    def test_caller_specific_reference_cannot_transfer(self):
        b = copy.deepcopy(self.b)
        # The same namespace contains A's local ID, but that definition is
        # scoped to A, so B's independently selected assertion is inapplicable.
        b['authorities'][self.a['reference']['authority']] = [
            copy.deepcopy(self.a['authorities'][self.a['reference']['authority']][0])]
        b['reference'] = copy.deepcopy(self.a['reference'])
        results = self.run_claims(self.a, b)
        self.assertEqual(results[0]['state'], 'assessed')
        self.assertEqual(results[1]['state'], 'contract_error')
        self.assertEqual(results[1]['error'], 'inapplicable reference')

    def test_envelope_cannot_substitute_an_unselected_same_namespace_reference(self):
        b = copy.deepcopy(self.b)
        selected = self.selection(b)
        selected['authorities'][selected['reference']['authority']].append(
            {'id': 'alternate', 'scope': copy.deepcopy(selected['scope']),
             'pairs': copy.deepcopy(selected['pairs'])})
        b['authorities'] = copy.deepcopy(selected['authorities'])
        b['reference'] = {'authority': selected['reference']['authority'], 'id': 'alternate'}
        result = assess(copy.deepcopy(OBSERVATION), [selected], [b],
                        selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
        self.assertEqual(result['state'], 'contract_error')
        self.assertEqual(result['error'], 'claim differs from independently selected reference')

    def test_unasserted_claim_stays_unassessed_with_selected_candidate_reference(self):
        b = copy.deepcopy(self.b)
        selected = self.selection(b)
        b.pop('reference')
        b.pop('verdict')
        result = assess(copy.deepcopy(OBSERVATION), [selected], [b],
                        selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
        self.assertEqual(result['state'], 'allow_unassessed')
        self.assertEqual(result['policy'], 'unassessed')

    def test_missing_gate_or_effect_stays_unknown_even_with_reference(self):
        for field in ('gate', 'effect'):
            with self.subTest(field=field):
                b = copy.deepcopy(self.b)
                b[field] = None
                result = self.run_claims(b)[0]
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['policy'], 'matched')

    def test_absent_claim_evidence_stays_unknown_when_selection_contains_positive_evidence(self):
        for field in ('gate', 'effect'):
            with self.subTest(field=field):
                b = copy.deepcopy(self.b)
                selected = self.selection(b)
                b[field] = None
                result = assess(copy.deepcopy(OBSERVATION), [selected], [b],
                                selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result[field], 'unknown')

    def test_supplementary_root_allow_does_not_supply_gate(self):
        b = copy.deepcopy(self.b)
        b['gate'] = None
        b['supplementary'] = [dict(b['effect'], allowed=True, role='supplementary-root')]
        self.assertEqual(self.run_claims(b)[0]['state'], 'unknown')
        b = copy.deepcopy(self.b)
        b['effect'] = None
        b['supplementary'] = [dict(b['gate'], available=True, role='supplementary-root')]
        self.assertEqual(self.run_claims(b)[0]['state'], 'unknown')

    def test_conflict_is_claim_local_even_without_match_in_second_authority(self):
        b = copy.deepcopy(self.b)
        b['authorities']['other-selected-authority'] = []
        results = self.run_claims(self.a, b)
        self.assertEqual([r['state'] for r in results], ['assessed', 'conflict'])

    def test_conflict_and_unknown_evidence_remain_orthogonal(self):
        b = copy.deepcopy(self.b)
        b['authorities']['other-selected-authority'] = []
        b['effect'] = None
        result = self.run_claims(b)[0]
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['policy'], 'conflict')
        self.assertEqual(result['gate'], 'allow')
        self.assertEqual(result['effect'], 'unknown')

    def test_invalid_reference_precedes_authority_conflict(self):
        b = copy.deepcopy(self.b)
        b['authorities']['other-selected-authority'] = []
        b['reference'] = {'authority': 'missing-authority', 'id': 'missing'}
        result = self.run_claims(self.a, b)[1]
        self.assertEqual(result['state'], 'contract_error')
        self.assertEqual(result['error'], 'missing reference')

    def test_each_scope_and_gate_dimension_is_bound(self):
        for field in ('scope', 'context', 'pairs'):
            with self.subTest(field=field):
                b = copy.deepcopy(self.b)
                record = b['gate']
                if field == 'context':
                    record[field] = dict(record[field], corpus='other-context')
                elif field == 'pairs':
                    record[field] = [{'target': 'other', 'operation': 'read'}]
                else:
                    record[field] = dict(record[field], caller='other-caller')
                self.assertEqual(self.run_claims(self.a, b)[1]['state'], 'unknown')

    def test_independent_selection_must_match_and_rebound_context_invalidates_old_evidence(self):
        claim = copy.deepcopy(self.b)
        selected = self.selection(claim)
        changed = copy.deepcopy(selected)
        changed['context']['inputs']['fixture'] = 'synthetic-input-b-revised'
        claim['context'] = copy.deepcopy(changed['context'])
        result = assess(copy.deepcopy(OBSERVATION), [changed], [claim],
                        selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual((result['gate'], result['effect']), ('unknown', 'unknown'))

        # Align envelope, selected scope/context/pairs, and applicable definition
        # after a provider, ingress, entrypoint, profile or operation change.
        # The old gate/effect records must still fail independently.
        for dimension in ('provider', 'ingress', 'entrypoint', 'profile', 'operation'):
            with self.subTest(dimension=dimension):
                claim = copy.deepcopy(self.b)
                selected = self.selection(claim)
                if dimension == 'provider':
                    selected['scope']['packages']['provider'] = (
                        'feed/new-provider/2@sha256:' + 'd' * 64)
                elif dimension == 'ingress':
                    selected['scope']['ingress'] = 'synthetic-ingress-revised'
                elif dimension == 'entrypoint':
                    selected['scope']['entrypoint'] = 'synthetic.entry-revised'
                elif dimension == 'profile':
                    selected['scope']['profile'] = 'sha256:' + 'd' * 64
                    selected['context']['profile'] = selected['scope']['profile']
                else:
                    selected['pairs'][0]['operation'] = 'invoke'
                for entries in selected['authorities'].values():
                    for definition in entries:
                        definition['scope'] = copy.deepcopy(selected['scope'])
                        definition['pairs'] = copy.deepcopy(selected['pairs'])
                for key in ('scope', 'context', 'pairs', 'authorities'):
                    claim[key] = copy.deepcopy(selected[key])
                result = assess(copy.deepcopy(OBSERVATION), [selected], [claim],
                                selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['policy'], 'matched')

        claim = copy.deepcopy(self.b)
        selected = self.selection(claim)
        claim['context'] = dict(claim['context'], corpus='envelope-selected-itself')
        self.assertEqual(assess(copy.deepcopy(OBSERVATION), [selected], [claim],
                                selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]['state'],
                         'contract_error')

    def test_gate_and_effect_substitution_are_individually_detected(self):
        for field in ('gate', 'effect'):
            with self.subTest(field=field):
                b = copy.deepcopy(self.b)
                b[field]['entrypoint'] = 'other-entrypoint'
                result = self.run_claims(b)[0]
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['gate'], 'unknown' if field == 'gate' else 'allow')
                self.assertEqual(result['effect'], 'unknown' if field == 'effect' else 'available')

    def test_gate_and_effect_scope_bypass_mutations_fail_independently(self):
        for field in ('gate', 'effect'):
            with self.subTest(field=field):
                b = copy.deepcopy(self.b)
                b[field]['scope'] = dict(b[field]['scope'], caller='other-caller')
                result = self.run_claims(b)[0]
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result[field], 'unknown')

    def test_each_gate_and_effect_binding_field_is_independently_checked(self):
        for record_name in ('gate', 'effect'):
            for field in ('claim_key', 'observation', 'scope', 'context', 'pairs'):
                with self.subTest(record=record_name, field=field):
                    b = copy.deepcopy(self.b)
                    record = b[record_name]
                    if field == 'claim_key':
                        record[field] = 'other-claim'
                    elif field == 'observation':
                        record[field] = dict(record[field], source='other-source')
                    elif field == 'scope':
                        record[field] = dict(record[field], caller='other-caller')
                    elif field == 'context':
                        record[field] = dict(record[field], corpus='other-corpus')
                    else:
                        record[field] = [{'target': 'other-target', 'operation': 'read'}]
                    result = self.run_claims(b)[0]
                    self.assertEqual(result['state'], 'unknown')
                    self.assertEqual(result[record_name], 'unknown')
                    self.assertEqual(result['effect' if record_name == 'gate' else 'gate'],
                                     'available' if record_name == 'gate' else 'allow')

    def test_selected_evidence_is_validated_and_envelope_must_repeat_it(self):
        b = copy.deepcopy(self.b)
        selection = self.selection(b)
        selection['gate']['allowed'] = False
        b['gate'] = copy.deepcopy(selection['gate'])
        result = assess(copy.deepcopy(OBSERVATION), [selection], [b],
                        selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['gate'], 'unknown')

        b['gate']['allowed'] = True  # Envelope-only mutation cannot override selection.
        result = assess(copy.deepcopy(OBSERVATION), [selection], [b],
                        selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
        self.assertEqual(result['state'], 'contract_error')

    def test_boolean_evidence_values_reject_integer_substitutions(self):
        for field in ('gate', 'effect'):
            with self.subTest(field=field):
                b = copy.deepcopy(self.b)
                selected = self.selection(b)
                bool_field = 'allowed' if field == 'gate' else 'available'
                selected[field][bool_field] = 1
                b[field] = copy.deepcopy(selected[field])
                result = assess(copy.deepcopy(OBSERVATION), [selected], [b],
                                selected_observation=copy.deepcopy(OBSERVATION['identity']))[0]
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result[field], 'unknown')

    def test_shared_observation_identity_is_bound_and_swap_is_structural(self):
        alternate = {'kind': 'synthetic-observation', 'version': 1,
                     'identity': {'id': 'other-observation', 'source': 'fixture.uc',
                                  'start': 2, 'end': 5}}
        with self.assertRaisesRegex(ResolutionError, 'shared observation selection mismatch'):
            assess(alternate, [self.selection(self.a)], [self.a],
                   selected_observation=copy.deepcopy(OBSERVATION['identity']))
        same_id_different_span = copy.deepcopy(OBSERVATION)
        same_id_different_span['identity']['start'] += 1
        with self.assertRaisesRegex(ResolutionError, 'shared observation selection mismatch'):
            assess(same_id_different_span, [self.selection(self.a)], [self.a],
                   selected_observation=copy.deepcopy(OBSERVATION['identity']))
        for field, invalid in (('start', False), ('end', True)):
            with self.subTest(field=field):
                selected = copy.deepcopy(OBSERVATION['identity'])
                selected[field] = invalid
                with self.assertRaisesRegex(ResolutionError, 'shared observation selection mismatch'):
                    assess(copy.deepcopy(OBSERVATION), [self.selection(self.a)], [self.a],
                           selected_observation=selected)
        malformed = copy.deepcopy(OBSERVATION)
        malformed['identity']['id'] = ''
        with self.assertRaisesRegex(ResolutionError, 'invalid shared observation'):
            assess(malformed, [self.selection(self.a)], [self.a],
                   selected_observation=copy.deepcopy(OBSERVATION['identity']))

    def test_duplicate_namespace_id_errors_but_cross_namespace_id_is_distinct(self):
        b = copy.deepcopy(self.b)
        definition = copy.deepcopy(b['authorities'][b['reference']['authority']][0])
        b['authorities'][b['reference']['authority']].append(definition)
        self.assertEqual(self.run_claims(b)[0]['state'], 'contract_error')
        b = copy.deepcopy(self.b)
        b['authorities']['another-namespace'] = [copy.deepcopy(b['authorities'][b['reference']['authority']][0])]
        self.assertEqual(self.run_claims(b)[0]['state'], 'conflict')

    def test_structural_errors_reject_request_but_claim_error_isolated(self):
        b = copy.deepcopy(self.b)
        b['reference'] = {'authority': 'missing', 'id': 'missing'}
        results = self.run_claims(self.a, b)
        self.assertEqual([r['state'] for r in results], ['assessed', 'contract_error'])
        with self.assertRaisesRegex(ResolutionError, 'duplicate claim key'):
            duplicate = dict(self.b, key=self.a['key'])
            assess(copy.deepcopy(OBSERVATION), [self.selection(self.a), self.selection(self.b)],
                   [self.a, duplicate],
                   selected_observation=copy.deepcopy(OBSERVATION['identity']))
        results = assess(copy.deepcopy(OBSERVATION), [self.selection(self.a)],
                         [self.a, self.b],
                         selected_observation=copy.deepcopy(OBSERVATION['identity']))
        self.assertEqual([r['state'] for r in results], ['assessed', 'contract_error'])
        extra = self.selection(self.b)
        extra['key'] = 'selection-with-no-claim'
        results = assess(copy.deepcopy(OBSERVATION), [extra, self.selection(self.a)],
                         [self.a],
                         selected_observation=copy.deepcopy(OBSERVATION['identity']))
        self.assertEqual([r['key'] for r in results], ['claim-a'])
        results = assess(copy.deepcopy(OBSERVATION), [self.selection(self.a), self.selection(self.b)],
                         [self.b, self.a],
                         selected_observation=copy.deepcopy(OBSERVATION['identity']))
        self.assertEqual([r['key'] for r in results], ['claim-b', 'claim-a'])
        alias = copy.deepcopy(self.a)
        alias['key'] = 'claim-a-alias'
        alias['gate']['claim_key'] = alias['key']
        alias['effect']['claim_key'] = alias['key']
        with self.assertRaisesRegex(ResolutionError, 'duplicate semantic primary claim'):
            self.run_claims(self.a, alias)
        bad_observation = copy.deepcopy(OBSERVATION)
        bad_observation['identity']['start'] = -1
        with self.assertRaisesRegex(ResolutionError, 'invalid shared observation'):
            assess(bad_observation, [self.selection(self.a), self.selection(self.b)],
                   [self.a, self.b],
                   selected_observation=copy.deepcopy(OBSERVATION['identity']))
        bool_span = copy.deepcopy(OBSERVATION)
        bool_span['identity']['start'] = False
        with self.assertRaisesRegex(ResolutionError, 'invalid shared observation'):
            assess(bool_span, [self.selection(self.a)], [self.a],
                   selected_observation=copy.deepcopy(OBSERVATION['identity']))

    def test_unsupported_verdict_and_no_reference_are_explicit(self):
        b = copy.deepcopy(self.b)
        b['verdict'] = 'authorization_violation'
        self.assertEqual(self.run_claims(b)[0]['state'], 'contract_error')
        b = copy.deepcopy(self.b)
        b.update(reference=None, verdict=None)
        self.assertEqual(self.run_claims(b)[0]['state'], 'allow_unassessed')
        b = copy.deepcopy(self.b)
        b['family'] = 'unsupported_family'
        self.assertEqual(self.run_claims(b)[0]['error'], 'unsupported family')

    def test_meaningful_cross_claim_substitution_mutation_is_detected(self):
        # Mutation model: accept an A gate record under B while ignoring caller
        # binding. The correct harness rejects this as unknown.
        b = copy.deepcopy(self.b)
        b['gate'] = copy.deepcopy(self.a['gate'])
        b['effect'] = copy.deepcopy(self.a['effect'])
        self.assertEqual(self.run_claims(self.a, b)[1]['state'], 'unknown')

    def test_unexpected_implementation_exception_is_not_a_claim_error(self):
        with patch.object(v2_multi_primary, 'resolve', side_effect=RuntimeError('bug')):
            with self.assertRaisesRegex(RuntimeError, 'bug'):
                self.run_claims(self.a)

    def test_malformed_peer_scope_is_claim_local(self):
        b = copy.deepcopy(self.b)
        b['scope']['packages'] = 1
        result = self.run_claims(self.a, b)
        self.assertEqual([r['state'] for r in result], ['assessed', 'contract_error'])

    def test_malformed_nested_selection_does_not_suppress_peer_and_nested_key_is_significant(self):
        b = copy.deepcopy(self.b)
        b['context']['inputs'][1] = 'invalid-non-string-key'
        result = self.run_claims(self.a, b)
        self.assertEqual([r['state'] for r in result], ['assessed', 'contract_error'])

        a = copy.deepcopy(self.a)
        alias = copy.deepcopy(self.a)
        alias['key'] = 'claim-a-alias'
        alias['context']['inputs']['key'] = 'different-context-key-value'
        for record in (alias['gate'], alias['effect']):
            record['claim_key'] = alias['key']
            record['context'] = copy.deepcopy(alias['context'])
        self.assertEqual([r['state'] for r in self.run_claims(a, alias)],
                         ['assessed', 'assessed'])


if __name__ == '__main__':
    unittest.main()
