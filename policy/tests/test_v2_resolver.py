import copy
import unittest

from policy.v2_resolver import ResolutionError, resolve, validate_context


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'caller': 'client', 'profile': 'sha256:' + 'a' * 64,
                      'ingress': 'fixture', 'entrypoint': 'status.read',
                      'packages': {'caller': 'feed-a/client/1@sha256:' + 'b' * 64,
                                   'provider': 'feed-a/provider/1@sha256:' + 'c' * 64}}
        self.pairs = [{'target': 'resource:status', 'operation': 'read'}]
        self.ref = {'authority': 'reviewed-fixture', 'id': 'status'}
        self.policies = {'reviewed-fixture': [{'id': 'status',
                          'scope': copy.deepcopy(self.scope), 'pairs': copy.deepcopy(self.pairs)}]}

    def run_resolver(self, **changes):
        args = dict(scope=self.scope, pairs=self.pairs, authorities=self.policies,
                    reference=self.ref, verdict='intended_access')
        args.update(changes)
        return resolve(**args)

    def test_explicit_context_and_no_downgrade(self):
        context = {'corpus': 'corpus:abc', 'profile': 'profile:abc',
                   'policy': 'policy:abc', 'inputs': {'provider': 'feed:source'}}
        envelope = {'kind': 'readonly-assessment', 'version': 2, 'context': copy.deepcopy(context)}
        validate_context(context, envelope)
        for version in (None, True, 1, 3, '2', 2.0):
            bad = copy.deepcopy(envelope)
            bad['version'] = version
            with self.subTest(version=version), self.assertRaisesRegex(ResolutionError, 'v2 context mismatch'):
                validate_context(context, bad)
        for key in ('corpus', 'profile', 'policy'):
            bad = copy.deepcopy(envelope)
            bad['context'][key] += '-other'
            with self.subTest(key=key), self.assertRaisesRegex(ResolutionError, 'v2 context mismatch'):
                validate_context(context, bad)
        with self.assertRaisesRegex(ResolutionError, 'invalid selected context'):
            validate_context({}, envelope)
        with self.assertRaisesRegex(ResolutionError, 'v2 context mismatch'):
            validate_context(context, {'analysis_revision': 'step3:setblock-typed-v1'})

    def test_assessed_and_unassessed(self):
        self.assertEqual(self.run_resolver()['status'], 'matched')
        self.assertEqual(self.run_resolver(reference=None, verdict=None)['status'], 'unassessed')
        self.assertEqual(self.run_resolver(authorities={'empty': []}, reference=None, verdict=None)['status'], 'unassessed')

    def test_exact_scope_and_operation(self):
        for field in ('caller', 'profile', 'ingress', 'entrypoint'):
            with self.subTest(field=field):
                scope = copy.deepcopy(self.scope)
                scope[field] = ('sha256:' + 'e' * 64) if field == 'profile' else scope[field] + '-other'
                with self.assertRaisesRegex(ResolutionError, 'inapplicable'):
                    self.run_resolver(scope=scope)
        scope = copy.deepcopy(self.scope)
        scope['packages']['provider'] = 'feed-b/provider/1@sha256:' + 'c' * 64
        with self.assertRaisesRegex(ResolutionError, 'inapplicable'):
            self.run_resolver(scope=scope)
        for pairs in ([{'target': 'resource:other', 'operation': 'read'}],
                      [{'target': 'resource:status', 'operation': 'write'}],
                      self.pairs + [{'target': 'resource:status', 'operation': 'write'}]):
            with self.assertRaisesRegex(ResolutionError, 'inapplicable'):
                self.run_resolver(pairs=pairs)

    def test_duplicates_before_applicability_and_authority_conflict(self):
        policies = copy.deepcopy(self.policies)
        other = copy.deepcopy(policies['reviewed-fixture'][0])
        other['scope']['caller'] = 'other'
        policies['reviewed-fixture'].append(other)
        with self.assertRaisesRegex(ResolutionError, 'duplicate definition'):
            self.run_resolver(authorities=policies)
        policies = copy.deepcopy(self.policies)
        policies['other-authority'] = copy.deepcopy(policies['reviewed-fixture'])
        self.assertEqual(self.run_resolver(authorities=policies), {'status': 'conflict'})
        self.assertEqual(self.run_resolver()['status'], 'matched')

    def test_multi_target_pairs_are_not_cartesian(self):
        policies = copy.deepcopy(self.policies)
        policies['reviewed-fixture'][0]['pairs'].append({'target': 'resource:other', 'operation': 'write'})
        self.assertEqual(self.run_resolver(authorities=policies, pairs=[
            {'target': 'resource:status', 'operation': 'read'},
            {'target': 'resource:other', 'operation': 'write'}])['status'], 'matched')
        with self.assertRaisesRegex(ResolutionError, 'inapplicable'):
            self.run_resolver(authorities=policies, pairs=[{'target': 'resource:other', 'operation': 'read'}])
        with self.assertRaisesRegex(ResolutionError, 'duplicate target/operation'):
            self.run_resolver(pairs=self.pairs + copy.deepcopy(self.pairs))

    def test_reference_pairing_and_namespace(self):
        for changes in ({'reference': None}, {'verdict': None}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ResolutionError, 'required together'):
                self.run_resolver(**changes)
        with self.assertRaisesRegex(ResolutionError, 'missing reference'):
            self.run_resolver(reference={'authority': 'wrong', 'id': 'status'})

    def test_context_input_key_and_value_are_bound(self):
        context = {'corpus': 'corpus:abc', 'profile': 'profile:abc',
                   'policy': 'policy:abc', 'inputs': {'provider': 'feed:source'}}
        for inputs in ({'other': 'feed:source'}, {'provider': 'feed:other'}):
            envelope = {'kind': 'readonly-assessment', 'version': 2,
                        'context': dict(context, inputs=inputs)}
            with self.subTest(inputs=inputs), self.assertRaisesRegex(ResolutionError, 'v2 context mismatch'):
                validate_context(context, envelope)

    def test_selected_candidates_conflict_even_if_empty_or_partial(self):
        for candidate in ([], [{'id': 'partial', 'scope': copy.deepcopy(self.scope),
                                'pairs': [{'target': 'resource:status', 'operation': 'write'}]}]):
            with self.subTest(candidate=candidate):
                policies = copy.deepcopy(self.policies)
                policies['second'] = candidate
                self.assertEqual(self.run_resolver(authorities=policies), {'status': 'conflict'})
                self.assertEqual(self.run_resolver(authorities=policies, reference=None, verdict=None),
                                 {'status': 'conflict'})
                # A catalog may contain other entries, but only the explicitly
                # chosen candidate is supplied to the resolver.
                self.assertEqual(self.run_resolver(authorities={'reviewed-fixture': policies['reviewed-fixture']})['status'], 'matched')
        self.assertEqual(self.run_resolver(authorities={'empty': []}, reference=None, verdict=None)['status'], 'unassessed')

    def test_invalid_assessed_reference_precedes_conflict(self):
        policies = copy.deepcopy(self.policies)
        policies['second'] = []
        with self.assertRaisesRegex(ResolutionError, 'missing reference'):
            self.run_resolver(authorities=policies, reference={'authority': 'second', 'id': 'missing'})
        policies['second'] = [{'id': 'status', 'scope': copy.deepcopy(self.scope),
                               'pairs': [{'target': 'resource:status', 'operation': 'write'}]}]
        with self.assertRaisesRegex(ResolutionError, 'inapplicable reference'):
            self.run_resolver(authorities=policies, reference={'authority': 'second', 'id': 'status'})
        self.assertEqual(self.run_resolver(authorities=policies), {'status': 'conflict'})
        # Local IDs may repeat across namespaces; an explicit choice selects one.
        policies['second'][0]['pairs'] = copy.deepcopy(self.pairs)
        self.assertEqual(self.run_resolver(authorities=policies), {'status': 'conflict'})
        self.assertEqual(self.run_resolver(authorities={'second': policies['second']},
                         reference={'authority': 'second', 'id': 'status'})['status'], 'matched')

    def test_invalid_reference_and_missing_scope(self):
        with self.assertRaisesRegex(ResolutionError, 'missing reference'):
            self.run_resolver(reference={'authority': 'reviewed-fixture', 'id': 'missing'})
        with self.assertRaisesRegex(ResolutionError, 'unsupported verdict'):
            self.run_resolver(verdict='authorization_violation')
        with self.assertRaisesRegex(ResolutionError, 'missing selected policy'):
            self.run_resolver(authorities={})
        scope = copy.deepcopy(self.scope)
        del scope['entrypoint']
        with self.assertRaisesRegex(ResolutionError, 'invalid scope'):
            self.run_resolver(scope=scope)
        scope = copy.deepcopy(self.scope)
        scope['packages']['provider'] = ''
        with self.assertRaisesRegex(ResolutionError, 'invalid package identities'):
            self.run_resolver(scope=scope)


if __name__ == '__main__':
    unittest.main()
