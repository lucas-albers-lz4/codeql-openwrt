"""Offline controls for the independent bounded live-handoff checker."""
import json
import csv
import hashlib
import io
import copy
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ObservationTests(unittest.TestCase):
    def test_independent_oracle_accepts_pinned_table(self):
        from policy.setblock_handoff import validate_csv_scope
        oracle = json.loads((ROOT / 'policy/fixtures/setblock-handoff-v1.json').read_bytes())
        data = (ROOT / 'policy/fixtures/setblock-observation.csv').read_bytes()
        self.assertEqual(validate_csv_scope(data, oracle, oracle['rows']), oracle['rows'])

    def test_coherent_omission_substitution_and_duplicates(self):
        from policy.setblock_handoff import HandoffError, validate_csv_scope
        oracle = json.loads((ROOT / 'policy/fixtures/setblock-handoff-v1.json').read_bytes())
        for rows, code in [([], 'scoped_observation_missing'),
                           ([['wrong'] * 9], 'scoped_observation_mismatch'),
                           (oracle['rows'] * 2, 'duplicate_observation')]:
            with self.subTest(code=code):
                stream = io.StringIO(newline='')
                writer = csv.writer(stream)
                writer.writerow(oracle['header'])
                writer.writerows(rows)
                with self.assertRaisesRegex(HandoffError, code):
                    validate_csv_scope(stream.getvalue().encode(), oracle, rows)

    def test_oracle_agrees_with_adapter_constants(self):
        from policy import setblock_table as adapter
        o = json.loads((ROOT / 'policy/fixtures/setblock-handoff-v1.json').read_bytes())
        self.assertEqual(tuple(o['header']), adapter.COLUMNS)
        self.assertEqual(tuple(o['rows'][0]), adapter.EXPECTED)
        self.assertEqual(o['effect']['unknowns'], adapter.IMPORTED_UNKNOWNS)
        self.assertEqual(o['effect']['assumptions'], adapter.IMPORTED_ASSUMPTIONS)
        self.assertEqual(o['effect']['evidence_refs'], adapter.IMPORTED_EVIDENCE_REFS)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ContextTests(unittest.TestCase):
    def test_context_binds_bytes_and_rejects_coherent_replacement(self):
        from policy.setblock_handoff import HandoffError, validate_context
        oracle = (ROOT / 'policy/fixtures/setblock-handoff-v1.json').read_bytes()
        consumer = {p: (ROOT / p).read_bytes() for p in (
            'policy/setblock_table.py', 'policy/setblock_handoff.py', 'policy/oracle.py',
            'policy/interchange_contract.py', 'policy/__init__.py', 'corpus/lock.json',
            'policy/grants.json', 'policy/policy_decisions.json', 'schemas/finding.schema.json',
            'corpus/profiles/luci-ssl-25.12/profile.json',
            'corpus/profiles/luci-ssl-25.12/expected-capabilities.json')}
        producer = {p: p.encode() for p in (
            'ql/src/m4/SetBlockDetectEffectTable.ql', 'ql/src/diagnostics/ExtractionErrors.ql',
            'ql/src/diagnostics/SuccessfullyExtractedFiles.ql', 'ql/src/qlpack.yml',
            'ql/src/codeql-pack.lock.yml', 'ql/lib/qlpack.yml', 'ql/lib/codeql-pack.lock.yml',
            'ql/lib/model.qll', '.codeqlmanifest.json', 'Cargo.lock',
            'scripts/create-extractor-pack.sh', 'extractor-pack/tools/linux64/extractor',
            'resolved-packs/pack.lock')}
        expected = {'version': 'setblock-handoff-context-v1',
                    'producer_commit': 'a' * 40, 'consumer_commit': 'b' * 40,
                    'oracle_sha256': digest(oracle), 'clean': True,
                    'consumer_files': {p: digest(v) for p, v in consumer.items()},
                    'producer_files': {p: digest(v) for p, v in producer.items()}}
        actual = copy.deepcopy(expected)
        validate_context(expected, actual, consumer, producer, oracle)
        for malformed in (None, [], 'context'):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(HandoffError, 'expected_context_mismatch'):
                    validate_context(expected, malformed, consumer, producer, oracle)
                with self.assertRaisesRegex(HandoffError, 'expected_context_mismatch'):
                    validate_context(malformed, actual, consumer, producer, oracle)
        for field in ('consumer_commit', 'oracle_sha256', 'clean'):
            with self.subTest(field=field):
                changed = copy.deepcopy(actual)
                changed[field] = 'bad'
                with self.assertRaisesRegex(HandoffError, 'expected_context_mismatch'):
                    validate_context(expected, changed, consumer, producer, oracle)
        for path in ('policy/grants.json', 'policy/setblock_table.py'):
            with self.subTest(path=path):
                changed_bytes = dict(consumer)
                changed_bytes[path] += b' '
                changed = copy.deepcopy(actual)
                changed['consumer_files'][path] = digest(changed_bytes[path])
                with self.assertRaises(HandoffError):
                    validate_context(expected, changed, changed_bytes, producer, oracle)
                with self.assertRaises(HandoffError):
                    validate_context(expected, actual, changed_bytes, producer, oracle)

        forged_oracle = json.loads(oracle)
        forged_oracle['rows'] = []
        forged_bytes = json.dumps(forged_oracle).encode()
        forged_claim = copy.deepcopy(actual)
        forged_claim['oracle_sha256'] = digest(forged_bytes)
        with self.assertRaisesRegex(HandoffError, 'expected_context_mismatch'):
            validate_context(expected, forged_claim, consumer, producer, forged_bytes)
        with self.assertRaisesRegex(HandoffError, 'expected_context_mismatch'):
            validate_context(expected, actual, consumer, producer, forged_bytes)

        reduced = copy.deepcopy(expected)
        reduced['producer_files'].pop('ql/src/codeql-pack.lock.yml')
        changed_producer = dict(producer)
        changed_producer.pop('ql/src/codeql-pack.lock.yml')
        with self.assertRaisesRegex(HandoffError, 'expected_context_mismatch'):
            validate_context(reduced, copy.deepcopy(reduced), consumer, changed_producer, oracle)


class RetainedTests(unittest.TestCase):
    def test_type_aware_json_equality_for_nested_values(self):
        from policy.setblock_handoff import _json_equal
        cases = [({'x': [True, {'n': 1}]}, {'x': [1, {'n': 1}]}, False),
                 ({'x': [False]}, {'x': [0]}, False),
                 ({'x': [{'n': 481}]}, {'x': [{'n': 481.0}]}, False),
                 ([1, 2], [2, 1], False),
                 ({'a': 1, 'b': [None, 'x']}, {'b': [None, 'x'], 'a': 1}, True),
                 ({'a': 1}, {'a': 1, 'b': None}, False),
                 (1.0, 1.0, True), (True, True, True)]
        for left, right, expected in cases:
            with self.subTest(left=left, right=right):
                self.assertIs(_json_equal(left, right), expected)
                self.assertIs(_json_equal(right, left), expected)

    def test_non_target_comparison_independently_rejects_type_changes(self):
        from unittest.mock import patch
        from policy import setblock_handoff, setblock_table
        real_prepare = setblock_table.prepare_updates
        for old_value, new_value in ((481, 481.0), (True, 1), (0, False)):
            with self.subTest(old=old_value, new=new_value):
                before, after = {}, {}
                for path, data in self.states.items():
                    rows = json.loads(data)
                    row = next(r for r in rows if r.get('record_id') == 'm4:effect:luci-getBlockDevices-popen')
                    row['audit_type_probe'] = {'nested': [old_value]}
                    before[path] = json.dumps(rows).encode()
                    row['audit_type_probe']['nested'][0] = new_value
                    after[path] = json.dumps(rows).encode()
                def altered_expected(*args):
                    states = copy.deepcopy(real_prepare(*args))
                    for rows in states:
                        row = next(r for r in rows if r.get('record_id') == 'm4:effect:luci-getBlockDevices-popen')
                        row['audit_type_probe']['nested'][0] = new_value
                    return states
                with patch.object(setblock_table, 'prepare_updates', side_effect=altered_expected):
                    with self.assertRaises(setblock_handoff.HandoffError) as caught:
                        setblock_handoff.validate_retained(before, after, after, ROOT, self.oracle)
                self.assertEqual(caught.exception.code, 'unexpected_mutation')
                self.assertNotIn('adapter transition', str(caught.exception))

    def test_adapter_transition_comparison_is_type_aware(self):
        from unittest.mock import patch
        from policy import setblock_handoff, setblock_table
        real_prepare = setblock_table.prepare_updates
        def altered_expected(*args):
            states = copy.deepcopy(real_prepare(*args))
            for rows in states:
                row = next(r for r in rows if r.get('record_id') == 'm4:effect:luci-getBlockDevices-popen')
                row['source_location']['start_line'] = 481.0
            return states
        with patch.object(setblock_table, 'prepare_updates', side_effect=altered_expected):
            with self.assertRaises(setblock_handoff.HandoffError) as caught:
                setblock_handoff.validate_retained(self.states, self.states, self.states, ROOT, self.oracle)
        self.assertEqual(caught.exception.code, 'unexpected_mutation')
        self.assertIn('adapter transition', str(caught.exception))

    def setUp(self):
        self.oracle = json.loads((ROOT / 'policy/fixtures/setblock-handoff-v1.json').read_bytes())
        self.states = {p: (ROOT / p).read_bytes() for p in self.oracle['artifacts']}

    def test_independent_grant_and_deny_oracle_are_enforced(self):
        from policy.setblock_handoff import HandoffError, validate_retained
        for field in ('grant', 'deny'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.oracle)
                if field == 'grant':
                    changed['grants'][0]['session_class'] = 'wrong'
                else:
                    changed['deny_id'] = 'wrong'
                with self.assertRaisesRegex(HandoffError, 'assessment_binding_mismatch'):
                    validate_retained(self.states, self.states, self.states, ROOT, changed)

    def test_paired_effects_and_idempotent_reimport(self):
        from policy.setblock_handoff import validate_retained
        validate_retained(self.states, self.states, self.states, ROOT, self.oracle)

    def test_coherent_target_omission_or_uncertainty_removal_fails(self):
        from policy.setblock_handoff import HandoffError, validate_retained
        for mode in ('omit', 'substitute', 'duplicate', 'unknowns', 'non_target', 'reimport'):
            with self.subTest(mode=mode):
                after = dict(self.states)
                for path in after:
                    rows = json.loads(after[path])
                    target = next(r for r in rows if r.get('record_id') == self.oracle['effect']['record_id'])
                    if mode == 'omit':
                        rows.remove(target)
                    elif mode == 'substitute':
                        target['record_id'] = 'other'
                    elif mode == 'duplicate':
                        rows.append(target)
                    elif mode == 'unknowns':
                        target['unknowns'] = []
                    elif mode == 'non_target':
                        next(r for r in rows if r is not target)['producer'] = 'changed'
                    after[path] = json.dumps(rows).encode()
                reimport = dict(after)
                if mode == 'reimport':
                    reimport[next(iter(reimport))] += b' '
                with self.assertRaises(HandoffError):
                    validate_retained(self.states, after, reimport, ROOT, self.oracle)

    def test_source_and_sealed_inputs(self):
        from policy.setblock_handoff import HandoffError, validate_inputs
        source = (ROOT / 'policy/fixtures/getblock-source' / self.oracle['source_path']).read_bytes()
        csv_data = (ROOT / 'policy/fixtures/setblock-observation.csv').read_bytes()
        inputs = {'source': source, 'csv': csv_data, 'policy': b'fixed'}
        validate_inputs(inputs, dict(inputs), self.oracle, self.oracle['rows'])
        for key in inputs:
            with self.subTest(key=key):
                changed = dict(inputs)
                changed[key] += b' '
                with self.assertRaisesRegex(HandoffError, 'handoff_input_mismatch'):
                    validate_inputs(inputs, changed, self.oracle, self.oracle['rows'])
