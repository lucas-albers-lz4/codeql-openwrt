"""Offline bundle controls: synthetic receipts are not execution evidence."""
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from policy import setblock_handoff as h

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.consumer = self.base / 'consumer'
        self.producer = self.base / 'producer'
        self.bundle = self.base / 'bundle'
        for path in ROOT.glob('policy/*.py'):
            dest = self.consumer / path.relative_to(ROOT)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
        for name in h.CONSUMER_REQUIRED:
            dest = self.consumer / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        for name in h.PRODUCER_REQUIRED | {'ql/lib/model.qll', 'resolved-packs/pack.lock'}:
            dest = self.producer / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(name)
        self.oracle_bytes = (ROOT / 'policy/fixtures/setblock-handoff-v1.json').read_bytes()
        self.oracle = json.loads(self.oracle_bytes)
        self.bundle.mkdir()
        source = (ROOT / 'policy/fixtures/getblock-source' / self.oracle['source_path']).read_bytes()
        csv_data = (ROOT / 'policy/fixtures/setblock-observation.csv').read_bytes()
        self.put('source', source)
        self.put('source_after', source)
        self.put('csv', csv_data)
        self.put('csv_after', csv_data)
        self.put('extracted_csv', ('"f","col1"\n"/run/sealed/source/' + self.oracle['source_path'] + '",""\n').encode())
        self.put('errors_csv', b'"error","col1","col2"\n')
        for role in ('effects_bqrs', 'extracted_bqrs', 'errors_bqrs'):
            self.put(role, role.encode())
        for phase in ('before', 'after', 'reimport'):
            for i, path in enumerate(self.oracle['artifacts']):
                self.put(f'{phase}_{i}', (ROOT / path).read_bytes())
        consumer_files = {p.relative_to(self.consumer).as_posix(): sha(p.read_bytes())
                          for p in self.consumer.rglob('*') if p.is_file()}
        producer_files = {p.relative_to(self.producer).as_posix(): sha(p.read_bytes())
                          for p in self.producer.rglob('*') if p.is_file()}
        self.context = {'version': 'setblock-handoff-context-v1', 'clean': True,
                        'producer_commit': 'a' * 40, 'consumer_commit': 'b' * 40,
                        'oracle_sha256': sha(self.oracle_bytes), 'consumer_files': consumer_files,
                        'producer_files': producer_files,
                        'handoff_csv': '/run/sealed/effects.csv',
                        'handoff_source_root': '/run/sealed/source', 'commands': {},
                        'codeql': '/tools/codeql', 'python': '/tools/python3', 'database': '/run/db',
                        'producer_run_root': '/run/producer',
                        'bqrs_paths': {name: '/run/db/' + name + '.bqrs'
                                       for name in ('effects', 'extracted', 'errors')}}
        for role in ('consumer_at_handoff', 'consumer_after_import', 'consumer_after_reimport'):
            self.put(role, encoded(consumer_files))
        for stage in h.STAGES:
            argv = ['tool', stage]
            if stage in ('init', 'index', 'finalize'):
                subcommand = {'init': 'init', 'index': 'index-files', 'finalize': 'finalize'}[stage]
                argv = ['/tools/codeql', 'database', subcommand, '/run/db']
                if stage in ('init', 'index'):
                    argv += ['--language=ucode']
                if stage == 'init':
                    argv += ['--source-root=/run/sealed/source']
                if stage == 'index':
                    argv += ['--working-dir=/run/sealed/source']
            if stage.endswith('_query'):
                name = stage.split('_')[0]
                query = {'effects': 'm4/SetBlockDetectEffectTable.ql',
                         'extracted': 'diagnostics/SuccessfullyExtractedFiles.ql',
                         'errors': 'diagnostics/ExtractionErrors.ql'}[name]
                argv = ['/tools/codeql', 'query', 'run', '/run/producer/ql/src/' + query,
                        '--database=/run/db', '--output=' + self.context['bqrs_paths'][name]]
            if stage.endswith('_decode'):
                name = stage.split('_')[0]
                argv = ['/tools/codeql', 'bqrs', 'decode', '--format=csv', self.context['bqrs_paths'][name]]
            if stage in ('adapter', 'reimport'):
                argv = [self.context['python'], '-B', '-m', 'policy.setblock_table', '--csv',
                        self.context['handoff_csv'], '--source-root', self.context['handoff_source_root']]
            self.context['commands'][stage] = {'argv': argv, 'cwd': '/run/consumer' if stage in ('adapter', 'reimport') else '/run/producer'}
            self.put(stage + '_stdout', b'')
            self.put(stage + '_stderr', b'')
        self.manifest = {'version': 'setblock-handoff-bundle-v1',
                         'context': copy.deepcopy(self.context), 'run_kind': 'offline_fixture',
                         'coverage': 'partial', 'advertised': self.oracle['rows'], 'receipts': {}}
        self.refresh()

    def put(self, role, data):
        (self.bundle / role).write_bytes(data)

    def refresh(self):
        for stage, role in (('effects_decode', 'csv'), ('extracted_decode', 'extracted_csv'),
                            ('errors_decode', 'errors_csv')):
            self.put(stage + '_stdout', (self.bundle / role).read_bytes())
        for stage, (inputs, outputs) in h.STAGES.items():
            self.manifest['receipts'][stage] = {
                **copy.deepcopy(self.context['commands'][stage]), 'exit_code': 0,
                'inputs': {r: sha((self.bundle / r).read_bytes()) for r in inputs},
                'outputs': {r: sha((self.bundle / r).read_bytes()) for r in outputs},
                'stdout': sha((self.bundle / (stage + '_stdout')).read_bytes()),
                'stderr': sha((self.bundle / (stage + '_stderr')).read_bytes())}
        self.put('manifest.json', encoded(self.manifest))

    def validate(self):
        return h.validate_bundle(self.bundle, expected_context=self.context,
                                 oracle_bytes=self.oracle_bytes,
                                 consumer_root=self.consumer, producer_root=self.producer)

    def test_real_adapter_control_and_coherent_numeric_type_mutant(self):
        from policy import interchange_contract, setblock_table

        # Run the actual adapter against the exact bundle pre-state in a copy.
        actual = self.base / 'actual-adapter'
        shutil.copytree(self.consumer, actual)
        for i, name in enumerate(self.oracle['artifacts']):
            dest = actual / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((self.bundle / f'before_{i}').read_bytes())
        setblock_table.import_table(self.bundle / 'csv', ROOT / 'policy/fixtures/getblock-source', actual)
        schema = json.loads((ROOT / 'schemas/finding.schema.json').read_bytes())
        row_id = 'm4:effect:luci-getBlockDevices-popen'
        for i, name in enumerate(self.oracle['artifacts']):
            rows = json.loads((actual / name).read_bytes())
            row = next(r for r in rows if r['record_id'] == row_id)
            self.assertIs(type(row['source_location']['start_line']), int)
            self.assertEqual(row['source_location']['start_line'], 481)
            for phase in ('after', 'reimport'):
                self.put(f'{phase}_{i}', (actual / name).read_bytes())
        self.refresh()
        context, oracle = self.base / 'expected.json', self.base / 'oracle.json'
        context.write_bytes(encoded(self.context))
        oracle.write_bytes(self.oracle_bytes)
        def cli(optimized=False):
            return subprocess.run([sys.executable, *(['-O'] if optimized else []), '-B', '-m',
                                   'policy.setblock_handoff', str(self.bundle),
                                   '--expected-context', str(context), '--oracle', str(oracle),
                                   '--consumer-root', str(self.consumer), '--producer-root', str(self.producer)],
                                  cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(self.validate()['status'], 'consistent_offline')
        for optimized in (False, True):
            with self.subTest(control=True, optimized=optimized):
                proc = cli(optimized)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout)['status'], 'consistent_offline')
        for i in range(2):
            rows = json.loads((self.bundle / f'after_{i}').read_bytes())
            row = next(r for r in rows if r['record_id'] == row_id)
            row['source_location']['start_line'] = 481.0
            self.assertTrue(any('start_line: expected integer' in e
                                for e in interchange_contract._validate(row, schema, 'row')))
            for phase in ('after', 'reimport'):
                self.put(f'{phase}_{i}', encoded(rows))
        self.refresh()
        with self.subTest(mutant='API'):
            with self.assertRaises(h.HandoffError) as caught:
                self.validate()
            self.assertEqual(caught.exception.code, 'unexpected_mutation')
        for optimized in (False, True):
            with self.subTest(mutant='CLI', optimized=optimized):
                proc = cli(optimized)
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn('unexpected_mutation', proc.stderr)

    def test_composed_offline_success_never_claims_live_execution(self):
        for run_kind in ('offline_fixture', 'live'):
            with self.subTest(run_kind=run_kind):
                self.manifest['run_kind'] = run_kind
                self.refresh()
                result = self.validate()
                self.assertEqual(result['status'], 'consistent_offline')
                self.assertEqual(result['coverage'], 'partial')
                self.assertIs(result['execution_verified'], False)
                self.assertIs(result['freshness_verified'], False)

    def real_diagnostics(self):
        evidence = ROOT / 'policy/tests/fixtures/codeql-diagnostics-afb1400'
        extracted = (evidence / 'extracted.csv').read_bytes()
        errors = (evidence / 'errors.csv').read_bytes()
        # This is a recorded CSV value, never a filesystem dependency.
        recorded_root = b'/root/workspace/wt-ucode-76/ql/test/extractor-smoke'
        approved_root = str(self.base / 'approved-source')
        (self.base / 'approved-source').mkdir()
        self.assertEqual(extracted.count(recorded_root + b'/'), 1)
        extracted = extracted.replace(recorded_root + b'/', approved_root.encode() + b'/', 1)
        old = self.context['handoff_source_root']
        self.context['handoff_source_root'] = approved_root
        for command in self.context['commands'].values():
            command['argv'] = [arg.replace(old, approved_root) for arg in command['argv']]
        self.manifest['context'] = copy.deepcopy(self.context)
        return extracted, errors

    def test_real_codeql_diagnostics_accept_exact_approved_root(self):
        extracted, errors = self.real_diagnostics()
        self.put('extracted_csv', extracted)
        self.put('errors_csv', errors)
        self.refresh()
        self.assertEqual(self.validate()['status'], 'consistent_offline')

    def test_real_codeql_diagnostics_reject_mutations(self):
        extracted, errors = self.real_diagnostics()
        row = extracted.splitlines(keepends=True)[1]
        root = self.context['handoff_source_root'].encode()
        cases = {
            'wrong_root': (extracted.replace(root + b'/', root + b'-other/', 1), errors),
            'extracted_header': (extracted.replace(b'"f","col1"', b'"col1","f"', 1), errors),
            'error_header': (extracted, errors.replace(b'"error","col1","col2"', b'"error","col2","col1"', 1)),
            'error_row': (extracted, errors + b'"error","x","y"\n'),
            'duplicate_row': (extracted + row, errors),
            'missing_row': (extracted.splitlines(keepends=True)[0], errors),
            'extra_column': (extracted.replace(b',""\n', b',"","extra"\n', 1), errors),
        }
        for name, (bad_extracted, bad_errors) in cases.items():
            with self.subTest(case=name):
                self.put('extracted_csv', bad_extracted)
                self.put('errors_csv', bad_errors)
                self.refresh()
                with self.assertRaises(h.HandoffError) as caught:
                    self.validate()
                self.assertEqual(caught.exception.code, 'execution_inconclusive')

    def test_diagnostics_reject_wrong_format_or_source(self):
        good = ('"f","col1"\n"/run/sealed/source/' + self.oracle['source_path'] + '",""\n').encode()
        bad_cases = [
            (b'wrong,headers\nwrong-file,usr/share/rpcd/ucode/luci\n', b'EXTRACTION FAILED\n'),
            (good, b'EXTRACTION FAILED\n'),
            (good, b'"error","col1","col2"\n"error","x","y"\n'),
            (good.replace(b'/run/sealed/source/', b'/other/root/'), b'"error","col1","col2"\n'),
            (good.replace(b'"/run/sealed/source/', b'"/run/sealed/source-evil/'), b'"error","col1","col2"\n'),
            (('f,col1\n,/run/sealed/source/' + self.oracle['source_path'] + '\n').encode(), b'error,col1,col2\n'),
            (good.replace(b',""\n', b',"",extra\n'), b'error,col1,col2\n'),
            (good + good.split(b'\n')[1] + b'\n', b'"error","col1","col2"\n'),
            (good + b'"/other/file",""\n', b'"error","col1","col2"\n'),
            (good.replace(b',""\n', b',"unexpected"\n'), b'"error","col1","col2"\n'),
            (good.replace(b'"f","col1"', b'"col1","f"'), b'"error","col1","col2"\n'),
        ]
        for extracted, errors in bad_cases:
            with self.subTest(extracted=extracted, errors=errors):
                self.put('extracted_csv', extracted)
                self.put('errors_csv', errors)
                self.refresh()
                with self.assertRaises(h.HandoffError) as caught:
                    self.validate()
                self.assertEqual(caught.exception.code, 'execution_inconclusive')

    def test_diagnostics_allow_root_directory_without_suffix_matching(self):
        extracted = ('f,col1\n/' + self.oracle['source_path'] + ',\n').encode()
        h._diagnostics(extracted, b'error,col1,col2\n', '/', self.oracle['source_path'])

    def test_cli_rejects_manifest_selected_trusted_context(self):
        context = self.bundle / 'expected.json'
        context.write_bytes(encoded(self.context))
        oracle = self.base / 'oracle.json'
        oracle.write_bytes(self.oracle_bytes)
        proc = subprocess.run([sys.executable, '-B', '-m', 'policy.setblock_handoff', str(self.bundle),
                               '--expected-context', str(context), '--oracle', str(oracle),
                               '--consumer-root', str(self.consumer), '--producer-root', str(self.producer)],
                              cwd=ROOT, text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('expected_context_mismatch', proc.stderr)

    def test_cli_composes_and_reports_offline_status(self):
        context = self.base / 'expected.json'
        oracle = self.base / 'oracle.json'
        context.write_bytes(encoded(self.context))
        oracle.write_bytes(self.oracle_bytes)
        cmd = [sys.executable, '-B', '-m', 'policy.setblock_handoff', str(self.bundle),
               '--expected-context', str(context), '--oracle', str(oracle),
               '--consumer-root', str(self.consumer), '--producer-root', str(self.producer)]
        for run_kind in ('offline_fixture', 'live'):
            with self.subTest(run_kind=run_kind):
                self.manifest['run_kind'] = run_kind
                self.refresh()
                proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                result = json.loads(proc.stdout)
                self.assertEqual(result['status'], 'consistent_offline')
                self.assertIs(result['execution_verified'], False)
                self.assertIs(result['freshness_verified'], False)
        (self.bundle / 'adapter_stdout').unlink()
        proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('missing_artifact', proc.stderr)

    def test_missing_preexisting_input_target_rejected(self):
        for i in range(2):
            rows = json.loads((self.bundle / f'before_{i}').read_bytes())
            rows = [row for row in rows if row.get('record_id') != self.oracle['effect']['record_id']]
            self.put(f'before_{i}', encoded(rows))
        self.refresh()
        with self.assertRaisesRegex(h.HandoffError, 'retained_target_missing'):
            self.validate()

    def test_mixed_legacy_import_prestate_fails_before_post_validation(self):
        legacy = json.loads((ROOT / 'policy/fixtures/setblock-legacy-effects.json').read_bytes())['snapshot_effect']
        rows = json.loads((self.bundle / 'before_0').read_bytes())
        rows = [legacy if r.get('record_id') == legacy['record_id'] else r for r in rows]
        self.put('before_0', encoded(rows))
        self.refresh()
        for corrupt_post in (False, True):
            with self.subTest(corrupt_post=corrupt_post):
                if corrupt_post:
                    self.put('after_0', b'not json')
                    self.refresh()
                with self.assertRaises(h.HandoffError) as caught:
                    self.validate()
                self.assertEqual(caught.exception.code, 'retained_prestate_mismatch')

    def test_effect_identity_alias_fails_before_post_validation(self):
        for phase in ('before', 'after', 'reimport'):
            for i in range(2):
                rows = json.loads((self.bundle / f'{phase}_{i}').read_bytes())
                target = next(r for r in rows if r.get('record_id') == self.oracle['effect']['record_id'])
                alias = dict(target, record_id='audit:alias:setblockdetect')
                rows.append(alias)
                self.put(f'{phase}_{i}', encoded(rows))
        self.refresh()
        for corrupt_post in (False, True):
            with self.subTest(corrupt_post=corrupt_post):
                if corrupt_post:
                    self.put('after_0', b'not json')
                    self.refresh()
                with self.assertRaises(h.HandoffError) as caught:
                    self.validate()
                self.assertEqual(caught.exception.code, 'effect_identity_collision')

    def test_target_position_must_match_adapter_replacement(self):
        for i in range(2):
            rows = json.loads((self.bundle / f'after_{i}').read_bytes())
            target = next(r for r in rows if r.get('record_id') == self.oracle['effect']['record_id'])
            index = rows.index(target)
            rows.remove(target)
            rows.insert(len(rows) if index == 0 else 0, target)
            self.put(f'after_{i}', encoded(rows))
            self.put(f'reimport_{i}', encoded(rows))
        self.refresh()
        with self.assertRaises(h.HandoffError) as caught:
            self.validate()
        self.assertEqual(caught.exception.code, 'unexpected_mutation')

    def test_matching_legacy_prestate_transitions_to_imported_poststate(self):
        legacy = json.loads((ROOT / 'policy/fixtures/setblock-legacy-effects.json').read_bytes())
        for i, key in enumerate(('snapshot_effect', 'catalog_effect')):
            rows = json.loads((self.bundle / f'before_{i}').read_bytes())
            rows = [legacy[key] if r.get('record_id') == legacy[key]['record_id'] else r for r in rows]
            self.put(f'before_{i}', encoded(rows))
        self.refresh()
        self.assertEqual(self.validate()['status'], 'consistent_offline')

    def test_changed_policy_at_read_boundary_is_rejected(self):
        changed = copy.deepcopy(self.context['consumer_files'])
        changed['policy/grants.json'] = '0' * 64
        self.put('consumer_after_import', encoded(changed))
        self.refresh()
        with self.assertRaisesRegex(h.HandoffError, 'policy_context_mismatch'):
            self.validate()

    def test_extractor_and_resolved_pack_inventory_required(self):
        for name in ('extractor-pack/tools/linux64/extractor', 'resolved-packs/pack.lock'):
            with self.subTest(name=name):
                expected = copy.deepcopy(self.context)
                producer = {p: (self.producer / p).read_bytes() for p in expected['producer_files']}
                expected['producer_files'].pop(name, None)
                producer.pop(name, None)
                consumer = {p: (self.consumer / p).read_bytes() for p in expected['consumer_files']}
                with self.assertRaisesRegex(h.HandoffError, 'expected_context_mismatch'):
                    h.validate_context(expected, copy.deepcopy(expected), consumer, producer, self.oracle_bytes)

    def test_undeclared_query_source_is_rejected(self):
        (self.producer / 'ql/src/extra.ql').write_text('undeclared')
        with self.assertRaisesRegex(h.HandoffError, 'expected_context_mismatch'):
            self.validate()

    def test_executed_code_must_equal_trusted_root(self):
        path = self.consumer / 'policy/interchange_contract.py'
        path.write_bytes(path.read_bytes() + b'\n# different executed code\n')
        self.context['consumer_files']['policy/interchange_contract.py'] = sha(path.read_bytes())
        self.manifest['context'] = copy.deepcopy(self.context)
        self.refresh()
        with self.assertRaisesRegex(h.HandoffError, 'execution_code_mismatch'):
            self.validate()

    def test_executed_package_initializer_must_equal_trusted_root(self):
        path = self.consumer / 'policy/__init__.py'
        path.write_bytes(path.read_bytes() + b'\nraise RuntimeError("different approved initializer")\n')
        self.context['consumer_files']['policy/__init__.py'] = sha(path.read_bytes())
        self.manifest['context'] = copy.deepcopy(self.context)
        for role in ('consumer_at_handoff', 'consumer_after_import', 'consumer_after_reimport'):
            self.put(role, encoded(self.context['consumer_files']))
        self.refresh()
        with self.assertRaises(h.HandoffError) as caught:
            self.validate()
        self.assertEqual(caught.exception.code, 'execution_code_mismatch')

    def test_coherent_omission_does_not_accept_preexisting_effect(self):
        self.put('csv', (','.join(self.oracle['header']) + '\n').encode())
        self.put('csv_after', (self.bundle / 'csv').read_bytes())
        self.manifest['advertised'] = []
        self.refresh()
        with self.assertRaisesRegex(h.HandoffError, 'scoped_observation_missing'):
            self.validate()

    def test_missing_or_failed_receipts_and_diagnostics_are_inconclusive(self):
        for mode in ('missing_receipt', 'failed_receipt', 'missing_diagnostics', 'wrong_extracted', 'errors'):
            with self.subTest(mode=mode):
                self.refresh()
                if mode == 'missing_receipt':
                    self.manifest['receipts'].pop('adapter')
                    self.put('manifest.json', encoded(self.manifest))
                elif mode == 'failed_receipt':
                    self.manifest['receipts']['adapter']['exit_code'] = 1
                    self.put('manifest.json', encoded(self.manifest))
                elif mode == 'missing_diagnostics':
                    (self.bundle / 'errors_csv').unlink()
                else:
                    self.put('extracted_csv' if mode == 'wrong_extracted' else 'errors_csv',
                             b'path\nwrong\n')
                    self.refresh()
                with self.assertRaises(h.HandoffError) as caught:
                    self.validate()
                self.assertIn(caught.exception.code, ('execution_inconclusive', 'missing_artifact'))
                self.put('errors_csv', b'"error","col1","col2"\n')
                self.put('extracted_csv', ('"f","col1"\n"/run/sealed/source/' + self.oracle['source_path'] + '",""\n').encode())

    def test_context_wrong_roots_and_immutable_policy(self):
        self.manifest['context']['consumer_commit'] = 'c' * 40
        self.put('manifest.json', encoded(self.manifest))
        with self.assertRaisesRegex(h.HandoffError, 'expected_context_mismatch'):
            self.validate()
        self.manifest['context'] = copy.deepcopy(self.context)
        self.refresh()
        with self.assertRaises(h.HandoffError):
            h.validate_bundle(self.bundle, expected_context=self.context, oracle_bytes=self.oracle_bytes,
                              consumer_root=self.producer, producer_root=self.consumer)
        with (self.consumer / 'policy/grants.json').open('ab') as f:
            f.write(b' ')
        with self.assertRaises(h.HandoffError):
            self.validate()

    def test_non_target_mutation_and_uncertainty_are_rejected(self):
        for mode in ('non_target', 'unknowns', 'target_omission'):
            with self.subTest(mode=mode):
                for i in range(2):
                    path = self.bundle / f'after_{i}'
                    rows = json.loads(path.read_bytes())
                    target = next(r for r in rows if r.get('record_id') == self.oracle['effect']['record_id'])
                    if mode == 'non_target':
                        next(r for r in rows if r is not target)['producer'] = 'changed'
                    elif mode == 'unknowns':
                        target['unknowns'] = []
                    else:
                        rows.remove(target)
                    self.put(f'after_{i}', encoded(rows))
                    self.put(f'reimport_{i}', encoded(rows))
                self.refresh()
                with self.assertRaises(h.HandoffError) as caught:
                    self.validate()
                self.assertEqual(caught.exception.code, {'non_target': 'unexpected_mutation',
                                 'unknowns': 'assessment_binding_mismatch',
                                 'target_omission': 'retained_target_missing'}[mode])
                for i, name in enumerate(self.oracle['artifacts']):
                    data = (ROOT / name).read_bytes()
                    self.put(f'after_{i}', data)
                    self.put(f'reimport_{i}', data)

    def test_decode_stdout_must_be_the_handoff_csv(self):
        self.put('effects_decode_stdout', b'stale')
        self.manifest['receipts']['effects_decode']['stdout'] = sha(b'stale')
        self.put('manifest.json', encoded(self.manifest))
        with self.assertRaisesRegex(h.HandoffError, 'handoff_input_mismatch'):
            self.validate()

    def test_wrong_query_command_is_not_a_receipt(self):
        self.context['commands']['effects_query']['argv'] = ['true']
        self.manifest['context'] = copy.deepcopy(self.context)
        self.refresh()
        with self.assertRaisesRegex(h.HandoffError, 'execution_inconclusive'):
            self.validate()

    def test_adapter_command_must_use_pinned_python_module_invocation(self):
        self.context['commands']['adapter']['argv'][0] = '/usr/bin/true'
        self.manifest['context'] = copy.deepcopy(self.context)
        self.refresh()
        with self.assertRaises(h.HandoffError) as caught:
            self.validate()
        self.assertEqual(caught.exception.code, 'handoff_input_mismatch')

    def test_bundle_symlink_is_rejected(self):
        (self.bundle / 'csv').unlink()
        (self.bundle / 'csv').symlink_to(ROOT / 'policy/fixtures/setblock-observation.csv')
        with self.assertRaisesRegex(h.HandoffError, 'invalid_artifact'):
            self.validate()

    def test_synthetic_negative_claim_is_not_ignored(self):
        self.manifest['outcome'] = 'no_path'
        self.put('manifest.json', encoded(self.manifest))
        with self.assertRaisesRegex(h.HandoffError, 'claim_strengthening'):
            self.validate()

    def test_stale_path_and_claim_strengthening_fail(self):
        self.manifest['coverage'] = 'complete'
        self.put('manifest.json', encoded(self.manifest))
        with self.assertRaisesRegex(h.HandoffError, 'claim_strengthening'):
            self.validate()
        self.manifest['coverage'] = 'partial'
        self.refresh()
        self.manifest['receipts']['adapter']['argv'][-3] = '/old.csv'
        self.put('manifest.json', encoded(self.manifest))
        with self.assertRaisesRegex(h.HandoffError, 'handoff_input_mismatch'):
            self.validate()
