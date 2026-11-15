"""Record-specific policy joins for the bounded interchange contract."""
import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
from pathlib import Path
import unittest

from policy import interchange_contract as contract


class RecordScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grants = contract._load_grants(contract.REPO_ROOT)
        cls.effects = json.loads((contract.REPO_ROOT / 'reports/handler_effects.json').read_text())

    def test_snapshot_cli_checks_missing_coverage(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            (root / 'docs/m3-coverage.json').unlink()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                contract.main(['--snapshot', '--ucode-root', str(root)])
            self.assertIn('snapshot documents missing', stderr.getvalue())

    def test_snapshot_document_coverage_and_required_evidence(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            self.assertEqual(contract.validate_ucode_snapshot(root), (5, 19))
            path = root / 'docs/m4-coverage.json'
            original = json.loads(path.read_text())
            for field, value in [('profile', 'luci-ssl-25.12-no-ubusauth'), ('analysis_revision', 'step3:wrong'), ('analyzed', [7])]:
                with self.subTest(coverage_field=field):
                    changed = dict(original, **{field: value})
                    path.write_text(json.dumps(changed))
                    with self.assertRaisesRegex(contract.ContractError, 'coverage'):
                        contract.validate_ucode_snapshot(root)
            path.write_text(json.dumps(original))
            path = root / 'docs/m4-findings.json'
            rows = json.loads(path.read_text())
            old = rows[0]['evidence_refs']
            rows[0]['evidence_refs'] = old[1:]
            path.write_text(json.dumps(rows))
            with self.assertRaisesRegex(contract.ContractError, 'evidence'):
                contract.validate_ucode_snapshot(root)
            rows[0]['evidence_refs'] = old
            path.write_text(json.dumps(rows))
            (root / 'docs/m3-coverage.json').unlink()
            with self.assertRaisesRegex(contract.ContractError, 'missing'):
                contract.validate_ucode_snapshot(root)

    def test_historical_taint_retag_cannot_bypass_caller_join(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            path = root / 'docs/m3-findings.json'
            rows = json.loads(path.read_text())
            row = next(r for r in rows if r['record_id'] == 'm3:getfeatures-netifd-request-args-no-path')
            row['record_type'] = 'handler_effect'
            row['evidence_refs'].append('policy:grant:root:ubus_http:luci.getFeatures')
            path.write_text(json.dumps(rows))
            for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
                with self.subTest(mode=validate.__name__), self.assertRaisesRegex(contract.ContractError, 'record_type'):
                    validate(root)

    def test_historical_rows_preserve_status_unknowns_and_scope_in_both_modes(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        mutations = [
            ('m4-shellquote-findings.json', 'm4:quote-ok-complete-arg-no-injection', 'evidence_status', 'no_path'),
            ('m4-shellquote-findings.json', 'm4:quote-ok-complete-arg-no-injection', 'unknowns', []),
            ('m4-imported-callee-findings.json', 'm4:setInitAction-init_action-unresolved', 'unknowns', []),
            ('m4-findings.json', 'm4:luci-getSwconfigFeatures-request-args-popen', 'method', 'other'),
        ]
        for name, rid, key, value in mutations:
            for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
                with self.subTest(name=name, key=key, mode=validate.__name__), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / 'ucode'
                    shutil.copytree(fixture, root)
                    path = root / 'docs' / name
                    rows = json.loads(path.read_text())
                    next(r for r in rows if r['record_id'] == rid)[key] = value
                    path.write_text(json.dumps(rows))
                    with self.assertRaisesRegex(contract.ContractError, key):
                        validate(root)

    def test_historical_unknowns_allow_additions_and_controls_allow_reordering(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            typed = root / 'docs/m4-findings.json'
            rows = json.loads(typed.read_text())
            rows[0]['unknowns'].append('additional conservative limitation')
            typed.write_text(json.dumps(rows))
            coverage = root / 'docs/m4-coverage.json'
            report = json.loads(coverage.read_text())
            report['unknowns'].append('additional conservative limitation')
            report['negative_controls'].reverse()
            coverage.write_text(json.dumps(report))
            for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
                with self.subTest(mode=validate.__name__):
                    self.assertEqual(validate(root), (5, 19))

    def test_coverage_scope_and_controls_cannot_be_removed_or_substituted(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        mutations = [
            ('m4-getfeatures-direct-exec-coverage.json', 'call_sites', 'omit'),
            ('m4-getfeatures-direct-exec-coverage.json', 'call_sites', 'replace'),
            ('m4-coverage.json', 'negative_controls', 'omit'),
            ('m4-coverage.json', 'methods_with_request_args_exec', 'replace'),
            ('m3-coverage.json', 'unknowns', 'omit'),
            ('m4-shellquote-coverage.json', 'extracted_files', 'replace'),
        ]
        for name, key, action in mutations:
            for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
                with self.subTest(name=name, key=key, action=action, mode=validate.__name__), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / 'ucode'
                    shutil.copytree(fixture, root)
                    path = root / 'docs' / name
                    report = json.loads(path.read_text())
                    if action == 'omit':
                        report[key].pop()
                    elif key == 'call_sites':
                        report[key][0]['command'] = 'unrelated command'
                    else:
                        report[key][0] = 'unrelated'
                    path.write_text(json.dumps(report))
                    with self.assertRaisesRegex(contract.ContractError, 'coverage'):
                        validate(root)

    def test_historical_coverage_rejects_extra_and_duplicate_members(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        manifest = json.loads((contract.REPO_ROOT / 'policy/ucode_snapshot_manifest.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            for name, spec in manifest['coverage'].items():
                path = root / 'docs' / name
                original_bytes = path.read_bytes()
                report = json.loads(original_bytes)
                for field, values in spec['contents'].items():
                    if field == 'unknowns':
                        continue
                    # An empty historical list has no member that can be duplicated.
                    for action in (('extra', 'duplicate') if values else ('extra',)):
                        changed = copy.deepcopy(report)
                        value = (copy.deepcopy(values[0]) if action == 'duplicate' else
                                 {'line': 9999, 'kind': 'system', 'command': 'extra probe'}
                                 if field == 'call_sites' else 'extra report member')
                        changed[field].append(value)
                        path.write_text(json.dumps(changed))
                        for validate in (contract.validate_ucode_root, contract.validate_ucode_snapshot):
                            with self.subTest(name=name, field=field, action=action, mode=validate.__name__):
                                with self.assertRaisesRegex(contract.ContractError, f'coverage {field} identity mismatch'):
                                    validate(root)
                        path.write_bytes(original_bytes)

    def test_partial_historical_document_identity_cannot_be_omitted_or_substituted(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        for action in ('omit', 'replace'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'ucode'
                shutil.copytree(fixture, root)
                path = root / 'docs/m3-findings.json'
                rows = json.loads(path.read_text())
                if action == 'omit':
                    rows.pop()
                else:
                    rows[-1]['record_id'] = 'm3:unrelated'
                path.write_text(json.dumps(rows))
                with self.assertRaisesRegex(contract.ContractError, 'identity'):
                    contract.validate_ucode_root(root)

    def test_partial_reserves_every_historical_revision_across_filenames(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot/docs'
        manifest = json.loads((contract.REPO_ROOT / 'policy/ucode_snapshot_manifest.json').read_text())
        original = json.loads((fixture / 'm3-findings.json').read_text())
        for row in original:
            row['record_id'] = 'renamed:' + row['record_id']
            if row['record_id'].endswith('getfeatures-netifd-request-args-no-path'):
                row['record_type'] = 'handler_effect'
                row['evidence_refs'].append('policy:grant:root:ubus_http:luci.getFeatures')
        revisions = [spec['revision'] for spec in manifest['typed'].values()]
        for revision in revisions:
            for filename in manifest['typed']:
                with self.subTest(revision=revision, filename=filename), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / 'docs').mkdir()
                    rows = [dict(row, analysis_revision=revision) for row in original]
                    (root / 'docs' / filename).write_text(json.dumps(rows))
                    with self.assertRaisesRegex(contract.ContractError, 'historical|identity'):
                        contract.validate_ucode_root(root)

    def test_partial_historical_families_require_correct_filename_and_revision(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot/docs'
        manifest = json.loads((contract.REPO_ROOT / 'policy/ucode_snapshot_manifest.json').read_text())
        filenames = list(manifest['typed'])
        for index, filename in enumerate(filenames):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'docs').mkdir()
                rows = json.loads((fixture / filename).read_text())
                correct = root / 'docs' / filename
                correct.write_text(json.dumps(rows))
                self.assertEqual(contract.validate_ucode_root(root), (1, len(rows)))
                wrong = root / 'docs' / filenames[(index + 1) % len(filenames)]
                correct.rename(wrong)
                with self.assertRaisesRegex(contract.ContractError, 'historical'):
                    contract.validate_ucode_root(root)
                wrong.rename(correct)
                rows[0]['analysis_revision'] = 'step3:new-family-v1'
                correct.write_text(json.dumps(rows))
                with self.assertRaisesRegex(contract.ContractError, 'analysis_revision'):
                    contract.validate_ucode_root(root)

    def test_partial_new_revision_and_ids_remain_structurally_valid(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot/docs/m3-findings.json'
        rows = json.loads(fixture.read_text())
        for row in rows:
            row['record_id'] = 'new:' + row['record_id']
            row['analysis_revision'] = 'step3:new-family-v1'
            if row['record_id'].endswith('getfeatures-netifd-request-args-no-path'):
                row['record_type'] = 'handler_effect'
                row['evidence_refs'].append('policy:grant:root:ubus_http:luci.getFeatures')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs').mkdir()
            (root / 'docs/m4-findings.json').write_text(json.dumps(rows))
            self.assertEqual(contract.validate_ucode_root(root), (1, 4))

    def test_partial_rejects_empty_evidence_reference(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        case.write_array([base_row(evidence_refs=[''])])
        with self.assertRaisesRegex(contract.ContractError, 'evidence_refs'):
            contract.validate_ucode_root(case.ucode_root)

    def test_partial_cli_reports_missing_documents_and_limited_scope(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        case.write_array([base_row()])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(contract.main(['--ucode-root', str(case.ucode_root)]), 0)
        self.assertIn('limited', output.getvalue())
        self.assertIn('m3-coverage.json', output.getvalue())
        self.assertIn('not full conformance', output.getvalue())

    def test_partial_inconclusive_requires_a_nonempty_unknown(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        case.write_array([base_row(evidence_status='inconclusive', unknowns=[])])
        with self.assertRaisesRegex(contract.ContractError, 'unknowns'):
            contract.validate_ucode_root(case.ucode_root)

    def test_duplicate_grants_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'policy').mkdir()
            grant = next(iter(self.grants.values()))
            (root / 'policy/grants.json').write_text(json.dumps([grant, grant]))
            with self.assertRaisesRegex(contract.ContractError, 'duplicate grant record_id'):
                contract._load_grants(root)

    def test_unresolved_imported_callee_cannot_become_no_path(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            path = root / 'docs/m4-imported-callee-findings.json'
            rows = json.loads(path.read_text())
            rows[0]['evidence_status'] = 'no_path'
            path.write_text(json.dumps(rows))
            with self.assertRaisesRegex(contract.ContractError, 'evidence_status'):
                contract.validate_ucode_snapshot(root)

    def test_snapshot_nested_coverage_and_identity_mutations(self):
        fixture = Path(__file__).parent / 'fixtures/ucode-snapshot'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'ucode'
            shutil.copytree(fixture, root)
            coverage = root / 'docs/m4-getfeatures-direct-exec-coverage.json'
            report = json.loads(coverage.read_text())
            report['call_sites'][0]['line'] = False
            coverage.write_text(json.dumps(report))
            with self.assertRaisesRegex(contract.ContractError, 'coverage call_sites'):
                contract.validate_ucode_snapshot(root)
            shutil.copy(fixture / 'docs/m4-getfeatures-direct-exec-coverage.json', coverage)
            typed = root / 'docs/m4-findings.json'
            rows = json.loads(typed.read_text())
            rows[0]['record_id'] = 'same-count-different-id'
            typed.write_text(json.dumps(rows))
            with self.assertRaisesRegex(contract.ContractError, 'record identity mismatch'):
                contract.validate_ucode_snapshot(root)
            typed.unlink()
            with self.assertRaisesRegex(contract.ContractError, 'documents missing'):
                contract.validate_ucode_snapshot(root)

    def test_catalog_effects_partition_each_cited_grant_by_expectation(self):
        for effect in self.effects:
            with self.subTest(record_id=effect['record_id']):
                primary, supplementary = contract.join_policy_grants(effect, self.grants, scope='aggregate')
                refs = [ref for ref in effect['evidence_refs'] if ref.startswith('policy:grant:')]
                expected_primary = [(ref, self.grants[ref]['expectation_id']) for ref in refs
                                    if self.grants[ref]['expectation_id'] == effect.get('expectation_id')]
                expected_supplementary = [(ref, self.grants[ref]['expectation_id']) for ref in refs
                                          if self.grants[ref]['expectation_id'] != effect.get('expectation_id')]
                self.assertCountEqual([(g['record_id'], g['expectation_id']) for g in primary], expected_primary)
                self.assertCountEqual([(g['record_id'], g['expectation_id']) for g in supplementary], expected_supplementary)

    def test_catalog_effects_partition_primary_and_supplementary(self):
        totals = [0, 0]
        for effect in self.effects:
            primary, supplementary = contract.join_policy_grants(effect, self.grants, scope='aggregate')
            totals[0] += len(primary)
            totals[1] += len(supplementary)
        self.assertEqual(totals, [58, 64])
        effect = next(e for e in self.effects if e['record_id'] == 'm4:effect:luci-setBlockDetect-system')
        primary, supplementary = contract.join_policy_grants(effect, self.grants, scope='aggregate')
        self.assertTrue(any(g['session_class'] == 'root' for g in supplementary))
        changed = dict(effect, evidence_refs=[g['record_id'] for g in supplementary])
        with self.assertRaisesRegex(contract.ContractError, 'primary'):
            contract.join_policy_grants(changed, self.grants, scope='aggregate')

    def test_shared_structural_cases(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        fixtures = (
            ('issue83-structural-v1.json', 'issue83-structural-v1',
             '86ab384ca31e2e448df5740f054640a9fd485f550b6d427a02a6e2b4143bebcc', 14),
            ('issue83-structural-v2.json', 'issue83-structural-v2',
             'ec2b76c8db2f36c96c7f8ee3bafa35e74fd2a5ce88e716aa8c1edb2e784c3a68', 24),
        )
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        for filename, version, digest, count in fixtures:
            path = Path(__file__).parent / 'fixtures' / filename
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            cases = json.loads(path.read_text())
            self.assertEqual(cases['contract'], version)
            self.assertEqual(len(cases['cases']), count)
            for item in cases['cases']:
                with self.subTest(fixture=version, name=item['name'], mode='partial-api'):
                    case.write_array([base_row(**item['overrides'])])
                    if item['valid']:
                        self.assertEqual(contract.validate_ucode_root(case.ucode_root), (1, 1))
                    else:
                        with self.assertRaisesRegex(contract.ContractError, item['error_field']):
                            contract.validate_ucode_root(case.ucode_root)
                with self.subTest(fixture=version, name=item['name'], mode='partial-cli'):
                    case.write_array([base_row(**item['overrides'])])
                    stderr = io.StringIO()
                    if item['valid']:
                        stdout = io.StringIO()
                        with contextlib.redirect_stdout(stdout):
                            self.assertEqual(contract.main(['--ucode-root', str(case.ucode_root)]), 0)
                        self.assertIn('limited partial documents', stdout.getvalue())
                    else:
                        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                            contract.main(['--ucode-root', str(case.ucode_root)])
                        self.assertEqual(raised.exception.code, 2)
                        self.assertIn(item['error_field'], stderr.getvalue())

    def test_malformed_structural_fields_fail_as_contract_error(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        for key in ('record_type', 'profile', 'assessment', 'ingress'):
            with self.subTest(key=key):
                case.write_array([base_row(**{key: []})])
                with self.assertRaises(contract.ContractError):
                    contract.validate_ucode_root(case.ucode_root)

    def test_validator_rejects_bad_revisions_and_undeclared_types(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        for revision in ('step3:', 'step3:has space', 'step3:a:b', 'step3:foo\n'):
            with self.subTest(revision=revision):
                case.write_array([base_row(analysis_revision=revision)])
                with self.assertRaisesRegex(contract.ContractError, 'analysis_revision'):
                    contract.validate_ucode_root(case.ucode_root)
        for typ in ('rpc_surface', 'backend_method'):
            with self.subTest(record_type=typ):
                case.write_array([base_row(record_type=typ)])
                with self.assertRaisesRegex(contract.ContractError, 'record_type'):
                    contract.validate_ucode_root(case.ucode_root)

    def test_validator_rejects_conflicting_caller(self):
        from policy.tests.test_interchange_contract import InterchangeContractTests, base_row
        case = InterchangeContractTests('test_unassessed_taint_path_needs_no_invented_grant')
        case.setUp()
        self.addCleanup(case.tearDown)
        row = base_row(assessment='intended_access', expectation_id='unauthenticated-getFeatures',
                       session_class='root', evidence_refs=['policy:grant:unauthenticated:ubus_http:luci.getFeatures'])
        case.write_array([row])
        with self.assertRaisesRegex(contract.ContractError, 'session_class'):
            contract.validate_ucode_root(case.ucode_root)

    def test_join_rejects_primary_removal_bad_scope_and_policy_identity(self):
        effect = next(e for e in self.effects if e['record_id'] == 'm4:effect:luci-setBlockDetect-system')
        primary, supplementary = contract.join_policy_grants(effect, self.grants, scope='aggregate')
        for caller in ('root', '', None):
            with self.subTest(caller=caller), self.assertRaisesRegex(contract.ContractError, 'session-neutral'):
                contract.join_policy_grants(dict(effect, session_class=caller), self.grants, scope='aggregate')
        for key in ('corpus_revision', 'profile', 'ingress', 'entrypoint_id', 'ubus_object', 'method'):
            with self.subTest(key=key), self.assertRaisesRegex(contract.ContractError, key):
                contract.join_policy_grants(dict(effect, **{key: 'wrong'}), self.grants, scope='aggregate')
        grant = primary[0]
        for key, bad in [('record_type', 'policy_decision'), ('producer', 'step3'), ('evidence_status', 'candidate')]:
            bad_grants = dict(self.grants, **{grant['record_id']: dict(grant, **{key: bad})})
            with self.subTest(key=key), self.assertRaisesRegex(contract.ContractError, 'invalid cited policy grant'):
                contract.join_policy_grants(effect, bad_grants, scope='aggregate')
        self.assertTrue(supplementary)

    def test_caller_conflict_is_not_hidden_by_matching_expectation(self):
        grant = self.grants['policy:grant:unauthenticated:ubus_http:luci.getFeatures']
        row = {k: grant[k] for k in ('corpus_revision', 'profile', 'ingress', 'entrypoint_id', 'ubus_object', 'method', 'expectation_id')}
        row.update(record_type='taint_path', assessment='intended_access', session_class='root', evidence_refs=[grant['record_id']])
        with self.assertRaisesRegex(contract.ContractError, 'session_class'):
            contract.join_policy_grants(row, self.grants, scope='caller')
        row['session_class'] = 'unauthenticated'
        contract.join_policy_grants(row, self.grants, scope='caller')
        with self.assertRaisesRegex(contract.ContractError, 'session_class'):
            contract.join_policy_grants(row, self.grants, scope='caller', requested_caller='root')
