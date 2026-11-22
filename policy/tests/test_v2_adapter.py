import copy
import hashlib
import json
import unittest

from policy.v2_adapter import assess_status
from policy.v2_resolver import ResolutionError


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def retained_inventory():
    """Hash worktree files, including names; omit transient interpreter caches."""
    import os
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    result = {}
    for directory, names, files in os.walk(root):
        names[:] = [name for name in names if name not in {'.git', '__pycache__'}]
        for name in files:
            if name.endswith(('.pyc', '.pyo')) or name == '.git':
                continue
            path = Path(directory) / name
            if path.is_file():
                result[str(path.relative_to(root))] = digest(path.read_bytes())
    return result


class StatusBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.caller_content_raw = b'synthetic client package'
        self.provider_content_raw = b'synthetic provider package'
        self.caller_package_raw = raw({'role': 'caller', 'feed': 'feed-a', 'name': 'client',
                                       'version': '1', 'content_sha256': digest(self.caller_content_raw)})
        self.provider_package_raw = raw({'role': 'provider', 'feed': 'feed-a', 'name': 'provider',
                                         'version': '1', 'content_sha256': digest(self.provider_content_raw)})
        self.corpus_raw = b'synthetic corpus'
        self.profile_raw = b'synthetic profile'
        self.scope = {'caller': 'status-client', 'profile': digest(self.profile_raw),
                      'ingress': 'fixture-transport', 'entrypoint': 'status.read',
                      'packages': {'caller': 'feed-a/client/1@' + digest(self.caller_package_raw),
                                   'provider': 'feed-a/provider/1@' + digest(self.provider_package_raw)}}
        self.pairs = [{'target': 'status', 'operation': 'read'}]
        self.fixture = {'scope': copy.deepcopy(self.scope), 'pairs': copy.deepcopy(self.pairs)}
        self.permission_raw = raw({'caller': 'status-client', 'package': self.scope['packages']['caller'],
                                   'ingress': 'fixture-transport', 'entrypoint': 'status.read',
                                   'corpus': digest(self.corpus_raw), 'profile': digest(self.profile_raw),
                                   'provider': self.scope['packages']['provider'], 'target': 'status',
                                   'operation': 'read', 'pairs': self.pairs, 'allowed': True})
        self.resource_raw = raw({'package': self.scope['packages']['provider'], 'target': 'status',
                                 'operation': 'read', 'pairs': self.pairs, 'corpus': digest(self.corpus_raw),
                                 'profile': digest(self.profile_raw), 'available': True})
        self.policy = {'fixture': [{'id': 'status', 'scope': copy.deepcopy(self.scope),
                                    'pairs': copy.deepcopy(self.pairs)}]}
        self.context = {'corpus': digest(self.corpus_raw), 'profile': self.scope['profile'],
                        'policy': digest(raw(self.policy)), 'inputs': {'status-fixture': digest(raw(self.fixture)),
                                  'caller-package': digest(self.caller_package_raw),
                                  'provider-package': digest(self.provider_package_raw),
                                  'permission': digest(self.permission_raw), 'resource': digest(self.resource_raw)}}
        self.selection = {'context': self.context, 'scope': self.scope, 'pairs': self.pairs}
        self.envelope = {'kind': 'readonly-assessment', 'version': 2, 'context': copy.deepcopy(self.context),
                         'reference': {'authority': 'fixture', 'id': 'status'}, 'verdict': 'intended_access'}

    def run_adapter(self):
        return assess_status(selection=self.selection, envelope_raw=raw(self.envelope),
                             policy_raw=raw(self.policy), fixture_raw=raw(self.fixture),
                             corpus_raw=self.corpus_raw, profile_raw=self.profile_raw,
                             caller_package_raw=self.caller_package_raw, provider_package_raw=self.provider_package_raw,
                             caller_content_raw=self.caller_content_raw, provider_content_raw=self.provider_content_raw,
                             permission_raw=self.permission_raw, resource_raw=self.resource_raw)

    def repin_fixture(self):
        self.context['inputs']['status-fixture'] = digest(raw(self.fixture))
        self.envelope['context'] = copy.deepcopy(self.context)

    def test_selected_fixture(self):
        self.assertEqual(self.run_adapter()['gate'], 'allow')
        self.assertEqual(self.run_adapter()['policy']['status'], 'assessed')

    def test_unsupported_assessed_verdict_rejected_at_api_boundary(self):
        before = retained_inventory()
        self.envelope['verdict'] = 'authorization_violation'
        with self.assertRaisesRegex(ResolutionError, 'unsupported verdict'):
            self.run_adapter()
        self.assertEqual(before, retained_inventory())

    def test_missing_conjuncts_are_unknown(self):
        for key in ('permission_raw', 'resource_raw'):
            with self.subTest(key=key):
                previous = getattr(self, key)
                setattr(self, key, None)
                self.assertEqual(self.run_adapter(), {'gate': 'unknown', 'policy': {'status': 'unassessed'}})
                setattr(self, key, previous)

    def test_bytes_and_version_are_bound(self):
        self.fixture['extra'] = False
        with self.assertRaisesRegex(ResolutionError, 'byte identity'):
            self.run_adapter()
        del self.fixture['extra']
        for version in (1, True, '2', 2.0, None):
            self.envelope['version'] = version
            with self.subTest(version=version), self.assertRaises(ResolutionError):
                self.run_adapter()

    def test_fixture_identity_and_wrong_asserted_reference(self):
        self.fixture['scope']['packages']['provider'] = self.fixture['scope']['packages']['provider'].replace('feed-a', 'feed-b')
        self.repin_fixture()
        with self.assertRaisesRegex(ResolutionError, 'fixture identity'):
            self.run_adapter()
        self.fixture['scope'] = copy.deepcopy(self.scope)
        self.repin_fixture()
        self.envelope['reference']['id'] = 'wrong'
        with self.assertRaisesRegex(ResolutionError, 'missing reference'):
            self.run_adapter()

    def test_conflict_visible_without_gate_evidence(self):
        self.policy['other'] = []
        self.context['policy'] = digest(raw(self.policy))
        self.permission_raw = None
        self.repin_fixture()
        self.assertEqual(self.run_adapter(), {'gate': 'unknown', 'policy': {'status': 'conflict'}})


class SetblockFixture:

    def setUp(self):
        from pathlib import Path
        import io
        import zipfile
        from policy.v2_adapter import _REAL_INPUTS, _REAL_PACKAGES
        root = Path(__file__).resolve().parents[2]
        archive = root / 'evidence/issue89-typed-ae946190-7f532ac/attempt/artifacts'
        with zipfile.ZipFile(io.BytesIO((archive / 'source-archive.zip').read_bytes())) as z:
            source = z.read(z.namelist()[0])
        self.inputs = {'typed': (archive / 'typed.json').read_bytes(), 'source': source,
                       'source-archive': (archive / 'source-archive.zip').read_bytes(),
                       'errors': (archive / 'errors.csv').read_bytes(),
                       'extracted': (archive / 'extracted.csv').read_bytes(),
                       'effects': (archive / 'effects.csv').read_bytes(),
                       'routing': (archive / 'routing.json').read_bytes(),
                       'login': (root / 'policy/fixtures/rpcd.config').read_bytes(),
                       'acl': (root / 'policy/fixtures/luci-mod-system.json').read_bytes()}
        pins = root / 'policy/fixtures/v2-source-pins'
        for key, filename in {'recipe-system': 'luci-mod-system.Makefile',
                              'recipe-base': 'luci-base.Makefile', 'recipe-ssl': 'luci-ssl.Makefile',
                              'recipe-light': 'luci-light.Makefile', 'recipe-admin': 'luci-mod-admin-full.Makefile',
                              'feed-config': 'feeds.conf.default', 'uhttpd-recipe': 'uhttpd.Makefile',
                              'uhttpd-default': 'ubus.default', 'uhttpd-config': 'uhttpd.config',
                              'uhttpd-init': 'uhttpd.init'}.items():
            self.inputs[key] = (pins / filename).read_bytes()
        self.corpus = (root / 'corpus/lock.json').read_bytes()
        self.profile = (root / 'corpus/profiles/luci-ssl-25.12/profile.json').read_bytes()
        self.scope = {'caller': 'luci-mod-system-mounts', 'profile': digest(self.profile),
                      'ingress': 'ubus_http', 'entrypoint': 'ubus_http:luci.setBlockDetect',
                      'packages': copy.deepcopy(_REAL_PACKAGES)}
        self.pairs = [{'target': 'ubus:luci.setBlockDetect', 'operation': 'invoke'}]
        self.policy = raw({'selected': []})
        self.context = {'corpus': digest(self.corpus), 'profile': digest(self.profile),
                        'policy': digest(self.policy), 'inputs': copy.deepcopy(_REAL_INPUTS)}
        self.selection = {'context': self.context, 'scope': self.scope, 'pairs': self.pairs}
        self.envelope = {'kind': 'readonly-assessment', 'version': 2, 'context': copy.deepcopy(self.context),
                         'reference': None, 'verdict': None}

    def run_adapter(self):
        from policy.v2_adapter import assess_setblock
        return assess_setblock(selection=self.selection, envelope_raw=raw(self.envelope),
                               policy_raw=self.policy, corpus_raw=self.corpus,
                               profile_raw=self.profile, inputs=self.inputs)


class SetblockBoundaryTests(SetblockFixture, unittest.TestCase):
    def test_archive_observation_remains_unassessed(self):
        import sys
        result = self.run_adapter()
        self.assertEqual(result['observation'], 'archived-neutral-observation')
        self.assertEqual(result['gate'], 'allow' if sys.platform == 'linux' else 'unknown')
        self.assertEqual(result['policy']['status'], 'unassessed')
        if sys.platform == 'linux':
            self.assertEqual(result['modeled_gate'], 'allow')
        else:
            self.assertEqual(result['modeled_gate'], 'unknown')

    def test_missing_and_mutated_evidence(self):
        for key in list(self.inputs):
            with self.subTest(key=key):
                original = self.inputs.pop(key)
                self.assertEqual(self.run_adapter()['observation'], 'unknown')
                self.inputs[key] = original + b'changed'
                with self.assertRaisesRegex(ResolutionError, 'evidence byte identity'):
                    self.run_adapter()
                self.inputs[key] = original

    def test_no_real_assessment_and_scope_change(self):
        self.envelope['reference'] = {'authority': 'selected', 'id': 'status'}
        self.envelope['verdict'] = 'intended_access'
        with self.assertRaisesRegex(ResolutionError, 'unsupported|missing reference'):
            self.run_adapter()
        self.envelope['reference'] = self.envelope['verdict'] = None
        self.scope['caller'] = 'root'
        with self.assertRaisesRegex(ResolutionError, 'scope'):
            self.run_adapter()


class AssessedSetblockTests(SetblockFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        self.policy = (root / 'corpus/profiles/luci-ssl-25.12/expected-capabilities.json').read_bytes()
        self.context['policy'] = digest(self.policy)
        self.envelope['context'] = copy.deepcopy(self.context)
        self.envelope['reference'] = {'authority': 'openwrt-consumer:luci-ssl-25.12',
                                      'id': 'luci-mod-system-mounts'}
        self.envelope['verdict'] = 'intended_access'

    def test_selected_snapshot_and_unknown_propagation(self):
        import sys
        result = self.run_adapter()
        self.assertEqual(result['policy']['status'], 'assessed' if sys.platform == 'linux' else 'unassessed')
        typed = json.loads(self.inputs['typed'])[0]
        self.assertEqual(result['typed_unknowns'], typed['unknowns'])
        self.assertEqual(result['typed_assumptions'], typed['assumptions'])
        for name in list(self.inputs):
            with self.subTest(name=name):
                saved = self.inputs.pop(name)
                self.assertEqual(self.run_adapter()['policy']['status'], 'unassessed')
                self.inputs[name] = saved

    def test_original_bytes_required_and_bad_reference_rejected(self):
        with self.subTest('projection cannot replace original'):
            self.policy = raw({'openwrt-consumer:luci-ssl-25.12': [{'id': 'luci-mod-system-mounts',
                                'scope': self.scope, 'pairs': self.pairs}]})
            self.context['policy'] = digest(self.policy)
            self.envelope['context'] = copy.deepcopy(self.context)
            with self.assertRaisesRegex(ResolutionError, 'unsupported real assessed policy'):
                self.run_adapter()
        self.setUp()
        for field, value in [('authority', 'other'), ('id', 'root')]:
            with self.subTest(field=field):
                original = self.envelope['reference'][field]
                self.envelope['reference'][field] = value
                with self.assertRaises(ResolutionError):
                    self.run_adapter()
                self.envelope['reference'][field] = original
        self.envelope['verdict'] = 'authorization_violation'
        with self.assertRaisesRegex(ResolutionError, 'unsupported verdict'):
            self.run_adapter()

    def test_projection_validates_entire_registry_and_helper(self):
        from policy.v2_adapter import _project_real_policy
        registry = json.loads(self.policy)
        entry = next(e for e in registry['expectations'] if e['expectation_id'] == 'luci-mod-system-mounts')
        for mutation in ('duplicate', 'profile', 'helper', 'command', 'examples_string', 'invoke'):
            changed = copy.deepcopy(registry)
            selected = next(e for e in changed['expectations'] if e['expectation_id'] == entry['expectation_id'])
            if mutation == 'duplicate':
                changed['expectations'].append(copy.deepcopy(changed['expectations'][0]))
            elif mutation == 'profile':
                changed['profile'] = 'other'
            elif mutation == 'helper':
                selected['allowed_helper_effects'][1]['sink_kind'] = 'popen'
            elif mutation == 'command':
                selected['allowed_helper_effects'][1]['examples'] = ['/sbin/block detect']
            elif mutation == 'examples_string':
                selected['allowed_helper_effects'][1]['examples'] = '/sbin/block detect > /etc/config/fstab'
            else:
                selected['intended_access'][1]['op'] = 'read'
            with self.subTest(mutation=mutation), self.assertRaises(ResolutionError):
                _project_real_policy(raw(changed), self.scope, self.pairs)
        # The unrelated permission is not a prerequisite for this projection.
        entry['intended_access'].pop(0)
        self.assertIn('openwrt-consumer:luci-ssl-25.12',
                      _project_real_policy(raw(registry), self.scope, self.pairs))

    @unittest.skipUnless(__import__('sys').platform == 'linux', 'requires Linux libc oracle')
    def test_real_oracle_gate_negatives_and_matched_conjunction(self):
        from dataclasses import replace
        from unittest.mock import patch
        from policy import oracle
        evaluate = oracle.evaluate_call
        for mutation in ('write_group', 'acl_method', 'matched_group'):
            observed = []
            def modified(**kwargs):
                sid = oracle.MOUNTS_FIXTURE_SID
                original = kwargs['sessions'][sid]
                if mutation == 'write_group':
                    login = replace(original.login, write=[])
                    session = replace(original, login=login,
                                      acls=oracle.session_acls(login, original.acls))
                    kwargs['sessions'] = dict(kwargs['sessions'], **{sid: session})
                elif mutation == 'acl_method':
                    acls = [a for a in original.acls if not (
                        a.group == 'luci-mod-system-mounts' and a.perm == 'write'
                        and a.object == 'luci' and a.function == 'setBlockDetect')]
                    kwargs['sessions'] = dict(kwargs['sessions'], **{sid: replace(original, acls=acls)})
                evaluated = evaluate(**kwargs)
                observed.append(evaluated.outcome)
                if mutation == 'matched_group':
                    self.assertEqual(evaluated.outcome, 'allow')
                    evaluated = replace(evaluated, matched=replace(evaluated.matched, group='other'))
                return evaluated
            with self.subTest(mutation=mutation), patch.object(oracle, 'evaluate_call', side_effect=modified):
                result = self.run_adapter()
                self.assertEqual(observed, ['allow' if mutation == 'matched_group' else 'deny'])
                self.assertEqual(result['gate'], 'unknown')
                self.assertEqual(result['modeled_gate'], 'unknown')
                self.assertEqual(result['policy']['status'], 'unassessed')

    @unittest.skipUnless(__import__('sys').platform == 'linux', 'requires Linux libc oracle')
    def test_root_support_is_independent_of_delegated_assessment(self):
        from unittest.mock import patch
        from policy import oracle

        before = retained_inventory()
        baseline = self.run_adapter()
        self.assertEqual((baseline['gate'], baseline['policy']['status']), ('allow', 'assessed'))
        evaluate = oracle.evaluate_call
        observed = []

        def with_root(**kwargs):
            mounts = kwargs['sessions'][oracle.MOUNTS_FIXTURE_SID]
            logins = {login.username: login for login in
                      oracle.parse_rpcd_logins(self.inputs['login'].decode())}
            root_login = logins['root']
            root = oracle.Session(session_class='root', sid=oracle.ROOT_FIXTURE_SID,
                                  login=root_login, acls=oracle.session_acls(root_login, mounts.acls))
            kwargs['sessions'] = dict(kwargs['sessions'], **{oracle.ROOT_FIXTURE_SID: root})
            root_result = evaluate(**dict(kwargs, session_class='root', sid=oracle.ROOT_FIXTURE_SID))
            self.assertIsNotNone(root_result.matched)
            observed.append((root_result.outcome, root_result.matched.group, root_result.matched.perm,
                             root_result.matched.object, root_result.matched.function, root_result.matched.source))
            return evaluate(**kwargs)

        with patch.object(oracle, 'evaluate_call', side_effect=with_root):
            self.assertEqual(self.run_adapter(), baseline)
        self.assertEqual(observed, [('allow', 'luci-mod-system-mounts', 'write', 'luci',
                                     'setBlockDetect', 'luci-mod-system.json')])
        self.assertEqual(self.run_adapter(), baseline)  # Remove supplementary root again.

        def root_without_primary(**kwargs):
            mounts = kwargs['sessions'][oracle.MOUNTS_FIXTURE_SID]
            root_login = next(login for login in oracle.parse_rpcd_logins(
                self.inputs['login'].decode()) if login.username == 'root')
            root = oracle.Session(session_class='root', sid=oracle.ROOT_FIXTURE_SID,
                                  login=root_login, acls=oracle.session_acls(root_login, mounts.acls))
            # Root can access the operation, but a missing mounts SID cannot borrow it.
            self.assertEqual(evaluate(**dict(kwargs, session_class='root', sid=oracle.ROOT_FIXTURE_SID,
                                             sessions={oracle.ROOT_FIXTURE_SID: root})).outcome, 'allow')
            result = evaluate(**dict(kwargs, sessions={oracle.ROOT_FIXTURE_SID: root}))
            self.assertEqual(result.outcome, 'deny')
            return result

        with patch.object(oracle, 'evaluate_call', side_effect=root_without_primary):
            result = self.run_adapter()
        self.assertEqual((result['gate'], result['policy']['status']), ('unknown', 'unassessed'))
        self.assertEqual(before, retained_inventory())

    @unittest.skipUnless(__import__('sys').platform == 'linux', 'requires Linux libc oracle')
    def test_acl_growth_does_not_expand_selected_real_policy(self):
        from dataclasses import replace
        from unittest.mock import patch
        from policy import oracle

        before = retained_inventory()
        baseline = self.run_adapter()
        self.assertEqual((baseline['gate'], baseline['policy']['status']), ('allow', 'assessed'))
        evaluate = oracle.evaluate_call
        observed = []

        def expanded(**kwargs):
            sid = oracle.MOUNTS_FIXTURE_SID
            session = kwargs['sessions'][sid]
            self.assertEqual(evaluate(**dict(kwargs, function='extraOperation')).outcome, 'deny')
            extra = oracle.AclEntry('luci-mod-system-mounts', 'write', 'ubus', 'luci',
                                    'extraOperation', 'in-memory-control')
            kwargs['sessions'] = {sid: replace(session, acls=session.acls + [extra])}
            observed.append(evaluate(**dict(kwargs, function='extraOperation')).outcome)
            return evaluate(**kwargs)

        with patch.object(oracle, 'evaluate_call', side_effect=expanded):
            self.assertEqual(self.run_adapter(), baseline)
            # The same supported real query remains allowed without an applicable
            # selected expectation; expanded ACL facts do not supply intent.
            self.policy = raw({'selected': []})
            self.context['policy'] = digest(self.policy)
            self.envelope['context'] = copy.deepcopy(self.context)
            self.envelope['reference'] = self.envelope['verdict'] = None
            result = self.run_adapter()
            self.assertEqual((result['gate'], result['policy']['status']), ('allow', 'unassessed'))
        self.assertEqual(observed, ['allow', 'allow'])
        self.assertEqual(before, retained_inventory())

    def test_assessed_api_does_not_open_files(self):
        from unittest.mock import patch
        before = retained_inventory()
        self.run_adapter()  # Initialize Linux libc before forbidding file opens.
        with patch('builtins.open', side_effect=AssertionError('unexpected open')), \
             patch('os.open', side_effect=AssertionError('unexpected os.open')):
            self.run_adapter()
            self.envelope['reference']['id'] = 'other'
            with self.assertRaises(ResolutionError):
                self.run_adapter()
        self.assertEqual(before, retained_inventory())

    def test_assessed_cli_read_only_and_invalid_verdict(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            values = {'selection': raw(self.selection), 'envelope': raw(self.envelope),
                      'policy': self.policy, 'corpus': self.corpus, 'profile': self.profile}
            for name, value in values.items():
                (base / name).write_bytes(value)
            for name, value in self.inputs.items():
                (base / ('evidence-' + name)).write_bytes(value)
            command = [sys.executable, '-B', '-m', 'policy.v2_adapter', '--family', 'setblock']
            for name in values:
                command.extend(['--' + name, str(base / name)])
            for name in self.inputs:
                command.extend(['--evidence', name + '=' + str(base / ('evidence-' + name))])
            inventory = lambda: {p.name: digest(p.read_bytes()) for p in base.iterdir()}
            before, retained = inventory(), retained_inventory()
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['policy']['status'],
                             'assessed' if sys.platform == 'linux' else 'unassessed')
            self.assertEqual(inventory(), before)
            self.assertEqual(retained_inventory(), retained)
            self.envelope['verdict'] = 'authorization_violation'
            (base / 'envelope').write_bytes(raw(self.envelope))
            before = inventory()
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'unsupported verdict', result.stderr)
            self.assertEqual(inventory(), before)
            self.assertEqual(retained_inventory(), retained)

    def test_scope_and_operations_are_exact(self):
        for field, value in [('caller', 'root'), ('ingress', 'ubus'),
                             ('entrypoint', 'ubus_http:luci.getBlockDevices')]:
            saved = self.scope[field]
            self.scope[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ResolutionError, 'scope'):
                self.run_adapter()
            self.scope[field] = saved
        for field, value in [('target', 'ubus:luci.getBlockDevices'), ('operation', 'exec')]:
            saved = self.pairs[0][field]
            self.pairs[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ResolutionError, 'scope'):
                self.run_adapter()
            self.pairs[0][field] = saved


class ReadOnlyTests(StatusBoundaryTests):
    def test_no_files_opened_by_api_on_success_or_failure(self):
        from unittest.mock import patch
        before = retained_inventory()
        with patch('builtins.open', side_effect=AssertionError('unexpected open')), \
             patch('os.open', side_effect=AssertionError('unexpected os.open')):
            self.assertEqual(self.run_adapter()['gate'], 'allow')
            self.envelope['version'] = 1
            with self.assertRaises(ResolutionError):
                self.run_adapter()
        self.assertEqual(before, retained_inventory())

    def test_cli_success_and_failure_do_not_write_files(self):
        from pathlib import Path
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            values = {'selection': raw(self.selection), 'envelope': raw(self.envelope),
                      'policy': raw(self.policy), 'fixture': raw(self.fixture),
                      'corpus': self.corpus_raw, 'profile': self.profile_raw,
                      'caller-package': self.caller_package_raw, 'provider-package': self.provider_package_raw,
                      'caller-content': self.caller_content_raw, 'provider-content': self.provider_content_raw,
                      'permission': self.permission_raw, 'resource': self.resource_raw}
            for name, value in values.items():
                (base / name).write_bytes(value)
            before = {p.name: digest(p.read_bytes()) for p in base.iterdir()}
            command = [sys.executable, '-B', '-m', 'policy.v2_adapter', '--family', 'status']
            for name in values:
                command.extend(['--' + name, str(base / name)])
            retained = retained_inventory()
            success = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(json.loads(success.stdout)['gate'], 'allow')
            self.assertEqual(before, {p.name: digest(p.read_bytes()) for p in base.iterdir()})
            self.assertEqual(retained, retained_inventory())
            self.envelope['verdict'] = 'authorization_violation'
            (base / 'envelope').write_bytes(raw(self.envelope))
            before = {p.name: digest(p.read_bytes()) for p in base.iterdir()}
            retained = retained_inventory()
            unsupported = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(unsupported.returncode, 2)
            self.assertEqual(unsupported.stdout, b'')
            self.assertIn(b'unsupported verdict', unsupported.stderr)
            self.assertEqual(before, {p.name: digest(p.read_bytes()) for p in base.iterdir()})
            self.assertEqual(retained, retained_inventory())
            self.envelope['verdict'] = 'intended_access'
            self.envelope['version'] = 1
            (base / 'envelope').write_bytes(raw(self.envelope))
            before = {p.name: digest(p.read_bytes()) for p in base.iterdir()}
            retained = retained_inventory()
            failure = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(failure.returncode, 2)
            self.assertEqual(before, {p.name: digest(p.read_bytes()) for p in base.iterdir()})
            self.assertEqual(retained, retained_inventory())


class ArchiveSemanticTests(SetblockBoundaryTests):
    def test_independent_semantic_mutations(self):
        from policy.v2_adapter import _validate_archive
        mutations = {
            'errors': self.inputs['errors'] + b'"failure","x","y"\n',
            'effects': self.inputs['effects'].replace(b'/sbin/block detect', b'/sbin/block mount'),
            'extracted': self.inputs['extracted'].replace(b'ucode/luci', b'ucode/other'),
            'routing': self.inputs['routing'].replace(b'plain_route_selected', b'not_selected'),
            'source': self.inputs['source'].replace(b'/sbin/block detect > /etc/config/fstab', b'/sbin/block mount > /etc/config/fstab'),
        }
        _validate_archive(self.inputs)
        for key, mutated in mutations.items():
            with self.subTest(key=key):
                changed = dict(self.inputs, **{key: mutated})
                with self.assertRaises(ResolutionError):
                    _validate_archive(changed)

    def test_real_api_no_file_opens(self):
        from unittest.mock import patch
        # On Linux, initialize the libc evaluator before blocking Python file opens.
        self.run_adapter()
        before = retained_inventory()
        with patch('builtins.open', side_effect=AssertionError('unexpected open')), \
             patch('os.open', side_effect=AssertionError('unexpected os.open')):
            self.assertIn(self.run_adapter()['gate'], ('allow', 'unknown'))
            self.inputs.pop('errors')
            self.assertEqual(self.run_adapter()['observation'], 'unknown')
        self.assertEqual(before, retained_inventory())


class PackageIdentityTests(StatusBoundaryTests):
    def test_manifest_content_and_feed_cannot_be_relabelled(self):
        self.caller_content_raw = b'wrong content'
        with self.assertRaisesRegex(ResolutionError, 'manifest identity'):
            self.run_adapter()
        self.caller_content_raw = b'synthetic client package'
        self.scope['packages']['caller'] = self.scope['packages']['caller'].replace('feed-a/', 'feed-b/')
        with self.assertRaisesRegex(ResolutionError, 'manifest identity'):
            self.run_adapter()

    def test_unknown_identity_rejected(self):
        self.scope['packages']['caller'] = 'unknown/unknown/unknown@sha256:' + '0' * 64
        with self.assertRaises(ResolutionError):
            self.run_adapter()


class RealCLITests(SetblockBoundaryTests):
    def test_real_cli_success_failure_inventory(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            values = {'selection': raw(self.selection), 'envelope': raw(self.envelope),
                      'policy': self.policy, 'corpus': self.corpus, 'profile': self.profile}
            for name, value in values.items():
                (base / name).write_bytes(value)
            for name, value in self.inputs.items():
                (base / ('evidence-' + name)).write_bytes(value)
            command = [sys.executable, '-B', '-m', 'policy.v2_adapter', '--family', 'setblock']
            for name in values:
                command.extend(['--' + name, str(base / name)])
            for name in self.inputs:
                command.extend(['--evidence', name + '=' + str(base / ('evidence-' + name))])
            inventory = lambda: {p.name: digest(p.read_bytes()) for p in base.iterdir()}
            before = inventory()
            retained = retained_inventory()
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['gate'], 'allow' if sys.platform == 'linux' else 'unknown')
            self.assertEqual(inventory(), before)
            self.assertEqual(retained, retained_inventory())
            (base / 'evidence-errors').write_bytes(b'invalid')
            before = inventory()
            retained = retained_inventory()
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(inventory(), before)
            self.assertEqual(retained, retained_inventory())


class ReviewRegressionTests(StatusBoundaryTests):
    def test_same_package_identity_different_roles_rejected(self):
        self.provider_content_raw = self.caller_content_raw
        self.provider_package_raw = raw({'role': 'provider', 'feed': 'feed-a', 'name': 'client',
                                         'version': '1', 'content_sha256': digest(self.provider_content_raw)})
        self.scope['packages']['provider'] = 'feed-a/client/1@' + digest(self.provider_package_raw)
        self.context['inputs']['provider-package'] = digest(self.provider_package_raw)
        self.fixture['scope'] = copy.deepcopy(self.scope)
        self.policy['fixture'][0]['scope'] = copy.deepcopy(self.scope)
        self.context['policy'] = digest(raw(self.policy))
        self.repin_fixture()
        with self.assertRaisesRegex(ResolutionError, 'selected scope'):
            self.run_adapter()

    def test_profile_change_does_not_reuse_old_permission_or_resource(self):
        self.profile_raw = b'different synthetic profile'
        self.context['profile'] = digest(self.profile_raw)
        self.scope['profile'] = self.context['profile']
        self.fixture['scope'] = copy.deepcopy(self.scope)
        self.policy['fixture'][0]['scope'] = copy.deepcopy(self.scope)
        self.context['policy'] = digest(raw(self.policy))
        self.repin_fixture()
        self.assertEqual(self.run_adapter()['gate'], 'unknown')
        permission = json.loads(self.permission_raw)
        permission['profile'] = self.context['profile']
        self.permission_raw = raw(permission)
        self.context['inputs']['permission'] = digest(self.permission_raw)
        self.envelope['context'] = copy.deepcopy(self.context)
        self.assertEqual(self.run_adapter()['gate'], 'unknown')
        resource = json.loads(self.resource_raw)
        resource['profile'] = self.context['profile']
        self.resource_raw = raw(resource)
        self.context['inputs']['resource'] = digest(self.resource_raw)
        self.envelope['context'] = copy.deepcopy(self.context)
        self.assertEqual(self.run_adapter()['gate'], 'allow')


class ArchiveReviewRegressionTests(SetblockBoundaryTests):
    def test_coherent_extraction_and_routing_root_substitution_rejected(self):
        from policy.v2_adapter import _validate_archive
        changed = dict(self.inputs)
        changed['extracted'] = changed['extracted'].replace(b'/root/workspace/', b'/other/workspace/')
        changed['routing'] = changed['routing'].replace(b'/root/workspace/', b'/other/workspace/')
        with self.assertRaisesRegex(ResolutionError, 'extraction inventory'):
            _validate_archive(changed)

    def test_source_name_substring_is_not_system_call(self):
        from policy.v2_adapter import _validate_archive
        changed = dict(self.inputs, source=self.inputs['source'].replace(b'system(\'/sbin/block detect',
                                                                          b'not_system(\'/sbin/block detect'))
        with self.assertRaisesRegex(ResolutionError, 'source command'):
            _validate_archive(changed)

    def test_invented_real_packages_rejected(self):
        self.scope['packages']['caller'] = 'other/luci-mod-system/1@sha256:' + 'a' * 64
        with self.assertRaisesRegex(ResolutionError, 'unsupported real scope'):
            self.run_adapter()


class ProviderBindingTests(StatusBoundaryTests):
    def test_permission_does_not_transfer_to_other_feed(self):
        provider_manifest = json.loads(self.provider_package_raw)
        provider_manifest['feed'] = 'feed-b'
        self.provider_package_raw = raw(provider_manifest)
        self.scope['packages']['provider'] = 'feed-b/provider/1@' + digest(self.provider_package_raw)
        self.context['inputs']['provider-package'] = digest(self.provider_package_raw)
        self.fixture['scope'] = copy.deepcopy(self.scope)
        self.policy['fixture'][0]['scope'] = copy.deepcopy(self.scope)
        self.context['policy'] = digest(raw(self.policy))
        resource = json.loads(self.resource_raw)
        resource['package'] = self.scope['packages']['provider']
        self.resource_raw = raw(resource)
        self.context['inputs']['resource'] = digest(self.resource_raw)
        self.repin_fixture()
        self.assertEqual(self.run_adapter()['gate'], 'unknown')
        permission = json.loads(self.permission_raw)
        permission['provider'] = self.scope['packages']['provider']
        self.permission_raw = raw(permission)
        self.context['inputs']['permission'] = digest(self.permission_raw)
        self.envelope['context'] = copy.deepcopy(self.context)
        self.assertEqual(self.run_adapter()['gate'], 'allow')
        self.assertEqual(self.run_adapter()['policy']['status'], 'assessed')


class ArchiveMembershipTests(SetblockBoundaryTests):
    def test_exact_archive_membership_and_content(self):
        import io
        import stat
        import zipfile
        from policy.v2_adapter import _ARCHIVE_SOURCE, _validate_source_archive
        member = _ARCHIVE_SOURCE.lstrip('/')
        def archive(rows):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as z:
                for name, content in rows:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    z.writestr(info, content)
            return buf.getvalue()
        _validate_source_archive(self.inputs['source-archive'], self.inputs['source'])
        for rows in ([(member + '.other', self.inputs['source'])],
                     [(member, b'wrong')], [(member, self.inputs['source']), ('extra', b'x')]):
            with self.subTest(rows=rows[0][0]), self.assertRaises(ResolutionError):
                _validate_source_archive(archive(rows), self.inputs['source'])


class ExpandedContractTests(StatusBoundaryTests):
    def test_multitarget_policy_requires_every_operation(self):
        self.pairs.append({'target': 'status-metadata', 'operation': 'inspect'})
        self.fixture['pairs'] = copy.deepcopy(self.pairs)
        for attribute, key in (('permission_raw', 'permission'), ('resource_raw', 'resource')):
            document = json.loads(getattr(self, attribute))
            document['pairs'] = copy.deepcopy(self.pairs)
            setattr(self, attribute, raw(document))
            self.context['inputs'][key] = digest(getattr(self, attribute))
        self.repin_fixture()
        with self.assertRaisesRegex(ResolutionError, 'inapplicable reference'):
            self.run_adapter()
        self.policy['fixture'][0]['pairs'] = copy.deepcopy(self.pairs)
        self.context['policy'] = digest(raw(self.policy))
        self.envelope['context'] = copy.deepcopy(self.context)
        self.assertEqual(self.run_adapter()['policy']['status'], 'assessed')

    def test_primary_cannot_borrow_supplementary_root_scope(self):
        root_scope = copy.deepcopy(self.scope)
        root_scope['caller'] = 'root'
        self.policy['fixture'].append({'id': 'root', 'scope': root_scope, 'pairs': copy.deepcopy(self.pairs)})
        self.context['policy'] = digest(raw(self.policy))
        self.envelope['context'] = copy.deepcopy(self.context)
        self.envelope['reference']['id'] = 'root'
        with self.assertRaisesRegex(ResolutionError, 'inapplicable reference'):
            self.run_adapter()
        self.envelope['reference']['id'] = 'status'
        self.assertEqual(self.run_adapter()['policy']['status'], 'assessed')


class SourceModelControls(SetblockBoundaryTests):
    def test_each_recipe_and_feed_is_required(self):
        from policy.v2_adapter import _validate_source_model
        profile = json.loads(self.profile)
        _validate_source_model(self.inputs, profile)
        changes = {'recipe-system': (b'+luci-base', b'+other'),
                   'recipe-admin': (b'+luci-mod-system', b'+other'),
                   'recipe-light': (b'+luci-mod-admin-full', b'+other'),
                   'recipe-ssl': (b'+luci-light', b'+other'),
                   'recipe-base': (b'PKG_NAME:=luci-base', b'PKG_NAME:=other'),
                   'feed-config': (b'src-git luci ', b'src-git other '),
                   'uhttpd-recipe': (b'./files/ubus.default', b'./files/other.default'),
                   'uhttpd-default': (b'uci set uhttpd.main.ubus_prefix=/ubus', b'uci set uhttpd.main.ubus_prefix=/other'),
                   'uhttpd-config': (b'#\toption ubus_prefix\t/ubus', b'#\toption ubus_prefix\t/other'),
                   'uhttpd-init': (b'append_arg "$cfg" ubus_prefix "-u"', b'append_arg "$cfg" ubus_prefix "-x"')}
        for key, (old, new) in changes.items():
            with self.subTest(key=key), self.assertRaises(ResolutionError):
                _validate_source_model(dict(self.inputs, **{key: self.inputs[key].replace(old, new)}), profile)

    def test_acl_growth_is_rejected_before_any_real_assessment(self):
        acl = json.loads(self.inputs['acl'])
        acl['luci-mod-system-mounts']['write']['ubus']['luci'].append('extraOperation')
        self.inputs['acl'] = raw(acl)
        with self.assertRaisesRegex(ResolutionError, 'evidence byte identity'):
            self.run_adapter()

    def test_zip_symlink_is_rejected(self):
        import io
        import stat
        import zipfile
        from policy.v2_adapter import _ARCHIVE_SOURCE, _validate_source_archive
        content = io.BytesIO()
        with zipfile.ZipFile(content, 'w') as z:
            info = zipfile.ZipInfo(_ARCHIVE_SOURCE.lstrip('/'))
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, self.inputs['source'])
        with self.assertRaisesRegex(ResolutionError, 'source inventory'):
            _validate_source_archive(content.getvalue(), self.inputs['source'])


class FiniteOperationControls(StatusBoundaryTests):
    def configure_pairs(self, added):
        self.pairs.append(added)
        self.fixture['pairs'] = copy.deepcopy(self.pairs)
        for attribute, key in (('permission_raw', 'permission'), ('resource_raw', 'resource')):
            document = json.loads(getattr(self, attribute))
            document['pairs'] = copy.deepcopy(self.pairs)
            setattr(self, attribute, raw(document))
            self.context['inputs'][key] = digest(getattr(self, attribute))
        self.repin_fixture()

    def test_unsupported_pair_rejected_even_if_all_evidence_and_policy_claim_it(self):
        self.configure_pairs({'target': 'resource:synthetic-unmodeled', 'operation': 'approve'})
        self.policy['fixture'][0]['pairs'] = copy.deepcopy(self.pairs)
        self.context['policy'] = digest(raw(self.policy))
        self.envelope['context'] = copy.deepcopy(self.context)
        with self.assertRaisesRegex(ResolutionError, 'invalid selected scope'):
            self.run_adapter()

    def test_synthetic_permission_growth_does_not_expand_policy(self):
        self.configure_pairs({'target': 'status-metadata', 'operation': 'inspect'})
        self.envelope['reference'] = self.envelope['verdict'] = None
        self.assertEqual(self.run_adapter(), {'gate': 'allow', 'policy': {'status': 'unassessed'}})
        self.envelope['reference'] = {'authority': 'fixture', 'id': 'status'}
        self.envelope['verdict'] = 'intended_access'
        with self.assertRaisesRegex(ResolutionError, 'inapplicable reference'):
            self.run_adapter()
        self.policy['fixture'][0]['pairs'] = copy.deepcopy(self.pairs)
        self.context['policy'] = digest(raw(self.policy))
        self.envelope['context'] = copy.deepcopy(self.context)
        self.assertEqual(self.run_adapter()['policy']['status'], 'assessed')
