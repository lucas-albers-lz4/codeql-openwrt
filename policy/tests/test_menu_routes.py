"""Source-only declaration controls; no dispatcher semantics are evaluated."""
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    from corpus import menu_routes
except ImportError:
    menu_routes = None


class MenuRouteTests(unittest.TestCase):
    def test_two_documents_keep_both_contributions_to_one_route(self):
        self.assertIsNotNone(menu_routes, 'source-only collector is not implemented')
        rows = menu_routes.observe_documents({
            'a.json': b'{"admin/example": {"title": "First"}}',
            'b.json': b'{"admin/example": {"order": 2}}',
        })
        self.assertEqual(rows, [
            {'source': 'a.json', 'route': 'admin/example',
             'json_pointer': '/admin~1example', 'spec': {'title': 'First'}},
            {'source': 'b.json', 'route': 'admin/example',
             'json_pointer': '/admin~1example', 'spec': {'order': 2}},
        ])
    def test_parent_auth_and_empty_child_auth_are_not_inherited(self):
        rows = menu_routes.observe_documents({'base.json': b'''{
            "admin": {"auth": {"methods": ["cookie:test"], "login": true}},
            "admin/ubus/*": {"auth": {}},
            "admin/no-auth-field": {"action": {"type": "view"}},
            "admin~literal": {"custom": [1, false, null]}
        }'''})
        by_route = {row['route']: row for row in rows}
        self.assertEqual(by_route['admin']['spec']['auth']['methods'], ['cookie:test'])
        self.assertEqual(by_route['admin/ubus/*']['spec'], {'auth': {}})
        self.assertNotIn('auth', by_route['admin/no-auth-field']['spec'])
        self.assertEqual(by_route['admin~literal']['json_pointer'], '/admin~0literal')
        self.assertEqual(by_route['admin~literal']['spec'], {'custom': [1, False, None]})

    def test_ambiguous_or_unsupported_json_is_not_silently_inventoried(self):
        invalid = [
            b'{"admin": {}, "admin": {"title": "replacement"}}',
            b'{"admin": {"auth": {}, "auth": {}}}',
            b'{"admin": {"custom": NaN}}',
            b'{"admin": {"custom": Infinity}}',
            b'{"admin": []}', b'[]', b'{broken', b'\xff',
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                menu_routes.observe_documents({'source.json': raw})


class PinnedMenuCollectorTests(unittest.TestCase):
    def test_retained_corpus_and_report_match_source_first_identity_list(self):
        root = Path(__file__).resolve().parents[2]
        corpus = root / 'corpus/menu-route-sources'
        report_path = root / 'reports/m4-menu-route-provenance.json'
        self.assertTrue(report_path.is_file(), 'retained provenance report is missing')
        report = menu_routes.strict_json(report_path.read_bytes())
        expected = menu_routes.strict_json((root / 'policy/tests/fixtures/menu-route-expected-v1.json').read_bytes())
        pinned = menu_routes.strict_json((root / 'policy/tests/fixtures/menu-route-pinned-v1.json').read_bytes())
        pinned_keys = {'kind', 'version', 'evidence_need', 'profile', 'corpus_revision',
                       'luci_pin', 'luci_url', 'source_tree', 'selection', 'ordering',
                       'semantics', 'runtime_executed', 'package_scope', 'source_evidence',
                       'files', 'unknowns'}
        self.assertEqual(set(pinned), pinned_keys)
        self.assertEqual(set(report), pinned_keys | {'scope_inputs_sha256', 'declarations',
                                                     'counts', 'duplicate_route_keys'})
        # Canonical JSON comparison keeps booleans, integers and floats distinct.
        for key, value in pinned.items():
            self.assertEqual(json.dumps(report[key], sort_keys=True), json.dumps(value, sort_keys=True), key)
        self.assertEqual(report['corpus_revision'], 'sha256:' + hashlib.sha256(
            (root / 'corpus/lock.json').read_bytes()).hexdigest())
        counts = {route: sum(row['route'] == route for row in report['declarations'])
                  for route in {row['route'] for row in report['declarations']}}
        derived_counts = {'source_files': len(report['files']),
                          'declarations': len(report['declarations']),
                          'distinct_route_keys': len(counts)}
        self.assertEqual(json.dumps(report['counts'], sort_keys=True), json.dumps(derived_counts, sort_keys=True))
        self.assertEqual(report['duplicate_route_keys'], sorted(k for k, n in counts.items() if n > 1))
        self.assertEqual(sorted(str(p.relative_to(corpus)) for p in corpus.rglob('*.json')), sorted(expected))
        self.assertEqual(sorted(row['source'] for row in report['files']), sorted(expected))
        self.assertEqual(sorted((row['source'], row['route']) for row in report['declarations']),
                         sorted((source, route) for source, routes in expected.items() for route in routes))
        self.assertEqual(set(report['scope_inputs_sha256']), {'corpus/luci_ssl_files.py', 'corpus/menu_routes.py'})
        for name in ('corpus/luci_ssl_files.py', 'corpus/menu_routes.py'):
            self.assertEqual(report['scope_inputs_sha256'][name], hashlib.sha256((root / name).read_bytes()).hexdigest())
        self.assertEqual(report['semantics'], 'unassessed')
        self.assertIs(report['runtime_executed'], False)
        for file in report['files']:
            raw = (corpus / file['source']).read_bytes()
            document = menu_routes.strict_json(raw)
            self.assertEqual(sorted(document), sorted(expected[file['source']]))
            self.assertEqual(file['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(file['source_blob'], hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
            self.assertEqual(file['bytes'], len(raw))
            self.assertEqual(file['installed'], '/usr/share/luci/menu.d/' + Path(file['source']).name)
            for row in report['declarations']:
                self.assertEqual(set(row), {'source', 'route', 'json_pointer', 'spec', 'source_blob', 'installed'})
                if row['source'] != file['source']:
                    continue
                self.assertEqual(json.dumps(row['spec'], sort_keys=True), json.dumps(document[row['route']], sort_keys=True))
                self.assertEqual(row['source_blob'], file['source_blob'])
                self.assertEqual(row['installed'], file['installed'])
                self.assertEqual(row['json_pointer'], '/' + row['route'].replace('~', '~0').replace('/', '~1'))

    def test_wrong_profile_or_source_pin_is_rejected_before_source_read(self):
        self.assertTrue(hasattr(menu_routes, 'collect'), 'pinned collector is missing')
        root = Path(__file__).resolve().parents[2]
        lock = json.loads((root / 'corpus/lock.json').read_bytes())
        for key in ('profile', 'pin'):
            changed = json.loads(json.dumps(lock))
            if key == 'profile':
                changed['profile'] = 'other-profile'
            else:
                changed['repos']['luci']['sha'] = '0' * 40
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'lock.json'
                path.write_text(json.dumps(changed), encoding='utf-8')
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'profile or LuCI pin changed'):
                    menu_routes.collect(Path(directory) / 'not-a-repo', lockfile=path)

    @unittest.skipUnless(os.environ.get('MENU_LUCI_GIT'), 'set MENU_LUCI_GIT for pinned Git read')
    def test_pinned_git_and_actual_cli_agree(self):
        self.assertTrue(hasattr(menu_routes, 'collect'), 'pinned collector is missing')
        repo = Path(os.environ['MENU_LUCI_GIT'])
        root = Path(__file__).resolve().parents[2]
        report = menu_routes.collect(repo)
        expected_packages = {
            'luci-base', 'luci-mod-network', 'luci-mod-status', 'luci-mod-system',
            'luci-app-firewall', 'luci-app-package-manager',
        }
        self.assertEqual({row['package'] for row in report['files']}, expected_packages)
        self.assertEqual(len(report['files']), 6)
        self.assertEqual(report['corpus_revision'], 'sha256:' + hashlib.sha256(
            (root / 'corpus/lock.json').read_bytes()).hexdigest())
        self.assertEqual(report['semantics'], 'unassessed')
        self.assertFalse(report['runtime_executed'])
        self.assertEqual(report['duplicate_route_keys'], [])
        self.assertEqual(len(report['declarations']), 60)
        process = subprocess.run([sys.executable, '-B', '-m', 'corpus.menu_routes',
                                  '--luci-git', str(repo)], cwd=root,
                                 capture_output=True, check=True)
        self.assertEqual(json.loads(process.stdout), report)
        self.assertEqual(process.stdout, (root / 'reports/m4-menu-route-provenance.json').read_bytes())
        for file in report['files']:
            self.assertEqual(menu_routes.git(repo, 'cat-file', 'blob', file['source_blob']),
                             (root / 'corpus/menu-route-sources' / file['source']).read_bytes())
        self.assertEqual(process.stderr, b'')


def coherent_forgery(clone, *, omit=False):
    report_path = clone / 'reports/m4-menu-route-provenance.json'
    report = json.loads(report_path.read_bytes())
    file = next(x for x in report['files'] if x['package'] == 'luci-base')
    source = clone / 'corpus/menu-route-sources' / file['source']
    doc = json.loads(source.read_bytes())
    if omit:
        del doc['admin/ubus/*']
        identity = clone / 'policy/tests/fixtures/menu-route-expected-v1.json'
        expected = json.loads(identity.read_bytes())
        expected[file['source']].remove('admin/ubus/*')
        identity.write_text(json.dumps(expected), encoding='utf-8')
        report['declarations'] = [r for r in report['declarations']
                                  if not (r['source'] == file['source'] and r['route'] == 'admin/ubus/*')]
        report['counts']['declarations'] -= 1
        report['counts']['distinct_route_keys'] -= 1
    else:
        doc['admin/ubus/*']['auth'] = {'methods': ['cookie:fake']}
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + '\n').encode()
    source.write_bytes(data)
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    file.update(source_blob=blob, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    for row in report['declarations']:
        if row['source'] == file['source']:
            row['source_blob'] = blob
            row['spec'] = doc[row['route']]
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def child_python():
    return [sys.executable, '-B', *(['-O'] if sys.flags.optimize else [])]


class RetainedMutationTests(unittest.TestCase):
    def test_coherent_source_and_metadata_mutations_are_rejected_offline(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory)
            for name in ('corpus', 'policy', 'reports'):
                shutil.copytree(root / name, clone / name,
                                ignore=shutil.ignore_patterns('__pycache__'))
            report_path = clone / 'reports/m4-menu-route-provenance.json'
            original = report_path.read_bytes()
            report = json.loads(original)
            file = next(x for x in report['files'] if x['package'] == 'luci-base')
            source = clone / 'corpus/menu-route-sources' / file['source']
            raw = source.read_bytes()
            identity = clone / 'policy/tests/fixtures/menu-route-expected-v1.json'
            identity_original = identity.read_bytes()
            mutations = {
                'coherent_source': None,
                'coherent_omission': None,
                'declaration_extra_semantics': lambda: dict(report, declarations=[dict(report['declarations'][0], effective_auth='open'), *report['declarations'][1:]]),
                'pin': lambda: dict(report, luci_pin='0' * 40),
                'profile': lambda: dict(report, profile='false'),
                'tree': lambda: dict(report, source_tree='0' * 40),
                'lock': lambda: dict(report, corpus_revision='sha256:' + '0' * 64),
                'package_scope': lambda: dict(report, package_scope=[]),
                'package_entry_deleted': lambda: dict(report, package_scope=report['package_scope'][1:]),
                'source_evidence': lambda: dict(report, source_evidence=[]),
                'source_evidence_deleted': lambda: dict(report, source_evidence=report['source_evidence'][1:]),
                'counts': lambda: dict(report, counts={'source_files': 0, 'declarations': 0, 'distinct_route_keys': 0}),
                'count_wrong_type': lambda: dict(report, counts={'source_files': 6.0, 'declarations': 60, 'distinct_route_keys': 60}),
                'duplicates': lambda: dict(report, duplicate_route_keys=['fake']),
                'unknowns': lambda: dict(report, unknowns=[]),
                'unknown_deleted': lambda: dict(report, unknowns=report['unknowns'][1:]),
            }
            for label, mutate in mutations.items():
                with self.subTest(mutation=label):
                    source.write_bytes(raw)
                    identity.write_bytes(identity_original)
                    report_path.write_bytes(original)
                    if mutate is None:
                        coherent_forgery(clone, omit=label == 'coherent_omission')
                    else:
                        report_path.write_text(json.dumps(mutate()), encoding='utf-8')
                    result = subprocess.run([*child_python(), '-m', 'unittest',
                        'policy.tests.test_menu_routes.PinnedMenuCollectorTests.test_retained_corpus_and_report_match_source_first_identity_list'],
                        cwd=clone, capture_output=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                    self.assertNotEqual(result.returncode, 0, label + ' was accepted')
                    self.assertIn(b'FAIL: test_retained_corpus_and_report_match_source_first_identity_list', result.stderr, result.stderr.decode())

    @unittest.skipUnless(os.environ.get('MENU_LUCI_GIT'), 'set MENU_LUCI_GIT for pinned Git read')
    def test_git_gate_rejects_mutated_retained_report(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory)
            for name in ('corpus', 'policy', 'reports'):
                shutil.copytree(root / name, clone / name,
                                ignore=shutil.ignore_patterns('__pycache__'))
            report_path = clone / 'reports/m4-menu-route-provenance.json'
            original = report_path.read_bytes()
            base = next(x for x in json.loads(original)['files'] if x['package'] == 'luci-base')
            source = clone / 'corpus/menu-route-sources' / base['source']
            original_source = source.read_bytes()
            coherent_forgery(clone)
            mutated = report_path.read_bytes()
            mutated_source = source.read_bytes()
            for label, data in [('coherent', mutated), ('bytes_only', original + b' ')]:
                with self.subTest(mutation=label):
                    source.write_bytes(mutated_source if label == 'coherent' else original_source)
                    report_path.write_bytes(data)
                    result = subprocess.run([*child_python(), '-m', 'unittest',
                        'policy.tests.test_menu_routes.PinnedMenuCollectorTests.test_pinned_git_and_actual_cli_agree'],
                        cwd=clone, capture_output=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                    self.assertNotEqual(result.returncode, 0, 'Git gate ignored retained report')
                    self.assertIn(b'FAIL: test_pinned_git_and_actual_cli_agree', result.stderr, result.stderr.decode())
                    self.assertIn(b'self.assertEqual(process.stdout,', result.stderr, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
