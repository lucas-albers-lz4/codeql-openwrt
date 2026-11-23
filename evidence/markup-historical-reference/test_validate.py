import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('historical', HERE / 'validate.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
BUNDLE = v.ROOT / 'evidence/markup-profile-0a6612f'

class HistoricalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bundle = self.root / 'bundle'
        shutil.copytree(BUNDLE, self.bundle)
        self.refpath = self.root / 'reference.json'
        shutil.copy(HERE / 'reference.json', self.refpath)
        self.ref = json.loads(self.refpath.read_text())
        self.manifest = json.loads((self.bundle / 'manifest.json').read_text())
        self.routing = json.loads((self.bundle / 'routing.json').read_text())
        self.extracted = json.loads((self.bundle / 'extracted.json').read_text())
        self.errors = json.loads((self.bundle / 'errors.json').read_text())
        self.ast = (self.bundle / 'uhttpd-ast.csv').read_bytes()
        self.inventory = json.loads((v.ROOT / 'reports/m4-luci-ssl-files.json').read_text())
        self.source = self.root / 'source'
        # A separate test repository independently supplies source objects. Positive
        # full-bundle integration uses the real pinned LuCI repository externally.
    def tearDown(self):
        self.tmp.cleanup()
    def attempt(self, **kw):
        args = dict(reference=self.refpath, evidence_root=self.bundle, source=self.source,
                    requested_profile='luci-ssl-25.12', lock=v.ROOT/'corpus/lock.json',
                    inventory=v.ROOT/'reports/m4-luci-ssl-files.json')
        args.update(kw)
        return v.validate(**args)['status']
    def semantic(self):
        return v.semantics(self.manifest, self.routing, json.dumps(self.extracted).encode(),
                           json.dumps(self.errors).encode(), self.ast, self.inventory, self.ref)
    def test_semantic_positive(self):
        self.assertEqual(len(self.semantic()), 12)
        self.assertTrue(all(d['status'] == 'inconclusive' and d['inconclusive_reason'] == 'markup_not_modeled' for d in self.routing['decisions']))
    def test_profile_and_missing(self):
        self.assertEqual(self.attempt(requested_profile='luci-ssl-25.12-no-ubusauth'), 'rejected')
        (self.bundle/'errors.json').unlink()
        self.assertEqual(self.attempt(), 'incomplete')
    def test_lock_and_missing_artifacts(self):
        lock = self.root / 'lock.json'
        lock.write_bytes(b'contradictory')
        self.assertEqual(self.attempt(lock=lock), 'rejected')
        lock.unlink()
        self.assertEqual(self.attempt(lock=lock), 'incomplete')
        for name in ('uhttpd-ast.csv', 'extracted.json', 'routing.json', 'manifest.json'):
            path = self.bundle / name
            old = path.read_bytes(); path.unlink()
            self.assertEqual(self.attempt(), 'incomplete', name)
            path.write_bytes(old)
    def test_contradictory_artifact(self):
        (self.bundle/'errors.json').write_text('{}')
        self.assertEqual(self.attempt(), 'rejected')
    def test_reference_strict_and_independent(self):
        original = self.refpath.read_bytes()
        duplicate = original.replace(b'"version": 1,', b'"version": 1, "version": 1,', 1)
        with self.assertRaisesRegex(v.Rejected, 'duplicate JSON key'):
            v.strict_json(duplicate)
        for version in (True, False, 2, '1'):
            fixture = copy.deepcopy(self.ref)
            fixture['version'] = version
            with self.subTest(version=version), self.assertRaisesRegex(v.Rejected, 'unsupported reference version'):
                v.check_reference_version(fixture)
        for field, value in [('producer', '97cc776f605dc007b6b85c4704b2caded1aa7023'),
                             ('bundle_commit', '0' * 40), ('extra', 'unexpected')]:
            fixture = copy.deepcopy(self.ref)
            fixture[field] = value
            self.refpath.write_text(json.dumps(fixture))
            self.assertEqual(self.attempt(), 'rejected', field)
        fixture = copy.deepcopy(self.ref)
        fixture['artifacts']['errors.json'] = '0' * 64
        self.refpath.write_text(json.dumps(fixture))
        self.assertEqual(self.attempt(), 'rejected')
        self.refpath.write_bytes(duplicate)
        self.assertEqual(self.attempt(), 'rejected')
        fixture = copy.deepcopy(self.ref)
        fixture['version'] = True
        self.refpath.write_text(json.dumps(fixture))
        self.assertEqual(self.attempt(), 'rejected')
    def test_public_api_rejects_invalid_file_types(self):
        target = self.bundle / 'errors.json'
        target.unlink()
        target.symlink_to('errors.json')
        self.assertEqual(self.attempt(), 'rejected')
        target.unlink()
        target.mkdir()
        self.assertEqual(self.attempt(), 'rejected')
        target.rmdir()
        os.mkfifo(target)
        self.assertEqual(self.attempt(), 'rejected')
        target.unlink()
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(target))
            self.assertEqual(self.attempt(), 'rejected')
        target.unlink()
        target.symlink_to(self.root / 'outside')
        with self.assertRaises(v.Rejected): v.confined(self.bundle, 'errors.json')
        self.assertEqual(self.attempt(), 'rejected')
    def test_confined_paths(self):
        with self.assertRaises(v.Rejected): v.confined(self.bundle, '../outside')
        (self.bundle/'escape').symlink_to(self.root/'outside')
        with self.assertRaises(v.Rejected): v.confined(self.bundle, 'escape')
    def test_inventory_binding(self):
        row = next(r for r in self.inventory if r.get('classification') == 'markup')
        for key in ('source', 'fs_path', 'corpus_revision', 'profile', 'analysis_revision'):
            old = row[key]; row[key] = 'different'
            with self.subTest(key=key), self.assertRaises(v.Rejected): self.semantic()
            row[key] = old
    def test_success_identity_cardinality_and_error_tuples(self):
        rows = self.extracted['#select']['tuples']
        original = copy.deepcopy(rows)
        for mutate in ('missing', 'duplicate', 'unexpected'):
            rows[:] = copy.deepcopy(original)
            if mutate == 'missing': rows.pop()
            elif mutate == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            else: rows[0][0]['label'] += '.other'
            with self.subTest(mutate=mutate), self.assertRaisesRegex(v.Rejected, 'success tuples'): self.semantic()
        rows[:] = original
        self.errors['#select']['tuples'] = [[{'label':'unrelated'}, 'outside', 1]]
        with self.assertRaisesRegex(v.Rejected, 'error tuples'): self.semantic()
    def test_first_import_and_scope(self):
        for old, new in [(b'ImportStatement',b'OtherStatement'), (b',3,1,3,39,',b',3,2,3,39,'), (b'"Markup",1',b'"Other",1')]:
            original = self.ast; self.ast = self.ast.replace(old,new,1)
            with self.subTest(old=old), self.assertRaisesRegex(v.Rejected, 'AST'): self.semantic()
            self.ast = original
        original = self.ast
        self.ast += self.ast.splitlines(keepends=True)[1]
        with self.assertRaisesRegex(v.Rejected, 'AST retained tuples'): self.semantic()
        self.ast = original + b'"Unexpected",1,1,1,2,"Markup",0\n'
        with self.assertRaisesRegex(v.Rejected, 'AST retained tuples'): self.semantic()
        self.ast = original
        self.ref['ast_scope'] = '/usr/share/ucode/luci/template/view.ut'
        with self.assertRaisesRegex(v.Rejected, 'AST scope'): self.semantic()
    def test_missing_and_contradictory_source(self):
        with mock.patch.object(v.subprocess, "run") as run:
            run.return_value.returncode = 1
            self.assertEqual(self.attempt(), "incomplete")
            run.return_value.returncode = 0
            run.return_value.stdout = b"commit\n"
            self.assertEqual(self.attempt(), "rejected") # contradictory tree entry
    def test_missing_source_tree_object(self):
        def git(args, **kwargs):
            if '-t' in args:
                return mock.Mock(returncode=0, stdout=b'commit\n')
            return mock.Mock(returncode=1, stdout=b'')
        with mock.patch.object(v.subprocess, 'run', side_effect=git):
            result = v.validate(self.refpath, self.bundle, self.source, 'luci-ssl-25.12', v.ROOT/'corpus/lock.json', v.ROOT/'reports/m4-luci-ssl-files.json')
            self.assertEqual(result['status'], 'incomplete')
            self.assertEqual(result['reason'], 'pinned source tree unavailable')
    def test_source_blob_bytes_gate(self):
        first = self.manifest[0]
        def git(args, **kwargs):
            result = mock.Mock(returncode=0)
            if 'ls-tree' in args:
                result.stdout = f"100644 blob {first['blob']}\t{first['source']}".encode() + b'\0'
            elif '-t' in args:
                result.stdout = b'commit\n'
            else:
                result.stdout = b'contradictory blob bytes'
            return result
        with mock.patch.object(v.subprocess, 'run', side_effect=git):
            result = v.validate(self.refpath, self.bundle, self.source, 'luci-ssl-25.12', v.ROOT/'corpus/lock.json', v.ROOT/'reports/m4-luci-ssl-files.json')
            self.assertEqual(result['status'], 'rejected')
            self.assertEqual(result['reason'], 'source blob or bytes differ')
    def test_real_pinned_source_when_supplied(self):
        source = os.environ.get('OPENWRT68_LUCI_SOURCE')
        if not source:
            self.skipTest('set OPENWRT68_LUCI_SOURCE to pinned LuCI repository')
        result = v.validate(self.refpath, self.bundle, Path(source), 'luci-ssl-25.12', v.ROOT/'corpus/lock.json', v.ROOT/'reports/m4-luci-ssl-files.json')
        self.assertEqual(result['status'], 'admitted', result)
        self.assertEqual(len(result['rows']), 12)
        self.assertEqual(sum(r['ast_scope'] == 'selected' for r in result['rows']), 1)
    def test_routing_mutation(self):
        self.routing['decisions'][0]['status'] = 'clean'
        with self.assertRaisesRegex(v.Rejected, 'routing'): self.semantic()

if __name__ == '__main__': unittest.main()
