import copy
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('validation', HERE / 'validate.py')
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


class ValidationControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.stage, self.source = root / 'stage', root / 'source'
        self.manifest = json.loads((HERE / 'manifest.json').read_text())
        self.receipt = json.loads((HERE / 'routing.json').read_text())
        self.extracted = json.loads((HERE / 'extracted.json').read_text())
        self.errors = json.loads((HERE / 'errors.json').read_text())
        # Tests use known, individually distinct content, with matching manifest hashes.
        import hashlib
        for i, row in enumerate(self.manifest):
            data = str(i).encode()
            row['sha256'] = hashlib.sha256(data).hexdigest()
            for p in (self.stage / row['installed'].lstrip('/'), self.source / row['source']):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
        for d in self.receipt['decisions']:
            d['path'] = str(self.stage / d['installed_path'])
        for row in self.extracted['#select']['tuples']:
            suffix = row[0]['label'].split('/usr/share/ucode/luci/', 1)[1]
            path = self.stage / 'usr/share/ucode/luci' / suffix
            row[0]['label'] = str(path)
            row[0]['url']['uri'] = path.as_uri()

    def check(self):
        validation.validate(self.manifest, self.stage, self.source, self.receipt, self.extracted, self.errors)

    def test_positive(self):
        self.check()

    def test_rejects_diagnostic_and_identity_failures(self):
        for kind in ('missing', 'unexpected', 'duplicate', 'error', 'receipt', 'reason', 'success_columns', 'error_columns', 'success_tuple', 'location'):
            with self.subTest(kind=kind):
                original = copy.deepcopy((self.receipt, self.extracted, self.errors))
                rows = self.extracted['#select']['tuples']
                if kind == 'missing': rows.pop()
                if kind == 'unexpected': rows[0][0]['label'] += '.other'
                if kind == 'duplicate': rows[-1] = copy.deepcopy(rows[0])
                if kind == 'error': self.errors['#select']['tuples'].append(['error'])
                if kind == 'receipt': self.receipt['decisions'][0]['status'] = 'success'
                if kind == 'reason': self.receipt['decisions'][0]['reason'] = 'wrong'
                if kind == 'success_columns': self.extracted['#select']['columns'].pop()
                if kind == 'error_columns': self.errors['#select']['columns'].pop()
                if kind == 'success_tuple': rows[0].pop()
                if kind == 'location': rows[0][0]['url']['startLine'] = 1
                with self.assertRaises(ValueError): self.check()
                self.receipt, self.extracted, self.errors = original

    def test_rejects_changed_and_extra_staged_files(self):
        p = self.stage / self.manifest[0]['installed'].lstrip('/')
        p.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.check()
        p.write_bytes(b'0')
        (self.stage / 'extra.ut').write_text('extra')
        with self.assertRaises(ValueError): self.check()

    def test_accepts_external_ancestor_alias(self):
        alias = Path(self.tmp.name).parent / (Path(self.tmp.name).name + '-alias')
        alias.symlink_to(Path(self.tmp.name), target_is_directory=True)
        self.addCleanup(alias.unlink)
        nested = Path(self.tmp.name) / 'nested'
        nested.mkdir()
        original_stage = self.stage
        original_stage.rename(nested / 'stage')
        self.stage = alias / 'nested' / 'stage'
        for d in self.receipt['decisions']:
            d['path'] = str((nested / 'stage' / d['installed_path']).resolve())
        for row in self.extracted['#select']['tuples']:
            suffix = row[0]['label'].split('/usr/share/ucode/luci/', 1)[1]
            path = (nested / 'stage' / 'usr/share/ucode/luci' / suffix).resolve()
            row[0]['label'] = str(path)
            row[0]['url']['uri'] = path.as_uri()
        # Receipt and decoded diagnostic identities are canonical, as produced by CodeQL.
        self.check()

    def test_rejects_symlinked_stage_root(self):
        alias = Path(self.tmp.name) / 'stage-alias'
        alias.symlink_to(self.stage, target_is_directory=True)
        self.stage = alias
        with self.assertRaises(ValueError): self.check()

    def test_rejects_extra_symlink_to_selected_file(self):
        target = self.stage / self.manifest[0]['installed'].lstrip('/')
        (self.stage / 'extra.ut').symlink_to(target)
        with self.assertRaises(ValueError): self.check()

    def test_rejects_symlinked_selected_file(self):
        target = self.stage / self.manifest[0]['installed'].lstrip('/')
        data = target.read_bytes()
        target.unlink()
        external = Path(self.tmp.name) / 'external'
        external.write_bytes(data)
        target.symlink_to(external)
        with self.assertRaises(ValueError): self.check()


class CliJsonControls(unittest.TestCase):
    def setUp(self):
        ValidationControls.setUp(self)
        self.cli_dir = Path(self.tmp.name) / 'cli'
        self.cli_dir.mkdir()
        shutil.copy(HERE / 'validate.py', self.cli_dir / 'validate.py')
        self.inputs = {
            'manifest': self.manifest, 'receipt': self.receipt,
            'extracted': self.extracted, 'errors': self.errors,
        }
        self.paths = {name: self.cli_dir / (name + '.json') for name in self.inputs}
        for name, data in self.inputs.items():
            self.paths[name].write_text(json.dumps(data))

    def run_cli(self):
        return subprocess.run([
            sys.executable, str(self.cli_dir / 'validate.py'),
            '--source', str(self.source), '--stage', str(self.stage),
            '--receipt', str(self.paths['receipt']),
            '--extracted', str(self.paths['extracted']),
            '--errors', str(self.paths['errors']),
        ], text=True, capture_output=True)

    def test_cli_accepts_valid_json(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_rejects_duplicate_keys_in_every_input(self):
        # Place a duplicate before the valid value: ordinary json.loads keeps the
        # last value, so even contradictory input otherwise passes validation.
        for name, key in (('manifest', 'installed'), ('receipt', 'input_count'),
                          ('extracted', '#select'), ('errors', '#select')):
            for equal in (False, True):
                with self.subTest(input=name, equal=equal):
                    path = self.paths[name]
                    original = path.read_text()
                    obj = self.inputs[name][0] if name == 'manifest' else self.inputs[name]
                    value = obj[key] if equal else None
                    token = json.dumps(key) + ':'
                    self.assertIn(token, original)
                    path.write_text(original.replace(token, token + ' ' + json.dumps(value) + ', ' + token, 1))
                    try:
                        result = self.run_cli()
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn('duplicate JSON object key', result.stderr)
                    finally:
                        path.write_text(original)

    def test_cli_rejects_nested_duplicate_key(self):
        path = self.paths['extracted']
        original = path.read_text()
        token = '"startLine":'
        self.assertIn(token, original)
        path.write_text(original.replace(token, token + ' 1, ' + token, 1))
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('duplicate JSON object key', result.stderr)


if __name__ == '__main__':
    unittest.main()
