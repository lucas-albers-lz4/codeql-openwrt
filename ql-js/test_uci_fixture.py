"""Frozen UCI fixture and opt-in isolated CodeQL comparison.

The opt-in extraction permits minified files; this is not the profile of the
historical fixture-c run, which disabled that extractor option.
"""
import hashlib
from collections import Counter
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import extraction_gate as gate
import uci_inventory

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'tests/uci-fixture'
PINS = {
    'fixture.js': '5aa0b33b5f773479c517cbeae78cf226fb9bf367f5059d194c50cfb43a8355c9',
    'literal_controls.js': '94f573e9f5aabc165f1203692fe565d05834bc02df11332f8f14836459fe67cf',
    'fixture-expected.json': '8629117aa5d27aa1466f6be44deb50a0e7856e4403682c502f791113d72a81fa',
    'literal-controls-expected.json': '08981d79ae94e97044fb2fd8eb9fca40b7670b926ab0a4f89b609cf627d2460a',
}
LIBRARIES = ('javascript-all/3.0.0', 'concepts/0.0.35', 'dataflow/2.1.17', 'controlflow/2.0.45',
             'mad/1.0.61', 'regex/1.0.61', 'ssa/2.0.37', 'threat-models/1.1.1',
             'tutorial/1.0.61', 'typetracking/2.0.45', 'util/2.0.48', 'xml/1.0.61', 'yaml/1.0.61')


def frozen():
    values = {name: (FIXTURES / name).read_bytes() for name in PINS}
    if any(hashlib.sha256(values[name]).hexdigest() != digest for name, digest in PINS.items()):
        raise ValueError('frozen fixture identity mismatch')
    return values


def validate_resolution(raw, packs, compile_cache):
    expected = [
        '--dbscheme=' + str(packs / 'codeql/javascript-all/3.0.0/semmlecode.javascript.dbscheme'),
        '--full-library-path=' + ':'.join([str(HERE), *(str(packs / 'codeql' / name) for name in LIBRARIES)]),
        '--no-default-compilation-cache', '--compilation-cache=' + str(compile_cache),
    ]
    if raw.decode('utf-8').splitlines() != expected:
        raise ValueError('unexpected library resolution')


def stage(root, values):
    source = root / 'source'
    source.mkdir()
    manifest = [{'source': name, 'sha256': PINS[name]}
                for name in ('fixture.js', 'literal_controls.js')]
    for row in manifest:
        name = row['source']
        (source / name).write_bytes(values[name])
    expected = sum((uci_inventory.expected_rows(values[name], source, manifest)
                    for name in ('fixture-expected.json', 'literal-controls-expected.json')), start=Counter())
    return source, manifest, expected


class UciFixtureTests(unittest.TestCase):
    def test_frozen_source_and_expectations(self):
        self.assertEqual(set(p.name for p in FIXTURES.iterdir()), set(PINS))
        values = frozen()
        with tempfile.TemporaryDirectory() as directory:
            source, manifest, expected = stage(Path(directory).resolve(), values)
            self.assertEqual(len(manifest), 2)
            self.assertIn(('fixture.js', 4, 1, 4, 13, 'L.uci', 'dot', True, 'get'), expected)
            self.assertIn(('fixture.js', 12, 1, 12, 16, 'bare', 'computed-index', True, '<unknown>'), expected)
            self.assertTrue(all(count > 0 for count in expected.values()))
            gate.check_staged(source, manifest)
            (source / 'unexpected.js').write_text('unexpected')
            with self.assertRaisesRegex(ValueError, 'file set differs'):
                gate.check_staged(source, manifest)

    def test_resolution_requires_exact_pack_and_private_cache(self):
        packs, cache = Path('/approved/packs'), Path('/owned/cache')
        lines = ['--dbscheme=' + str(packs / 'codeql/javascript-all/3.0.0/semmlecode.javascript.dbscheme'),
                 '--full-library-path=' + ':'.join([str(HERE), *(str(packs / 'codeql' / n) for n in LIBRARIES)]),
                 '--no-default-compilation-cache', '--compilation-cache=' + str(cache)]
        raw = ('\n'.join(lines) + '\n').encode()
        validate_resolution(raw, packs, cache)
        for changed in (raw.replace(b'/approved/packs', b'/foreign/packs', 1),
                        raw.replace(b'/owned/cache', b'/shared/cache'), raw + b'extra\n'):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'resolution'):
                validate_resolution(changed, packs, cache)

    @unittest.skipUnless(os.environ.get('UCI_CODEQL') and os.environ.get('UCI_PACKS'),
                         'set UCI_CODEQL and UCI_PACKS to explicitly enable isolated CodeQL fixture')
    def test_real_fixture_exact_multiset(self):
        values = frozen()  # Bind all source and expectation bytes before any child process.
        codeql = Path(os.environ['UCI_CODEQL'])
        packs = Path(os.environ['UCI_PACKS'])
        for path in (codeql, packs):
            self.assertTrue(path.is_absolute() and path.resolve(strict=True) == path)
        self.assertTrue(codeql.is_file() and os.access(codeql, os.X_OK))
        self.assertTrue(packs.is_dir())
        self.assertTrue((packs / 'codeql/javascript-all/3.0.0/qlpack.yml').is_file(),
                        'explicit packs must contain codeql/javascript-all 3.0.0')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, manifest, expected = stage(root, values)
            caches = root / 'caches'; caches.mkdir()
            compile_cache = root / 'compile-cache'; compile_cache.mkdir()
            tmp = root / 'tmp'; tmp.mkdir()
            config = root / 'config'; config.write_bytes(b'')
            env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C',
                   'CODEQL_CONFIG_FILE': str(config), 'TMPDIR': str(tmp),
                   'JAVA_TOOL_OPTIONS': '-Djava.io.tmpdir=' + str(tmp) + ' -XX:-UsePerfData'}
            def run(args, compile=False, minified=False):
                command = [str(codeql), *args, '--common-caches=' + str(caches)]
                if compile:
                    command.extend(['--no-default-compilation-cache', '--compilation-cache=' + str(compile_cache)])
                child_env = dict(env)
                if minified:
                    child_env['CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES'] = 'true'
                result = subprocess.run(command, env=child_env, cwd=root, check=False,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode:
                    self.fail(f'command failed {command!r}: stdout={result.stdout!r}; stderr={result.stderr!r}')
                return result.stdout
            self.assertIn(b'toolchain release 2.27.4.', run(['version']))
            for name in ('files', 'errors', 'uci_surface'):
                resolution = run(['resolve', 'library-path', '--additional-packs=' + str(packs),
                                  '--query=' + str(HERE / (name + '.ql'))], compile=True)
                validate_resolution(resolution, packs, compile_cache)
            db = root / 'db'
            gate.check_staged(source, manifest)
            run(['database', 'create', str(db), '--language=javascript', '--source-root=' + str(source),
                 '--threads=1', '--ram=2048'], minified=True)
            gate.check_staged(source, manifest)
            for name in ('files', 'errors', 'uci_surface'):
                if name == 'uci_surface':
                    gate.check_staged(source, manifest)
                bqrs, decoded = root / (name + '.bqrs'), root / (name + '.json')
                run(['query', 'run', str(HERE / (name + '.ql')), '--database', str(db),
                     '--additional-packs=' + str(packs), '--output', str(bqrs), '--threads=1', '--ram=2048'], compile=True)
                run(['bqrs', 'decode', str(bqrs), '--format=json',
                     '--entities=' + ('id' if name == 'uci_surface' else 'url,string'), '--output', str(decoded)])
                if name == 'errors':
                    gate.check_results([str(source / row['source']) for row in manifest],
                        uci_inventory._parse((root / 'files.json').read_bytes()), uci_inventory._parse(decoded.read_bytes()))
            self.assertEqual(uci_inventory.project((root / 'uci_surface.json').read_bytes(), source, manifest), expected)
            gate.check_staged(source, manifest)


if __name__ == '__main__':
    unittest.main()
