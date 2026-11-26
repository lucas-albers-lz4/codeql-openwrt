import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.issuer_consumer_prerequisite import check_scan
from tools.r3_linux_handoff import ROOT
from tools.sarif_accept import triage


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ConsumerGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root / 'out').mkdir()
        (self.root / 'stage').mkdir()
        (self.root / 'stage/a.uc').write_text('one\n')
        self.rule = 'ucode/m4/direct-rpc-shell-word'
        self.lock = {'release': {'commit': 'a'*40, 'asset_sha256': 'b'*64, 'suite_sha256': 'c'*64, 'tag': 'v1', 'expected_rules': [self.rule], 'codeql_binary_sha256': 'd'*64}, 'codeql': {'version': '2.27.4'}}
        self.manifest = {'selected': [{'proposed_installed_path': 'a.uc', 'source_sha256': digest(self.root / 'stage/a.uc'), 'expected_route': {'classification': 'plain', 'reason': 'extension'}, 'repo': 'luci', 'source_commit': 'e'*40, 'source_path': 'a.uc', 'git_blob': 'f'*40}], 'pins': {'luci': 'e'*40}, 'event': {'repository': 'luci'}, 'excluded': []}
        self.identity = {'sha': 'a'*40, 'pack_sha256': 'b'*64, 'suite_sha256': 'c'*64, 'codeql_version': '2.27.4'}
        self.accept = {'schema': 'ucode-sarif-event-triage-v1', 'producer': self.identity, 'sources': [{'uri': 'a.uc', 'sha256': self.manifest['selected'][0]['source_sha256']}], 'expected_extracted': ['a.uc'], 'expected_rules': [self.rule], 'expected_sarif_descriptors': [self.rule]}
        self.sarif = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL', 'semanticVersion': '2.27.4', 'rules': [{'id': self.rule}]}}, 'columnKind': 'utf16CodeUnits', 'invocations': [{'executionSuccessful': True}], 'results': []}]}
        labels = ['db-init', 'db-index', 'db-finalize', 'errors-query', 'errors-decode', 'successful-query', 'successful-decode', 'resolve-suite', 'analyze', 'triage']
        self.commands = [{'label': label, 'argv': ['tool'], 'exit': 0} for label in labels]
        self.producer = {'schema': 'ucode-sarif-run-v1', 'run_id': 'job/1', 'producer': self.identity, 'successful_files': ['a.uc'], 'extraction_errors': [], 'resolved_rules': [self.rule], 'commands': self.commands[:-1]}
        self.manifest_path = self.root / 'manifest.json'
        self.write('manifest.json', self.manifest)
        self.write_graph()

    def write(self, path, value):
        (self.root / path).write_text(json.dumps(value) + '\n')

    def write_graph(self):
        self.write('out/event-triage-input.json', self.accept)
        self.write('out/default-suite.sarif', self.sarif)
        self.write('out/routing.json', {'decisions': [{'installed_path': 'a.uc', 'classification': 'plain', 'reason': 'extension', 'status': 'plain_route_selected'}], 'input_count': 1, 'plain_count': 1, 'markup_count': 0, 'markup_inconclusive_count': 0, 'excluded_count': 0, 'uncertain_count': 0, 'duplicate_input_count': 0})
        self.write('out/successful.json', {'#select': {'tuples': [[{'url': {'uri': (self.root / 'stage/a.uc').as_uri()}}]]}})
        self.write('out/errors.json', {'#select': {'tuples': []}})
        (self.root / 'commands').mkdir(exist_ok=True)
        root = self.root
        codeql = str(root.parent / 'cli/codeql/codeql')
        db = str(root / 'db/current')
        argv = {'db-init': [codeql, 'database', 'init', db, '--source-root=' + str(root / 'stage')], 'db-index': [codeql, 'database', 'index-files', '--working-dir=' + str(root / 'stage'), db], 'db-finalize': [codeql, 'database', 'finalize', db], 'resolve-suite': [codeql, 'resolve', 'queries', str(root / 'bundle/codeql-ucode-linux/ql/src/codeql-suites/code-scanning.qls')], 'analyze': [codeql, 'database', 'analyze', db, str(root / 'bundle/codeql-ucode-linux/ql/src/codeql-suites/code-scanning.qls'), '--output=' + str(root / 'out/default-suite.sarif')], 'triage': ['python3', '-B', str(ROOT / 'tools/sarif_accept.py'), '--sarif', str(root / 'out/default-suite.sarif'), '--manifest', str(root / 'out/event-triage-input.json'), '--receipt', str(root / 'out/producer-receipt.json'), '--source-root', str(root / 'stage'), '--event-triage']}
        for label, query in [('errors', 'ExtractionErrors.ql'), ('successful', 'SuccessfullyExtractedFiles.ql')]:
            argv[label + '-query'] = [codeql, 'query', 'run', str(root / 'bundle/codeql-ucode-linux/ql/src/diagnostics' / query), '--database=' + db, '--output=' + str(root / 'out' / (label + '.bqrs'))]
            argv[label + '-decode'] = [codeql, 'bqrs', 'decode', str(root / 'out' / (label + '.bqrs'))]
            (root / 'commands' / (label + '-decode.stdout')).write_bytes((root / 'out' / (label + '.json')).read_bytes())
        for command in self.commands:
            command['argv'] = argv[command['label']]
            command['stdout'] = 'commands/' + command['label'] + '.stdout'
        self.producer['commands'] = copy.deepcopy(self.commands[:-1])
        self.write('commands.json', self.commands)
        self.producer['sarif_sha256'] = digest(self.root / 'out/default-suite.sarif')
        self.producer.update(consumer_sha='9'*40, release_tag='v1', codeql_binary_sha256='d'*64)
        self.producer['route_sha256'] = digest(self.root / 'out/routing.json')
        self.write('out/producer-receipt.json', self.producer)
        actual = triage(self.root / 'out/default-suite.sarif', self.root / 'out/event-triage-input.json', self.root / 'out/producer-receipt.json', self.root / 'stage')
        self.write('out/triage.json', actual)
        (self.root / 'commands/triage.stdout').write_bytes((self.root / 'out/triage.json').read_bytes())
        row = self.manifest['selected'][0]
        coverage = {'schema': 'ucode-event-corpus-coverage-v1', 'source_manifest_sha256': digest(self.manifest_path), 'event': self.manifest['event'], 'release_tag': 'v1', 'producer_commit': 'a'*40, 'source_pins': self.manifest['pins'], 'actual_package_installed_bytes_verified': False, 'counts': {'selected': 1, 'extracted_once': 1, 'errored': 0, 'modeled_markup_inconclusive': 0, 'excluded': 0}, 'selected': [{'repo': row['repo'], 'source_commit': row['source_commit'], 'source_path': row['source_path'], 'source_sha256': row['source_sha256'], 'git_blob': row['git_blob'], 'staged_path': 'a.uc', 'route_classification': 'plain', 'route_reason': 'extension', 'route_status': 'plain_route_selected', 'extracted_count': 1, 'extraction_error_count': 0}], 'excluded': []}
        self.write('out/coverage-event.json', coverage)
        self.write('preflight.json', {'run_id': 'job/1', 'consumer_sha': '9'*40, 'manifest_sha256': digest(self.manifest_path), 'source_pins': self.manifest['pins'], 'event': self.manifest['event'], 'release_tag': 'v1', 'release_commit': 'a'*40, 'selected_count': 1, 'excluded_count': 0})
        self.corpus = {'schema': 'ucode-event-corpus-linux-v1', 'run_id': 'job/1', 'producer_commit': 'a'*40, 'release_tag': 'v1', 'status': actual['status'], 'sarif_sha256': digest(self.root / 'out/default-suite.sarif'), 'accepted_sha256': digest(self.root / 'out/triage.json'), 'commands_sha256': digest(self.root / 'commands.json')}
        self.corpus.update(manifest_sha256=digest(self.manifest_path), source_pins=self.manifest['pins'], event=self.manifest['event'], consumer_sha='9'*40, resolved_rules=[self.rule], coverage_sha256=digest(self.root / 'out/coverage-event.json'), route_counts={k: self.read_route(k) for k in ('input_count', 'plain_count', 'markup_count', 'markup_inconclusive_count', 'uncertain_count', 'excluded_count', 'duplicate_input_count')}, selected_count=1, successful_count=1, extraction_error_count=0)
        self.write('receipt.json', self.corpus)

    def read_route(self, key):
        return json.loads((self.root / 'out/routing.json').read_text())[key]

    def verify(self):
        return check_scan(self.root, self.manifest_path, self.manifest, self.lock, 'job/1', '9'*40)

    def test_real_consumer_replay(self):
        self.assertEqual(self.verify()['status'], 'clean_scan')

    def test_swapped_triage_even_with_rehashed_receipt(self):
        self.write('out/triage.json', {'status': 'clean_scan', 'result_count': 0})
        self.corpus['accepted_sha256'] = digest(self.root / 'out/triage.json')
        self.write('receipt.json', self.corpus)
        with self.assertRaisesRegex((ValueError, RuntimeError), 'consumer stdout mismatch'):
            self.verify()

    def test_extraction_and_oracle_swaps(self):
        self.producer['successful_files'] = ['other.uc']
        self.write('out/producer-receipt.json', self.producer)
        with self.assertRaisesRegex((ValueError, RuntimeError), 'raw diagnostics differ'):
            self.verify()
        self.producer['successful_files'] = ['a.uc']
        self.write_graph()
        altered = copy.deepcopy(self.manifest)
        altered['selected'][0]['source_sha256'] = '0'*64
        with self.assertRaisesRegex((ValueError, RuntimeError), 'manifest bytes differ'):
            check_scan(self.root, self.manifest_path, altered, self.lock, 'job/1', '9'*40)

    def test_missing_and_failed_commands(self):
        self.commands[-1]['exit'] = 1
        self.write('commands.json', self.commands)
        with self.assertRaisesRegex((ValueError, RuntimeError), 'failed command'):
            self.verify()
        self.commands.pop()
        self.write('commands.json', self.commands)
        with self.assertRaisesRegex((ValueError, RuntimeError), 'missing or duplicate'):
            self.verify()

    def test_duplicate_json_and_symlink(self):
        (self.root / 'out/routing.json').write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex((ValueError, RuntimeError), 'duplicate JSON'):
            self.verify()
        (self.root / 'out/routing.json').unlink()
        (self.root / 'out/routing.json').symlink_to(self.root / 'commands.json')
        with self.assertRaisesRegex((ValueError, RuntimeError), 'symlink'):
            self.verify()

    def test_corpus_identity_count_and_coverage_links(self):
        for field, value in [('manifest_sha256', '0'*64), ('coverage_sha256', '0'*64),
                             ('source_pins', {}), ('event', {}), ('resolved_rules', []),
                             ('selected_count', 2), ('successful_count', 0),
                             ('extraction_error_count', 1), ('route_counts', {})]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.corpus)
                changed[field] = value
                self.write('receipt.json', changed)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.verify()
        self.write('receipt.json', self.corpus)
        coverage = json.loads((self.root / 'out/coverage-event.json').read_text())
        coverage['selected'][0]['git_blob'] = '0'*40
        self.write('out/coverage-event.json', coverage)
        self.corpus['coverage_sha256'] = digest(self.root / 'out/coverage-event.json')
        self.write('receipt.json', self.corpus)
        with self.assertRaisesRegex(RuntimeError, 'coverage differs'):
            self.verify()

    def test_producer_identity_and_command_binding(self):
        for field in ('consumer_sha', 'release_tag', 'codeql_binary_sha256'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.producer)
                changed[field] = 'wrong'
                self.write('out/producer-receipt.json', changed)
                with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
                    self.verify()
        self.write('out/producer-receipt.json', self.producer)
        command = next(c for c in self.commands if c['label'] == 'analyze')
        command['argv'][-1] = '--output=/tmp/swapped.sarif'
        self.write('commands.json', self.commands)
        with self.assertRaisesRegex(RuntimeError, 'SARIF output path mismatch'):
            self.verify()

    def test_root_symlink_rejected(self):
        link = self.root.parent / (self.root.name + '-link')
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(RuntimeError, 'unsafe scan root'):
            check_scan(link, self.manifest_path, self.manifest, self.lock, 'job/1', '9'*40)

    def test_sarif_swap(self):
        self.sarif['version'] = '3.0'
        self.write('out/default-suite.sarif', self.sarif)
        with self.assertRaisesRegex((ValueError, RuntimeError), 'digest mismatch'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
