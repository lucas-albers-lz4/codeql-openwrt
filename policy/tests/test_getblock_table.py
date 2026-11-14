"""Fail-closed source table import and exact grant join controls."""
import csv
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from policy.getblock_table import (CATALOG, COLUMNS, EFFECT_ID, EXPECTED, GRANT_IDS,
                                   JOIN_KEYS, SNAPSHOT, import_table)

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / 'policy/fixtures/getblock-observation.csv'
SOURCE = ROOT / 'policy/fixtures/getblock-source'


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        for path in ('corpus/lock.json', 'corpus/profiles/luci-ssl-25.12/expected-capabilities.json',
                     'policy/grants.json', str(SNAPSHOT), str(CATALOG)):
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        self.csv = Path(self.temp.name) / 'observation.csv'
        shutil.copyfile(CSV, self.csv)
        self.source = Path(self.temp.name) / 'source'
        shutil.copytree(SOURCE, self.source)

    def artifacts(self):
        return tuple((self.repo / p).read_bytes() for p in (SNAPSHOT, CATALOG, Path('policy/grants.json')))

    def write_csv(self, header=COLUMNS, rows=(EXPECTED,)):
        with self.csv.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)

    def rejected_unchanged(self):
        before = self.artifacts()
        with self.assertRaises((ValueError, OSError, KeyError, csv.Error)):
            import_table(self.csv, self.source, self.repo)
        self.assertEqual(self.artifacts(), before)

    def test_valid_replaces_and_deduplicates_without_grant_rewrite(self):
        grants_before = (self.repo / 'policy/grants.json').read_bytes()
        original = {}
        for path in (SNAPSHOT, CATALOG):
            file = self.repo / path
            rows = json.loads(file.read_text())
            original[path] = [r for r in rows if r.get('record_id') != EFFECT_ID]
            rows.append(next(r for r in rows if r.get('record_id') == EFFECT_ID))
            file.write_text(json.dumps(rows))
        import_table(self.csv, self.source, self.repo)
        for path in (SNAPSHOT, CATALOG):
            rows = json.loads((self.repo / path).read_text())
            self.assertEqual([r for r in rows if r.get('record_id') != EFFECT_ID], original[path])
            matches = [r for r in rows if r.get('record_id') == EFFECT_ID]
            self.assertEqual(len(matches), 1)
            effect = matches[0]
            self.assertEqual(effect['effect_id'], 'getBlockDevices.block-info.popen')
            self.assertEqual(effect['target_id'], 'command:block-info')
            self.assertEqual(effect['entrypoint_id'], 'ubus_http:luci.getBlockDevices')
            self.assertEqual(effect['evidence_status'], 'fact')
            self.assertTrue(set(GRANT_IDS.values()) <= set(effect['evidence_refs']))
            self.assertEqual(effect['source_location']['start_line'], 481)
            self.assertNotIn('path_found', json.dumps(effect))
            self.assertNotIn('authorization_violation', json.dumps(effect))
        self.assertEqual((self.repo / 'policy/grants.json').read_bytes(), grants_before)
        once = self.artifacts()
        import_table(self.csv, self.source, self.repo)
        self.assertEqual(self.artifacts(), once)

    def test_invalid_or_missing_table_fails_without_writes(self):
        self.csv.unlink()
        self.rejected_unchanged()
        for header, rows in ((COLUMNS[:-1], [EXPECTED]), (COLUMNS, []), (COLUMNS, [EXPECTED, EXPECTED]),
                             (('method',) + COLUMNS[1:], [EXPECTED])):
            self.write_csv(header, rows)
            self.rejected_unchanged()
        for i in range(len(EXPECTED)):
            with self.subTest(column=COLUMNS[i]):
                row = list(EXPECTED)
                row[i] = 'unexpected'
                self.write_csv(rows=[row])
                self.rejected_unchanged()

    def test_stale_source_and_lock_fail_without_writes(self):
        source = self.source / 'usr/share/rpcd/ucode/luci'
        source.write_bytes(source.read_bytes() + b'\n')
        self.rejected_unchanged()
        shutil.copyfile(SOURCE / 'usr/share/rpcd/ucode/luci', source)
        lock = self.repo / 'corpus/lock.json'
        data = json.loads(lock.read_text())
        data['repos']['luci']['sha'] = 'other'
        lock.write_text(json.dumps(data))
        self.rejected_unchanged()

    def test_missing_duplicate_or_mismatched_grant_fails_without_writes(self):
        path = self.repo / 'policy/grants.json'
        original = json.loads(path.read_text())
        for record_id in GRANT_IDS.values():
            with self.subTest(record_id=record_id, case='missing'):
                path.write_text(json.dumps([g for g in original if g.get('record_id') != record_id]))
                self.rejected_unchanged()
            grant = next(g for g in original if g.get('record_id') == record_id)
            path.write_text(json.dumps(original + [grant]))
            self.rejected_unchanged()
            for key in (*JOIN_KEYS, 'session_class', 'target_id', 'op', 'assessment', 'expectation_id'):
                with self.subTest(record_id=record_id, key=key):
                    changed = json.loads(json.dumps(original))
                    next(g for g in changed if g.get('record_id') == record_id)[key] = 'other'
                    path.write_text(json.dumps(changed))
                    self.rejected_unchanged()
        path.write_text(json.dumps(original))

    def test_missing_effect_or_expectation_fails_without_writes(self):
        path = self.repo / CATALOG
        rows = json.loads(path.read_text())
        path.write_text(json.dumps([r for r in rows if r.get('record_id') != EFFECT_ID]))
        self.rejected_unchanged()
        shutil.copyfile(ROOT / CATALOG, path)
        path = self.repo / 'corpus/profiles/luci-ssl-25.12/expected-capabilities.json'
        expectations = json.loads(path.read_text())
        expectations['expectations'] = [e for e in expectations['expectations']
                                        if e.get('expectation_id') != 'luci-mod-system-mounts']
        path.write_text(json.dumps(expectations))
        self.rejected_unchanged()

    def test_conflicting_effect_identity_fails_without_writes(self):
        path = self.repo / CATALOG
        rows = json.loads(path.read_text())
        rows.append({"record_id": "other", "effect_id": "getBlockDevices.block-info.popen"})
        path.write_text(json.dumps(rows))
        self.rejected_unchanged()

    def test_second_replace_failure_restores_both_artifacts(self):
        for path in (SNAPSHOT, CATALOG):
            file = self.repo / path
            file.write_text(json.dumps(json.loads(file.read_text())))
        before = self.artifacts()
        real_replace = os.replace
        calls = []

        def fail_second(src, dst):
            calls.append((src, dst))
            if len(calls) == 2:
                raise OSError('injected second replace failure')
            return real_replace(src, dst)

        with patch('policy.getblock_table.os.replace', side_effect=fail_second):
            with self.assertRaisesRegex(OSError, 'injected second replace'):
                import_table(self.csv, self.source, self.repo)
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.artifacts(), before)

    def test_source_location_conforms_to_schema(self):
        import_table(self.csv, self.source, self.repo)
        rows = json.loads((self.repo / CATALOG).read_text())
        location = next(r['source_location'] for r in rows if r.get('record_id') == EFFECT_ID)
        schema = json.loads((ROOT / 'schemas/finding.schema.json').read_text())
        spec = schema['properties']['source_location']
        self.assertEqual(spec['type'], 'object')
        self.assertEqual(set(spec['required']), set(location))
        for key, value in location.items():
            prop = spec['properties'][key]
            if prop['type'] == 'string':
                self.assertIsInstance(value, str)
                self.assertTrue(value)
            else:
                self.assertEqual(prop['type'], 'integer')
                self.assertIsInstance(value, int)
                self.assertGreaterEqual(value, prop['minimum'])


if __name__ == '__main__':
    unittest.main()
