import copy
import io
import tarfile
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('statistics_compare', HERE / 'compare.py')
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)

class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.oracle = compare.load_oracle()

    def test_exact_126_projection_and_controls(self):
        rows = compare.expected_rows(self.oracle)
        self.assertEqual(len(rows), 126)
        self.assertEqual(rows['usr/libexec/stat-genconfig']['sha256'], '5c45628d2a6a4c9414a93e26cff9c1c5d35ea4c0160f86575ee6c2f3f92c629b')
        self.assertIn('etc/init.d/luci_statistics', rows)
        self.assertIn('usr/share/rpcd/acl.d/luci-app-statistics.json', rows)

    def test_missing_and_duplicate_projection_rejected(self):
        for mutation in ('missing', 'duplicate'):
            oracle = copy.deepcopy(self.oracle)
            rows = oracle['entries']
            row = next(r for r in rows if r['package'] == 'luci-app-statistics' and r['projected_member'])
            if mutation == 'missing':
                rows.remove(row)
            else:
                rows.append(copy.deepcopy(row))
            with self.assertRaisesRegex(ValueError, 'Statistics source projection differs'):
                compare.expected_rows(oracle)

    def test_real_archive_and_stages_with_isolated_mutations(self):
        def pack(entries):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode='w:gz') as tf:
                for name, body, mode in entries:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(body), mode
                    tf.addfile(info, io.BytesIO(body))
            return out.getvalue()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            luci, prepared, stage = [root / x for x in ('luci', 'prepared', 'stage')]
            for directory in (luci, prepared, stage):
                directory.mkdir()
            expected = compare.expected_rows(self.oracle)
            entries, source = [], {}
            for path, row in expected.items():
                body = row['source_path'].encode()
                source[row['source_path']] = body
                mode = int(row['source_mode_projected'], 8)
                for target in (prepared / row['source_path'].removeprefix('applications/luci-app-statistics/'), stage / path):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(body)
                    target.chmod(mode)
                entries.append((path, body, mode))
            control = b'Package: luci-app-statistics\nVersion: 26.205.85817~58d43e5\nArchitecture: all\n'
            (stage / 'CONTROL').mkdir()
            (stage / 'CONTROL/control').write_bytes(control)
            (stage / 'CONTROL/control').chmod(0o644)
            def ipk(items):
                return pack([('debian-binary', b'2.0\n', 0o644), ('control.tar.gz', pack([('control', control, 0o644)]), 0o644), ('data.tar.gz', pack(items), 0o644)])
            config = b'# CONFIG_LUCI_JSMIN is not set\n# CONFIG_LUCI_CSSTIDY is not set\n'
            with patch.object(compare.batch, 'git_blob', side_effect=lambda repo, rev, row: source[row['source_path']]):
                result = compare.compare(luci, prepared, stage, ipk(entries), self.oracle, root, config)
                self.assertEqual(len(result['members']), 126)
                first = stage / entries[0][0]
                first.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'source/stage/IPK bytes or mode differ'):
                    compare.compare(luci, prepared, stage, ipk(entries), self.oracle, root, config)
                first.chmod(entries[0][2])
                first.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'source/stage/IPK bytes or mode differ'):
                    compare.compare(luci, prepared, stage, ipk(entries), self.oracle, root, config)
                first.write_bytes(entries[0][1])
                with self.assertRaisesRegex(ValueError, 'package member set differs'):
                    compare.compare(luci, prepared, stage, ipk(entries + [('unexpected', b'x', 0o644)]), self.oracle, root, config)

    def test_wrong_control_and_missing_package_member_rejected(self):
        oracle = self.oracle
        with patch.object(compare, 'physical_directory'), patch.object(compare.batch.archive, 'read_ipk', return_value=({}, {}, {})), patch.object(compare.batch.base, 'control_from_rows', return_value={'Package': 'wrong'}):
            with self.assertRaisesRegex(ValueError, 'package control differs'):
                compare.compare(None, None, None, b'', oracle, None, b'# CONFIG_LUCI_JSMIN is not set\n# CONFIG_LUCI_CSSTIDY is not set\n')
        fields = {'Package': 'luci-app-statistics', 'Version': '26.205.85817~58d43e5', 'Architecture': 'all'}
        with patch.object(compare, 'physical_directory'), patch.object(compare.batch.archive, 'read_ipk', return_value=({}, {}, {})), patch.object(compare.batch.base, 'control_from_rows', return_value=fields):
            with self.assertRaisesRegex(ValueError, 'package member set differs'):
                compare.compare(None, None, None, b'', oracle, None, b'# CONFIG_LUCI_JSMIN is not set\n# CONFIG_LUCI_CSSTIDY is not set\n')

if __name__ == '__main__':
    unittest.main()
