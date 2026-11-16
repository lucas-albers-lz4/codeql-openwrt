"""Canonical publication must not retain unsupported assessed effects."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from policy import cgi_backup, cgi_download, ubus_file_exec_list_backup
from policy.interchange_contract import ContractError, join_policy_grants

ROOT = Path(__file__).resolve().parents[2]
# Independent publication contract: update deliberately when outputs change.
# The successful-emission trace below must match exactly, catching both missing
# writes and new outputs that also need rejection-path sentinel coverage.
EXPECTED_OUTPUTS = frozenset(map(Path, (
    'policy/cgi_backup_decisions.json',
    'policy/cgi_download_decisions.json',
    'policy/cgi_exec_decisions.json',
    'policy/cgi_exec_file_decisions.json',
    'policy/cgi_exec_status_decisions.json',
    'policy/cgi_upload_decisions.json',
    'policy/grants.json',
    'policy/no_ubusauth_decisions.json',
    'policy/policy_decisions.json',
    'policy/ubus_file_exec_decisions.json',
    'policy/ubus_file_exec_ifup_decisions.json',
    'policy/ubus_file_exec_kill_decisions.json',
    'policy/ubus_file_exec_list_backup_decisions.json',
    'policy/ubus_file_exec_mounts_decisions.json',
    'policy/ubus_hostapd_del_client_decisions.json',
    'policy/ubus_hostapd_wps_cancel_decisions.json',
    'policy/ubus_hostapd_wps_start_decisions.json',
    'policy/ubus_hostapd_wps_status_decisions.json',
    'policy/ubus_luci_getbuiltinethernetports_decisions.json',
    'policy/ubus_luci_getconntrackhelpers_decisions.json',
    'policy/ubus_luci_getleds_decisions.json',
    'policy/ubus_luci_getmountpoints_decisions.json',
    'policy/ubus_luci_getodhcp6cstats_decisions.json',
    'policy/ubus_luci_gettimezones_decisions.json',
    'policy/ubus_luci_getunixtime_decisions.json',
    'policy/ubus_luci_getversion_decisions.json',
    'policy/ubus_rc_init_decisions.json',
    'policy/ubus_rc_list_decisions.json',
    'policy/ubus_system_board_decisions.json',
    'policy/ubus_system_info_decisions.json',
    'policy/ubus_system_reboot_decisions.json',
    'policy/uci_consumers.json',
    'reports/handler_effects.json',
    'reports/m2-cgi-download-effect.json',
    'reports/m2-cgi-exec-effect.json',
    'reports/m2-cgi-exec-file-effect.json',
    'reports/m2-cgi-exec-status-effect.json',
    'reports/m2-cgi-upload-effect.json',
    'reports/m2-ubus-file-exec-effect.json',
    'reports/m2-ubus-file-exec-ifup-effect.json',
    'reports/m2-ubus-file-exec-kill-effect.json',
    'reports/m2-ubus-file-exec-list-backup-effect.json',
    'reports/m2-ubus-file-exec-mounts-effect.json',
    'reports/m2-ubus-hostapd-del-client-effect.json',
    'reports/m2-ubus-hostapd-wps-cancel-effect.json',
    'reports/m2-ubus-hostapd-wps-start-effect.json',
    'reports/m2-ubus-hostapd-wps-status-effect.json',
    'reports/m2-ubus-luci-getbuiltinethernetports-effect.json',
    'reports/m2-ubus-luci-getconntrackhelpers-effect.json',
    'reports/m2-ubus-luci-getleds-effect.json',
    'reports/m2-ubus-luci-getmountpoints-effect.json',
    'reports/m2-ubus-luci-getodhcp6cstats-effect.json',
    'reports/m2-ubus-luci-gettimezones-effect.json',
    'reports/m2-ubus-luci-getunixtime-effect.json',
    'reports/m2-ubus-luci-getversion-effect.json',
    'reports/m2-ubus-rc-init-effect.json',
    'reports/m2-ubus-rc-list-effect.json',
    'reports/m2-ubus-system-board-effect.json',
    'reports/m2-ubus-system-info-effect.json',
    'reports/m2-ubus-system-reboot-effect.json',
)))
CASES = (
    (cgi_backup, 'policy:effect:cgi-backup-sensitive-read', 'luci-mod-system-flash-backup', 'policy:grant:root:cgi_io:cgi-backup'),
    (cgi_download, 'policy:effect:cgi-download-file-read', 'luci-mod-system-flash-download', 'policy:grant:root:cgi_io:cgi-download'),
    (ubus_file_exec_list_backup, 'policy:effect:ubus-file-exec-list-backup:list-backup', 'luci-mod-system-flash-list-backup', 'policy:grant:root:ubus_http:file.exec:list-backup'),
)


class CanonicalPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        for name in ('policy', 'corpus', 'reports', 'schemas'):
            shutil.copytree(ROOT / name, self.repo / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))

    def files(self, root=None):
        root = root or self.repo
        result = {}
        for p in root.rglob('*'):
            if '__pycache__' in p.parts:
                continue
            mode = p.lstat().st_mode
            if p.is_symlink():
                value = ('link', os.readlink(p), p.read_bytes())
            elif p.is_file():
                value = ('file', p.read_bytes())
            else:
                value = ('directory',)
            result[p.relative_to(root)] = (mode, value)
        return result

    def output_targets(self):
        # A real successful emission in a separate copy discovers every actual
        # write, including paths not returned by the CLI and repeated upserts.
        calibration = Path(self.temp.name) / 'calibration'
        shutil.copytree(self.repo, calibration, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        trace = r'''
import contextlib, io, json, os, pathlib, runpy, sys
root = pathlib.Path.cwd()
writes, reads_before_write = set(), set()
def audit(event, args):
    if event != 'open' or not isinstance(args[0], (str, bytes, os.PathLike)):
        return
    path = pathlib.Path(os.fsdecode(args[0]))
    if not path.is_absolute():
        path = root / path
    try:
        path = path.relative_to(root).as_posix()
    except ValueError:
        return
    flags = args[2]
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        writes.add(path)
    elif path not in writes:
        reads_before_write.add(path)
sys.addaudithook(audit)
sys.argv = ['policy', 'emit']
with contextlib.redirect_stdout(io.StringIO()):
    try:
        runpy.run_module('policy', run_name='__main__', alter_sys=True)
    except SystemExit as exc:
        if exc.code not in (None, 0):
            raise
print(json.dumps({'writes': sorted(writes), 'read_outputs': sorted(writes & reads_before_write)}))
'''
        env = os.environ.copy()
        env.pop('PYTHONPATH', None)
        flags = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        result = subprocess.run([sys.executable, *flags, '-B', '-c', trace], cwd=calibration,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        targets = {Path(p) for p in data['writes']}
        self.assertSetEqual(targets, EXPECTED_OUTPUTS, 'successful emission output set changed')
        # This retained output is also input to preflight. If another output
        # becomes an input, review its sentinel before corrupting its semantics.
        self.assertEqual(data['read_outputs'], ['reports/handler_effects.json'])
        for target in targets:
            self.assertTrue((self.repo / target).is_file(), str(target))
            self.assertEqual(target.suffix, '.json', str(target))
        return targets

    def seed_outputs(self, targets):
        # Whitespace makes each existing JSON output noncanonical without
        # changing its parsed value, including the retained aggregate input.
        for target in targets:
            path = self.repo / target
            original = path.read_bytes()
            json.loads(original)
            path.write_bytes(original + b' \t\n')
            self.assertNotEqual(path.read_bytes(), original, str(target))

    def emit(self):
        env = os.environ.copy()
        env.pop('PYTHONPATH', None)
        flags = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        return subprocess.run([sys.executable, *flags, '-B', '-m', 'policy', 'emit'],
                              cwd=self.repo, env=env, capture_output=True, text=True)

    def emit_traced(self):
        # A byte snapshot alone cannot detect writing identical bytes or
        # writing and restoring them. Audit actual write-capable opens too.
        env = os.environ.copy()
        env.pop('PYTHONPATH', None)
        flags = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        trace_file = Path(self.temp.name) / 'rejection-writes.json'
        env['POLICY_TEST_WRITE_TRACE'] = str(trace_file)
        command = ['-c', r'''
import json, os, runpy, sys
writes = []
def audit(event, args):
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(args[0])
        # Imports may open the null device; it is not a publication target.
        if path != os.devnull and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            writes.append(path)
sys.addaudithook(audit)
sys.argv = ['policy', 'emit']
try:
    runpy.run_module('policy', run_name='__main__', alter_sys=True)
finally:
    data = json.dumps(writes)
    with open(os.environ['POLICY_TEST_WRITE_TRACE'], 'w') as f:
        f.write(data)
''']
        result = subprocess.run([sys.executable, *flags, '-B', *command], cwd=self.repo,
                                env=env, capture_output=True, text=True)
        return result, json.loads(trace_file.read_text())

    def test_missing_delegated_support_rejects_before_any_write(self):
        targets = self.output_targets()
        fixture = self.repo / 'policy/fixtures/rpcd.config'
        original = fixture.read_text()
        line = "\tlist read 'luci-mod-system-flash'\n"
        self.assertEqual(original.count(line), 1)
        fixture.write_text(original.replace(line, ''))
        # Independently exercise the actual mutated producers and consumer join.
        # The root grant remains factual, but is supplementary to each expectation.
        for module, record_id, expectation, root_id in CASES:
            with self.subTest(record_id=record_id):
                grants, bundle, effects = module.build_artifacts(self.repo / 'policy/fixtures', self.repo)
                row = next(r for r in (effects if isinstance(effects, list) else [effects]) if r['record_id'] == record_id)
                self.assertEqual(row['expectation_id'], expectation)
                self.assertEqual(row['assessment'], 'intended_access')
                self.assertEqual([g['record_id'] for g in grants if g['record_id'] in row['evidence_refs']], [root_id])
                relevant = [d for d in bundle['decisions'] if d['record_id'].endswith(('cgi-backup-allow', 'cgi-download-allow', 'list-backup-allow'))]
                delegated = next(d for d in relevant if d['session_class'] == 'luci-mod-system-flash')
                root = next(d for d in relevant if d['session_class'] == 'root')
                self.assertNotEqual(delegated['outcome'], 'allow')
                self.assertEqual(root['outcome'], 'allow')
                with self.assertRaisesRegex(ContractError, 'primary expectation-matching grant'):
                    join_policy_grants(row, {g['record_id']: g for g in grants}, scope='aggregate')
        self.seed_outputs(targets)
        seeded = {target: (self.repo / target).read_bytes() for target in targets}
        aliases = Path(self.temp.name) / 'aliases'
        aliases.mkdir()
        for aliased in (False, True):
            if aliased:
                # Relative symlinks point outside the repo, one per output;
                # the aggregate remains a valid, readable retained input.
                for target in targets:
                    path = self.repo / target
                    backing = aliases / target
                    backing.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(path, backing)
                    path.symlink_to(os.path.relpath(backing, path.parent))
            for traced in (False, True):
                with self.subTest(aliased=aliased, traced=traced):
                    # Keep each subtest independent even if a mutant wrote.
                    for target in targets:
                        (self.repo / target).write_bytes(seeded[target])
                    before = self.files()
                    before_aliases = self.files(aliases)
                    if traced:
                        result, writes = self.emit_traced()
                    else:
                        result, writes = self.emit(), []
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertNotIn('Traceback', result.stderr)
                    for _, record_id, expectation, _ in CASES:
                        self.assertIn(record_id, result.stderr)
                        self.assertIn(expectation, result.stderr)
                    self.assertIn('primary expectation-matching grant', result.stderr)
                    self.assertIn('not a denial', result.stderr)
                    self.assertEqual(writes, [], 'write-capable opens on rejection')
                    after = self.files()
                    changed = sorted(str(p) for p in before.keys() | after.keys()
                                     if before.get(p) != after.get(p))
                    self.assertEqual(changed, [], 'repository paths changed on rejection')
                    self.assertEqual(before_aliases, self.files(aliases))

    def test_retained_effect_is_validated_against_fresh_grants(self):
        catalog = self.repo / 'reports/handler_effects.json'
        rows = json.loads(catalog.read_text())
        row = next(r for r in rows if r['record_id'] == 'm4:effect:luci-setBlockDetect-system')
        row['evidence_refs'] = [ref for ref in row['evidence_refs']
                                if ref != 'policy:grant:luci-mod-system-mounts:ubus_http:luci.setBlockDetect']
        catalog.write_text(json.dumps(rows))
        before = self.files()
        result = self.emit()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('Traceback', result.stderr)
        self.assertIn(row['record_id'], result.stderr)
        self.assertIn('primary expectation-matching grant', result.stderr)
        self.assertEqual(before, self.files())

    def test_stock_cli_is_byte_stable_and_joins_all_effects(self):
        before = self.files()
        for _ in range(2):
            result = self.emit()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(before, self.files())
        grants = json.loads((self.repo / 'policy/grants.json').read_text())
        by_id = {g['record_id']: g for g in grants}
        rows = json.loads((self.repo / 'reports/handler_effects.json').read_text())
        self.assertTrue(rows)
        for row in rows:
            join_policy_grants(row, by_id, scope='aggregate')
        for _, record_id, expectation, root_id in CASES:
            row = next(r for r in rows if r['record_id'] == record_id)
            self.assertEqual(row['expectation_id'], expectation)
            self.assertEqual(row['assessment'], 'intended_access')
            primary, supplementary = join_policy_grants(row, by_id, scope='aggregate')
            self.assertTrue(primary)
            self.assertEqual([g['record_id'] for g in supplementary], [root_id])


if __name__ == '__main__':
    unittest.main()
