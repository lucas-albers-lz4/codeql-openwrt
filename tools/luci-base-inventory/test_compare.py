import pathlib
import tempfile
import unittest
from unittest.mock import patch
import compare


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.prepared = self.base / 'prepared'
        self.staged = self.base / 'staged'
        self.prepared.mkdir(); self.staged.mkdir()
        self.contents = {}
        self.members = {}
        selected = []
        for i in range(17):
            src = f'modules/luci-base/ucode/file{i}.uc'
            member = f'usr/share/ucode/luci/file{i}.uc'
            data = f'file {i}\n'.encode()
            self.contents[src] = data
            self.put(self.prepared, f'ucode/file{i}.uc', data)
            self.put(self.staged, member, data)
            self.members[member] = {'type': 'file', 'bytes': data, 'mode': 0o644}
            selected.append({'source_path': src, 'git_blob': f'blob{i}', 'git_mode': '100644',
                             'sha256': compare.sha(data), 'expected_member_mode_bits': 0o644,
                             'expected_package_member_path': member})
        unknown = []
        for i in range(3):
            unknown.append({'source_path': f'modules/luci-base/root/unknown{i}', 'git_blob': f'u{i}',
                            'git_mode':'100644', 'sha256': compare.sha(b'unknown'),
                            'expected_member_mode_bits': 0o644, 'expected_package_member_path': f'unknown{i}'})
            self.contents[unknown[-1]['source_path']] = b'unknown'
        shell = unknown[0]; shell['source_path'] = 'modules/luci-base/root/etc/init.d/ucitrack'; shell['expected_package_member_path'] = 'etc/init.d/ucitrack'
        shell_data = b'#!/bin/sh /etc/rc.common\n'
        shell['sha256'] = compare.sha(shell_data)
        self.contents[shell['source_path']] = shell_data
        self.put(self.prepared, 'root/etc/init.d/ucitrack', shell_data)
        self.put(self.staged, 'etc/init.d/ucitrack', shell_data)
        self.members['etc/init.d/ucitrack'] = {'type':'file', 'bytes':shell_data, 'mode':0o644}
        generated = b'generated\n'
        path = 'usr/share/ucode/luci/version.uc'
        self.put(self.staged, path, generated)
        self.put(self.prepared, 'src/version.uc', generated)
        self.members[path] = {'type':'file', 'bytes':generated, 'mode':0o644}
        self.oracle = {'source_inventory':{'source':{'commit':compare.PINS['luci']}},
                       'selected_source_candidates':selected, 'unknown_extensionless_candidates':unknown,
                       'generated_expected_members':[{'path':path, 'expected_bytes_utf8': generated.decode(), 'expected_mode_bits_under_umask_022':0o644}]}
        self.gitpatch = patch.object(compare, 'git', side_effect=self.fake_git); self.gitpatch.start(); self.addCleanup(self.gitpatch.stop)
        self.showpatch = patch.object(compare.subprocess, 'check_output', side_effect=lambda args: self.contents[args[-1].split(':',1)[1]]); self.showpatch.start(); self.addCleanup(self.showpatch.stop)
    def put(self, root, path, data):
        p = root / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data); p.chmod(0o644)
    def fake_git(self, repo, *args):
        path = args[-1].split(':',1)[1]
        for r in self.oracle['selected_source_candidates'] + self.oracle['unknown_extensionless_candidates']:
            if r['source_path'] == path: return r['git_blob']
        raise AssertionError(path)
    def run_check(self):
        return compare.compare_candidates(self.oracle, self.base, self.prepared, self.staged, self.members, compare.EXPECTED_VERSION)
    def test_positive_and_absent_unknown(self):
        got = self.run_check()
        self.assertEqual(sum(x['status']=='selected present' for x in got), 17)
        self.assertEqual(sum(x['status']=='unknown absent' for x in got), 2)
        self.assertEqual(sum(x['status']=='excluded shell control' for x in got), 1)
    def test_rejects_stale_source_and_wrong_mode(self):
        first = self.oracle['selected_source_candidates'][0]
        first['sha256'] = compare.sha(b'stale')
        with self.assertRaisesRegex(ValueError, 'source identity differs'): self.run_check()
        first['sha256'] = compare.sha(self.contents[first['source_path']])
        self.members[first['expected_package_member_path']]['mode'] = 0o755
        with self.assertRaisesRegex(ValueError, 'candidate mode differs'): self.run_check()
    def test_rejects_stage_drift_and_generated_drift(self):
        p = self.oracle['selected_source_candidates'][0]['expected_package_member_path']
        self.members[p]['bytes'] = b'drift'
        with self.assertRaisesRegex(ValueError, 'stage/IPK candidate bytes differ'): self.run_check()
        self.members[p]['bytes'] = self.contents[self.oracle['selected_source_candidates'][0]['source_path']]
        self.members['usr/share/ucode/luci/version.uc']['bytes'] = b'bad generated'
        with self.assertRaisesRegex(ValueError, 'generated version.uc differs'): self.run_check()
    def test_transformed_hash_is_required(self):
        row = self.oracle['selected_source_candidates'][0]
        member = row['expected_package_member_path']
        expected = b'expected transformed header'
        row['transform'] = {'expected_member_sha256_from_pinned_source_and_recipe': compare.sha(expected)}
        self.put(self.staged, member, expected)
        self.members[member]['bytes'] = expected
        self.run_check()
        self.put(self.staged, member, b'wrong transformation')
        self.members[member]['bytes'] = b'wrong transformation'
        with self.assertRaisesRegex(ValueError, 'stage/IPK candidate bytes differ'): self.run_check()
    def test_unexpected_extensionless_under_ucode_root(self):
        self.members['usr/share/ucode/.extra'] = {'type':'file','bytes':b'extra','mode':0o644}
        with self.assertRaisesRegex(ValueError, 'unexpected Ucode candidate'): self.run_check()
    def test_rejects_unexpected_candidate_and_duplicate_oracle(self):
        self.members['other/extra.uc'] = {'type':'file','bytes':b'extra','mode':0o644}
        with self.assertRaisesRegex(ValueError, 'unexpected Ucode candidate'): self.run_check()
        del self.members['other/extra.uc']
        self.oracle['selected_source_candidates'][1]['expected_package_member_path'] = self.oracle['selected_source_candidates'][0]['expected_package_member_path']
        with self.assertRaisesRegex(ValueError, 'duplicate oracle member'): self.run_check()
    def test_near_miss_required_and_shebang_predicate(self):
        del self.members['etc/init.d/ucitrack']
        with self.assertRaisesRegex(ValueError, 'missing candidate member'): self.run_check()
        self.assertTrue(compare.recognized_shebang(b'#!/usr/bin/env -S ucode -S'))
        self.assertFalse(compare.recognized_shebang(b'#!/bin/sh # ucode'))
    def test_rejects_symlink_parent(self):
        p = self.staged / 'usr/share/ucode/luci'
        p.rename(self.base / 'moved-luci')
        p.symlink_to(self.base / 'moved-luci', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink in source/stage path'): self.run_check()

if __name__ == '__main__': unittest.main()
