import tempfile
import json
import os
import subprocess
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.default_tip_event import InvalidEvent, checkpoint_event, resolve, validate_pair


class DefaultTipTests(unittest.TestCase):
    def setUp(self):
        self.source = '1' * 40
        self.tree = '2' * 40
        self.control = '3' * 40
        self.event = {'repository': 'openwrt/openwrt', 'kind': 'default_branch', 'ref': 'main',
                      'source': {'commit': self.source, 'tree': self.tree}}
        self.meta = {'full_name': 'openwrt/openwrt', 'default_branch': 'main'}
        self.commit = {'sha': self.source, 'commit': {'tree': {'sha': self.tree}}}
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name).resolve() / 'run'

    def call(self, event=None, responses=None, identities=None):
        ids = identities or [self.event['source'], {'commit': self.control, 'tree': '4' * 40}]
        def output(args, **kwargs):
            if 'rev-parse' in args:
                i = 0 if 'source' in Path(args[2]).parts else 1
                return (ids[i]['tree'] if args[-1].endswith('^{tree}') else args[-1].removesuffix('^{commit}') if args[-1].endswith('^{commit}') and args[-1][:-9] not in (self.source, self.control) else ids[i]['commit']) + '\n'
            return ''
        with patch('tools.default_tip_event.api', side_effect=responses or [self.meta, self.commit]), \
             patch('tools.default_tip_event.subprocess.check_output', side_effect=output) as git:
            result = resolve(event or self.event, {'commit': self.control, 'tree': '4' * 40}, self.run)
            return result, git

    def test_fresh_ref_and_control_are_fetched(self):
        result, git = self.call()
        self.assertEqual(result['source'], self.event['source'])
        self.assertEqual(result['status'], 'identities_resolved_only')
        self.assertTrue(any('refs/heads/main' in c.args[0] for c in git.call_args_list))
        self.assertTrue(any(self.control in c.args[0] for c in git.call_args_list))

    def test_luci_discovery_repository_maps_to_consumer_alias(self):
        event = {**self.event, 'repository': 'openwrt/luci'}
        receipt, _ = self.call(event=event, responses=[{'full_name': 'openwrt/luci', 'default_branch': 'main'}, self.commit])
        self.assertEqual(receipt['repository'], 'luci')
        self.assertEqual(receipt['discovery_repository'], 'openwrt/luci')
        self.assertEqual(receipt['repository_url'], 'https://github.com/openwrt/luci.git')

    def test_rejects_metadata_and_tree_drift(self):
        with self.assertRaisesRegex(InvalidEvent, 'branch or repository drift'):
            self.call(responses=[dict(self.meta, default_branch='other')])
        with self.assertRaisesRegex(InvalidEvent, 'commit/tree drift'):
            self.call(responses=[self.meta, {'sha': self.source, 'commit': {'tree': {'sha': '5' * 40}}}])

    def test_rejects_fetched_tree_drift(self):
        with self.assertRaisesRegex(InvalidEvent, 'fetched default branch'):
            self.call(identities=[{'commit': self.source, 'tree': '5' * 40}, {'commit': self.control, 'tree': '4' * 40}])

    def test_rejects_untrusted_inputs_before_fetch(self):
        for changes in ({'ref': '--upload-pack=bad'}, {'ref': 'a/../b'},
                        {'repository': 'attacker'}, {'source': {'commit': 'main', 'tree': self.tree}},
                        {'extra': 'x'}):
            with self.subTest(changes=changes), self.assertRaises(InvalidEvent):
                self.call(event={**self.event, **changes})

    def test_checkpoint_binds_real_v3_event(self):
        path = Path(self.temp.name) / 'decisions.json'
        doc = {'schema': 'incoming-poll-v3', 'status': 'complete',
               'observed_at': '2026-11-24T12:00:00+00:00',
               'decisions': [{'event': self.event, 'decision': 'selected', 'reason': 'new', 'status': 'pending'}]}
        path.write_text(json.dumps(doc))
        event, binding = checkpoint_event(path, 0)
        self.assertEqual(event, self.event)
        self.assertEqual(binding['event_key'], ['openwrt/openwrt', 'default_branch', 'main', self.source, '', ''])
        self.assertEqual(binding['observed_at'], doc['observed_at'])
        import hashlib
        self.assertEqual(binding['checkpoint_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        doc['decisions'].append(doc['decisions'][0])
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(InvalidEvent, 'duplicate discovery'):
            checkpoint_event(path, 0)

    def test_rejects_unsafe_run_paths_without_network(self):
        from tools.default_tip_event import validate_run_path
        link = Path(self.temp.name).resolve() / 'link'
        link.symlink_to(Path(self.temp.name).resolve(), target_is_directory=True)
        for path in (Path('relative/run'), Path('/tmp/-bad/run'), link / 'new', Path('/tmp/../new')):
            with self.subTest(path=path), self.assertRaises(InvalidEvent):
                validate_run_path(path)

    def test_git_environment_disables_redirects(self):
        _, commands = self.call()
        for call in commands.call_args_list:
            env = call.kwargs['env']
            self.assertEqual(env['GIT_CONFIG_KEY_0'], 'http.followRedirects')
            self.assertEqual(env['GIT_CONFIG_VALUE_0'], 'false')
            self.assertEqual(env['GIT_CONFIG_COUNT'], '1')

    def test_control_requires_earlier_same_branch_observation(self):
        now = {'observed_at': '2026-11-24T12:00:00Z'}
        prior = {'observed_at': '2026-11-23T12:00:00Z'}
        validate_pair(self.event, now, self.event, prior)
        with self.assertRaisesRegex(InvalidEvent, 'must precede'):
            validate_pair(self.event, now, self.event, now)
        with self.assertRaisesRegex(InvalidEvent, 'repository or branch differs'):
            validate_pair(self.event, now, {**self.event, 'repository': 'openwrt/luci'}, prior)

    def test_rejects_control_tree_drift(self):
        with self.assertRaisesRegex(InvalidEvent, 'control commit/tree drift'):
            self.call(identities=[self.event['source'], {'commit': self.control, 'tree': '5' * 40}])

    def test_hostile_git_dir_does_not_affect_identity(self):
        upstream = Path(self.temp.name) / 'upstream'
        subprocess.check_call(['git', 'init', '-q', '-b', 'main', str(upstream)])
        subprocess.check_call(['git', '-C', str(upstream), 'config', 'user.name', 'Test'])
        subprocess.check_call(['git', '-C', str(upstream), 'config', 'user.email', 'test@example.invalid'])
        (upstream / 'a').write_text('control')
        subprocess.check_call(['git', '-C', str(upstream), 'add', 'a'])
        subprocess.check_call(['git', '-C', str(upstream), 'commit', '-qm', 'control'])
        control = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
        (upstream / 'a').write_text('source')
        subprocess.check_call(['git', '-C', str(upstream), 'commit', '-qam', 'source'])
        source = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
        tree = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
        event = {**self.event, 'source': {'commit': source, 'tree': tree}}
        meta = self.meta
        commit = {'sha': source, 'commit': {'tree': {'sha': tree}}}
        real = subprocess.check_output
        def fetch_local(args, **kwargs):
            if 'fetch' in args:
                args = list(args)
                if args[-1] not in ('refs/heads/main', control):
                    return ''
                args[args.index('origin')] = str(upstream)
            if 'rev-parse' in args and args[-1].endswith('^{commit}') and args[-1][:-9] not in (source, control):
                return args[-1][:-9] + '\n'
            return real(args, **kwargs)
        control_tree = real(['git', '-C', str(upstream), 'rev-parse', control + '^{tree}'], text=True).strip()
        with patch.dict(os.environ, {'GIT_DIR': str(Path(self.temp.name) / 'hostile')}), \
             patch('tools.default_tip_event.api', side_effect=[meta, commit]), \
             patch('tools.default_tip_event.subprocess.check_output', side_effect=fetch_local):
            receipt = resolve(event, {'commit': control, 'tree': control_tree}, self.run)
        self.assertEqual(receipt['source'], event['source'])
        self.assertEqual(receipt['control']['commit'], control)

    def test_refuses_existing_run(self):
        self.run.mkdir()
        with self.assertRaisesRegex(InvalidEvent, 'already exists'):
            self.call()


if __name__ == '__main__':
    unittest.main()
