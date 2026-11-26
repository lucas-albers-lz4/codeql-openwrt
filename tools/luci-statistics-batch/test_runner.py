import importlib.util
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('statistics_runner', HERE / 'run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class RunnerTests(unittest.TestCase):
    def test_prerequisite_logs_copied_and_alias_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source, output = root / 'prereq', root / 'output'
            source.mkdir()
            output.mkdir()
            names = ('apt-update.log', 'apt-update.time', 'apt-install.log', 'apt-install.time')
            for name in names:
                (source / name).write_text(name)
            runner.capture_prerequisites(SimpleNamespace(out=output), source)
            self.assertEqual((output / names[0]).read_text(), names[0])
            for path in output.iterdir():
                path.unlink()
            (source / names[0]).unlink()
            (source / names[0]).symlink_to(source / names[1])
            with self.assertRaisesRegex(ValueError, 'prerequisite log exceeds limit'):
                runner.capture_prerequisites(SimpleNamespace(out=output), source)

    def test_host_preflight_records_capacity_and_rejects_small_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / 'output'
            output.mkdir()
            probe = SimpleNamespace(root=root, out=output)
            with patch.object(runner.platform, 'system', return_value='Linux'), patch.object(runner.platform, 'machine', return_value='x86_64'), patch.object(runner.platform, 'platform', return_value='Linux-test'), patch.object(runner.os, 'cpu_count', return_value=2), patch.object(runner.Path, 'read_text', return_value='MemTotal: 16777216 kB\n'), patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=70 * 1024**3)):
                runner.host_preflight(probe)
            facts = __import__('json').loads((output / 'host-preflight.json').read_text())
            self.assertEqual(facts['disk_free_bytes'], 70 * 1024**3)
            with patch.object(runner.platform, 'system', return_value='Linux'), patch.object(runner.platform, 'machine', return_value='x86_64'), patch.object(runner.os, 'cpu_count', return_value=2), patch.object(runner.Path, 'read_text', return_value='MemTotal: 16777216 kB\n'), patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=1)):
                with self.assertRaisesRegex(ValueError, 'host disk below 60 GiB'):
                    runner.host_preflight(probe)

    def test_source_status_uses_tracked_only_for_openwrt(self):
        calls = []
        expected = {name: {'tree': 'tree-' + name} for name in runner.metadata.PINS}
        def git(label, repo, *argv):
            name = repo.name
            calls.append((name, argv))
            if argv[0] == 'rev-parse':
                return (runner.metadata.PINS[name][1] + '\n' + expected[name]['tree'] + '\n').encode()
            return b''
        runner.post_sources(SimpleNamespace(root=Path('/tmp/probe'), git=git), 'test', expected)
        statuses = {name: argv for name, argv in calls if argv[0] == 'status'}
        self.assertIn('--untracked-files=no', statuses['openwrt'])
        self.assertIn('--untracked-files=all', statuses['luci'])
        self.assertIn('--untracked-files=all', statuses['packages'])

    def test_metadata_mismatch_retains_both_exact_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ow, output = root / 'openwrt', root / 'output'
            (ow / 'tmp').mkdir(parents=True)
            output.mkdir()
            (ow / '.config').write_bytes(b'changed config')
            (ow / 'tmp/.packagedeps').write_bytes(b'changed graph')
            probe = SimpleNamespace(root=root, out=output)
            with self.assertRaisesRegex(ValueError, 'frozen Statistics config differs'):
                runner.frozen_metadata(probe, 'sample')
            self.assertEqual((output / 'metadata-sample-config').read_bytes(), b'changed config')
            self.assertEqual((output / 'metadata-sample-packagedeps').read_bytes(), b'changed graph')

    def test_exact_initial_graph_allowlist_and_in_run_lock(self):
        self.assertEqual(runner.GRAPH_SHAS, frozenset({
            '48bbf0a4525d53718fb8271f52857082e7917b09c268873706261b897ecf3b69',
            '2f934e455a22f63289ebb82e87f59866f002167dae7418b5ed5464cf6a608a80',
        }))
        variants = (b'graph variant A\n', b'graph variant B\n')
        digests = frozenset(hashlib.sha256(x).hexdigest() for x in variants)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ow, output = root / 'openwrt', root / 'output'
            (ow / 'tmp').mkdir(parents=True)
            output.mkdir()
            (ow / '.config').write_bytes(b'fixture config')
            graph = ow / 'tmp/.packagedeps'
            probe = SimpleNamespace(root=root, out=output)
            with patch.object(runner, 'CONFIG_SHA', hashlib.sha256(b'fixture config').hexdigest()), patch.object(runner, 'GRAPH_SHAS', digests), patch.object(runner.check, 'validate_final_config'), patch.object(runner.check, 'validate_packagedeps'):
                for index, variant in enumerate(variants):
                    graph.write_bytes(variant)
                    # Each separate run starts with the actual pre-build label.
                    run_output = root / ('output-' + str(index))
                    run_output.mkdir()
                    probe.out = run_output
                    _, chosen = runner.frozen_metadata(probe, 'pre-build')
                    self.assertEqual(chosen, hashlib.sha256(variant).hexdigest())
                    runner.frozen_metadata(probe, 'phase-before', chosen)
                    graph.write_bytes(variants[1 - index])
                    with self.assertRaisesRegex(ValueError, 'Statistics graph changed after initial lock'):
                        runner.frozen_metadata(probe, 'phase-after', chosen)
                    graph.write_bytes(variant + b'unexpected edge\n')
                    probe.out = root / ('unexpected-' + str(index))
                    probe.out.mkdir()
                    with self.assertRaisesRegex(ValueError, 'initial Statistics graph not approved'):
                        runner.frozen_metadata(probe, 'pre-build')

    def test_kernel_ipk_inventory_identity_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            directory = root / 'openwrt/bin/targets/x86/64/packages'
            directory.mkdir(parents=True)
            (directory / 'kernel_6.12.116.ipk').write_bytes(b'kernel ipk')
            probe = SimpleNamespace(root=root)
            linux = root / 'openwrt/build_dir/linux'
            linux.mkdir(parents=True)
            magic = '0123456789abcdef0123456789abcdef'
            (linux / '.vermagic').write_text(magic + '\n')
            (linux / 'modules.builtin').write_bytes(b'kernel/net/example.ko\n')
            version = '6.12.116~' + magic + '-r1'
            version_file = root / 'openwrt/staging_dir/target-x86_64_musl/kernel.version'
            version_file.parent.mkdir(parents=True)
            version_file.write_text(version + '\n')
            fields = {'Package': 'kernel', 'Version': version, 'Architecture': 'x86_64'}
            members = {'lib/modules/6.12.116/modules.builtin': {'type': 'file', 'mode': 0o644, 'bytes': b'example.ko\n'},
                       'lib/modules/6.12.116/modules.builtin.modinfo': {'type': 'file', 'mode': 0o644, 'bytes': b'metadata'}}
            with patch.object(runner.compare.batch.archive, 'read_ipk', return_value=({}, members, {})), patch.object(runner.compare.batch.base, 'control_from_rows', return_value=fields):
                self.assertEqual(len(runner.kernel_package_inventory(probe, linux)), 1)
                (directory / 'kernel_duplicate.ipk').write_bytes(b'duplicate')
                with self.assertRaisesRegex(ValueError, 'kernel package output inventory missing or ambiguous'):
                    runner.kernel_package_inventory(probe, linux)
                (directory / 'kernel_duplicate.ipk').unlink()
                fields['Version'] = '6.12.116~unknown-r1'
                with self.assertRaisesRegex(ValueError, 'kernel control identity differs'):
                    runner.kernel_package_inventory(probe, linux)
                fields['Version'] = version
                members['lib/modules/6.12.116/modules.builtin']['bytes'] = b'wrong\n'
                with self.assertRaisesRegex(ValueError, 'kernel builtin projection differs'):
                    runner.kernel_package_inventory(probe, linux)

    def test_same_job_sequence_and_kernel_failure_stops_statistics(self):
        for fail in (False, True):
            with self.subTest(kernel_failure=fail), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                output = root / 'output'
                output.mkdir()
                linux = root / 'openwrt/build_dir/target-x86_64_musl/linux-x86_64/linux-6.12.116'
                linux.mkdir(parents=True)
                (linux / '.modules').write_bytes(b'')
                for name in ('.config', '.vermagic', 'modules.builtin', 'modules.builtin.modinfo', 'include/config/kernel.release'):
                    p = linux / name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(b'evidence')
                kp = root / 'openwrt/bin/targets/x86/64/packages/kernel_test.ipk'
                kp.parent.mkdir(parents=True)
                kp.write_bytes(b'kernel ipk')
                kv = root / 'openwrt/staging_dir/target-x86_64_musl/kernel.version'
                kv.parent.mkdir(parents=True)
                kv.write_bytes(b'version')
                ipk = root / 'openwrt/bin/packages/x86_64/luci/luci-app-statistics_26.205.85817~58d43e5_all.ipk'
                ipk.parent.mkdir(parents=True)
                ipk.write_bytes(b'ipk')
                probe = SimpleNamespace(root=root, out=output, run=lambda: {'source_before': {}})
                calls = []
                def invoke(probe, label, target, sources, graph_lock):
                    calls.append(target)
                    if fail and target == 'package/kernel/linux/compile':
                        raise ValueError('missing kernel module')
                with patch.object(runner, 'invoke_make', side_effect=invoke), patch.object(runner, 'host_preflight'), patch.object(runner, 'source_preflight'), patch.object(runner, 'frozen_metadata', return_value=(b'config', 'locked')), patch.object(runner.compare, 'load_oracle', return_value={}), patch.object(runner.compare, 'physical_directory'), patch.object(runner.compare, 'compare', return_value={}), patch.object(runner.kernel, 'inventory', return_value={'kernel': 'same'}), patch.object(runner, 'kernel_package_inventory', return_value={'kernel_test.ipk': 'same'}):
                    if fail:
                        with self.assertRaisesRegex(ValueError, 'missing kernel module'):
                            runner.run_build(probe)
                        self.assertNotIn('package/feeds/luci/luci-app-statistics/compile', calls)
                    else:
                        result = runner.run_build(probe)
                        self.assertEqual(result['status'], 'statistics_package_compared_review_required')
                        self.assertEqual(calls, ['tools/install', 'toolchain/install', 'target/linux/compile', 'package/kernel/linux/compile', 'package/feeds/luci/luci-app-statistics/compile'])

    def test_make_checks_metadata_before_and_after_and_stops_on_kernel_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / 'output'
            output.mkdir()
            (root / 'openwrt').mkdir()
            probe = SimpleNamespace(root=root, out=output, quiescent=True, phases=[], sources=lambda suffix: None, consumer_identity=lambda suffix: None)
            calls = []
            def invoke(label, argv, cwd, timeout):
                calls.append((label, argv, cwd, timeout))
                (output / (label + '.time')).write_bytes(b'Maximum resident set size (kbytes): 123\n')
                (output / (label + '.stdout')).write_bytes(b'')
                (output / (label + '.stderr')).write_bytes(b'is not available in the kernel config - generating empty package')
            probe.invoke = invoke
            with patch.object(runner, 'frozen_metadata') as guard, patch.object(runner.check, 'validate_link'), patch.object(runner, 'post_sources'):
                with self.assertRaisesRegex(RuntimeError, 'selected kernel package generated empty'):
                    runner.invoke_make(probe, 'kernel-compile', 'target/linux/compile', {}, 'locked')
            self.assertEqual(guard.call_count, 2)
            self.assertEqual(calls[0][1][-4:], ['make', '-j2', 'target/linux/compile', 'V=s'])

    def test_nonquiescent_failure_never_reads_metadata_after_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            probe = SimpleNamespace(root=root, out=root, quiescent=True)
            def invoke(*args, **kwargs):
                probe.quiescent = False
                raise RuntimeError('process not quiescent')
            probe.invoke = invoke
            with patch.object(runner, 'frozen_metadata') as guard:
                with self.assertRaisesRegex(RuntimeError, 'process not quiescent'):
                    runner.invoke_make(probe, 'kernel-compile', 'target/linux/compile', {}, 'locked')
            self.assertEqual(guard.call_count, 1)

if __name__ == '__main__':
    unittest.main()
