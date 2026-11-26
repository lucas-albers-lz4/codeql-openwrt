import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).with_name('locate-paths.sh').resolve()

class PackageResolutionTests(unittest.TestCase):
    def run_find(self, root, expression):
        return subprocess.run(['bash', '-c', f'source "$HELPER"; {expression}'],
                              env={**os.environ, 'HELPER':str(HELPER), 'ROOT':str(root.resolve())},
                              capture_output=True, check=True).stdout.split(b'\0')[:-1]

    def test_exact_package_stage_and_per_feed_ipk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stage = root/'build_dir/target-x86_64_musl/luci-mod-status/ipkg-x86_64/luci-mod-status'
            other = root/'build_dir/target-x86_64_musl/luci-mod-status-old/ipkg-x86_64/luci-mod-status'
            ipk = root/'bin/packages/x86_64/luci/luci-mod-status_26.284.22350~8125d12_x86_64.ipk'
            for p in (stage, other, ipk):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.mkdir() if p.suffix == '' else p.touch()
            found = self.run_find(root, 'find_package_stage "$ROOT" luci-mod-status')
            self.assertEqual(found, [os.fsencode(stage.resolve())])
            found = self.run_find(root, 'find_package_ipk "$ROOT" luci-mod-status')
            self.assertEqual(found, [os.fsencode(ipk.resolve())])
            duplicate = root/'bin/packages/x86_64/base/luci-mod-status_26.284.22350~8125d12_all.ipk'
            duplicate.parent.mkdir(parents=True)
            duplicate.touch()
            found = self.run_find(root, 'find_package_ipk "$ROOT" luci-mod-status')
            self.assertEqual(set(found), {os.fsencode(ipk.resolve()), os.fsencode(duplicate.resolve())})


    def test_check_feed_links_includes_three_packages_and_dependency_recipe(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); openwrt=root/'openwrt'; luci=root/'luci'; packages=root/'packages'
            (openwrt/'feeds').mkdir(parents=True); (openwrt/'package/feeds/luci').mkdir(parents=True)
            luci.mkdir(); packages.mkdir()
            (openwrt/'feeds/luci').symlink_to(luci, target_is_directory=True)
            (openwrt/'feeds/packages').symlink_to(packages, target_is_directory=True)
            for pkg in ('luci-mod-status','luci-mod-network','luci-mod-system','luci-mod-admin-full'):
                target=luci/'modules'/pkg; target.mkdir(parents=True)
                (openwrt/'package/feeds/luci'/pkg).symlink_to(target, target_is_directory=True)
            result=subprocess.run(['bash','-c','source "$HELPER"; pkg=luci-mod-status; check_feed_links "$ROOT/openwrt" "$ROOT/luci" "$ROOT/packages"; printf \"%s\\n\" "$pkg"'],
                                  env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve())},capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),b'luci-mod-status','feed helper must not overwrite caller target')
            (openwrt/'package/feeds/luci/luci-mod-admin-full').unlink()
            (openwrt/'package/feeds/luci/luci-mod-admin-full').symlink_to(luci/'modules/luci-mod-system',target_is_directory=True)
            result=subprocess.run(['bash','-c','source "$HELPER"; check_feed_links "$ROOT/openwrt" "$ROOT/luci" "$ROOT/packages"'],
                                  env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve())},capture_output=True)
            self.assertNotEqual(result.returncode,0)


    def test_real_runner_target_loop_builds_only_three_selected_packages(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); openwrt=root/'openwrt'; luci=root/'luci'; packages=root/'packages'
            (openwrt/'feeds').mkdir(parents=True); (openwrt/'package/feeds/luci').mkdir(parents=True)
            luci.mkdir(); packages.mkdir()
            (openwrt/'feeds/luci').symlink_to(luci,target_is_directory=True)
            (openwrt/'feeds/packages').symlink_to(packages,target_is_directory=True)
            for pkg in ('luci-mod-status','luci-mod-network','luci-mod-system','luci-mod-admin-full'):
                target=luci/'modules'/pkg; target.mkdir(parents=True)
                (openwrt/'package/feeds/luci'/pkg).symlink_to(target,target_is_directory=True)
            script='source "$HELPER"; targets=(); capture(){ targets+=("$1"); }; run_package_batches "$ROOT/openwrt" "$ROOT/luci" "$ROOT/packages" capture; printf "%s\n" "${targets[@]}"'
            result=subprocess.run(['bash','-c',script],env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve())},capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.splitlines(),[b'luci-mod-status',b'luci-mod-network',b'luci-mod-system'])
            runner=HELPER.with_name('run.sh').read_text()
            self.assertIn('run_package_batches "$RUN/openwrt" "$RUN/luci" "$RUN/packages" build_core_package',runner)
            self.assertNotIn('package/feeds/luci/luci-mod-admin-full/compile',runner)

    def test_runner_loop_stops_on_callback_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); openwrt=root/'openwrt'; luci=root/'luci'; packages=root/'packages'
            (openwrt/'feeds').mkdir(parents=True); (openwrt/'package/feeds/luci').mkdir(parents=True)
            luci.mkdir(); packages.mkdir()
            (openwrt/'feeds/luci').symlink_to(luci,target_is_directory=True)
            (openwrt/'feeds/packages').symlink_to(packages,target_is_directory=True)
            for pkg in ('luci-mod-status','luci-mod-network','luci-mod-system','luci-mod-admin-full'):
                target=luci/'modules'/pkg; target.mkdir(parents=True)
                (openwrt/'package/feeds/luci'/pkg).symlink_to(target,target_is_directory=True)
            called=root/'called.txt'
            script='set -e; source "$HELPER"; callback(){ printf "%s\n" "$1" >> "$ROOT/called.txt"; [[ "$1" != luci-mod-network ]] || return 37; }; run_package_batches "$ROOT/openwrt" "$ROOT/luci" "$ROOT/packages" callback'
            result=subprocess.run(['bash','-c',script],env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve())},capture_output=True)
            self.assertEqual(result.returncode,37,result.stderr)
            self.assertEqual(called.read_text().splitlines(),['luci-mod-status','luci-mod-network'])

    def test_stage_ambiguity_is_visible(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            paths=[root/f'build_dir/{arch}/luci-mod-system/ipkg-all/luci-mod-system' for arch in ('target-a','target-b')]
            for p in paths:
                p.mkdir(parents=True)
            found=self.run_find(root,'find_package_stage "$ROOT" luci-mod-system')
            self.assertEqual(set(found),{os.fsencode(p.resolve()) for p in paths})

if __name__ == '__main__': unittest.main()
