import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HELPER=Path(__file__).with_name('batch-order.sh').resolve()
RUNNER=HELPER.with_name('run.sh')
PACKAGES=['luci-app-ddns','luci-app-advanced-reboot','luci-app-wifihistory']


def fixture(root):
    openwrt=root/'openwrt';luci=root/'luci';packages=root/'packages'
    (openwrt/'feeds').mkdir(parents=True);(openwrt/'package/feeds/luci').mkdir(parents=True);(openwrt/'package/feeds/packages').mkdir(parents=True)
    luci.mkdir();packages.mkdir()
    (openwrt/'feeds/luci').symlink_to(luci,target_is_directory=True)
    (openwrt/'feeds/packages').symlink_to(packages,target_is_directory=True)
    for pkg in (*PACKAGES,'luci-mod-admin-full'):
        recipe=luci/'applications'/pkg if pkg.startswith('luci-app') else luci/'modules'/pkg
        recipe.mkdir(parents=True)
        (openwrt/'package/feeds/luci'/pkg).symlink_to(recipe,target_is_directory=True)
    (packages/'net/ddns-scripts').mkdir(parents=True)
    (openwrt/'package/feeds/packages/ddns-scripts').symlink_to(packages/'net/ddns-scripts',target_is_directory=True)
    return openwrt,luci,packages

class AppBatchLoopTests(unittest.TestCase):
    def test_kernel_prerequisites_precede_serial_apps(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);openwrt,luci,packages=fixture(root)
            script='set -e; source "$HELPER"; kernel(){ printf "%s %s\\n" "$1" "$2" >> "$ROOT/order.txt"; }; app(){ printf "app %s\\n" "$1" >> "$ROOT/order.txt"; }; run_kernel_prelude kernel; run_app_batches "$OPENWRT" "$LUCI" "$PACKAGES" app'
            env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve()),'OPENWRT':str(openwrt.resolve()),'LUCI':str(luci.resolve()),'PACKAGES':str(packages.resolve())}
            result=subprocess.run(['bash','-c',script],check=False,env=env,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((root/'order.txt').read_text().splitlines(),[
                'kernel-compile target/linux/compile',
                'kernel-package-compile package/kernel/linux/compile',
                *['app '+name for name in PACKAGES],
            ])
            runner=RUNNER.read_text()
            self.assertIn('run_kernel_prelude build_kernel_phase',runner)
            self.assertLess(runner.index('run_kernel_prelude build_kernel_phase'),runner.index('run_app_batches "$RUN/openwrt"'))
            self.assertNotIn('NO_DEPS',runner)

    def test_kernel_package_failure_propagates_before_any_app(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);openwrt,luci,packages=fixture(root)
            script='set -e; source "$HELPER"; kernel(){ printf "%s %s\\n" "$1" "$2" >> "$ROOT/order.txt"; [[ "$1" != kernel-package-compile ]] || return 37; }; app(){ printf "app %s\\n" "$1" >> "$ROOT/order.txt"; }; run_kernel_prelude kernel; run_app_batches "$OPENWRT" "$LUCI" "$PACKAGES" app'
            env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve()),'OPENWRT':str(openwrt.resolve()),'LUCI':str(luci.resolve()),'PACKAGES':str(packages.resolve())}
            result=subprocess.run(['bash','-c',script],check=False,env=env,capture_output=True)
            self.assertEqual(result.returncode,37,result.stderr)
            self.assertEqual((root/'order.txt').read_text().splitlines(),[
                'kernel-compile target/linux/compile',
                'kernel-package-compile package/kernel/linux/compile',
            ])

    def test_kernel_compile_failure_skips_kernel_package_and_apps(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);openwrt,luci,packages=fixture(root)
            script='set -e; source "$HELPER"; kernel(){ printf "%s %s\\n" "$1" "$2" >> "$ROOT/order.txt"; return 41; }; app(){ printf "app %s\\n" "$1" >> "$ROOT/order.txt"; }; run_kernel_prelude kernel; run_app_batches "$OPENWRT" "$LUCI" "$PACKAGES" app'
            env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve()),'OPENWRT':str(openwrt.resolve()),'LUCI':str(luci.resolve()),'PACKAGES':str(packages.resolve())}
            result=subprocess.run(['bash','-c',script],check=False,env=env,capture_output=True)
            self.assertEqual(result.returncode,41,result.stderr)
            self.assertEqual((root/'order.txt').read_text().splitlines(),[
                'kernel-compile target/linux/compile',
            ])

    def test_successful_check_and_runner_loop_preserve_name_and_exact_selection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);openwrt,luci,packages=fixture(root)
            script='source "$HELPER"; name=luci-app-ddns; check_inputs "$OPENWRT" "$LUCI" "$PACKAGES"; printf "caller=%s\\n" "$name"; capture(){ check_inputs "$OPENWRT" "$LUCI" "$PACKAGES"; printf "%s\\n" "$1" >> "$ROOT/targets.txt"; }; run_app_batches "$OPENWRT" "$LUCI" "$PACKAGES" capture; printf "after=%s\\n" "$name"'
            env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve()),'OPENWRT':str(openwrt.resolve()),'LUCI':str(luci.resolve()),'PACKAGES':str(packages.resolve())}
            result=subprocess.run(['bash','-c',script],check=False,env=env,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.splitlines(),[b'caller=luci-app-ddns',b'after=luci-app-ddns'])
            self.assertEqual((root/'targets.txt').read_text().splitlines(),PACKAGES)
            runner=RUNNER.read_text()
            self.assertIn('run_app_batches "$RUN/openwrt" "$RUN/luci" "$RUN/packages" build_app_package',runner)
            self.assertIn('local trigger=$1 name',runner)
            self.assertNotIn('package/feeds/luci/luci-mod-admin-full/compile',runner)

    def test_bash_errexit_stops_serial_loop_at_failed_package(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);openwrt,luci,packages=fixture(root)
            script='set -e; source "$HELPER"; callback(){ check_inputs "$OPENWRT" "$LUCI" "$PACKAGES"; printf "%s\\n" "$1" >> "$ROOT/targets.txt"; [[ "$1" != luci-app-advanced-reboot ]] || return 37; }; run_app_batches "$OPENWRT" "$LUCI" "$PACKAGES" callback'
            env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root.resolve()),'OPENWRT':str(openwrt.resolve()),'LUCI':str(luci.resolve()),'PACKAGES':str(packages.resolve())}
            result=subprocess.run(['bash','-c',script],check=False,env=env,capture_output=True)
            self.assertEqual(result.returncode,37,result.stderr)
            self.assertEqual((root/'targets.txt').read_text().splitlines(),PACKAGES[:2])

if __name__=='__main__': unittest.main()
