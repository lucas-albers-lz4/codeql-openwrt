import os
from pathlib import Path
import subprocess
import unittest

HELPER=Path(__file__).with_name('batch-order.sh').resolve()
class OrderTests(unittest.TestCase):
    def run_order(self, fail):
        script='''set -e
source "$HELPER"
for n in build_service build_app verify_service finish_app; do
  eval "$n() { printf '%s\\n' $n; [[ \\\"$FAIL\\\" != $n ]]; }"
done
run_batches
'''
        return subprocess.run(['bash','-c',script],env={**os.environ,'HELPER':str(HELPER),'FAIL':fail},capture_output=True,text=True)
    def test_exact_order(self):
        p=self.run_order('none');self.assertEqual(p.returncode,0);self.assertEqual(p.stdout.splitlines(),['build_service','build_app','verify_service','finish_app'])
    def test_each_failure_stops_later_steps(self):
        steps=['build_service','build_app','verify_service','finish_app']
        for i,step in enumerate(steps):
            with self.subTest(step=step):
                p=self.run_order(step);self.assertNotEqual(p.returncode,0);self.assertEqual(p.stdout.splitlines(),steps[:i+1])
    def test_failure_inside_callback_stops_immediately(self):
        script = "set -e; source \"$HELPER\"; build_service() { echo before; false; echo unsafe; }; build_app() { echo app; }; verify_service() { :; }; finish_app() { :; }; run_batches"
        p=subprocess.run(['bash','-c',script],env={**os.environ,'HELPER':str(HELPER)},capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertEqual(p.stdout.splitlines(),['before'])
if __name__=='__main__':unittest.main()
