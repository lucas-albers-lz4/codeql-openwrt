import os
from pathlib import Path
import subprocess
import tempfile
import unittest
HELPER=Path(__file__).with_name('locate-paths.sh').resolve()
class LocateTests(unittest.TestCase):
    def test_versioned_stage_and_duplicate_per_feed_ipks(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); stage=root/'build_dir/target/adblock-fast-1.2.4/ipkg-all/adblock-fast/lib/adblock-fast/adblock-fast.uc'
            wrong=root/'build_dir/target/adblock-fast/ipkg-all/adblock-fast/lib/adblock-fast/adblock-fast.uc'
            archive=root/'bin/packages/x86_64/luci/adblock-fast_1.2.4-r4_all.ipk'
            for p in (stage,wrong,archive): p.parent.mkdir(parents=True,exist_ok=True);p.touch()
            result=subprocess.run(['bash','-c','source "$HELPER"; find_service_stage "$ROOT"; find_service_ipk "$ROOT"'],env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root)},capture_output=True,check=True).stdout.split(b'\0')
            self.assertEqual(result[:-1],[os.fsencode(stage),os.fsencode(archive)])
            archive2=root/'bin/packages/x86_64/base/adblock-fast_1.2.4-r4_all.ipk';archive2.parent.mkdir(parents=True,exist_ok=True);archive2.touch()
            got=subprocess.run(['bash','-c','source "$HELPER"; find_service_ipk "$ROOT"'],env={**os.environ,'HELPER':str(HELPER),'ROOT':str(root)},capture_output=True,check=True).stdout.split(b'\0')[:-1]
            self.assertEqual(set(got),{os.fsencode(archive),os.fsencode(archive2)})
if __name__=='__main__':unittest.main()
