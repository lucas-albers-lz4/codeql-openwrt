import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER=Path(__file__).with_name('run-root.sh').resolve()

class RunRootTests(unittest.TestCase):
    def invoke(self, path):
        return subprocess.run(['bash','-c','source "$HELPER"; create_run_root "$RUN"'],
                              env={**os.environ,'HELPER':str(HELPER),'RUN':str(path)},
                              capture_output=True,text=True)

    def test_exclusive_creation_prevents_existing_output_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()/'attempt'
            first=self.invoke(root)
            self.assertEqual(first.returncode,0,first.stderr)
            sentinel=root/'output/run.log'; sentinel.write_text('preserve me\n')
            second=self.invoke(root)
            self.assertNotEqual(second.returncode,0)
            self.assertEqual(sentinel.read_text(),'preserve me\n')
            self.assertEqual(set(p.name for p in root.iterdir()),{'tmp','home','output'})

    def test_rejects_nonphysical_and_relative_paths_before_creation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            alias=root/'missing'/'..'/'run'
            result=self.invoke(alias)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((root/'run').exists())
            rel=self.invoke(Path('relative-run'))
            self.assertNotEqual(rel.returncode,0)

if __name__ == '__main__': unittest.main()
