from pathlib import Path
import hashlib, subprocess, tempfile, unittest
from tools.source_policy_drift import analyze, DriftError

class SourcePolicyDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Path(self.tmp.name)/'repo'; self.repo.mkdir()
        self.git('init','-q',str(self.repo)); self.git('-C',str(self.repo),'config','user.email','test@example.invalid'); self.git('-C',str(self.repo),'config','user.name','Test')
        (self.repo/'known.uc').write_text('let a=1;\n'); self.git('-C',str(self.repo),'add','.'); self.git('-C',str(self.repo),'commit','-qm','base'); self.base=self.git('-C',str(self.repo),'rev-parse','HEAD')
        self.manifest={'schema':'mvp-bounded-corpus-v0.4','selected':[{'repo':'luci','source_path':'known.uc','git_blob':self.git('-C',str(self.repo),'rev-parse',f'{self.base}:known.uc'),'source_sha256':hashlib.sha256(b'let a=1;\n').hexdigest(),'expected_route':{'classification':'plain'}}],'excluded':[]}
    def tearDown(self): self.tmp.cleanup()
    @staticmethod
    def git(*args): return subprocess.check_output(['git',*args],text=True).strip()
    def test_added_candidate_fails_closed_and_preserves_baseline_identity(self):
        (self.repo/'new.uc').write_text('let b=2;\n'); self.git('-C',str(self.repo),'add','.'); self.git('-C',str(self.repo),'commit','-qm','incoming'); head=self.git('-C',str(self.repo),'rev-parse','HEAD')
        r=analyze(self.manifest,'luci',self.repo,head)
        self.assertTrue(r['fail_closed']); self.assertEqual(r['drift'][0]['class'],'new_candidate'); self.assertEqual(r['selected_and_excluded_identities'][0]['expected_route']['classification'],'plain')
    def test_changed_selected_path_recalculates_hash_and_blob(self):
        (self.repo/'known.uc').write_text('let a=3;\n'); self.git('-C',str(self.repo),'commit','-qam','change'); head=self.git('-C',str(self.repo),'rev-parse','HEAD')
        r=analyze(self.manifest,'luci',self.repo,head)
        self.assertTrue(r['fail_closed']); self.assertEqual(r['changed_selected_or_excluded'][0]['event_identity']['sha256'],hashlib.sha256(b'let a=3;\n').hexdigest())
    def test_rejects_wrong_checkout_revision(self):
        with self.assertRaisesRegex(DriftError,'git rev-parse'): analyze(self.manifest,'luci',self.repo,'0'*40)
