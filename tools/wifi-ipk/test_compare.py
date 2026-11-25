import io
import json
import pathlib
import tarfile
import tempfile
import unittest
import compare


def tar(entries):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as t:
        for name, data in entries:
            info=tarfile.TarInfo(name)
            if data is None:
                info.type=tarfile.SYMTYPE; info.linkname='target'; t.addfile(info)
            else:
                info.size=len(data); t.addfile(info,io.BytesIO(data))
    return out.getvalue()

def archive(entries):
    control=tar([('control',b'Package: wifi-scripts\nVersion: 1.0-r1\nArchitecture: all\n')])
    return tar([('debian-binary',b'2.0\n'),('control.tar.gz',control),('data.tar.gz',tar(entries))])

class ComparatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        self.oracle=json.loads((compare.HERE/'oracle.json').read_text())
        self.src={r['source_path']:('ucode '+str(i)).encode() for i,r in enumerate(self.oracle['selected'])}
        self.src[compare.SHELL]=b'#!/bin/sh\n'
        for r in self.oracle['selected']:
            # Use synthetic source bytes while preserving source-derived identities and partition.
            b=self.src[r['source_path']]
            if not r['stage_path'].endswith('.uc'):
                b=b'#!/usr/bin/env ucode\n'+b; self.src[r['source_path']]=b
            r['sha256']=compare.digest(b)
            r['git_blob']=__import__('hashlib').sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
        shell=self.src[compare.SHELL]
        self.oracle['excluded_alternative']['sha256']=compare.digest(shell)
        self.oracle['excluded_alternative']['git_blob']=__import__('hashlib').sha1(b'blob '+str(len(shell)).encode()+b'\0'+shell).hexdigest()
        self.stages={}; self.archives={}; self.configs={}
        for v in (True,False):
            stage=self.root/str(v); stage.mkdir(); self.stages[v]=stage
            entries=[]
            for row in self.oracle['selected']:
                if not v and row['config_condition']=='CONFIG_WIFI_SCRIPTS_UCODE=y': continue
                p=row['stage_path']; b=self.src[row['source_path']]; entries.append((p,b))
            if not v: entries.append((compare.COLLISION,self.src[compare.SHELL]))
            for p,b in entries:
                f=stage/p; f.parent.mkdir(parents=True,exist_ok=True); f.write_bytes(b)
            a=self.root/(str(v)+'.ipk'); a.write_bytes(archive(entries)); self.archives[v]=a
            c=self.root/(str(v)+'.config'); c.write_text('CONFIG_TARGET_x86=y\nCONFIG_TARGET_x86_64=y\nCONFIG_PACKAGE_wifi-scripts=m\n# CONFIG_USE_APK is not set\n'+('CONFIG_WIFI_SCRIPTS_UCODE=y\n' if v else '# CONFIG_WIFI_SCRIPTS_UCODE is not set\n')); self.configs[v]=c
    def run_comparison(self):
        return compare.compare(self.oracle,self.src.__getitem__,self.stages,self.archives,self.configs)
    def test_pass(self):
        result=self.run_comparison(); self.assertEqual(len(result['y']['ucode_members']),17); self.assertEqual(len(result['n']['ucode_members']),7)
    def test_changed_stage_rejected(self):
        (self.stages[True]/compare.COLLISION).write_bytes(b'bad')
        with self.assertRaises(ValueError): self.run_comparison()
    def test_collision_wrong_variant_rejected(self):
        (self.stages[False]/compare.COLLISION).write_bytes(self.src[self.oracle['selected'][0]['source_path']])
        with self.assertRaises(ValueError): self.run_comparison()
    def test_duplicate_and_extra_member_rejected(self):
        for entries in [[('x.uc',b'x'),('x.uc',b'x')],[('extra.uc',b'x')]]:
            self.archives[True].write_bytes(archive(entries))
            with self.assertRaises(ValueError): self.run_comparison()
    def test_nonregular_extra_ucode_member_rejected(self):
        entries=[(r['stage_path'],self.src[r['source_path']]) for r in self.oracle['selected']]
        self.archives[True].write_bytes(archive(entries+[('extra.uc',None)]))
        with self.assertRaisesRegex(ValueError,'nonregular Ucode-suffix'):
            self.run_comparison()
    def test_config_difference_rejected(self):
        with self.configs[False].open('a') as f: f.write('CONFIG_OTHER=y\n')
        with self.assertRaises(ValueError): self.run_comparison()
    def test_source_mutation_rejected(self):
        self.src[self.oracle['selected'][1]['source_path']]=b'mutated'
        with self.assertRaises(ValueError): self.run_comparison()

if __name__=='__main__': unittest.main()
