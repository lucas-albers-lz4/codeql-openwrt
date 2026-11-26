import gzip
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import compare


def tar_bytes(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:') as tf:
        for name, body, mode in entries:
            item = tarfile.TarInfo(name)
            item.mode = mode
            if body is None:
                item.type = tarfile.DIRTYPE
                tf.addfile(item)
            else:
                item.size = len(body)
                tf.addfile(item, io.BytesIO(body))
    return gzip.compress(raw.getvalue(), mtime=0)


def ipk(control, data):
    ctl = tar_bytes([('./control', control, 0o644)])
    dat = tar_bytes(data)
    return tar_bytes([('./debian-binary', b'2.0\n', 0o644),
                      ('./control.tar.gz', ctl, 0o644),
                      ('./data.tar.gz', dat, 0o644)])


class CoreBatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.openwrt = self.base / 'openwrt'
        self.openwrt.mkdir()
        self.packages = self.base / 'packages'
        self.packages.mkdir()
        self.luci = self.base / 'luci'
        self.luci.mkdir()
        self.oracle = {'rows': [], 'recipes': {pkg:{'recipe':'modules/'+pkg+'/Makefile', 'recipe_blob':'recipe', 'recipe_sha256':'0'*64, 'projected_pkg_src_version':'26.284.22350~8125d12'} for pkg in compare.PACKAGE_NAMES}}
        self.sources = {}
        self.fixtures = {}
        specs = {
            'luci-mod-status': [
                ('modules/luci-mod-status/ucode/template/admin_status/index.ut',
                 'usr/share/ucode/luci/template/admin_status/index.ut', b'{# selected markup #}\n', 0o644, 'selected_markup_candidate'),
                ('modules/luci-mod-status/root/usr/libexec/syslog-wrapper',
                 'usr/libexec/syslog-wrapper', b'#!/bin/sh\necho status\n', 0o755, 'extensionless_unknown_shell'),
            ],
            'luci-mod-network': [
                ('modules/luci-mod-network/root/etc/uci-defaults/50_luci-mod-admin-full',
                 'etc/uci-defaults/50_luci-mod-admin-full', b'#!/bin/sh\necho defaults\n', 0o755, 'extensionless_unknown_shell'),
                ('modules/luci-mod-network/root/usr/libexec/luci-peeraddr',
                 'usr/libexec/luci-peeraddr', b'#!/bin/sh\necho peer\n', 0o755, 'extensionless_unknown_shell'),
                ('modules/luci-mod-network/htdocs/luci-static/resources/view/network/fixture.js',
                 'www/luci-static/resources/view/network/fixture.js', b'export default 1;\n', 0o644, 'auxiliary_htdocs_js'),
            ],
            'luci-mod-system': [
                ('modules/luci-mod-system/root/usr/share/rpcd/acl.d/luci-mod-system.json',
                 'usr/share/rpcd/acl.d/luci-mod-system.json', b'{"luci.setLocaltime": {}}\n', 0o644, 'auxiliary_acl'),
            ],
        }
        for pkg, rows in specs.items():
            arch = 'x86_64' if pkg == 'luci-mod-status' else 'all'
            build = self.openwrt / 'build_dir' / 'target-x86_64_musl' / pkg
            stage = build / f'ipkg-{arch}' / pkg
            stage.mkdir(parents=True)
            build_files = []
            for src, member, data, mode, classification in rows:
                self.sources[src] = data
                self.put(build / src.split('/', 2)[2], data, mode)
                self.put(stage / member, data, mode)
                self.oracle['rows'].append({'package':pkg, 'source_path':src, 'git_mode':f'100{mode:03o}',
                                            'git_blob':'fixture-blob', 'source_sha256':compare.digest(data),
                                            'size':len(data), 'first_line':data.splitlines()[0].decode(),
                                            'projected_member':member, 'projected_mode':f'{mode:03o}',
                                            'classification':classification})
                build_files.append((member, data, mode))
            if pkg == 'luci-mod-status':
                src = 'modules/luci-mod-status/src/luci-bwc.c'
                data = b'/* build input */\n'
                self.sources[src] = data
                self.put(build / 'src/luci-bwc.c', data, 0o644)
                self.oracle['rows'].append({'package':pkg, 'source_path':src, 'git_mode':'100644',
                                            'git_blob':'fixture-src', 'source_sha256':compare.digest(data),
                                            'size':len(data), 'first_line':'/* build input */',
                                            'projected_member':None, 'projected_mode':None,
                                            'classification':'build_input_not_direct_member'})
                generated = b'compiled fixture binary\n'
                self.put(stage / 'usr/bin/luci-bwc', generated, 0o755)
                build_files.append(('usr/bin/luci-bwc', generated, 0o755))
            control = (f'Package: {pkg}\nVersion: 26.284.22350~8125d12\nArchitecture: {arch}\n').encode()
            self.put(stage / 'CONTROL/control', control, 0o644)
            archive = ipk(control, [(f'./{p}', b, m) for p, b, m in build_files])
            ipk_path = self.base / f'{pkg}.ipk'
            ipk_path.write_bytes(archive)
            self.fixtures[pkg] = (stage, ipk_path)
        self.config = {'js_minification':'# CONFIG_LUCI_JSMIN is not set',
                       'css_tidy':'# CONFIG_LUCI_CSSTIDY is not set'}

    def put(self, path, data, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def run_package(self, pkg):
        stage, ipk_path = self.fixtures[pkg]
        return compare.compare_package(pkg, self.oracle, self.luci, stage, ipk_path, self.config)

    def patch_source(self):
        def source_blob(repo, path, mode, blob, sha):
            return self.sources.get(path, b'')
        return patch.object(compare, 'source_blob', side_effect=source_blob)

    def test_positive_three_package_packets_and_unknown_status_binary(self):
        with self.patch_source():
            results = {pkg:self.run_package(pkg) for pkg in compare.PACKAGE_NAMES}
        self.assertEqual(set(results), set(compare.PACKAGE_NAMES))
        status = results['luci-mod-status']
        generated = {x['path']:x for x in status['generated_or_unclassified_members']}
        self.assertEqual(generated['usr/bin/luci-bwc']['status'], 'observed_generated_build_artifact_no_source_projection')
        self.assertEqual(generated['usr/bin/luci-bwc']['mode'], '0755')
        self.assertEqual(len(results['luci-mod-network']['route_expectations']), 3)
        self.assertIn('usr/share/rpcd/acl.d/luci-mod-system.json',
                      [x['projected_member'] for x in results['luci-mod-system']['source_mappings']])
        self.assertTrue(any(x['classification'] == 'selected_markup_candidate'
                            for x in status['source_mappings']))
        network_routes=results['luci-mod-network']['route_expectations']
        self.assertEqual(sum(x['source_classification'] == 'extensionless_unknown_shell' for x in network_routes),2)

    def test_rejects_prepared_source_mutation(self):
        with self.patch_source():
            stage, _ = self.fixtures['luci-mod-network']
            prepared = stage.parents[1] / 'root/usr/libexec/luci-peeraddr'
            prepared.write_bytes(b'changed before stage\n')
            with self.assertRaisesRegex(ValueError, 'prepared input differs'):
                self.run_package('luci-mod-network')

    def test_rejects_stage_ipk_byte_and_mode_mismatch(self):
        with self.patch_source():
            stage, _ = self.fixtures['luci-mod-system']
            acl = stage / 'usr/share/rpcd/acl.d/luci-mod-system.json'
            acl.write_bytes(b'changed stage\n')
            with self.assertRaisesRegex(ValueError, 'stage/IPK bytes or mode differ'):
                self.run_package('luci-mod-system')
            acl.write_bytes(b'{"luci.setLocaltime": {}}\n')
            acl.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'stage/IPK bytes or mode differ'):
                self.run_package('luci-mod-system')

    def test_rejects_control_identity_and_missing_acl(self):
        with self.patch_source():
            stage, path = self.fixtures['luci-mod-system']
            wrong = ipk(b'Package: wrong\nVersion: 26.284.22350~8125d12\nArchitecture: all\n',
                        [('./usr/share/rpcd/acl.d/luci-mod-system.json', b'{"luci.setLocaltime": {}}\n', 0o644)])
            path.write_bytes(wrong)
            with self.assertRaisesRegex(ValueError, 'control metadata differs'):
                self.run_package('luci-mod-system')
            path.write_bytes(ipk(b'Package: luci-mod-system\nVersion: 26.284.22350~8125d12\nArchitecture: all\n',
                                 [('./usr/share/rpcd/acl.d/other.json', b'{}\n', 0o644)]))
            (stage / 'usr/share/rpcd/acl.d/luci-mod-system.json').unlink()
            (stage / 'usr/share/rpcd/acl.d/other.json').write_bytes(b'{}\n')
            with self.assertRaisesRegex(ValueError, 'stage/IPK member set differs|missing source-projected member'):
                self.run_package('luci-mod-system')

    def test_rejects_minified_bytes_when_config_says_disabled(self):
        with self.patch_source():
            stage, path = self.fixtures['luci-mod-status']
            markup = 'usr/share/ucode/luci/template/admin_status/index.ut'
            (stage / markup).write_bytes(b'modified template\n')
            # Rebuild a syntactically valid archive with the changed member and keep source/prepared fixed.
            rows = [('usr/share/ucode/luci/template/admin_status/index.ut', b'modified template\n', 0o644),
                    ('usr/libexec/syslog-wrapper', b'#!/bin/sh\necho status\n', 0o755),
                    ('usr/bin/luci-bwc', b'compiled fixture binary\n', 0o755)]
            (stage / 'usr/share/ucode/luci/template/admin_status/index.ut').chmod(0o644)
            path.write_bytes(ipk(b'Package: luci-mod-status\nVersion: 26.284.22350~8125d12\nArchitecture: x86_64\n',
                                 [('./'+p, body, mode) for p, body, mode in rows]))
            with self.assertRaisesRegex(ValueError, 'direct copy/output bytes differ'):
                self.run_package('luci-mod-status')


    def test_minification_enabled_output_is_observed_unknown(self):
        with self.patch_source():
            stage, path = self.fixtures['luci-mod-network']
            js_path='www/luci-static/resources/view/network/fixture.js'
            minified=b'export default 1;'
            (stage/js_path).write_bytes(minified)
            (stage/js_path).chmod(0o644)
            control=b'Package: luci-mod-network\nVersion: 26.284.22350~8125d12\nArchitecture: all\n'
            entries=[]
            for candidate in ('etc/uci-defaults/50_luci-mod-admin-full','usr/libexec/luci-peeraddr',js_path):
                p=stage/candidate; entries.append(('./'+candidate,p.read_bytes(),p.stat().st_mode&0o777))
            path.write_bytes(ipk(control,entries))
            self.config['js_minification']='CONFIG_LUCI_JSMIN=y'
            receipt=self.run_package('luci-mod-network')
            js=next(x for x in receipt['source_mappings'] if x['projected_member']==js_path)
            self.assertEqual(js['transform'],'minification-enabled-output-bytes-unknown')
            self.assertEqual(js['stage_sha256'],compare.digest(minified))

    def test_rejects_duplicate_unselected_archive_member(self):
        with self.patch_source():
            stage,path=self.fixtures['luci-mod-system']
            data=b'{"luci.setLocaltime": {}}\n'
            control=b'Package: luci-mod-system\nVersion: 26.284.22350~8125d12\nArchitecture: all\n'
            path.write_bytes(ipk(control,[('./usr/share/rpcd/acl.d/luci-mod-system.json',data,0o644),
                                           ('usr/share/rpcd/acl.d/luci-mod-system.json',data,0o644)]))
            with self.assertRaisesRegex(ValueError,'duplicate archive path'):
                self.run_package('luci-mod-system')


    def test_rejects_unmapped_ucode_shaped_member_forms(self):
        with self.patch_source():
            stage,path=self.fixtures['luci-mod-system']
            acl='usr/share/rpcd/acl.d/luci-mod-system.json'; body=(stage/acl).read_bytes()
            control=b'Package: luci-mod-system\nVersion: 26.284.22350~8125d12\nArchitecture: all\n'
            candidates=(
                ('usr/share/ucode/luci/new.uc',b'function unexpected() {}\n'),
                ('usr/lib/ucode/luci/generated.ucode',b'function generated() {}\n'),
                ('usr/lib/ucode/luci/generated',b'function generated() {}\n'),
                ('usr/libexec/ucode-helper',b'#!/usr/bin/env -S ucode -S\n'),
            )
            for extra,extra_body in candidates:
                with self.subTest(path=extra):
                    self.put(stage/extra,extra_body,0o644)
                    path.write_bytes(ipk(control,[('./'+acl,body,0o644),('./'+extra,extra_body,0o644)]))
                    with self.assertRaisesRegex(ValueError,'unexpected Ucode-shaped IPK member'):
                        self.run_package('luci-mod-system')
                    (stage/extra).unlink()

    def test_pinned_source_oracle_digest(self):
        good = compare.load_oracle(compare.HERE / 'source-oracle.json')
        self.assertEqual(good['luci_commit'], compare.PINS['luci'])
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / 'bad.json'
            fake.write_bytes((compare.HERE / 'source-oracle.json').read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'SHA-256 differs'):
                compare.load_oracle(fake)


if __name__ == '__main__':
    unittest.main()
