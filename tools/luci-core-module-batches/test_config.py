from pathlib import Path
import tempfile
import unittest
import compare

class ConfigTests(unittest.TestCase):
    def make_config(self, extra=''):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        (root/'.config').write_text('''CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_PACKAGE_luci-mod-status=m
CONFIG_PACKAGE_luci-mod-network=m
CONFIG_PACKAGE_luci-mod-system=m
CONFIG_PACKAGE_luci-base=m
CONFIG_PACKAGE_libiwinfo=m
CONFIG_PACKAGE_rpcd-mod-iwinfo=m
CONFIG_PACKAGE_luci-lib-uqr=m
CONFIG_PER_FEED_REPO=y
CONFIG_USE_APK=n
# CONFIG_LUCI_JSMIN is not set
# CONFIG_LUCI_CSSTIDY is not set
''' + extra)
        return root

    def test_resolved_configuration_records_transform_flags(self):
        facts=compare.config_facts(self.make_config())
        self.assertEqual(facts['target'],'x86_64')
        self.assertEqual(facts['js_minification'],'# CONFIG_LUCI_JSMIN is not set')
        self.assertEqual(facts['css_tidy'],'# CONFIG_LUCI_CSSTIDY is not set')

    def test_rejects_wrong_target_ambiguous_or_admin_full_selection(self):
        root=self.make_config().resolve()
        p=root/'.config'; p.write_text(p.read_text().replace('CONFIG_TARGET_x86=y','CONFIG_TARGET_x=y'))
        with self.assertRaisesRegex(ValueError,'config symbol missing|build config value differs'):
            compare.config_facts(root)
        p.write_text('''CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_PACKAGE_luci-mod-status=m
CONFIG_PACKAGE_luci-mod-network=m
CONFIG_PACKAGE_luci-mod-system=m
CONFIG_PACKAGE_luci-base=m
CONFIG_PACKAGE_libiwinfo=m
CONFIG_PACKAGE_rpcd-mod-iwinfo=m
CONFIG_PACKAGE_luci-lib-uqr=m
CONFIG_PACKAGE_luci-mod-admin-full=m
CONFIG_PER_FEED_REPO=y
CONFIG_USE_APK=n
''')
        with self.assertRaisesRegex(ValueError,'dependency collection only'):
            compare.config_facts(root)

if __name__ == '__main__': unittest.main()
