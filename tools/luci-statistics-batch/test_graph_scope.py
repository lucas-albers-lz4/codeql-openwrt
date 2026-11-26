import unittest
import graph_scope


class GraphScopeTests(unittest.TestCase):
    def test_both_conditional_branches_and_selected_declarations(self):
        data = (b'$(curdir)/feeds/luci/luci-app-statistics/compile += $(if $(CONFIG_PACKAGE_x),$(curdir)/first/compile,$(curdir)/second/compile)\n'
                b'$(curdir)/first/compile += $(curdir)/leaf/compile\n'
                b'$(curdir)/second/compile += $(curdir)/other/compile\n'
                b'prereq-$(CONFIG_PACKAGE_x) += first\n'
                b'package-$(CONFIG_PACKAGE_x) += first\n'
                b'package-$(CONFIG_PACKAGE_z) += unrelated\n')
        result = graph_scope.scope(data, b'CONFIG_PACKAGE_x=y\n')
        self.assertEqual(result, graph_scope.scope(data, b'CONFIG_PACKAGE_x=y\n',
                         roots=('feeds/luci/luci-app-statistics', 'kernel/linux')))
        for roots in ((), ('first', 'first'), ('../bad',), ('$(shell x)',)):
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                graph_scope.scope(data, b'CONFIG_PACKAGE_x=y\n', roots=roots)
        self.assertNotEqual(result, graph_scope.scope(data, b'CONFIG_PACKAGE_x=y\n', roots=('second',)))
        self.assertIn(b'$(curdir)/second/compile', result)
        self.assertIn(b'prereq-$(CONFIG_PACKAGE_x)', result)
        self.assertNotIn(b'package-$(CONFIG_PACKAGE_z)', result)
        changed = data.replace(b'$(curdir)/other/compile', b'$(curdir)/changed/compile')
        self.assertNotEqual(result, graph_scope.scope(changed, b'CONFIG_PACKAGE_x=y\n'))
        condition = data.replace(b'$(CONFIG_PACKAGE_x),$(curdir)/first', b'$(CONFIG_PACKAGE_y),$(curdir)/first', 1)
        self.assertNotEqual(result, graph_scope.scope(condition, b'CONFIG_PACKAGE_x=y\n'))
        duplicate = data + data.splitlines()[0] + b'\n'
        self.assertNotEqual(result, graph_scope.scope(duplicate, b'CONFIG_PACKAGE_x=y\n'))
        self.assertEqual(result, graph_scope.scope(data + b'package-$(CONFIG_PACKAGE_z) += another\n', b'CONFIG_PACKAGE_x=y\n'))
        with self.assertRaisesRegex(ValueError, 'graph path alias'):
            graph_scope.scope(data.replace(b'$(curdir)/leaf/compile', b'$(curdir)/../leaf/compile'), b'CONFIG_PACKAGE_x=y\n')
        with self.assertRaisesRegex(ValueError, 'ASCII LF lines'):
            graph_scope.scope(data.replace(b'\n', b'\r\n', 1), b'CONFIG_PACKAGE_x=y\n')
        with self.assertRaisesRegex(ValueError, 'unknown graph directive'):
            graph_scope.scope(data + b'include attacker.mk\n', b'CONFIG_PACKAGE_x=y\n')
        with self.assertRaisesRegex(ValueError, 'unknown graph dependency'):
            graph_scope.scope(data.replace(b'$(curdir)/leaf/compile', b'$(shell command)'), b'CONFIG_PACKAGE_x=y\n')


if __name__ == '__main__':
    unittest.main()
