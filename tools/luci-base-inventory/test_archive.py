import gzip
import io
import tarfile
import unittest
import archive


def pack(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tf:
        for name, kind, body in entries:
            t = tarfile.TarInfo(name)
            t.type = kind
            if kind == tarfile.REGTYPE:
                t.size = len(body)
                tf.addfile(t, io.BytesIO(body))
            else:
                t.linkname = 'target'
                tf.addfile(t)
    return out.getvalue()


def ipk(entries):
    control = pack([('./control', tarfile.REGTYPE, b'Package: luci-base\n')])
    return pack([('./debian-binary', tarfile.REGTYPE, b'2.0\n'),
                 ('./data.tar.gz', tarfile.REGTYPE, pack(entries)),
                 ('./control.tar.gz', tarfile.REGTYPE, control)])


class ArchiveTests(unittest.TestCase):
    def test_extensionless_and_near_miss_enumerated(self):
        _, rows, _ = archive.read_ipk(ipk([('./usr/share/rpcd/ucode/luci', tarfile.REGTYPE, b'code'),
                                        ('./etc/init.d/ucitrack', tarfile.REGTYPE, b'#!/bin/sh\n')]))
        self.assertEqual(rows['usr/share/rpcd/ucode/luci']['bytes'], b'code')
        self.assertEqual(rows['etc/init.d/ucitrack']['bytes'], b'#!/bin/sh\n')
    def test_rejects_duplicate_unselected_alias(self):
        with self.assertRaisesRegex(ValueError, 'duplicate archive path'):
            archive.read_ipk(ipk([('other', tarfile.REGTYPE, b'a'), ('./other', tarfile.REGTYPE, b'b')]))
    def test_rejects_symlink_and_special_even_unselected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'unsupported archive type'):
                archive.read_ipk(ipk([('other', kind, b'')]))
    def test_rejects_unsafe_paths(self):
        for name in ('../x', '/absolute', 'a//b', 'a/./b', 'a\\b'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unsafe archive path'):
                archive.read_ipk(ipk([(name, tarfile.REGTYPE, b'x')]))
    def test_rejects_sparse_even_unselected(self):
        for kind in (tarfile.GNUTYPE_SPARSE, tarfile.CONTTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'unsupported archive type'):
                archive.read_ipk(ipk([('other', kind, b'')]))
    def test_rejects_negative_size(self):
        item = tarfile.TarInfo('bad'); item.size = -1
        raw = item.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024)
        with self.assertRaisesRegex(ValueError, 'negative archive size'):
            archive.members(gzip.compress(raw))
    def test_rejects_nonzero_archive_trailer(self):
        data = pack([('other', tarfile.REGTYPE, b'x')])
        raw = gzip.decompress(data) + b'x' * 512
        with self.assertRaisesRegex(ValueError, 'archive trailer'):
            archive.members(gzip.compress(raw))
    def test_rejects_file_ancestor(self):
        with self.assertRaisesRegex(ValueError, 'file used as directory'):
            archive.read_ipk(ipk([('a', tarfile.REGTYPE, b'a'), ('a/b', tarfile.REGTYPE, b'b')]))
    def test_rejects_duplicate_outer(self):
        with self.assertRaisesRegex(ValueError, 'duplicate archive path'):
            archive.read_ipk(pack([('debian-binary', tarfile.REGTYPE, b'2.0\n'), ('./debian-binary', tarfile.REGTYPE, b'2.0\n')]))

if __name__ == '__main__': unittest.main()
