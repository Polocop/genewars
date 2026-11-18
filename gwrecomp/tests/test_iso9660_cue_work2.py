import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from dos_cdrom import CueImage
from dos_iso9660 import Iso9660Error, Iso9660Volume


def dual(value, size):
    half = size // 2
    return value.to_bytes(half, 'little') + value.to_bytes(half, 'big')


def record(name, extent, size, *, directory=False, multi=False):
    ident = name if isinstance(name, bytes) else name.encode('ascii')
    length = 33 + len(ident) + (1 if len(ident) % 2 == 0 else 0)
    out = bytearray(length)
    out[0] = length
    out[2:10] = dual(extent, 8)
    out[10:18] = dual(size, 8)
    out[25] = (2 if directory else 0) | (0x80 if multi else 0)
    out[28:32] = dual(1, 4)
    out[32] = len(ident)
    out[33:33 + len(ident)] = ident
    return bytes(out)


class Iso9660CueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.cue = self.root / 'disc.cue'
        self.bin = self.root / 'disc.bin'
        self.payload = b'GeneWars ISO payload\r\n'
        self._write_iso()
        self.image = CueImage.from_cue(self.cue)

    def tearDown(self):
        self.temp.cleanup()

    def _write_iso(self, *, bad_pvd=False, bad_extent=False, multi=False):
        sectors = [bytearray(2048) for _ in range(40)]
        pvd = sectors[16]
        pvd[0] = 1
        pvd[1:6] = b'XXXXX' if bad_pvd else b'CD001'
        pvd[6] = 1
        pvd[80:88] = dual(40, 8)
        pvd[128:132] = dual(2048, 4)
        pvd[156:190] = record(b'\0', 20, 2048, directory=True)
        sectors[17][0:7] = bytes((255,)) + b'CD001' + bytes((1,))
        sectors[20][0:34] = record(b'\0', 20, 2048, directory=True)
        sectors[20][34:68] = record(b'\1', 20, 2048, directory=True)
        data_dir = record('DATA', 21, 2048, directory=True)
        sectors[20][68:68 + len(data_dir)] = data_dir
        text_extent = 40 if bad_extent else 22
        sectors[21][0:34] = record(b'\0', 21, 2048, directory=True)
        sectors[21][34:68] = record(b'\1', 20, 2048, directory=True)
        data_record = record('TEXT.DAT;1', text_extent, len(self.payload), multi=multi)
        sectors[21][68:68 + len(data_record)] = data_record
        sectors[22][:len(self.payload)] = self.payload
        self.bin.write_bytes(b''.join(sectors))
        self.cue.write_text('FILE "disc.bin" BINARY\n TRACK 01 MODE1/2048\n  INDEX 01 00:00:00\n', encoding='ascii')

    def test_case_insensitive_lookup_version_suffix_and_listing(self):
        volume = Iso9660Volume(self.image)
        self.assertEqual(volume.listdir(), ['DATA'])
        self.assertEqual(volume.listdir('data'), ['TEXT.DAT;1'])
        self.assertEqual(volume.read_file('data/text.dat'), self.payload)
        self.assertEqual(volume.read_file('DATA/TEXT.DAT;1'), self.payload)
        with self.assertRaises(Iso9660Error):
            volume.read_file('../TEXT.DAT')

    def test_rejects_invalid_signature_extent_and_multi_extent(self):
        self._write_iso(bad_pvd=True)
        with self.assertRaises(Iso9660Error):
            Iso9660Volume(CueImage.from_cue(self.cue))
        self._write_iso(bad_extent=True)
        with self.assertRaises(Iso9660Error):
            Iso9660Volume(CueImage.from_cue(self.cue)).read_file('DATA/TEXT.DAT')
        self._write_iso(multi=True)
        with self.assertRaises(Iso9660Error):
            Iso9660Volume(CueImage.from_cue(self.cue)).read_file('DATA/TEXT.DAT')

    def test_limits_and_directory_file_type_are_enforced(self):
        with self.assertRaises(ValueError):
            Iso9660Volume(self.image, max_file_bytes=0)
        volume = Iso9660Volume(self.image, max_file_bytes=4)
        with self.assertRaises(Iso9660Error):
            volume.read_file('DATA/TEXT.DAT')
        with self.assertRaises(NotADirectoryError):
            volume.listdir('DATA/TEXT.DAT')


if __name__ == '__main__':
    unittest.main()
