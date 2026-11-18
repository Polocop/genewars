import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from dos_filesystem import DosFileSystem, DosFsError
from tests.test_iso9660_cue_work2 import Iso9660CueTests


class DosFilesystemIsoTests(unittest.TestCase):
    def setUp(self):
        fixture = Iso9660CueTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        self.payload = fixture.payload
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name) / 'cdrive'
        self.root.mkdir()
        self.volume = __import__('dos_iso9660').Iso9660Volume(fixture.image)
        self.fs = DosFileSystem(self.root, iso_volume=self.volume)

    def test_iso_file_attributes_access_open_read_seek_and_close(self):
        self.assertTrue(self.fs.access('data/text.dat'))
        self.assertEqual(self.fs.attributes('data/text.dat'), 0x21)
        self.assertEqual(self.fs.attributes('data'), 0x11)
        handle = self.fs.open('DATA/TEXT.DAT;1')
        self.assertEqual(self.fs.read(handle, 6), self.payload[:6])
        self.assertEqual(self.fs.seek(handle, 7), 7)
        self.assertEqual(self.fs.read(handle, 4), self.payload[7:11])
        self.fs.close(handle)
        self.assertFalse(self.fs.access('data/missing.bin'))
        with self.assertRaises(DosFsError):
            self.fs.open('data/text.dat', access='w')
        self.assertEqual(self.volume.read_file('DATA/TEXT.DAT'), self.payload)

    def test_host_file_precedes_iso_and_write_does_not_mutate_iso(self):
        host_dir = self.root / 'GENEWARS' / 'DATA'
        host_dir.mkdir(parents=True)
        (host_dir / 'TEXT.DAT').write_bytes(b'host copy')
        fs = DosFileSystem(self.root, iso_volume=self.volume)
        handle = fs.open('data/text.dat')
        self.assertEqual(fs.read(handle, 20), b'host copy')
        fs.close(handle)
        self.assertEqual(self.volume.read_file('DATA/TEXT.DAT'), self.payload)

    def test_overlay_file_precedes_host_and_iso(self):
        host_dir = self.root / 'GENEWARS' / 'DATA'
        overlay_dir = pathlib.Path(self.temp.name) / 'overlay' / 'GENEWARS' / 'DATA'
        host_dir.mkdir(parents=True)
        overlay_dir.mkdir(parents=True)
        (host_dir / 'TEXT.DAT').write_bytes(b'host copy')
        (overlay_dir / 'TEXT.DAT').write_bytes(b'overlay copy')
        fs = DosFileSystem(self.root, overlay_root=overlay_dir.parents[1], iso_volume=self.volume)
        handle = fs.open('data/text.dat')
        self.assertEqual(fs.read(handle, 20), b'overlay copy')
        fs.close(handle)


if __name__ == '__main__':
    unittest.main()
