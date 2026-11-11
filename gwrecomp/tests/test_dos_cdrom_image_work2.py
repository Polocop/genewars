import pathlib
import hashlib
import json
import tempfile
import unittest

from runtime.dos_cdrom import CueImage, CueImageError

class CueImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.bin = self.root / 'data.bin'
        sector0 = bytes((i & 0xff for i in range(2352)))
        sector1 = bytes([0x5a]) * 2352
        self.bin.write_bytes(sector0 + sector1)
        (self.root / 'disc.cue').write_text('FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n', encoding='ascii')
        self.image = CueImage.from_cue(self.root / 'disc.cue')

    def tearDown(self):
        self.temp.cleanup()

    def test_raw_and_cooked_reads(self):
        raw = self.image.read_sectors(0, 1, raw=True)
        cooked = self.image.read_sectors(0, 1, raw=False)
        self.assertEqual(len(raw), 2352)
        self.assertEqual(len(cooked), 2048)
        self.assertEqual(cooked, raw[16:2064])
        self.assertEqual(self.image.read_sectors(1, 1, raw=False), bytes([0x5a]) * 2048)

    def test_rejects_bounds_and_raw_formats_without_writing_image(self):
        before = self.bin.read_bytes()
        for args in ((-1, 1, False), (0, 0, False), (0, 65, True), (1, 2, True)):
            with self.assertRaises(CueImageError):
                self.image.read_sectors(*args)
        self.assertEqual(self.bin.read_bytes(), before)

    def test_original_read_only_disc_track1_sector(self):
        cue = pathlib.Path(r'E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue')
        if not cue.is_file():
            self.skipTest('read-only reference CD fixture is unavailable')
        image = CueImage.from_cue(cue)
        evidence = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'evidence/mscdex_read_long_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(hashlib.sha256(cue.read_bytes()).hexdigest(), evidence['cue_sha256'])
        self.assertEqual(len(image.tracks), 5)
        raw = image.read_sectors(0, 1, raw=True)
        cooked = image.read_sectors(0, 1, raw=False)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), evidence['probe']['raw_sha256'])
        self.assertEqual(hashlib.sha256(cooked).hexdigest(), evidence['probe']['cooked_sha256'])

if __name__ == '__main__':
    unittest.main()
