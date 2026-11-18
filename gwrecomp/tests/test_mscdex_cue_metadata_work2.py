import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from dos_cdrom import CueImage
from dos_services import CpuRegs, DosHost
from guest_boot import prepare_guest


class MscdexCueMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        (root / 'data.bin').write_bytes(bytes(2 * 2352))
        (root / 'audio.bin').write_bytes(bytes(4 * 2352))
        (root / 'disc.cue').write_text(
            'FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n'
            'FILE "audio.bin" BINARY\n TRACK 02 AUDIO\n  INDEX 00 00:00:00\n  INDEX 01 00:00:02\n', encoding='ascii')
        self.image = CueImage.from_cue(root / 'disc.cue')
        self.host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                            cdrom_drives=('D',), cdrom_images=(self.image,))

    def tearDown(self):
        self.temp.cleanup()

    def ioctl(self, subfunction, track=0):
        data = bytes((subfunction, track, 0, 0, 0, 0, 0))
        packet = bytearray(26)
        packet[0], packet[2] = 0x1a, 0x03
        struct.pack_into('<HHH', packet, 0x0e, 0, 0x2107, len(data))
        return self.host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3),
            device_request_address=0x21040, device_request=bytes(packet),
            device_transfer_address=0x21070, device_transfer=data)

    def test_disc_and_tracks_derive_red_book_fields_and_track_type(self):
        disc = self.ioctl(0x0a)
        self.assertTrue(disc.handled, disc.trap)
        self.assertEqual(dict(disc.guest_writes)[0x21070], bytes((0x0a, 1, 2, 6, 2, 0, 0)))
        data_track = self.ioctl(0x0b, 1)
        self.assertTrue(data_track.handled, data_track.trap)
        self.assertEqual(dict(data_track.guest_writes)[0x21070], bytes((0x0b, 1, 0, 2, 0, 0, 0x40)))
        audio_track = self.ioctl(0x0b, 2)
        self.assertTrue(audio_track.handled, audio_track.trap)
        self.assertEqual(dict(audio_track.guest_writes)[0x21070], bytes((0x0b, 2, 4, 2, 0, 0, 0)))

    def test_explicit_metadata_overrides_cue_and_missing_cue_traps(self):
        override = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'), cdrom_drives=('D',),
            cdrom_images=(self.image,), cdrom_audio_disc_info=(3, 4, 5, 6, 7),
            cdrom_audio_track_info=((2, 8, 9, 10, 0),))
        self.host = override
        self.assertEqual(dict(self.ioctl(0x0a).guest_writes)[0x21070], bytes((0x0a, 3, 4, 5, 6, 7, 0)))
        self.assertEqual(dict(self.ioctl(0x0b, 2).guest_writes)[0x21070], bytes((0x0b, 2, 8, 9, 10, 0, 0)))
        self.host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'), cdrom_drives=('D',))
        self.assertFalse(self.ioctl(0x0a).handled)
        self.assertFalse(self.ioctl(0x0b, 1).handled)


if __name__ == '__main__':
    unittest.main()
