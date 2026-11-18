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


class MscdexCueSubchannelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        (root / 'data.bin').write_bytes(bytes(2 * 2352))
        (root / 'audio.bin').write_bytes(bytes(4 * 2352))
        (root / 'disc.cue').write_text(
            'FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n'
            'FILE "audio.bin" BINARY\n TRACK 02 AUDIO\n  INDEX 01 00:00:03\n', encoding='ascii')
        self.image = CueImage.from_cue(root / 'disc.cue')
        self.host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                            cdrom_drives=('D',), cdrom_images=(self.image,))

    def tearDown(self):
        self.temp.cleanup()

    def ioctl(self, sub=0x0c, length=11):
        data = bytes((sub,)) + bytes(length - 1)
        packet = bytearray(26)
        packet[0], packet[2] = 0x1a, 0x03
        struct.pack_into('<HHH', packet, 0x0e, 0, 0x2107, len(data))
        return self.host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3),
            device_request_address=0x21040, device_request=bytes(packet),
            device_transfer_address=0x21070, device_transfer=data)

    def test_idle_subchannel_is_derived_from_first_track_index01(self):
        result = self.ioctl()
        self.assertTrue(result.handled, result.trap)
        self.assertEqual(dict(result.guest_writes)[0x21070], bytes.fromhex('0c40010100000000000200'))

    def test_explicit_override_wins_and_active_audio_without_time_traps(self):
        self.host.cdrom_audio_subchannel = (0, 2, 4, 0, 1, 2, 0, 3, 4)
        result = self.ioctl()
        self.assertEqual(dict(result.guest_writes)[0x21070], bytes.fromhex('0c00020400010200000304'))
        self.host.cdrom_audio_subchannel = None
        packet = bytearray(26)
        packet[0], packet[2] = 0x1a, 0x84
        struct.pack_into('<II', packet, 0x0e, 5, 1)
        play = self.host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3),
            device_request_address=0x21040, device_request=bytes(packet))
        self.assertTrue(play.handled, play.trap)
        self.assertFalse(self.ioctl().handled)

    def test_missing_media_and_bad_length_trap(self):
        empty = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'), cdrom_drives=('D',))
        self.host = empty
        self.assertFalse(self.ioctl().handled)
        self.host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                            cdrom_drives=('D',), cdrom_images=(self.image,))
        self.assertFalse(self.ioctl(length=9).handled)


if __name__ == '__main__':
    unittest.main()
