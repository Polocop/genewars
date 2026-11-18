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


class MscdexStatusGeometryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        (root / 'data.bin').write_bytes(bytes(2 * 2352))
        (root / 'audio.bin').write_bytes(bytes(4 * 2352))
        (root / 'disc.cue').write_text(
            'FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n'
            'FILE "audio.bin" BINARY\n TRACK 02 AUDIO\n  INDEX 01 00:00:00\n', encoding='ascii')
        self.image = CueImage.from_cue(root / 'disc.cue')
        self.host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                            cdrom_drives=('D',), cdrom_images=(self.image,))

    def tearDown(self):
        self.temp.cleanup()

    def ioctl(self, subfunction, payload=b'', length=None):
        if length is None:
            length = {0x06: 5, 0x07: 4, 0x08: 5, 0x09: 2}.get(subfunction, 1 + len(payload))
        data = bytes((subfunction,)) + payload
        data = data[:length].ljust(length, b'\0')
        packet = bytearray(26)
        packet[0], packet[2] = 0x1a, 0x03
        struct.pack_into('<HHH', packet, 0x0e, 0x70, 0x2100, len(data))
        return self.host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3),
            device_request_address=0x21040, device_request=bytes(packet),
            device_transfer_address=0x21070, device_transfer=data)

    def response(self, result):
        self.assertTrue(result.handled, result.trap)
        return dict(result.guest_writes)[0x21070]

    def test_device_status_and_sector_sizes(self):
        self.assertEqual(self.response(self.ioctl(0x06)), struct.pack('<BI', 0x06, 0x314))
        self.assertEqual(self.response(self.ioctl(0x07, b'\0\0\0')), bytes.fromhex('07000008'))
        self.assertEqual(self.response(self.ioctl(0x07, b'\1\0\0')), bytes.fromhex('07013009'))

    def test_volume_frames_and_unchanged_media_status(self):
        self.assertEqual(self.response(self.ioctl(0x08)), struct.pack('<BI', 0x08, 156))
        self.assertEqual(self.response(self.ioctl(0x09)), bytes.fromhex('0900'))

    def test_playing_status_bit_and_invalid_contracts(self):
        packet = bytearray(26)
        packet[0], packet[2] = 0x1a, 0x84
        packet[0x0d] = 0
        struct.pack_into('<II', packet, 0x0e, 2, 2)
        play = self.host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3),
            device_request_address=0x21040, device_request=bytes(packet))
        self.assertTrue(play.handled, play.trap)
        self.assertEqual(self.response(self.ioctl(0x06)), struct.pack('<BI', 0x06, 0x714))
        self.assertFalse(self.ioctl(0x07, b'\2\0\0').handled)
        for sub, size in ((0x06, 4), (0x07, 5), (0x08, 4), (0x09, 1)):
            self.assertFalse(self.ioctl(sub, length=size).handled)
        empty = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'), cdrom_drives=('D',))
        self.host = empty
        self.assertFalse(self.ioctl(0x08).handled)


if __name__ == '__main__':
    unittest.main()
