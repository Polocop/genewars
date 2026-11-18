import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from dos_cdrom import CueImage
from dos_filesystem import DosFileSystem
from dos_services import CpuRegs, DosHost
from dos_iso9660 import Iso9660Volume
from guest_boot import prepare_guest
from tests.test_iso9660_cue_work2 import Iso9660CueTests


class DosHostCueFilesystemTests(unittest.TestCase):
    def test_host_mounts_cue_iso_and_reads_file_through_dos_fs(self):
        fixture = Iso9660CueTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                       cdrom_drives=('D',), cdrom_images=(fixture.image,))
        self.assertIsNotNone(host.filesystem.iso_volume)
        self.assertIsNone(host.iso_mount_error)
        handle = host.filesystem.open('DATA/TEXT.DAT')
        self.assertEqual(host.filesystem.read(handle, 100), fixture.payload)
        host.filesystem.close(handle)

    def test_explicit_filesystem_mount_is_preserved(self):
        fixture = Iso9660CueTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        explicit = fixture.image
        volume = Iso9660Volume(explicit)
        with tempfile.TemporaryDirectory() as temp:
            fs = DosFileSystem(pathlib.Path(temp), iso_volume=volume)
            host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                           cdrom_drives=('D',), cdrom_images=(explicit,), filesystem=fs)
            self.assertIs(host.filesystem.iso_volume, volume)

    def test_cd_audio_only_keeps_audio_host_and_diagnoses_no_iso(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'audio.bin').write_bytes(bytes(3 * 2352))
            cue = root / 'audio.cue'
            cue.write_text('FILE "audio.bin" BINARY\n TRACK 01 AUDIO\n  INDEX 01 00:00:00\n', encoding='ascii')
            image = CueImage.from_cue(cue)
            host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'),
                           cdrom_drives=('D',), cdrom_images=(image,))
            self.assertIsNone(host.filesystem.iso_volume)
            self.assertIn('no ISO-capable', host.iso_mount_error)
            packet = bytearray(26)
            packet[0], packet[2] = 0x1a, 0x84
            struct.pack_into('<II', packet, 0x0e, 0, 1)
            result = host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3),
                                   device_request_address=0x21040, device_request=bytes(packet))
            self.assertTrue(result.handled, result.trap)


if __name__ == '__main__':
    unittest.main()
