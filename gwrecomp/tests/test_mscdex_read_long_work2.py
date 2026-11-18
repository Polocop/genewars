import pathlib
import hashlib
import json
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from dos_cdrom import CueImage
from dos_services import CpuRegs, DosHost
from guest_boot import prepare_guest

class MscdexReadLongTests(unittest.TestCase):
    def setUp(self):
        self.temp = __import__('tempfile').TemporaryDirectory()
        p = pathlib.Path(self.temp.name)
        (p/'data.bin').write_bytes(bytes([0x11])*2352 + bytes([0x22])*2352)
        (p/'disc.cue').write_text('FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n', encoding='ascii')
        self.image = CueImage.from_cue(p/'disc.cue')

    def tearDown(self):
        self.temp.cleanup()

    def request(self, command=0x80, lba=0, count=1, raw=0, image=True):
        packet = bytearray(26)
        packet[0] = 0x1a
        packet[2] = command
        struct.pack_into('<HHH', packet, 0x0e, 0x70, 0x2100, count)
        struct.pack_into('<I', packet, 0x14, lba)
        packet[0x18] = raw
        host = DosHost(prepare_guest(ROOT/'evidence/genewars-1_1.exe'), cdrom_drives=('D',),
                       cdrom_images=(self.image,) if image else ())
        return host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3, es=0x2104),
            device_request_address=0x21040, device_request=bytes(packet), device_transfer_address=0x21070)

    def test_read_long_and_prefetch_write_cooked_and_raw_data(self):
        for command in (0x80, 0x82):
            cooked = self.request(command=command)
            self.assertTrue(cooked.handled)
            self.assertEqual(dict(cooked.guest_writes)[0x21070], bytes([0x11])*2048)
            raw = self.request(command=command, raw=1)
            self.assertTrue(raw.handled)
            self.assertEqual(dict(raw.guest_writes)[0x21070], bytes([0x11])*2352)

    def test_invalid_or_unconfigured_reads_trap_without_fabricating_writes(self):
        for result in (self.request(lba=5), self.request(image=False), self.request(raw=2)):
            self.assertFalse(result.handled)
            self.assertEqual(result.guest_writes, ())

    def test_evidence_fingerprint_matches_runtime_and_target(self):
        evidence = json.loads((ROOT/'evidence/mscdex_read_long_work2.json').read_text(encoding='utf-8'))
        self.assertFalse(evidence['original_byte_replay_issued_read_long'])
        self.assertEqual(hashlib.sha256((ROOT/'evidence/genewars-1_1.exe').read_bytes()).hexdigest(), evidence['target_sha256'])
        for item in evidence['runtime_files']:
            self.assertTrue((ROOT/item['path']).is_file())
            self.assertEqual(len(item['sha256']), 64)
        combined = hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in evidence['runtime_files']).encode()).hexdigest()
        self.assertEqual(combined, evidence['runtime_sha256'])

if __name__ == '__main__':
    unittest.main()
