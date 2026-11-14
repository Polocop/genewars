import pathlib
import hashlib
import json
import sys
import struct
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'runtime'))
from dos_cdrom import CueImage
from dos_services import CpuRegs, DosHost
from guest_boot import prepare_guest

class MscdexAudioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        p = pathlib.Path(self.temp.name)
        (p/'data.bin').write_bytes(bytes([0x44])* (2*2352))
        (p/'audio.bin').write_bytes(bytes([0x77])* (3*2352))
        (p/'disc.cue').write_text(
            'FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n'
            'FILE "audio.bin" BINARY\n TRACK 02 AUDIO\n  INDEX 00 00:00:00\n  INDEX 01 00:00:00\n', encoding='ascii')
        self.image = CueImage.from_cue(p/'disc.cue')
        self.host = DosHost(prepare_guest(ROOT/'evidence/genewars-1_1.exe'), cdrom_drives=('D',), cdrom_images=(self.image,))

    def tearDown(self):
        self.temp.cleanup()

    def request(self, command, start=2, count=2, mode=0):
        packet = bytearray(26)
        packet[0] = 0x1a
        packet[2] = command
        packet[0x0d] = mode
        struct.pack_into('<II', packet, 0x0e, start, count)
        return self.host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3, es=0x2104),
            device_request_address=0x21040, device_request=bytes(packet))

    def test_play_pause_resume_stop_records_logical_audio_without_claiming_samples(self):
        play = self.request(0x84)
        self.assertTrue(play.handled)
        self.assertEqual(play.service, 'int2f.mscdex_play_audio')
        self.assertEqual(self.host.cdrom_audio_states[0].status, 'playing')
        self.assertEqual(self.host.audio_sink.events[-1].operation, 'cd_play')
        self.assertEqual((self.host.audio_sink.events[-1].start_lba, self.host.audio_sink.events[-1].sector_count), (2, 2))
        self.assertEqual(dict(play.guest_writes)[0x21043], struct.pack('<H', 0x0100))
        self.assertTrue(self.request(0x85).handled)
        self.assertEqual(self.host.cdrom_audio_states[0].status, 'paused')
        self.assertEqual(self.host.audio_sink.events[-1].operation, 'cd_pause')
        self.assertTrue(self.request(0x88).handled)
        self.assertEqual(self.host.cdrom_audio_states[0].status, 'playing')
        self.assertEqual(self.host.audio_sink.events[-1].operation, 'cd_resume')
        self.assertTrue(self.request(0x85).handled)
        self.assertTrue(self.request(0x85).handled)
        self.assertEqual(self.host.cdrom_audio_states[0].status, 'stopped')
        self.assertEqual(self.host.audio_sink.events[-1].operation, 'cd_stop')

    def test_rejects_data_track_out_of_range_bad_msf_and_resume_without_pause(self):
        self.assertFalse(self.request(0x84, start=0).handled)
        self.assertFalse(self.request(0x84, start=4, count=2).handled)
        self.assertFalse(self.request(0x84, start=(0<<16)|(2<<8)|0, mode=1).handled)
        self.assertFalse(self.request(0x88).handled)
        self.assertEqual(self.host.audio_sink.events, [])

    def test_red_book_msf_start_maps_back_to_hsg_lba(self):
        result = self.request(0x84, start=0x000202, count=2, mode=1)
        self.assertTrue(result.handled)
        self.assertEqual(self.host.cdrom_audio_states[0].start_lba, 2)

    def test_evidence_fingerprint_is_self_consistent_and_gate_claim_is_false(self):
        evidence = json.loads((ROOT/'evidence/mscdex_audio_work2.json').read_text(encoding='utf-8'))
        self.assertFalse(evidence['original_byte_audio_commands_seen'])
        self.assertFalse(evidence['menu_reached'])
        for item in evidence['runtime_files']:
            self.assertTrue((ROOT/item['path']).is_file())
        combined = hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in evidence['runtime_files']).encode()).hexdigest()
        self.assertEqual(combined, evidence['runtime_sha256'])

if __name__ == '__main__':
    unittest.main()
