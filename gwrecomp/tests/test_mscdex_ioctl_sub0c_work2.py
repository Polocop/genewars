import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from dos_services import CpuRegs, DosHost  # noqa: E402
from guest_boot import prepare_guest  # noqa: E402

class MscdexSub0CTests(unittest.TestCase):
    def dispatch(self, data, metadata=(0x40, 1, 1, 0, 0, 0, 0, 2, 0)):
        packet = bytearray(26)
        packet[0] = 0x1a
        packet[2] = 3
        struct.pack_into('<HHH', packet, 0x0e, 0, 0x2107, len(data))
        host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'), cdrom_drives=('D',),
                       cdrom_audio_subchannel=metadata)
        return host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3, es=0x2104),
                             device_request_address=0x21040, device_request=bytes(packet),
                             device_transfer_address=0x21070, device_transfer=data)

    def test_idle_disc_subchannel_is_explicit_and_writes_full_ten_fields(self):
        result = self.dispatch(bytes.fromhex('0c052a3436000000000000'))
        self.assertTrue(result.handled)
        self.assertEqual(result.service, 'int2f.mscdex_ioctl_audio_subchannel')
        writes = dict(result.guest_writes)
        self.assertEqual(writes[0x21070], bytes.fromhex('0c40010100000000000200'))
        self.assertEqual(writes[0x21043], struct.pack('<H', 0x0100))

    def test_missing_metadata_and_wrong_length_trap(self):
        bad = self.dispatch(bytes.fromhex('0c00000000000000000000'), metadata=None)
        self.assertFalse(bad.handled)
        wrong = self.dispatch(bytes.fromhex('0c00000000000000'))
        self.assertFalse(wrong.handled)

    def test_original_replay_freshness_and_next_frontier(self):
        e = json.loads((ROOT / 'evidence/mscdex_ioctl_sub0c_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(e['target_sha256'], '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        # W2-061 checkpoint; current runtime freshness is asserted by the later 0x04 replay.
        events = e['cdrom_request_events']
        self.assertEqual(events[-2]['real_mode_interrupt']['service'], 'int2f.mscdex_ioctl_audio_subchannel')
        self.assertEqual(events[-2]['guest_writes'][0]['data_hex'], '0c40010100000000000200')
        self.assertEqual(events[-1]['real_mode_interrupt']['device_request']['transfer_before_hex'], '040000010002000300')
        self.assertEqual(e['executed_instruction_count'], 7_768_190)
        self.assertIn('subfunction 04', e['first_unsupported']['reason'])

if __name__ == '__main__':
    unittest.main()
