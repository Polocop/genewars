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

class MscdexSub04Tests(unittest.TestCase):
    def dispatch(self, data, control=(0, 0, 0, 0, 0, 0, 0, 0)):
        packet = bytearray(26)
        packet[0] = 0x1a
        packet[2] = 3
        struct.pack_into('<HHH', packet, 0x0e, 0, 0x2107, len(data))
        host = DosHost(prepare_guest(ROOT / 'evidence/genewars-1_1.exe'), cdrom_drives=('D',),
                       cdrom_audio_channel_control=control)
        return host.dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3, es=0x2104),
                             device_request_address=0x21040, device_request=bytes(packet),
                             device_transfer_address=0x21070, device_transfer=data)

    def test_four_channel_output_state(self):
        data = bytes.fromhex('040000010002000300')
        result = self.dispatch(data)
        self.assertTrue(result.handled)
        self.assertEqual(result.service, 'int2f.mscdex_ioctl_audio_channel_control')
        writes = dict(result.guest_writes)
        self.assertEqual(writes[0x21070], bytes.fromhex('040000000000000000'))
        self.assertEqual(writes[0x21043], struct.pack('<H', 0x0100))

    def test_explicit_nonzero_channels_and_invalid_length(self):
        data = bytes.fromhex('040000010002000300')
        self.assertEqual(dict(self.dispatch(data, (1, 255, 0, 128, 1, 64, 0, 0)).guest_writes)[0x21070],
                         bytes.fromhex('0401ff008001400000'))
        self.assertFalse(self.dispatch(data[:-1]).handled)

    def test_fresh_original_replay_writes_audio_responses_then_reaches_core_fault(self):
        e = json.loads((ROOT / 'evidence/mscdex_ioctl_sub04_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(e['target_sha256'], '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        for item in e['runtime_files']:
            self.assertTrue((ROOT / item['path']).is_file())
            self.assertEqual(len(item['sha256']), 64)
        combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n' for x in e['runtime_files']).encode()).hexdigest()
        self.assertEqual(combined, e['runtime_sha256'])
        events = e['cdrom_request_events']
        self.assertEqual(events[-2]['real_mode_interrupt']['service'], 'int2f.mscdex_ioctl_audio_subchannel')
        self.assertEqual(events[-1]['real_mode_interrupt']['service'], 'int2f.mscdex_ioctl_audio_channel_control')
        self.assertEqual(events[-1]['guest_writes'][0]['size'], 9)
        self.assertEqual(events[-1]['guest_writes'][0]['data_hex'], '040000000000000000')
        self.assertEqual(e['executed_instruction_count'], 7_771_728)
        self.assertEqual(e['stop_reason'], 'backend_error')
        self.assertEqual((e['first_unsupported']['eip'], e['first_unsupported']['address']), ('0x00194b5a', '0x00000000'))
        self.assertEqual(e['last_guest_instruction']['bytes'], '8807')

if __name__ == '__main__':
    unittest.main()
