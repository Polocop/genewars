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


class MscdexIoctlInputTests(unittest.TestCase):
    def host(self, info=(1, 5, 60, 38, 59), track_info=((1, 0, 2, 0, 0x40),)):
        return DosHost(prepare_guest(ROOT / 'evidence' / 'genewars-1_1.exe'),
                       cdrom_drives=('D',), cdrom_audio_disc_info=info, cdrom_audio_track_info=track_info)

    def request(self, subfunction=0x0a, drive=3, declared=7, buf=None):
        packet = bytearray(26)
        packet[0] = 0x1a
        packet[2] = 0x03
        struct.pack_into('<HHH', packet, 0x0e, 0, 0x2107, declared)
        data = bytes((subfunction, 0, 0, 0, 0, 0, 0)) if buf is None else buf
        result = self.host().dispatch(0x2f, CpuRegs(eax=0x1510, ecx=drive, es=0x2104),
            device_request_address=0x21040, device_request=bytes(packet),
            device_transfer_address=0x21070, device_transfer=data)
        return result

    def test_subfunction_0a_emits_audio_disc_info_and_driver_status(self):
        result = self.request()
        self.assertTrue(result.handled)
        self.assertEqual(result.service, 'int2f.mscdex_ioctl_audio_disc_info')
        writes = dict(result.guest_writes)
        self.assertEqual(writes[0x21070], bytes((0x0a, 1, 5, 60, 38, 59, 0)))
        self.assertEqual(writes[0x21041], bytes((0,)))
        self.assertEqual(writes[0x21043], struct.pack('<H', 0x0100))

    def test_subfunction_0b_returns_measured_track1_start_and_attribute(self):
        packet = bytearray(26)
        packet[0] = 0x1a
        packet[2] = 0x03
        struct.pack_into('<HHH', packet, 0x0e, 0, 0x2107, 7)
        data = bytes((0x0b, 1, 0, 0, 0, 0, 0))
        result = self.host().dispatch(0x2f, CpuRegs(eax=0x1510, ecx=3, es=0x2104),
            device_request_address=0x21040, device_request=bytes(packet),
            device_transfer_address=0x21070, device_transfer=data)
        self.assertTrue(result.handled)
        self.assertEqual(result.service, 'int2f.mscdex_ioctl_audio_track_info')
        writes = dict(result.guest_writes)
        self.assertEqual(writes[0x21070], bytes((0x0b, 1, 0, 2, 0, 0, 0x40)))
        self.assertEqual(writes[0x21043], struct.pack('<H', 0x0100))

    def test_other_subfunction_drive_and_length_mismatch_remain_traps(self):
        self.assertFalse(self.request(subfunction=0x0c).handled)
        self.assertFalse(self.request(drive=2).handled)
        self.assertFalse(self.request(declared=8).handled)

    def test_original_byte_replay_writes_measured_buffer_and_stops_at_0b(self):
        e = json.loads((ROOT / 'evidence' / 'mscdex_ioctl_input_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(e['target_sha256'], '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        # Historical pre-0B replay; freshness is verified by the newer track replay test.
        disk = json.loads((ROOT / 'evidence' / 'genewars_cd_audio_info_work2.json').read_text(encoding='utf-8'))
        self.assertEqual((disk['first_track'], disk['last_track'], disk['leadout_msf_red_book']),
                         (1, 5, {'minute': 59, 'second': 38, 'frame': 60}))
        self.assertEqual(sum(x['sectors'] for x in disk['tracks']), disk['leadout_lba'])
        a = e['cdrom_request_events']
        self.assertEqual([x['real_mode_interrupt']['device_request']['transfer_before_hex'][:2] for x in a], ['0a', '0b'])
        writes = a[0]['guest_writes']
        self.assertEqual(writes[0], {'address': '0x00021070', 'size': 7, 'data_hex': '0a01053c263b00'})
        self.assertEqual(writes[2], {'address': '0x00021043', 'size': 2, 'data_hex': '0001'})
        self.assertEqual(a[0]['real_mode_interrupt']['registers_after']['eax'], '0x00001510')
        self.assertEqual(e['executed_instruction_count'], 7_766_670)
        self.assertEqual(e['first_unsupported']['reason'], 'MSCDEX IOCTL input subfunction 0b is not implemented')
        self.assertEqual(e['first_unsupported']['eip'], '0x001d23a7')


if __name__ == '__main__':
    unittest.main()

