import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class MscdexTrackReplayTests(unittest.TestCase):
    def test_track1_reply_and_track2_frontier(self):
        e = json.loads((ROOT / 'evidence/mscdex_ioctl_track_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(e['target_sha256'], '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        for item in e['runtime_files']:
            self.assertEqual(hashlib.sha256((ROOT / item['path']).read_bytes()).hexdigest(), item['sha256'])
        combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n' for x in e['runtime_files']).encode()).hexdigest()
        self.assertEqual(combined, e['runtime_sha256'])
        disc = json.loads((ROOT / 'evidence/genewars_cd_audio_info_work2.json').read_text(encoding='utf-8'))
        track = disc['track_info'][0]
        self.assertEqual((track['track'], track['mode'], track['index_01'], track['attribute']), (1, 'MODE1/2352', '00:00:00', 0x40))
        event = e['cdrom_request_events'][1]
        request = event['real_mode_interrupt']['device_request']
        self.assertEqual((request['command'], request['transfer_length'], request['transfer_before_hex']), (3, 7, '0b01053c263b00'))
        writes = event['guest_writes']
        self.assertEqual(writes[0], {'address': '0x00021070', 'size': 7, 'data_hex': '0b010002000040'})
        self.assertEqual(writes[2], {'address': '0x00021043', 'size': 2, 'data_hex': '0001'})
        frontier = e['cdrom_request_events'][2]['real_mode_interrupt']['device_request']
        self.assertEqual(frontier['transfer_before_hex'], '0b020002000040')
        self.assertEqual(e['executed_instruction_count'], 7_766_883)
        self.assertEqual(e['first_unsupported']['reason'], 'MSCDEX audio-track metadata for track 2 is not configured')
        self.assertEqual(e['first_unsupported']['eip'], '0x001d23a7')

if __name__ == '__main__':
    unittest.main()
