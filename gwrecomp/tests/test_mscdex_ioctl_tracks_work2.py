import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = {
    1: (0, 2, 0, 0x40),
    2: (26, 38, 22, 0),
    3: (3, 45, 31, 0),
    4: (2, 38, 41, 0),
    5: (42, 52, 54, 0),
}

class MscdexAllTracksReplayTests(unittest.TestCase):
    def test_cue_metadata_and_replay_to_next_subfunction(self):
        disk = json.loads((ROOT / 'evidence/genewars_cd_audio_info_work2.json').read_text(encoding='utf-8'))
        tracks = disk['track_info']
        self.assertEqual(len(tracks), 5)
        for entry in tracks:
            n = entry['track']
            msf = entry['start_red_book_msf']
            self.assertEqual((msf['frame'], msf['second'], msf['minute'], entry['attribute']), EXPECTED[n])
        self.assertEqual(disk['cue_sha256'], '1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5')
        e = json.loads((ROOT / 'evidence/mscdex_ioctl_tracks_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(e['target_sha256'], '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        # This trace is the W2-060 checkpoint. Later runtime freshness is checked by the 0C trace test.
        events = e['cdrom_request_events']
        self.assertEqual([x['real_mode_interrupt']['device_request']['transfer_before_hex'][:2] for x in events],
                         ['0a', '0b', '0b', '0b', '0b', '0b', '0c'])
        for n, event in enumerate(events[1:6], 1):
            req = event['real_mode_interrupt']['device_request']['transfer_before_hex']
            writes = event['guest_writes'][0]['data_hex']
            frame, second, minute, attr = EXPECTED[n]
            self.assertEqual(req[0:4], f'0b{n:02x}')
            self.assertEqual(writes, f'0b{n:02x}{frame:02x}{second:02x}{minute:02x}00{attr:02x}')
        self.assertEqual(e['executed_instruction_count'], 7_767_996)
        self.assertEqual(e['first_unsupported']['reason'], 'MSCDEX IOCTL input subfunction 0c is not implemented')
        self.assertEqual(e['first_unsupported']['eip'], '0x001d23a7')

if __name__ == '__main__':
    unittest.main()
