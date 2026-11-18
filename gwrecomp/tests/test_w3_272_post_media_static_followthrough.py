from __future__ import annotations
import unittest
from tools.w3_272_post_media_static_followthrough import correlate

class PostMediaStaticFollowthroughTests(unittest.TestCase):
    def test_runtime_mapping_and_order_are_preserved(self):
        rows = [
            {'event':'w3_269_game_transition_checkpoint','sequence':10,'runtime_linear':0x27DAE2,'code_rebase':0x1EB000,'link_va':0x92AE2,'cs':0x160,'eflags':0x206},
            {'event':'w3_269_game_transition_checkpoint','sequence':12,'runtime_linear':0x27D996,'code_rebase':0x1EB000,'link_va':0x92996,'cs':0x160,'eflags':0x202},
        ]
        got = correlate(rows, 0x1EB000)
        self.assertEqual([item['link_va'] for item in got], ['0x00092AE2','0x00092996'])
        self.assertEqual([item['sequence'] for item in got], [10,12])

    def test_mapping_mismatch_fails_closed(self):
        rows = [{'event':'w3_269_game_transition_checkpoint','sequence':1,'runtime_linear':0x27DAE2,'code_rebase':0x1EB000,'link_va':0x92996,'cs':0x160,'eflags':0x206}]
        with self.assertRaisesRegex(ValueError, 'mapping mismatch'):
            correlate(rows, 0x1EB000)

    def test_foreign_mapping_fails_closed(self):
        rows = [{'event':'w3_269_game_transition_checkpoint','sequence':1,'runtime_linear':0x27DAE2,'code_rebase':0x1EA000,'link_va':0x92AE2,'cs':0x160,'eflags':0x206}]
        with self.assertRaisesRegex(ValueError, 'mapping mismatch'):
            correlate(rows, 0x1EB000)

if __name__ == '__main__': unittest.main()
