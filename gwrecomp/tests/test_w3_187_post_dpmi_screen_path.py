import unittest
from tools.w3_187_post_dpmi_screen_path import audit

class PostDpmiScreenPathTests(unittest.TestCase):
    def test_original_order_and_mapping(self):
        d=audit()
        names=[x['name'] for x in d['ordered_checkpoints']]
        self.assertLess(names.index('W3_182_DPMI0300_ENTRY'),names.index('W3_182_DPMI0300_RETURN'))
        self.assertLess(names.index('W3_182_DPMI0300_RETURN'),names.index('MAIN_ENTRY_CHECKPOINT'))
        self.assertLess(names.index('MAIN_ENTRY_CHECKPOINT'),names.index('SETUP_GAME_ENTRY'))
        self.assertLess(names.index('SETUP_GAME_ENTRY'),names.index('PLAYINTRO_ENTRY'))
        self.assertLess(names.index('PLAYINTRO_ENTRY'),names.index('W3_142_SMACKDOFRAME_ENTRY'))
        self.assertLess(names.index('W3_129_B_SCREEN_POST_STORE'),names.index('W3_129_MEMORY_FREE_ENTRY'))
        self.assertTrue(d['mapping']['dpmi_mapping_consistent'])
        self.assertTrue(d['b_screen']['free_matches_pointer'])

    def test_pointer_is_not_misreported_as_pixel_payload(self):
        d=audit()
        self.assertTrue(d['b_screen']['global_read_valid'])
        self.assertFalse(d['b_screen']['pointed_buffer_content_sample_present'])
        self.assertFalse(d['claims']['pixel_payload_observed'])
        self.assertFalse(d['claims']['visible_frame_confirmed'])
        self.assertEqual(d['b_screen']['buffer_pointer'],'0x8b03c8')

if __name__=='__main__': unittest.main()
