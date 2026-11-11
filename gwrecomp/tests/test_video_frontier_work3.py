import json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class VideoFrontier(unittest.TestCase):
 @classmethod
 def setUpClass(cls): cls.d=json.loads((ROOT/'evidence/video_frontier_work3.json').read_text())
 def test_int_sites_are_deduplicated_and_owned(self):
  d=self.d['closures']; self.assertEqual(d['entry_path_combined']['unique_int10_sites'],[])
  expected=['0x000A3A91','0x000A3AB7']
  self.assertEqual(d['entry_path_closure']['unique_int10_sites'],expected); self.assertEqual(d['broad_282']['unique_int10_sites'],expected)
  self.assertEqual([x['map_owner'] for x in self.d['vesa_page_int10_sites']],['LbVesaSetPage_']*2)
 def test_static_mode_and_framebuffer_candidates(self):
  self.assertEqual(self.d['screen_setup_to_mode_call_sites'],['0x0009FDCC'])
  self.assertEqual(self.d['framebuffer_base_store']['assigned_value'],'0x000A0000')
  self.assertIn('static framebuffer base candidate',self.d['framebuffer_base_store']['meaning'])
  self.assertFalse(self.d['dynamic_gate']['first_visible_menu_observed'])
 def test_callback_and_dynamic_limits_remain_explicit(self):
  self.assertEqual(self.d['callback']['prior_status'],'BLOCKED'); self.assertFalse(self.d['callback']['dynamic_callback_reached'])
  self.assertTrue(self.d['dynamic_gate']['setup_game_fault_precedes_this_video_frontier'])
  self.assertTrue(any(x.startswith('0x000A3A91') for x in self.d['post_W1_033_capture_points']))
if __name__=='__main__':unittest.main()
