import unittest
from tools.audit_main_post_setup_frontier_work3 import run
class MainPostSetupFrontier(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.d=run()
 def test_mapped_symbols_and_ordered_calls(self):
  d=self.d;self.assertTrue(all(x['present'] for x in d['main_map_symbols'].values()))
  self.assertEqual([(x['callee_link_va'],x['callsite_link_va']) for x in d['calls']],[(x['callee_link_va'],x['callsite_link_va']) for x in d['expected_calls']])
 def test_gate_and_dynamic_return_crosscheck(self):
  self.assertEqual((self.d['branch']['oracle_option_gate_locals']['local_64'],self.d['branch']['oracle_option_gate_locals']['local_68']),('01','01'))
  self.assertTrue(self.d['dynamic_return_crosscheck']['matches']);self.assertEqual(self.d['dynamic_return_crosscheck']['link_return'],'0x00094342')
 def test_menu_is_not_inferred(self):
  self.assertFalse(self.d['menu_reached']);self.assertIn('neither PlayIntro entry nor a visible MENU',self.d['interpretation'])
if __name__=='__main__':unittest.main()
