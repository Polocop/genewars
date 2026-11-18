import unittest
from tools.w3_276_play_smk_entry_comparison import compare
class PlaySmkEntryComparisonTests(unittest.TestCase):
 def test_only_shared_registers_are_compared(self):
  a={'eax':1,'esi':5,'esp':8,'stack':[1,2]}; b={'eax':1,'esi':20,'esp':8}
  r=compare(a,b)
  self.assertEqual(r['different_fields'],['esi'])
  self.assertNotIn('stack',r['common_fields'])
 def test_empty_common_state_does_not_invent_differences(self):
  self.assertEqual(compare({'eax':1},{'ebx':2}),{'common_fields':{},'different_fields':[]})
 def test_same_state_reports_equal(self):
  r=compare({'eax':3,'eflags':0x202},{'eax':3,'eflags':0x202})
  self.assertEqual(r['different_fields'],[])
if __name__=='__main__':unittest.main()
