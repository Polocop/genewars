import unittest
from tools.w3_274_second_play_smacker import analyze,parse_bounded
class SecondPlaySmackerTests(unittest.TestCase):
 def rows(self):
  return [
   {'event':'main_mapping','mapping_matches':True,'code_rebase':0x1EB000},
   {'event':'w3_269_first_guest_checkpoint_after_present','sequence':1},
   {'event':'w3_269_game_transition_checkpoint','sequence':2,'link_va':0x92996,'runtime_linear':0x27D996,'code_rebase':0x1EB000,'cs':0x160,'eflags':0x246},
   {'event':'w3_269_game_transition_checkpoint','sequence':3,'link_va':0x929D0,'runtime_linear':0x27D9D0,'code_rebase':0x1EB000,'cs':0x160,'eflags':0x202},
  ]
 def test_bounded_jsonl_and_natural_entry_order(self):
  raw=b'\n'.join(__import__('json').dumps(x).encode() for x in self.rows())
  result=analyze(parse_bounded(raw))
  self.assertTrue(result['callsite_92996_seen'])
  self.assertTrue(result['play_smacker_entry_929d0_seen'])
  self.assertEqual([e['link_va'] for e in result['target_checkpoints']],['0x00092996','0x000929D0'])
 def test_bad_rebase_fails_closed(self):
  rows=self.rows(); rows[-1]['runtime_linear']+=1
  with self.assertRaisesRegex(ValueError,'mapping mismatch'): analyze(rows)
 def test_duplicate_mapping_rejected(self):
  rows=self.rows(); rows.append(dict(rows[0]))
  with self.assertRaisesRegex(ValueError,'duplicate mapping'): analyze(rows)
if __name__=='__main__':unittest.main()
