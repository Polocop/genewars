import json,unittest
from tools.w3_275_second_smacker_call import analyze,parse_bounded
class SecondSmackerCallTests(unittest.TestCase):
 def rows(self):
  return [{'event':'main_mapping','mapping_matches':True,'code_rebase':0x1EB000},
   {'event':'w3_269_game_transition_checkpoint','sequence':10,'link_va':0x929D0,'runtime_linear':0x27D9D0,'code_rebase':0x1EB000,'cs':0x160,'eflags':0x246},
   {'event':'w3_275_second_smacker_callsite','sequence':11,'link_va':0x92ADD,'runtime_linear':0x27DADD,'code_rebase':0x1EB000,'cs':0x160,'eflags':0x202},
   {'event':'w3_275_second_smacker_media_entry','sequence':12,'link_va':0xAE2D0,'runtime_linear':0x2992D0,'code_rebase':0x1EB000,'cs':0x160,'eflags':0x202},
   {'event':'w3_275_second_smacker_return','sequence':13,'link_va':0x92AE2,'runtime_linear':0x27DAE2,'code_rebase':0x1EB000,'cs':0x160,'eflags':0x206}]
 def test_bounded_jsonl_and_second_call_order(self):
  raw=b'\n'.join(json.dumps(x).encode() for x in self.rows())
  a=analyze(parse_bounded(raw)); self.assertTrue(a['ordered']); self.assertTrue(a['second_return_92ae2_seen'])
 def test_wrong_runtime_mapping_rejected(self):
  rows=self.rows(); rows[2]['runtime_linear']+=1
  with self.assertRaisesRegex(ValueError,'runtime mapping mismatch'): analyze(rows)
 def test_missing_main_mapping_rejected(self):
  with self.assertRaisesRegex(ValueError,'MAIN mapping'): analyze(self.rows()[1:])
if __name__=='__main__':unittest.main()
