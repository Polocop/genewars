import json,unittest
from tools.w3_278_play_smk_branch import analyze,parse
class CorrectLatchBranchTests(unittest.TestCase):
 def rows(self):
  rows=[{'event':'main_mapping','mapping_matches':True,'code_rebase':0x1EB000}]
  for n,e,link in [(10,'w3_278_later_play_smk_entry',0xAE2D0),(11,'w3_278_global_load',0xAE2DF),(12,'w3_278_branch_test',0xAE2E1),(13,'w3_278_branch_target',0xAE2E8)]:
   rows.append({'event':e,'sequence':n,'link_va':link,'runtime_linear':0x1EB000+link,'code_rebase':0x1EB000,'cs':0x160,'eax':1,'ebx':0,'ecx':0x55,'edx':0,'esi':2,'edi':3,'ebp':4,'esp':5,'eflags':0x202})
  return rows
 def test_later_entry_then_global_and_taken_buffer_branch(self):
  a=analyze(parse(b'\n'.join(json.dumps(x).encode() for x in self.rows())))
  self.assertTrue(a['ordered']); self.assertTrue(a['branch_capture_complete']); self.assertEqual(a['missing_events'],[]); self.assertEqual(a['global_value_ecx'],'0x00000055'); self.assertEqual(a['branch_path'],'via_buffer')
 def test_bad_mapping_rejected(self):
  rows=self.rows(); rows[-1]['runtime_linear']+=1
  with self.assertRaisesRegex(ValueError,'runtime mapping mismatch'): analyze(rows)
 def test_missing_checkpoint_kept_unknown(self):
  rows=self.rows()[:2]
  a=analyze(rows); self.assertIsNone(a['branch_destination']); self.assertEqual(a['branch_path'],'unknown'); self.assertFalse(a['branch_capture_complete']); self.assertIn('w3_278_branch_target',a['missing_events'])
if __name__=='__main__':unittest.main()
