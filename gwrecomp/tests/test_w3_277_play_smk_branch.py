import json,unittest
from tools.w3_277_play_smk_branch import analyze,parse
class PlaySmkBranchTests(unittest.TestCase):
 def rows(self):
  r=[{'event':'main_mapping','mapping_matches':True,'code_rebase':0x1EB000}]
  for n,event,link in [(1,'w3_277_play_smk_entry',0xAE2D0),(2,'w3_277_play_smk_entry',0xAE2D0),(3,'w3_277_second_global_load',0xAE2DF),(4,'w3_277_branch_test',0xAE2E1),(5,'w3_277_branch_target',0xAE2E8)]:
   r.append({'event':event,'sequence':n,'ordinal':2 if n>1 else 1,'link_va':link,'runtime_linear':0x1EB000+link,'code_rebase':0x1EB000,'cs':0x160,'eax':1,'ebx':0,'ecx':1,'edx':0,'esi':2,'edi':3,'ebp':4,'esp':5,'eflags':0x202})
  return r
 def test_order_and_via_buffer_branch(self):
  a=analyze(parse(b'\n'.join(json.dumps(x).encode() for x in self.rows())))
  self.assertTrue(a['second_invocation_path_complete']); self.assertEqual(a['branch_taken_path'],'via_buffer')
 def test_mapping_mismatch_rejected(self):
  r=self.rows(); r[-1]['runtime_linear']+=1
  with self.assertRaisesRegex(ValueError,'runtime mapping mismatch'): analyze(r)
 def test_missing_mapping_rejected(self):
  with self.assertRaisesRegex(ValueError,'fresh mapping'): analyze(self.rows()[1:])
if __name__=='__main__':unittest.main()
