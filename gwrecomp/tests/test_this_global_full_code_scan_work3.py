import json,unittest
from tools.scan_this_global_full_code_work3 import ROOT,scan
class FullCodeThisScan(unittest.TestCase):
 @classmethod
 def setUpClass(cls): cls.data=json.loads((ROOT/'evidence/this_global_full_code_scan_work3.json').read_text(encoding='utf-8'))
 def test_hash_scope_counts_and_no_direct_writer(self):
  d=self.data; self.assertEqual(d['target_sha256'],'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
  self.assertGreater(d['unique_decoded_instructions'],0); self.assertEqual(d['unique_decoded_instructions'],len(d['instructions']))
  self.assertEqual(d['counts']['read'],d['unique_decoded_instructions']); self.assertEqual(d['counts']['write'],0); self.assertEqual(d['counts']['unknown'],0)
  self.assertEqual(len({(x['link_va'],x['bytes']) for x in d['instructions']}),d['unique_decoded_instructions'])
 def test_original_probe_matches_static_target_and_fault(self):
  q=self.data['dynamic_oracle']; self.assertEqual(q['target_sha256'],self.data['target_sha256'])
  self.assertEqual((q['first_access'],q['first_access_kind'],q['first_access_old_bytes']),('0x00194b51','read','00000000'))
  self.assertEqual((q['fault_eip'],q['fault_address'],q['fault_edi']),('0x00194b5a','0x00000000','0x00000000'))
  self.assertIn('original-byte',q['probe_command'])
 def test_evidence_reproduces_scan(self):
  d=scan(); self.assertEqual(d['counts'],self.data['counts']); self.assertEqual(d['unique_decoded_instructions'],self.data['unique_decoded_instructions']); self.assertEqual(d['unmatched_displacement_offsets'],self.data['unmatched_displacement_offsets'])
if __name__=='__main__':unittest.main()
