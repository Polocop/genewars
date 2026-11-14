import json, unittest
from pathlib import Path
from tools.audit_this_global_assembly_work3 import ROOT,FILES,audit

class ThisGlobalAssemblyAudit(unittest.TestCase):
 def test_each_closure_counts_instructions_and_classifies_destinations(self):
  for name,rel in FILES.items():
   with self.subTest(name=name):
    result=audit(rel)
    self.assertEqual(result['counts']['read']+result['counts']['write']+result['counts']['other'],len(result['sites']))
    self.assertEqual(result['counts']['write'],0)
    self.assertTrue(result['counts']['read']>0)
    self.assertTrue(all(s['link_va'] and s['instruction'] and s['owner'] for s in result['sites']))
 def test_saved_evidence_reconciles_oracle_and_limits_claim(self):
  ev=json.loads((ROOT/'evidence/this_global_assembly_audit_work3.json').read_text())
  self.assertEqual(ev['oracle_crosscheck']['first_access'],'0x00194b51')
  self.assertEqual(ev['oracle_crosscheck']['fault_eip'],'0x00194b5a')
  self.assertFalse(ev['determination']['closure_has_writer'])
  self.assertIn('does not enumerate all original executable instructions',ev['scope_limit'])
  for key,rel in FILES.items(): self.assertEqual(ev['closures'][key]['sha256'],audit(rel)['sha256'])
if __name__=='__main__': unittest.main()

