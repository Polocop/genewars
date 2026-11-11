import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class W1035DynamicReachAuditTests(unittest.TestCase):
    def test_audited_indirect_sites_are_not_claimed_reached(self):
        data=json.loads((ROOT/'evidence/w1_035_dynamic_reach_audit_work1.json').read_text())
        self.assertEqual(data['current_frontier']['instruction_va'],'0x000C3D42')
        self.assertTrue(all(not row['reached'] for row in data['audited_candidate_reachability']))
        self.assertEqual(data['dynamic_chain_instruction_audit']['icall_in_recorded_chain_bodies'],0)
        self.assertFalse(data['dynamic_chain_instruction_audit']['itail_taken_in_recorded_chain'])
        self.assertIn('tests/test_native_guest_trap_wrappers.c', data['differential_tests_prepared_for_when_reached'][0])
        self.assertIn('W1-033',data['classification'])
if __name__=='__main__': unittest.main()
