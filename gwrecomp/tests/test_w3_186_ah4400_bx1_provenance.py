import unittest
from tools.w3_186_ah4400_bx1_provenance import build_result

class Ax4400Bx1ProvenanceTests(unittest.TestCase):
    def test_original_bx1_contract_is_scoped_and_seed_gap_preserved(self):
        d=build_result()
        self.assertEqual(d['classification'],'ORIGINAL_BX1_CONTRACT_VALID_BUT_NOT_FULL_RUN_EQUIVALENCE')
        self.assertTrue(d['comparison']['same_callsite_and_bx1'])
        self.assertTrue(d['comparison']['same_console_handle_class'])
        self.assertFalse(d['comparison']['full_environment_equivalence'])
        self.assertFalse(d['seed_provenance']['address_txt_original_initial_contents_proven'])
        self.assertFalse(d['new_original_replay_needed'])

    def test_blocked_dependants_are_not_released(self):
        d=build_result()
        self.assertEqual(d['queue_snapshot']['W3-060'],'BLOCKED')
        self.assertEqual(d['queue_snapshot']['W1-043'],'BLOCKED')
        self.assertEqual(d['queue_snapshot']['W2-086'],'READY')

if __name__=='__main__': unittest.main()
