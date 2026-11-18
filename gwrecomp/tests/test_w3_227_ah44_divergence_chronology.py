import json
import unittest
from tools.w3_227_ah44_divergence_chronology import OUT, build_contract

class W3227ChronologyTests(unittest.TestCase):
    def test_original_first_divergence_lifecycle(self):
        d=build_contract()
        self.assertTrue(d['acceptance_checks']['input_target_hashes_match_exact_target'])
        self.assertTrue(d['acceptance_checks']['original_requests_5_6_7_reconciled'])
        self.assertTrue(d['acceptance_checks']['original_ordinal6_is_bx2_and_success'])
        self.assertTrue(d['acceptance_checks']['gw_err_opened_entry2_before_ordinal6'])
        events=d['original_sequence']['lifecycle_before_ordinal6']
        gw=next(x for x in events if x['event']=='dos_handle_open' and x['path'].upper().endswith('GW.ERR'))
        self.assertLess(gw['sequence'],d['original_sequence']['ordinal6']['sequence'])
        self.assertEqual(gw['entry'],2)
    def test_native_comparison_stays_separate_and_bounded(self):
        d=build_contract()
        self.assertTrue(d['acceptance_checks']['native_sixth_request_bx5'])
        self.assertEqual(d['native_comparison']['sixth_original_vs_native_BX'],{'original':2,'native':5})
        self.assertFalse(d['cross_run_scope']['same_run_equivalence'])
        self.assertIn('absence is not established',d['native_comparison']['native_file_lifecycle_coverage'])
        self.assertEqual(d['original_sequence']['direct_caller_ordinal6'][:7],'UNKNOWN')
        self.assertTrue(d['acceptance_checks']['causal_claim_prohibited'])
    def test_output_is_valid_and_repeatable(self):
        first=build_contract()
        second=json.loads(OUT.read_text(encoding='utf-8'))
        self.assertEqual(first,second)
        self.assertEqual(first['evidence_levels'],{'original':'ORIGINAL_OBSERVED','native':'NATIVE_VERIFIED'})
if __name__=='__main__': unittest.main()
