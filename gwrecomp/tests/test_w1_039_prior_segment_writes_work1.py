import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class W1039PriorSegmentWritesTests(unittest.TestCase):
    def test_earlier_writes_are_identity_or_untaken(self):
        d=json.loads((ROOT/'evidence/w1_039_prior_segment_writes_work1.json').read_text())
        self.assertEqual(d['target_sha256'],'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        sites={x['site']:x for x in d['prior_segment_sites']}
        self.assertTrue(sites['0x000C389C']['reached'])
        self.assertFalse(sites['0x000C389C']['divergence'])
        self.assertEqual(sites['0x000C389C']['dataflow'],['0x000ADFF8: mov edx, ds','0x000AE002: and edx, 0xffff','0x000C389C: mov ds, edx'])
        self.assertFalse(sites['0x000C3AD4']['reached'])
        self.assertTrue(sites['0x000C3D42']['reached'])
        self.assertTrue(sites['0x000C3D42']['divergence'])
        native=json.loads((ROOT/'evidence/native_w1_037_es_ah49.json').read_text())
        p=native['native_generated_c_progress']
        self.assertEqual(p['dpmi_linear_allocation']['instruction_va'],'0x000C3CC1')
        self.assertEqual(p['dos_ah49_contract_test']['segment_write_fault']['instruction_va'],'0x000C3D42')
if __name__=='__main__': unittest.main()
