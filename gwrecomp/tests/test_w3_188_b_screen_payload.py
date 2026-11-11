import unittest
from tools.w3_188_b_screen_payload_runner import classify

class BScreenPayloadTests(unittest.TestCase):
    def rows(self, sample='00'*64, **changes):
        rows=[
          {'checkpoint':'W3_188_B_SCREEN_ALLOC_REQUEST','sequence':1,'link_va':0x91e00,'eax':0x4b000},
          {'checkpoint':'W3_188_B_SCREEN_ALLOC_RETURN','sequence':2,'link_va':0x92b82,'eax':0x8b03c8},
          {'checkpoint':'W3_129_B_SCREEN_POST_STORE','sequence':3,'link_va':0x92b87,'eip':0x27db87,'ds_descriptor_valid':True,'ds_base':0,'ds_limit':0xffffffff,'eax':0x8b03c8,'w3_129_b_screen_sample_valid':True,'w3_129_b_screen_value':0x8b03c8,'w3_188_sample_bounds_valid':True,'w3_188_sample_bytes':len(bytes.fromhex(sample)),'w3_188_sample_hex':sample},
          {'checkpoint':'W3_129_MEMORY_FREE_ENTRY','sequence':4,'link_va':0x92030,'eax':0x8b03c8},
        ]
        for k,v in changes.items(): rows[2][k]=v
        return rows

    def test_accepts_only_bounded_same_allocation_chain(self):
        r=classify(self.rows())
        self.assertEqual(r['classification'],'SAMPLE_CAPTURED')
        self.assertEqual(r['sample_bytes'],64)
        self.assertEqual(r['nonzero_bytes'],0)
        self.assertEqual(r['checkpoints']['request']['link_va'],'0x91e00')
        self.assertTrue(r['checkpoints']['store']['ds_descriptor_valid'])

    def test_rejects_oversize_pointer_mismatch_or_reordering(self):
        self.assertEqual(classify(self.rows('00'*65))['classification'],'INCONCLUSIVE')
        self.assertEqual(classify(self.rows(w3_129_b_screen_value=0x8b03c9))['classification'],'INCONCLUSIVE')
        rows=self.rows(); rows[3]['sequence']=0
        self.assertEqual(classify(rows)['classification'],'INCONCLUSIVE')

    def test_missing_event_is_inconclusive(self):
        self.assertEqual(classify([])['classification'],'INCONCLUSIVE')

if __name__=='__main__': unittest.main()



