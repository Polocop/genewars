import unittest
from tools.w3_296_pit_routine_static import classify_refs, decode, named_block
from pathlib import Path
from tools.w3_270_post_present_static_frontier import map_le_link_va

class StaticAuditTests(unittest.TestCase):
    def test_classifies_address_storage_not_as_direct_call(self):
        asm='''func_c41c0:\n mov $func_c4270,%esi\n mov %esi,data_10c82c\n push $func_c4270\n call _VMM_lock_range\n ret\nfunc_c4270:\n ret\n'''
        refs=classify_refs(asm,'func_c4270')
        self.assertEqual([r['kind'] for r in refs],['address_load','address_argument','definition'])
        self.assertFalse(any(r['kind']=='direct_call' for r in refs))

    def test_bounded_disassembly_mapping_contains_pit_instruction(self):
        image=Path('build/dosboxx_oracle/C/GENEWARS/GW.EXE').read_bytes()
        result=decode(image,0xC4180,0xC42F0,(0xC427E,0xC4293))
        self.assertEqual(result['mapping']['object'],1)
        self.assertTrue(any(i['link_va']==0xC427E and i['mnemonic']=='in' for i in result['instructions']))

    def test_named_block_is_bounded_by_next_known_label(self):
        asm='''func_c41c0:\n call timer\n ret\nfunc_c4270:\n in\n ret\n'''
        self.assertEqual(named_block(asm,'func_c41c0',('func_c4270',)),['func_c41c0:',' call timer',' ret'])

if __name__=='__main__': unittest.main()
