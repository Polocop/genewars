import unittest

from tools.w3_132_smacker_alloc_static import TARGET_SHA256, analyze_text


class SmackerAllocStaticTests(unittest.TestCase):
    def test_static_chain_keeps_dynamic_caller_unknown(self):
        disasm = """
play_smk_:\n call   play_smk_via_buffer\n call   play_smk_direct\nplay_smk_direct:\n call   SMACKOPEN\nplay_smk_via_buffer:\n call   SMACKOPEN\n call   LbMemoryAlloc_\nRADMALLOC:\n call   *_smack_malloc\nRADFREE:\n ret\nSMACKOPEN:\n push   $0x4ac\n call   RADMALLOC\nunknown_libname_11:\n ret\n_smack_malloc: /* 0x10b4dc */\n .long   LbMemoryAlloc_\n_smack_free:\n .long   LbMemoryFree_\n"""
        map_text = "0001:000AE308 play_smk_direct\n0001:000AE4D8 play_smk_via_buffer\n0001:000AE63C RADMALLOC\n0001:000C62F0 SMACKOPEN"
        rows = [
            {"event": "target_runtime_checkpoint", "link_va": 0x92ADD, "sequence": 12},
            {"event": "w3_127_target_instruction_restart", "link_va": 0x91E00,
             "eax": 0x4AC, "sequence": 14},
        ]
        result = analyze_text(disasm, map_text, TARGET_SHA256, rows)
        self.assertEqual(result["classification"], "STATIC_PATH_MATCH_DYNAMIC_CALLER_UNPROVEN")
        self.assertTrue(all(result["static"].values()))
        self.assertIsNone(result["dynamic"]["caller_link_va"])
        self.assertFalse(result["dynamic"]["caller_identity_proven"])

    def test_hash_mismatch_fails_closed(self):
        with self.assertRaises(ValueError):
            analyze_text("", "", "0" * 64, [])

    def test_no_allocation_event_is_static_only(self):
        disasm = """
play_smk_:\n call   play_smk_via_buffer\n call   play_smk_direct\nplay_smk_direct:\n call   SMACKOPEN\nplay_smk_via_buffer:\n call   SMACKOPEN\n call   LbMemoryAlloc_\nRADMALLOC:\n call   *_smack_malloc\nRADFREE:\n ret\nSMACKOPEN:\n push   $0x4ac\n call   RADMALLOC\nunknown_libname_11:\n ret\n_smack_malloc: /* 0x10b4dc */\n .long   LbMemoryAlloc_\n_smack_free:\n .long   LbMemoryFree_\n"""
        map_text = "0001:000AE308 play_smk_direct\n0001:000AE4D8 play_smk_via_buffer\n0001:000AE63C RADMALLOC\n0001:000C62F0 SMACKOPEN"
        result = analyze_text(disasm, map_text, TARGET_SHA256, [])
        self.assertEqual(result["classification"], "STATIC_PATH_ONLY")
        self.assertFalse(result["dynamic"]["caller_identity_proven"])


if __name__ == "__main__":
    unittest.main()
