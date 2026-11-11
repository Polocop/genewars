import unittest

from tools.w3_141_smacker_frontier import audit, parse_jsonl


class SmackerFrontierTests(unittest.TestCase):
    def test_synthetic_dispatch_observations_and_static_routes(self):
        disasm = """play_smk_: /* 0xae2d0 */
 mov _smack_draw_callback,%ecx
 test $0x84,%bl
 call play_smk_via_buffer
 call play_smk_direct
play_smk_direct: /* 0xae308 */
 call SMACKTOBUFFER
 call LbScreenSwap_
play_smk_via_buffer: /* 0xae4d8 */
 call copy_to_screen
"""
        entry = {"checkpoint": "W3_133_PLAY_SMK_ENTRY", "link_va": 0xAE2D0,
                 "eip": 0x002992D0, "data_rebase": 0x001DA000,
                 "w3_133_draw_callback_valid": True, "w3_133_draw_callback_value": 0,
                 "w3_133_draw_callback_offset": 0x0037A29C, "ebx": 0}
        direct = {"checkpoint": "W3_133_PLAY_SMK_DIRECT_ENTRY", "link_va": 0xAE308,
                  "eip": 0x00299308}
        rows = [entry, direct]
        w3_139 = {"target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
                  "trace": {"copy_to_screen_entry_observed": False}}
        w3_140 = {"source": {"target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"}}
        result = audit(disasm, rows, w3_139, w3_140)
        self.assertEqual(result["same_run_original"]["dispatch_result"], "DIRECT_PLAY_SMK_DIRECT")
        self.assertFalse(result["same_run_original"]["copy_to_screen_entry_observed"])
        self.assertTrue(result["static_route"]["buffered_copy_to_screen"])

    def test_jsonl_cap_and_target_hash_validation(self):
        self.assertEqual(parse_jsonl(b'{"event":"x"}\n'), [{"event": "x"}])
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))


if __name__ == "__main__":
    unittest.main()
