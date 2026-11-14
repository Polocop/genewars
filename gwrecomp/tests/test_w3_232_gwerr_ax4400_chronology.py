import json
import unittest

from tools.w3_232_gwerr_ax4400_chronology import extract_same_run


def fixture_events():
    return [
        {"sequence": 51, "event": "w3_230_gwerr_dos_dispatch_entry",
         "service": "INT21_AH3D", "process_psp": 7811,
         "in_ax": 0x3D01, "requested_path": "GW.ERR"},
        {"sequence": 52, "event": "dos_handle_open", "process_psp": 7811,
         "path": "GENEWARS\\GW.ERR", "requested_path": "gw.err",
         "entry": 2, "internal_handle": 3, "flags": 1},
        {"sequence": 104, "event": "original_cpu_int21_ah44_bx1_entry",
         "process_psp": 7811, "eax": 0x4400, "ebx": 1,
         "mapping_valid": True, "int21_bytes_verified": True,
         "int_instruction_link_va": 0xC8973, "return_link_va": 0xC8975,
         "setup_dos_api_callback_ordinal": 24, "eflags": 0x246},
        {"sequence": 107, "event": "setup_dos_api", "process_psp": 7811,
         "operation": "INT21_AH44", "in_ax": 0x4400, "in_bx": 1,
         "ordinal": 24, "out_ax": 0x80D3, "out_dx": 0x80D3,
         "cf": False, "cwd": "GENEWARS", "resolved_path": "CON"},
    ]


class W3232ChronologyTests(unittest.TestCase):
    def test_correlates_same_psp_order_mapping_and_callback(self):
        result = extract_same_run(fixture_events())
        self.assertTrue(result["same_run"])
        self.assertEqual(result["event_order"], [51, 52, 104, 107])
        self.assertEqual(result["ax4400_bx1_entry"]["int_instruction_link_va"], 0xC8973)
        self.assertEqual(result["ax4400_callback"]["out_ax"], 0x80D3)
        self.assertFalse(result["ax4400_callback"]["cf"])
        self.assertIn("not established", result["limitations"]["causality_from_gwerr_to_ax4400_state"])

    def test_rejects_different_psp_or_wrong_order(self):
        events = fixture_events()
        events[1]["process_psp"] = 9
        with self.assertRaises(ValueError):
            extract_same_run(events)
        events = fixture_events()
        events[2]["sequence"] = 50
        with self.assertRaises(ValueError):
            extract_same_run(events)

    def test_rejects_unmapped_or_wrong_instruction_candidate(self):
        events = fixture_events()
        events[2]["mapping_valid"] = False
        with self.assertRaises(ValueError):
            extract_same_run(events)
        events = fixture_events()
        events[2]["int_instruction_link_va"] = 0xC8975
        with self.assertRaises(ValueError):
            extract_same_run(events)

    def test_result_json_is_bounded_and_valid(self):
        result = extract_same_run(fixture_events())
        encoded = json.dumps(result, ensure_ascii=False).encode("utf-8")
        self.assertLess(len(encoded), 16 * 1024)
        self.assertEqual(json.loads(encoded), result)


if __name__ == "__main__":
    unittest.main()
