import json
import unittest

from tools.w3_213_adjustment_capture import MAX_TRACE_BYTES, parse_jsonl, summarize


def event(name, link, seq, psp=7811):
    return {
        "event": "target_runtime_checkpoint", "checkpoint": name, "link_va": link,
        "sequence": seq, "checkpoint_ordinal": seq, "process_psp": psp, "cs": 352, "eip": link + 0x1EB000,
        "w3_213_data_rebase": 0x1DA000, "w3_213_globals_valid": name != "W3_213_ADJUST_CALLSITE",
        "w3_213_mode_bytes_10b78e_10b790_hex": "010203" if name != "W3_213_ADJUST_CALLSITE" else "",
        "w3_213_size_slot_valid": name != "W3_213_ADJUST_CALLSITE",
    }


class CaptureTests(unittest.TestCase):
    def fixture(self):
        return [
            {"event": "target_code_anchor", "anchor": "MAIN_ENTRY", "link_va": 0xAF96C,
             "measured_address_matches": True, "candidate_rebase": 0x1EB000},
            {"event": "target_code_anchor", "anchor": "CREATE_NEW_NHEAP_ENTRY",
             "link_va": 0xC3D7A, "candidate_rebase": 0x1EB000,
             "measured_address_matches": True, "data_rebase": 0x1DA000},
            event("W3_213_ADJUST_CALLSITE", 0xC3D98, 1),
            event("W3_213_ADJUST_ENTRY", 0xC3F76, 2),
            event("W3_213_ADJUST_RETURN", 0xC3D9D, 3),
        ]

    def test_original_contract_requires_mapping_and_ordered_three_checkpoints(self):
        result = summarize(self.fixture())
        self.assertEqual(result["classification"], "ORIGINAL_ADJUSTAMOUNT_CAPTURED")
        self.assertTrue(result["main_mapping"]["verified_for_all_checkpoints"])
        self.assertEqual(result["main_mapping"]["runtime_rebase"], 0x1EB000)
        self.assertEqual(result["target_count"], 3)

    def test_missing_or_mismapped_event_is_inconclusive(self):
        events = self.fixture()[:-1]
        self.assertEqual(summarize(events)["classification"], "INCONCLUSIVE")
        events[-1]["w3_213_data_rebase"] = 0
        self.assertEqual(summarize(events + [event("W3_213_ADJUST_RETURN", 0xC3D9D, 4)])
                         ["classification"], "INCONCLUSIVE")

    def test_out_of_order_checkpoints_are_inconclusive(self):
        events = self.fixture()
        events[2]["checkpoint_ordinal"] = 4
        self.assertEqual(summarize(events)["classification"], "INCONCLUSIVE")

    def test_trace_cap_and_jsonl(self):
        raw = b"\n".join(json.dumps(row).encode() for row in self.fixture())
        self.assertEqual(len(parse_jsonl(raw)), 5)
        with self.assertRaises(ValueError):
            parse_jsonl(b" " * (MAX_TRACE_BYTES + 1))


if __name__ == "__main__":
    unittest.main()

