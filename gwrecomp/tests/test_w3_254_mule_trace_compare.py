import unittest

from tools.w3_254_mule_trace_compare import reduce_events, normalized_pair


class W3254MuleTraceCompareTests(unittest.TestCase):
    def test_pairs_only_ordered_open_then_close(self):
        events = [
            {"sequence": 1, "event": "dos_handle_open", "path": "GENEWARS\\DATA\\CREATURE\\MULE.ANB", "requested_path": "C:\\GENEWARS\\data\\creature\\mule.anb", "entry": 5, "internal_handle": 4, "flags": 64, "process_psp": 7811},
            {"sequence": 2, "event": "dos_handle_close", "path": "GENEWARS\\DATA\\CREATURE\\MULE.ANB", "entry": 5, "internal_handle": 4, "process_psp": 7811},
        ]
        result = reduce_events(events)
        self.assertEqual(result["complete_pair_count"], 1)
        self.assertEqual(result["operations"][0]["requested_path"], "C:\\GENEWARS\\data\\creature\\mule.anb")

    def test_unclosed_open_is_not_a_complete_pair(self):
        events = [{"sequence": 1, "event": "dos_handle_open", "path": "GENEWARS\\DATA\\CREATURE\\MULE.ANB"}]
        self.assertEqual(reduce_events(events)["complete_pair_count"], 0)

    def test_pair_fingerprint_ignores_sequence_but_keeps_guest_identity(self):
        pair = {"open": {"sequence": 10, "process_psp": 7, "requested_path": "C:\\x", "path": "x", "entry": 2, "internal_handle": 3, "flags": 64},
                "close": {"sequence": 11, "process_psp": 7, "path": "x", "entry": 2, "internal_handle": 3}}
        pair2 = {"open": {**pair["open"], "sequence": 90}, "close": {**pair["close"], "sequence": 91}}
        self.assertEqual(normalized_pair(pair), normalized_pair(pair2))


if __name__ == "__main__":
    unittest.main()
